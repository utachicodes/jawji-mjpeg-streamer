import argparse
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Tuple, Union

from .server import Server
from .stream import AudioStream, ManagedStream


def _sanitize_source(source: Union[int, str]) -> Union[int, str]:
    """Sanitize source input to prevent path traversal attacks."""
    if isinstance(source, int):
        if source < 0:
            raise ValueError("Camera index must be non-negative")
        return source
    if not isinstance(source, str):
        raise ValueError("Source must be a string or integer")
    
    # Check for path traversal attempts
    source_path = Path(source)
    try:
        # Resolve the path to check for traversal
        resolved = source_path.resolve()
        # Ensure it's not trying to escape the current directory in a suspicious way
        # Allow relative paths but block obvious traversal patterns
        if ".." in source_path.parts:
            raise ValueError("Path traversal detected in source")
    except (OSError, ValueError):
        # If resolution fails, it might be a URL or device path - allow but validate
        pass
    
    # Block null bytes
    if "\x00" in source:
        raise ValueError("Null byte detected in source")
    
    # Allow common video device patterns and URLs
    if source.startswith(("rtsp://", "rtmp://", "http://", "https://", "/dev/video", "v4l2://")):
        return source
    
    # For file paths, ensure they're safe
    if os.path.isabs(source) or source.startswith(("./", "../")):
        # Validate it's a reasonable video file extension or device
        allowed_extensions = {".mp4", ".avi", ".mkv", ".mov", ".flv", ".webm", ".mjpeg", ".mjpg"}
        suffix = source_path.suffix.lower()
        if suffix and suffix not in allowed_extensions:
            raise ValueError(f"Unsupported file extension: {suffix}. Allowed: {allowed_extensions}")
    
    return source


def _validate_bounds(value: int, min_val: int, max_val: int, name: str) -> int:
    """Validate that a value is within bounds."""
    if not min_val <= value <= max_val:
        raise ValueError(f"{name} must be between {min_val} and {max_val}, got {value}")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--prefix", type=str, default="", help="Name prefix for the streams"
    )
    parser.add_argument(
        "--source",
        "-s",
        action="append",
        nargs="+",
        required=False,
        help="Source(s) to stream (repeatable)",
    )
    parser.add_argument("--width", type=int, default=640)
    parser.add_argument("--height", type=int, default=480)
    parser.add_argument("--quality", "-q", type=int, default=50)
    parser.add_argument("--fps", type=int, default=30)
    parser.add_argument(
        "--show-bandwidth",
        action="store_true",
        help="Shows the bandwidth used by each stream in kilobytes per second",
    )
    parser.add_argument(
        "--audio",
        action="append",
        nargs="?",
        const=None,
        default=None,
        metavar="DEVICE",
        help="Enable audio streaming. Optionally pass a device index (repeatable, e.g. --audio 0 --audio 1)",
    )
    parser.add_argument(
        "--audio-rate",
        type=int,
        default=44100,
        help="Audio sample rate in Hz (default: 44100)",
    )
    parser.add_argument(
        "--audio-channels",
        type=int,
        default=1,
        help="Number of audio channels (default: 1)",
    )
    parser.add_argument(
        "--list-devices",
        action="store_true",
        help="List available audio input devices and exit",
    )
    args: argparse.Namespace = parser.parse_args()
    
    # Validate and sanitize inputs
    args.prefix = re.sub("[^0-9a-zA-Z]+", "_", args.prefix)
    args.prefix = args.prefix[:50]  # Limit prefix length
    
    # Validate numeric bounds
    args.port = _validate_bounds(args.port, 1, 65535, "port")
    args.width = _validate_bounds(args.width, 1, 7680, "width")
    args.height = _validate_bounds(args.height, 1, 4320, "height")
    args.quality = _validate_bounds(args.quality, 1, 100, "quality")
    args.fps = _validate_bounds(args.fps, 1, 120, "fps")
    args.audio_rate = _validate_bounds(args.audio_rate, 8000, 192000, "audio-rate")
    args.audio_channels = _validate_bounds(args.audio_channels, 1, 8, "audio-channels")
    
    args.source = [[0]] if args.source is None else args.source
    args.source = [item for sublist in args.source for item in sublist]
    
    # Sanitize each source
    sanitized_sources = []
    for src in args.source:
        try:
            sanitized = _sanitize_source(src)
            sanitized_sources.append(sanitized)
        except ValueError as e:
            print(f"Warning: Invalid source '{src}': {e}")
    args.source = list(set(sanitized_sources))
    
    # Validate audio device indices
    if args.audio:
        sanitized_audio = []
        for device in args.audio:
            if device is not None:
                try:
                    device_idx = int(device)
                    device_idx = _validate_bounds(device_idx, 0, 100, "audio device index")
                    sanitized_audio.append(device_idx)
                except ValueError as e:
                    print(f"Warning: Invalid audio device '{device}': {e}")
            else:
                sanitized_audio.append(None)
        args.audio = sanitized_audio
    
    return args


def main() -> None:
    args = parse_args()

    if args.list_devices:
        try:
            import pyaudio

            pa = pyaudio.PyAudio()
            print("Audio input devices:\n")
            for i in range(pa.get_device_count()):
                info = pa.get_device_info_by_index(i)
                if info["maxInputChannels"] > 0:
                    print(f"  [{i}] {info['name']}")
                    print(
                        f"       Channels: {int(info['maxInputChannels'])}, "
                        f"Rate: {int(info['defaultSampleRate'])} Hz"
                    )
            pa.terminate()
        except ImportError:
            print("pyaudio is not installed. Install it with: pip install pyaudio")
        return

    size: Tuple[int, int] = (args.width, args.height)
    streams: List[ManagedStream] = []
    audio_streams: List[AudioStream] = []
    server = Server(args.host, args.port)

    if args.show_bandwidth:
        bandwidth: Dict[str, int] = {}

    for source in args.source:
        source_display = (
            re.sub("[^0-9a-zA-Z]+", "_", str(source)) if isinstance(source, str) else source
        )
        stream = ManagedStream(
            f"{args.prefix}{'_' if args.prefix else ''}{source_display!s}",
            source=source,
            size=size,
            quality=args.quality,
            fps=args.fps,
        )
        server.add_stream(stream)
        streams.append(stream)

    if args.audio:
        try:
            for i, device in enumerate(args.audio):
                device_index = device if device is not None else None
                name = (
                    f"{args.prefix}{'_' if args.prefix else ''}audio_{device_index}"
                    if device_index is not None
                    else f"{args.prefix}{'_' if args.prefix else ''}audio"
                )
                audio_stream = AudioStream(
                    name=name,
                    source=device_index,
                    sample_rate=args.audio_rate,
                    channels=args.audio_channels,
                )
                server.add_stream(audio_stream)
                audio_streams.append(audio_stream)
        except ImportError as e:
            print(f"Audio not available: {e}")
        except Exception as e:
            print(f"Audio setup error: {e}")

    try:
        for stream in streams:
            stream.start()
        for astream in audio_streams:
            astream.start()
        server.start()
        while True:
            if args.show_bandwidth:
                for stream in streams:
                    bandwidth[stream.name] = stream.get_bandwidth()
                for astream in audio_streams:
                    bandwidth[astream.name] = astream.get_bandwidth()
                print(
                    f"{' | '.join([f'{k}: {round(v / 1024, 2)} KB/s' for k, v in bandwidth.items()])}",
                    end="\r",
                )
            else:
                time.sleep(1)  # Keep the main thread alive, but don't consume CPU
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print("Error:", e)
    finally:
        for stream in streams:
            stream.stop()
        for astream in audio_streams:
            astream.stop()
        server.stop()


if __name__ == "__main__":
    main()
