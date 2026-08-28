import argparse
import os
import re
import ssl
import time
from pathlib import Path
from typing import Dict, List, Tuple, Union

from .server import Server
from .stream import AudioStream, ManagedStream


def _sanitize_source(source: Union[int, str]) -> Union[int, str]:
    """Sanitize source input to prevent path traversal and SSRF attacks."""
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
    
    # Validate URL sources to prevent SSRF
    if source.startswith(("rtsp://", "rtmp://", "http://", "https://")):
        return _validate_url_source(source)
    
    # Allow common video device patterns
    if source.startswith(("/dev/video", "v4l2://")):
        return source
    
    # For file paths, ensure they're safe
    if os.path.isabs(source) or source.startswith(("./", "../")):
        # Validate it's a reasonable video file extension or device
        allowed_extensions = {".mp4", ".avi", ".mkv", ".mov", ".flv", ".webm", ".mjpeg", ".mjpg"}
        suffix = source_path.suffix.lower()
        if suffix and suffix not in allowed_extensions:
            raise ValueError(f"Unsupported file extension: {suffix}. Allowed: {allowed_extensions}")
    
    return source


def _validate_url_source(url: str) -> str:
    """Validate URL source to prevent SSRF attacks."""
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValueError(f"Invalid URL: {e}")
    
    # Only allow specific schemes
    allowed_schemes = {"rtsp", "rtmp", "http", "https"}
    if parsed.scheme not in allowed_schemes:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}. Allowed: {allowed_schemes}")
    
    # Block private IP addresses (RFC 1918) to prevent SSRF
    hostname = parsed.hostname
    if hostname:
        import ipaddress
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            # Not an IP address, could be a hostname - allow but could add DNS resolution check
            pass
        else:
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                raise ValueError(f"Access to private/internal IP addresses is blocked: {hostname}")
    
    # Block localhost and local hostnames
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError(f"Access to localhost is blocked: {hostname}")
    
    # Block metadata service IPs (cloud provider metadata endpoints)
    metadata_ips = {
        "169.254.169.254",  # AWS, GCP, Azure, DigitalOcean
        "169.254.169.253",  # Azure
        "169.254.169.123",  # GCP
    }
    if hostname in metadata_ips:
        raise ValueError(f"Access to metadata service IP is blocked: {hostname}")
    
    return url


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
    parser.add_argument(
        "--auth-token",
        type=str,
        default=None,
        help="Authentication token for streams (optional). If set, clients must provide this token via Authorization header (Bearer token). Query parameter tokens are rejected for security.",
    )
    parser.add_argument(
        "--auth-header",
        type=str,
        default="Authorization",
        help="HTTP header name for authentication token (default: Authorization)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=0,
        help="Enable rate limiting: max requests per window (0 to disable, default: 0)",
    )
    parser.add_argument(
        "--rate-limit-window",
        type=int,
        default=60,
        help="Rate limit window in seconds (default: 60)",
    )
    parser.add_argument(
        "--ssl-certfile",
        type=str,
        default=None,
        help="Path to SSL certificate file (PEM format). Enables HTTPS.",
    )
    parser.add_argument(
        "--ssl-keyfile",
        type=str,
        default=None,
        help="Path to SSL private key file (PEM format). Required with --ssl-certfile.",
    )
    parser.add_argument(
        "--ssl-password",
        type=str,
        default=None,
        help="Password for SSL private key (if encrypted).",
    )
    parser.add_argument(
        "--ssl-ca-certs",
        type=str,
        default=None,
        help="Path to CA certificates file for client verification (optional).",
    )
    parser.add_argument(
        "--ssl-verify-mode",
        type=int,
        default=ssl.CERT_NONE,
        help="SSL verify mode: 0=CERT_NONE, 1=CERT_OPTIONAL, 2=CERT_REQUIRED (default: 0).",
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
    args.rate_limit = _validate_bounds(args.rate_limit, 0, 10000, "rate-limit")
    args.rate_limit_window = _validate_bounds(args.rate_limit_window, 1, 3600, "rate-limit-window")
    
    # Validate auth token if provided
    if args.auth_token:
        if len(args.auth_token) < 8:
            raise ValueError("Auth token must be at least 8 characters long")
        if len(args.auth_token) > 256:
            raise ValueError("Auth token must be at most 256 characters long")
        # Only allow alphanumeric and common safe characters
        if not re.match(r"^[a-zA-Z0-9._-]+$", args.auth_token):
            raise ValueError("Auth token can only contain alphanumeric characters, dots, underscores, and hyphens")
    
    # Validate SSL arguments
    if args.ssl_certfile and not args.ssl_keyfile:
        raise ValueError("--ssl-keyfile is required when --ssl-certfile is provided")
    if args.ssl_keyfile and not args.ssl_certfile:
        raise ValueError("--ssl-certfile is required when --ssl-keyfile is provided")
    if args.ssl_certfile and not os.path.isfile(args.ssl_certfile):
        raise ValueError(f"SSL certificate file not found: {args.ssl_certfile}")
    if args.ssl_keyfile and not os.path.isfile(args.ssl_keyfile):
        raise ValueError(f"SSL key file not found: {args.ssl_keyfile}")
    if args.ssl_ca_certs and not os.path.isfile(args.ssl_ca_certs):
        raise ValueError(f"SSL CA certificates file not found: {args.ssl_ca_certs}")
    if not 0 <= args.ssl_verify_mode <= 2:
        raise ValueError("SSL verify mode must be 0 (CERT_NONE), 1 (CERT_OPTIONAL), or 2 (CERT_REQUIRED)")
    
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
    server = Server(
        args.host,
        args.port,
        auth_token=args.auth_token,
        auth_header=args.auth_header,
        enable_rate_limiting=args.rate_limit > 0,
        rate_limit_max=args.rate_limit,
        rate_limit_window=args.rate_limit_window,
        ssl_certfile=args.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile,
        ssl_password=args.ssl_password,
        ssl_ca_certs=args.ssl_ca_certs,
        ssl_verify_mode=args.ssl_verify_mode,
    )

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
