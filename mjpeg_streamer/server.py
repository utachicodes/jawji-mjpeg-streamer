import asyncio
import hmac
import ssl
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import List, Optional, Union

import aiohttp
from aiohttp import MultipartWriter, web
from aiohttp.web_runner import GracefulExit
from multidict import MultiDict

from .stream import AudioStream, StreamBase


class RateLimiter:
    """Simple token bucket rate limiter per IP."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: defaultdict[str, List[float]] = defaultdict(list)
        self._lock = asyncio.Lock()
    
    async def is_allowed(self, client_ip: str) -> bool:
        async with self._lock:
            now = time.time()
            # Clean old requests
            self._requests[client_ip] = [
                req_time for req_time in self._requests[client_ip]
                if now - req_time < self.window_seconds
            ]
            if len(self._requests[client_ip]) >= self.max_requests:
                return False
            self._requests[client_ip].append(now)
            return True
    
    def get_remaining(self, client_ip: str) -> int:
        now = time.time()
        recent = [
            req_time for req_time in self._requests[client_ip]
            if now - req_time < self.window_seconds
        ]
        return max(0, self.max_requests - len(recent))


def _security_headers_middleware(app: web.Application, handler):
    async def middleware_handler(request: web.Request) -> web.Response:
        response = await handler(request)
        if hasattr(app, "_server_instance") and app._server_instance._enable_security_headers:
            server = app._server_instance
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Content-Security-Policy"] = server._csp_policy
            if request.url.scheme == "https":
                response.headers["Strict-Transport-Security"] = f"max-age={server._hsts_max_age}; includeSubDomains"
        return response
    return middleware_handler


def _rate_limit_middleware(app: web.Application, handler):
    async def middleware_handler(request: web.Request) -> web.Response:
        if hasattr(app, "_server_instance") and app._server_instance._rate_limiter:
            server = app._server_instance
            client_ip = request.remote or "unknown"
            if not await server._rate_limiter.is_allowed(client_ip):
                return web.Response(
                    status=429,
                    text="Rate limit exceeded",
                    headers={
                        "Retry-After": str(server._rate_limit_window),
                        "X-RateLimit-Limit": str(server._rate_limit_max),
                        "X-RateLimit-Remaining": "0",
                    }
                )
            response = await handler(request)
            response.headers["X-RateLimit-Limit"] = str(server._rate_limit_max)
            response.headers["X-RateLimit-Remaining"] = str(server._rate_limiter.get_remaining(client_ip))
            return response
        return await handler(request)
    return middleware_handler


def _auth_middleware(app: web.Application, handler):
    async def middleware_handler(request: web.Request) -> web.Response:
        if hasattr(app, "_server_instance"):
            server = app._server_instance
            if server._auth_token:
                # Skip auth for root and player page
                if request.path in ("/", "/player"):
                    return await handler(request)
                
                auth_header = request.headers.get(server._auth_header, "")
                # Support Bearer token format
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                else:
                    token = auth_header
                
                # Reject query parameter tokens (security: tokens in URLs are logged)
                if "token" in request.query:
                    return web.Response(
                        status=401,
                        text="Unauthorized: Token in query parameter not allowed",
                        headers={"WWW-Authenticate": f'Bearer realm="mjpeg-streamer"'}
                    )
                
                # Timing-safe comparison to prevent timing attacks
                if not token or not hmac.compare_digest(token, server._auth_token):
                    return web.Response(
                        status=401,
                        text="Unauthorized: Invalid or missing token",
                        headers={"WWW-Authenticate": f'Bearer realm="mjpeg-streamer"'}
                    )
        return await handler(request)
    return middleware_handler


class _StreamHandler:
    def __init__(self, stream: StreamBase, server: "Server") -> None:
        self._stream = stream
        self._server = server

    async def __call__(self, request: web.Request) -> web.StreamResponse:
        viewer_token = request.cookies.get("viewer_token")
        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "multipart/x-mixed-replace;boundary=image-boundary",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
        if self._server._enable_security_headers:
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = self._server._csp_policy
            if request.url.scheme == "https":
                response.headers["Strict-Transport-Security"] = f"max-age={self._server._hsts_max_age}; includeSubDomains"
        try:
            await response.prepare(request)
        except (ConnectionResetError, ConnectionAbortedError, ConnectionError):
            pass
        if not viewer_token:
            viewer_token = await self._stream._add_viewer()
            response.set_cookie("viewer_token", viewer_token)
        elif viewer_token not in self._stream._active_viewers:
            await self._stream._add_viewer(viewer_token)
        try:
            while True:
                try:
                    await asyncio.sleep(1 / self._stream.fps)
                    frame = await self._stream._get_frame()
                    with MultipartWriter(
                        "image/jpeg", boundary="image-boundary"
                    ) as mpwriter:
                        mpwriter.append(
                            frame.tobytes(),
                            MultiDict({"Content-Type": "image/jpeg"}),
                        )
                        await mpwriter.write(response, close_boundary=False)
                    await response.write(b"\r\n")
                except (ConnectionResetError, ConnectionAbortedError, ConnectionError):
                    break
        finally:
            await self._stream._remove_viewer(viewer_token)
        return response


class _AudioHandler:
    def __init__(self, stream: AudioStream, server: "Server") -> None:
        self._stream = stream
        self._server = server

    async def __call__(self, request: web.Request) -> web.StreamResponse:
        viewer_token = request.cookies.get("viewer_token")
        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "audio/wav",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
        if self._server._enable_security_headers:
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = self._server._csp_policy
            if request.url.scheme == "https":
                response.headers["Strict-Transport-Security"] = f"max-age={self._server._hsts_max_age}; includeSubDomains"
        try:
            await response.prepare(request)
        except (ConnectionResetError, ConnectionAbortedError, ConnectionError):
            pass
        if not viewer_token:
            viewer_token = await self._stream._add_viewer()
            response.set_cookie("viewer_token", viewer_token)
        elif viewer_token not in self._stream._active_viewers:
            await self._stream._add_viewer(viewer_token)
        try:
            # Wait for first chunk so the browser gets real audio immediately
            try:
                await asyncio.wait_for(
                    self._stream._first_chunk_ready.wait(), timeout=5.0
                )
            except asyncio.TimeoutError:
                pass
            header = self._stream._make_wav_header_bytes()
            await response.write(header)
            while True:
                try:
                    await asyncio.sleep(
                        1.0 / (self._stream.sample_rate / self._stream.chunk_size)
                    )
                    chunk = self._stream._last_chunk
                    if chunk:
                        await response.write(chunk)
                except (ConnectionResetError, ConnectionAbortedError, ConnectionError):
                    break
        finally:
            await self._stream._remove_viewer(viewer_token)
        return response


class Server:
    def __init__(
        self,
        host: Union[str, List[str,]] = "localhost",
        port: int = 8080,
        *,
        enable_security_headers: bool = True,
        hsts_max_age: int = 31536000,
        csp_policy: Optional[str] = None,
        enable_rate_limiting: bool = False,
        rate_limit_max: int = 100,
        rate_limit_window: int = 60,
        auth_token: Optional[str] = None,
        auth_header: str = "Authorization",
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
        ssl_password: Optional[str] = None,
        ssl_ca_certs: Optional[str] = None,
        ssl_verify_mode: int = ssl.CERT_NONE,
    ) -> None:
        if isinstance(host, str):
            self._host: List[str,] = [
                host,
            ]
        elif isinstance(host, list):
            if "0.0.0.0" in host:
                host = ["0.0.0.0"]
            if "localhost" in host and "127.0.0.1" in host:
                host.remove("localhost")
            self._host = list(set(host))
        self._port = port
        self._enable_security_headers = enable_security_headers
        self._hsts_max_age = hsts_max_age
        self._csp_policy = csp_policy or "default-src 'none'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        self._enable_rate_limiting = enable_rate_limiting
        self._rate_limit_max = rate_limit_max
        self._rate_limit_window = rate_limit_window
        self._rate_limiter: Optional[RateLimiter] = (
            RateLimiter(rate_limit_max, rate_limit_window) if enable_rate_limiting else None
        )
        self._auth_token = auth_token
        self._auth_header = auth_header
        self._ssl_certfile = ssl_certfile
        self._ssl_keyfile = ssl_keyfile
        self._ssl_password = ssl_password
        self._ssl_ca_certs = ssl_ca_certs
        self._ssl_verify_mode = ssl_verify_mode
        self._ssl_context: Optional[ssl.SSLContext] = None
        if ssl_certfile and ssl_keyfile:
            self._ssl_context = self._create_ssl_context()
        self._app: web.Application = web.Application()
        self._app_is_running: bool = False
        self._cap_routes: List[str,] = []
        self._audio_routes: List[str] = []

    def _create_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=self._ssl_certfile,
            keyfile=self._ssl_keyfile,
            password=self._ssl_password,
        )
        if self._ssl_ca_certs:
            context.load_verify_locations(cafile=self._ssl_ca_certs)
            context.verify_mode = self._ssl_verify_mode
        # Modern security settings
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
        return context

    def is_running(self) -> bool:
        return self._app_is_running

    async def __root_handler(self, _) -> web.Response:
        scheme = "https" if self._ssl_context else "http"
        text = "<h2>Available streams:</h2>"
        for route in self._cap_routes:
            text += f"<a href='{scheme}://{self._host[0]}:{self._port}{route}'>{route}</a>\n<br>\n"
        if self._audio_routes:
            text += "<h2>Audio streams:</h2>"
            for route in self._audio_routes:
                text += f"<a href='{scheme}://{self._host[0]}:{self._port}{route}'>{route}</a>\n<br>\n"
        if self._cap_routes and self._audio_routes:
            text += f"<h2><a href='{scheme}://{self._host[0]}:{self._port}/player'>Player (synced audio+video)</a></h2>"
        elif self._audio_routes:
            text += f"<h2><a href='{scheme}://{self._host[0]}:{self._port}/player'>Player</a></h2>"
        return aiohttp.web.Response(text=text, content_type="text/html")

    def add_stream(self, stream: Union[StreamBase, AudioStream]) -> None:
        if self.is_running():
            raise RuntimeError("Cannot add stream after the server has started")
        route = f"/{stream.name}"
        if isinstance(stream, AudioStream):
            if route in self._audio_routes:
                raise ValueError(
                    f"An audio stream with the name {route} already exists"
                )
            self._audio_routes.append(route)
            self._app.router.add_route("GET", route, _AudioHandler(stream, self))
        else:
            if route in self._cap_routes:
                raise ValueError(f"A stream with the name {route} already exists")
            self._cap_routes.append(route)
            self._app.router.add_route("GET", route, _StreamHandler(stream, self))
        if self._audio_routes:
            from .player import PlayerHandler

            self._app.router.add_route("GET", "/player", PlayerHandler(self))

    def __start_func(self) -> None:
        self._app.middlewares.append(_security_headers_middleware)
        if self._enable_rate_limiting:
            self._app.middlewares.append(_rate_limit_middleware)
        if self._auth_token:
            self._app.middlewares.append(_auth_middleware)
        self._app._server_instance = self
        self._app.router.add_route("GET", "/", self.__root_handler)
        if self._audio_routes:
            from .player import PlayerHandler

            self._app.router.add_route("GET", "/player", PlayerHandler(self))
        runner = web.AppRunner(self._app)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, self._host, self._port, ssl_context=self._ssl_context)
        loop.run_until_complete(site.start())
        loop.run_forever()

    def start(self) -> None:
        if not self.is_running():
            thread = threading.Thread(target=self.__start_func, daemon=True)
            thread.start()
            self._app_is_running = True
        else:
            print("\nServer is already running\n")

        scheme = "https" if self._ssl_context else "http"
        for addr in self._host:
            print(f"\nStreams index: {scheme}://{addr}:{self._port!s}")
            print("Available streams:\n")
            for route in self._cap_routes:  # route has a leading slash
                print(f"{scheme}://{addr}:{self._port!s}{route}")
            if self._audio_routes:
                print("\nAudio streams:\n")
                for route in self._audio_routes:
                    print(f"{scheme}://{addr}:{self._port!s}{route}")
                print(f"\nPlayer: {scheme}://{addr}:{self._port!s}/player")
            print("--------------------------------\n")
        print("\nPress Ctrl+C to stop the server\n")

    def stop(self) -> None:
        if self.is_running():
            self._app_is_running = False
            print("\nStopping...\n")
            GracefulExit()
            print("\nServer stopped\n")
        else:
            print("\nServer is not running\n")


class MjpegServer(Server):
    # Alias for Server, to maintain backwards compatibility
    pass
