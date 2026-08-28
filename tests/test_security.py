"""Security tests for mjpeg-streamer."""

import pytest
from mjpeg_streamer.cli import _sanitize_source, _validate_url_source, _validate_bounds


class TestURLValidation:
    """Tests for SSRF protection in URL validation."""

    def test_valid_public_urls(self):
        """Valid public URLs should be allowed."""
        valid_urls = [
            "http://example.com/stream",
            "https://camera.example.com/video.mp4",
            "rtsp://stream.example.com/live",
            "rtmp://media.example.com/app/stream",
            "http://8.8.8.8/stream",
            "https://1.1.1.1/video",
        ]
        for url in valid_urls:
            assert _validate_url_source(url) == url

    def test_blocked_private_ips_rfc1918(self):
        """RFC 1918 private IPs should be blocked."""
        private_ips = [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
        ]
        for ip in private_ips:
            with pytest.raises(ValueError, match="private/internal IP"):
                _validate_url_source(f"http://{ip}/stream")

    def test_blocked_loopback(self):
        """Loopback addresses should be blocked."""
        loopback_ips = ["127.0.0.1"]
        for ip in loopback_ips:
            with pytest.raises(ValueError, match="private/internal IP|localhost"):
                _validate_url_source(f"http://{ip}/stream")
        
        # IPv6 loopback and unspecified are blocked by private IP check
        with pytest.raises(ValueError, match="private/internal IP"):
            _validate_url_source("http://[::1]/stream")
        with pytest.raises(ValueError, match="private/internal IP|localhost"):
            _validate_url_source("http://0.0.0.0/stream")

    def test_blocked_localhost_hostname(self):
        """Localhost hostname should be blocked."""
        with pytest.raises(ValueError, match="localhost"):
            _validate_url_source("http://localhost/stream")

    def test_blocked_link_local(self):
        """Link-local addresses should be blocked."""
        with pytest.raises(ValueError, match="private/internal IP"):
            _validate_url_source("http://169.254.1.1/stream")

    def test_blocked_multicast(self):
        """Multicast addresses should be blocked."""
        with pytest.raises(ValueError, match="private/internal IP"):
            _validate_url_source("http://224.0.0.1/stream")

    def test_blocked_metadata_ips(self):
        """Cloud metadata service IPs should be blocked."""
        metadata_ips = [
            "169.254.169.254",  # AWS, GCP, Azure, DigitalOcean
            "169.254.169.253",  # Azure
            "169.254.169.123",  # GCP
        ]
        for ip in metadata_ips:
            with pytest.raises(ValueError, match="private/internal IP|metadata service"):
                _validate_url_source(f"http://{ip}/latest/meta-data/")

    def test_blocked_invalid_schemes(self):
        """Invalid URL schemes should be blocked."""
        invalid_urls = [
            "ftp://example.com/file",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]
        for url in invalid_urls:
            with pytest.raises(ValueError, match="Unsupported URL scheme"):
                _validate_url_source(url)

    def test_sanitize_source_integration(self):
        """Test _sanitize_source integrates URL validation."""
        # Valid sources
        assert _sanitize_source("http://example.com/stream") == "http://example.com/stream"
        assert _sanitize_source("/dev/video0") == "/dev/video0"
        assert _sanitize_source("test.mp4") == "test.mp4"
        
        # Blocked sources
        with pytest.raises(ValueError):
            _sanitize_source("http://192.168.1.100/stream")
        with pytest.raises(ValueError):
            _sanitize_source("http://127.0.0.1/stream")


class TestAuthSecurity:
    """Tests for authentication security."""

    def test_hmac_compare_digest(self):
        """Test timing-safe comparison."""
        import hmac
        
        # Valid token
        assert hmac.compare_digest("secret123", "secret123") is True
        
        # Invalid token
        assert hmac.compare_digest("secret123", "wrong") is False
        
        # Empty token
        assert hmac.compare_digest("", "secret123") is False
        assert hmac.compare_digest("secret123", "") is False

    def test_auth_token_validation(self):
        """Test auth token validation in CLI."""
        from mjpeg_streamer.cli import parse_args
        import sys
        
        # Test valid token
        sys.argv = ["cli.py", "--auth-token", "valid_token123"]
        args = parse_args()
        assert args.auth_token == "valid_token123"
        
        # Test token too short
        sys.argv = ["cli.py", "--auth-token", "short"]
        with pytest.raises(ValueError, match="at least 8 characters"):
            parse_args()
        
        # Test token too long
        sys.argv = ["cli.py", "--auth-token", "a" * 257]
        with pytest.raises(ValueError, match="at most 256 characters"):
            parse_args()
        
        # Test invalid characters
        sys.argv = ["cli.py", "--auth-token", "invalid@token"]
        with pytest.raises(ValueError, match="alphanumeric"):
            parse_args()


class TestInputValidation:
    """Tests for input validation and bounds checking."""

    def test_validate_bounds(self):
        """Test bounds validation helper."""
        assert _validate_bounds(50, 1, 100, "test") == 50
        
        with pytest.raises(ValueError, match="between 1 and 100"):
            _validate_bounds(0, 1, 100, "test")
        
        with pytest.raises(ValueError, match="between 1 and 100"):
            _validate_bounds(101, 1, 100, "test")

    def test_fps_bounds(self):
        """Test FPS bounds in StreamBase."""
        from mjpeg_streamer.stream import StreamBase
        
        # Valid FPS
        stream = StreamBase("test", fps=30)
        assert stream.fps == 30
        
        # Invalid FPS
        with pytest.raises(ValueError, match="FPS must be between 1 and 120"):
            StreamBase("test", fps=0)
        with pytest.raises(ValueError, match="FPS must be between 1 and 120"):
            StreamBase("test", fps=121)

    def test_dimension_bounds(self):
        """Test dimension bounds in Stream."""
        from mjpeg_streamer.stream import Stream
        
        stream = Stream("test")
        
        # Valid dimensions
        stream.set_size((1920, 1080))
        assert stream.size == (1920, 1080)
        
        # Invalid dimensions
        with pytest.raises(ValueError, match="Width must be between 1 and 7680"):
            stream.set_size((0, 1080))
        with pytest.raises(ValueError, match="Width must be between 1 and 7680"):
            stream.set_size((7681, 1080))
        with pytest.raises(ValueError, match="Height must be between 1 and 4320"):
            stream.set_size((1920, 0))
        with pytest.raises(ValueError, match="Height must be between 1 and 4320"):
            stream.set_size((1920, 4321))

    def test_quality_bounds(self):
        """Test quality bounds in Stream."""
        from mjpeg_streamer.stream import Stream
        
        stream = Stream("test")
        
        # Valid quality
        stream.set_quality(50)
        assert stream.quality == 50
        
        # Invalid quality
        with pytest.raises(ValueError, match="Quality must be between 1 and 100"):
            stream.set_quality(0)
        with pytest.raises(ValueError, match="Quality must be between 1 and 100"):
            stream.set_quality(101)

    def test_frame_size_validation(self):
        """Test frame size validation to prevent DoS."""
        from mjpeg_streamer.stream import StreamBase
        import numpy as np
        
        stream = StreamBase("test")
        
        # Normal frame should pass
        normal_frame = np.zeros((480, 640, 3), dtype=np.uint8)
        stream._validate_frame_size(normal_frame)  # Should not raise
        
        # Large frame should fail
        large_frame = np.zeros((5000, 5000, 3), dtype=np.uint8)  # ~75MB
        with pytest.raises(ValueError, match="exceeds maximum allowed"):
            stream._validate_frame_size(large_frame)


class TestRateLimiter:
    """Tests for rate limiting."""

    @pytest.mark.asyncio
    async def test_in_memory_rate_limiter(self):
        """Test in-memory rate limiter."""
        from mjpeg_streamer.server import RateLimiter
        
        rl = RateLimiter(max_requests=5, window_seconds=60)
        
        # First 5 requests should succeed
        for i in range(5):
            assert await rl.is_allowed("192.168.1.1") is True
        
        # 6th request should fail
        assert await rl.is_allowed("192.168.1.1") is False
        
        # Different IP should have separate limit
        assert await rl.is_allowed("192.168.1.2") is True

    @pytest.mark.asyncio
    async def test_redis_rate_limiter_fallback(self):
        """Test Redis rate limiter falls back to in-memory."""
        from mjpeg_streamer.server import RedisRateLimiter
        
        rl = RedisRateLimiter(max_requests=3, window_seconds=60, redis_url=None)
        
        for i in range(3):
            assert await rl.is_allowed("10.0.0.1") is True
        assert await rl.is_allowed("10.0.0.1") is False
        
        await rl.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])