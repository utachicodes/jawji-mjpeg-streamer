# Security Model

## Threat Model

This document describes the security architecture and threat model for mjpeg-streamer.

### Assets Protected

1. **Video/audio streams** - Prevent unauthorized access
2. **Server resources** - Prevent DoS via resource exhaustion
3. **Network infrastructure** - Prevent SSRF attacks against internal services
4. **Authentication credentials** - Prevent token leakage

### Threat Actors

- **External attackers** - Unauthenticated network attackers
- **Malicious stream sources** - Compromised cameras/RTSP servers
- **Insider threats** - Users with legitimate access attempting privilege escalation

## Security Controls

### Authentication

- **Bearer token authentication** via `Authorization` header only
- **Query parameter tokens rejected** - Tokens in URLs leak in:
  - Server access logs
  - Browser history
  - Referrer headers
  - Proxy logs
- **Timing-safe comparison** using `hmac.compare_digest()`
- **Minimum token length**: 8 characters
- **Maximum token length**: 256 characters
- **Allowed characters**: alphanumeric, dot, underscore, hyphen

### Authorization

- **Per-stream authentication** - Each stream can have its own token
- **Root and player pages exempt** - Allows unauthenticated discovery

### Transport Security (TLS/SSL)

- **TLS 1.2 minimum** - TLS 1.0/1.1 disabled
- **Secure cipher suites only**: ECDHE+AESGCM, ECDHE+CHACHA20, DHE+AESGCM, DHE+CHACHA20
- **Certificate validation** - Optional client certificate verification
- **Self-signed cert support** - For development/testing

### Input Validation

#### URL/Source Validation (SSRF Prevention)

- **Scheme allowlist**: `rtsp`, `rtmp`, `http`, `https`
- **Blocked IP ranges**:
  - RFC 1918 private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Loopback: `127.0.0.0/8`, `::1`
  - Link-local: `169.254.0.0/16`
  - Multicast: `224.0.0.0/4`
  - Reserved: `240.0.0.0/4`
- **Blocked hostnames**: `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`
- **Blocked metadata IPs**: `169.254.169.254`, `169.254.169.253`, `169.254.169.123`
- **Path traversal prevention** for file sources
- **Null byte rejection**

#### Frame/Stream Validation (DoS Prevention)

- **Maximum frame size**: 10 MB
- **Maximum dimensions**: 7680×4320 (8K)
- **Maximum FPS**: 120
- **Minimum FPS**: 1
- **Quality range**: 1-100
- **JPEG header validation** on encoded frames

#### Rate Limiting

- **Sliding window** algorithm (per IP)
- **Configurable limits** per deployment
- **Distributed rate limiting** via Redis (Upstash compatible)
- **Automatic fallback** to in-memory if Redis unavailable
- **Rate limit headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`

### Security Headers

All HTTP responses include:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'none'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains (HTTPS only)
```

### Stream Security

- **Viewer tokens** - Unique per viewer session (UUIDv4)
- **Cookie-based session tracking** - HttpOnly, Secure (HTTPS)
- **Automatic cleanup** on disconnect
- **Bandwidth monitoring** per stream

### Subprocess Safety

- **No shell command execution** - Uses OpenCV and PyAudio directly
- **No `subprocess`, `os.system`, `os.popen`** calls
- **Input sanitization** for all external library calls

## Configuration

### Environment Variables

No secrets in environment variables. All configuration via CLI arguments.

### CLI Arguments

```bash
# Authentication
--auth-token TOKEN        # Bearer token for stream access
--auth-header HEADER      # Custom auth header name (default: Authorization)

# Rate Limiting
--rate-limit N            # Max requests per window (0 = disabled)
--rate-limit-window SEC   # Window size in seconds
--rate-limit-redis-url URL # Redis URL for distributed rate limiting

# TLS/SSL
--ssl-certfile PATH       # Certificate file (PEM)
--ssl-keyfile PATH        # Private key file (PEM)
--ssl-password PASS       # Key password (if encrypted)
--ssl-ca-certs PATH       # CA certs for client verification
--ssl-verify-mode MODE    # 0=NONE, 1=OPTIONAL, 2=REQUIRED
```

## Deployment Recommendations

### Production

1. **Always use TLS** - Generate valid certificates or use `--ssl-certfile`/`--ssl-keyfile`
2. **Enable authentication** - Set `--auth-token` with a strong random token
3. **Enable rate limiting** - Set `--rate-limit` appropriate for your traffic
4. **Use Redis for distributed deployments** - Set `--rate-limit-redis-url`
5. **Run behind a reverse proxy** - nginx/Traefik for additional protection
6. **Monitor logs** - Watch for 401/429 responses indicating attacks

### Network

- **Bind to specific interfaces** - Use `--host 192.168.1.100` not `0.0.0.0` unless necessary
- **Firewall rules** - Restrict access to trusted networks
- **Separate networks** - Camera network separate from management network

### Monitoring

- **Log authentication failures** - Alert on repeated 401s
- **Log rate limit hits** - Alert on repeated 429s
- **Monitor bandwidth** - Detect anomalous stream usage

## Vulnerability Reporting

Report security vulnerabilities to: security@example.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Security Checklist for Releases

- [ ] All dependencies updated (`pip-audit`, `bandit`)
- [ ] Security tests pass (`pytest tests/test_security.py`)
- [ ] No hardcoded secrets
- [ ] TLS configuration validated
- [ ] Rate limiting tested under load
- [ ] SSRF protections validated
- [ ] Input validation tested with fuzzing