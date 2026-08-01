# NetGuard — Proxy Trust Model & Deployment Guide

This document covers the `TRUST_PROXY_HEADERS` configuration flag, the risks of
misconfiguration, and which proxy setups are safe to use with it enabled.

For general installation and systemd setup, see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## Table of Contents

1. [Why proxy trust matters](#why-proxy-trust-matters)
2. [When to enable TRUST_PROXY_HEADERS](#when-to-enable-trust_proxy_headers)
3. [Safe proxy configurations](#safe-proxy-configurations)
4. [Spoofing risk when misconfigured](#spoofing-risk-when-misconfigured)
5. [Other deployment-relevant environment variables](#other-deployment-relevant-environment-variables)

---

## Why proxy trust matters

NetGuard's rate limiter identifies clients by IP address. When Flask receives a
request, the TCP-layer source IP is `request.remote_addr`. Behind a reverse proxy,
`remote_addr` is always the proxy's IP — not the real client's.

To recover the real client IP, proxies commonly set the `X-Forwarded-For` header:

```
X-Forwarded-For: <real-client-ip>, <optional-intermediate-proxy>
```

The leftmost entry is the original client IP (by convention). However, this header
is set by the proxy — nothing prevents a client from forging it before the request
reaches the proxy, or from reaching Flask directly and setting it themselves.

`TRUST_PROXY_HEADERS` controls whether NetGuard reads this header:

| Setting | Behaviour |
|---|---|
| `false` (default) | `X-Forwarded-For` is ignored; rate limiting uses `remote_addr` |
| `true` | Leftmost IP in `X-Forwarded-For` is used for rate limiting |

---

## When to enable TRUST_PROXY_HEADERS

Enable it **only** when both conditions are true:

1. **A trusted proxy sits in front of Flask** and reliably overwrites (not appends
   to) the `X-Forwarded-For` header with the real client IP.
2. **The Flask port is not directly reachable** from untrusted networks — only the
   proxy is exposed. In practice: bind Flask to `127.0.0.1` and let the proxy
   listen on the public interface.

If either condition is not met, leave it `false`.

---

## Safe proxy configurations

### nginx (recommended)

Bind Flask to loopback (`FLASK_HOST=127.0.0.1`) and configure nginx to set the
header:

```nginx
server {
    listen 80;
    server_name netguard.internal;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Overwrite — do not append — to prevent client forgery
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Key point: `proxy_set_header X-Forwarded-For $remote_addr` **overwrites** the
header with nginx's view of the client address, discarding any value the client
sent. This is safe.

Avoid `$proxy_add_x_forwarded_for` in this setup — it appends the client-supplied
value, which can still be forged.

### HAProxy

```
frontend netguard_front
    bind *:80
    default_backend netguard_back
    http-request set-header X-Forwarded-For %[src]

backend netguard_back
    server flask 127.0.0.1:5000 check
```

`set-header` replaces any existing value, making this safe.

### AWS Application Load Balancer (ALB)

ALB automatically adds the real client IP as the last entry in `X-Forwarded-For`.
NetGuard currently reads the **leftmost** entry (standard convention). Behind an
ALB, you would need to adapt `_client_ip()` to read the last entry instead, or
configure the ALB to send `X-Real-IP`. This is a known limitation.

---

## Spoofing risk when misconfigured

If `TRUST_PROXY_HEADERS=true` and a client can reach Flask directly (i.e. the
Flask port is exposed on a public or untrusted interface), the following attack is
trivial:

```bash
# Attacker sends requests with a forged header, impersonating 1.2.3.4
curl -H "X-Forwarded-For: 1.2.3.4" http://<flask-host>:5000/api/v1/events
```

NetGuard's rate limiter will count the request against `1.2.3.4`, not the real
attacker IP. The attacker can:

- Exhaust the rate limit for a legitimate IP (`1.2.3.4`), causing that IP to be
  rate-limited or blocked.
- Cycle through arbitrary source IPs to avoid hitting their own rate limit,
  enabling a high-rate attack that bypasses per-IP throttling.

**Mitigation:** Bind Flask to `127.0.0.1` (`FLASK_HOST=127.0.0.1`) so only the
proxy can reach it. Verify with:

```bash
ss -tlnp | grep 5000
# Safe:    127.0.0.1:5000
# Unsafe:  0.0.0.0:5000
```

---

## Other deployment-relevant environment variables

| Variable | Default | Notes |
|---|---|---|
| `TRUST_PROXY_HEADERS` | `false` | Enable only behind a trusted proxy; see above |
| `NETGUARD_API_KEY` | (unset) | Set to require `X-API-Key` on mutating requests |
| `REQUIRE_AUTH_FOR_READS` | `false` | Set `true` to also gate GET endpoints |
| `SECRET_KEY` | placeholder | **Must** be changed before any production deployment |
| `FLASK_HOST` | `0.0.0.0` | Set to `127.0.0.1` when behind a reverse proxy |
| `FLASK_ENV` | `development` | Set to `production` to enforce `SECRET_KEY` check |

See [`.env.example`](.env.example) for full documentation of all variables.
