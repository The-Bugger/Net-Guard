# Dockerfile — Net-Guard Enterprise IDPS
# Requirements: 11.2, 12.1
#
# Build:  docker build -t netguard .
# Run:    docker compose up
#
# Non-root user UID ≥ 1000; no secrets in layers;
# HEALTHCHECK every 30 s; minimum TLS 1.2 via env vars.

FROM python:3.12-slim AS base

# ── system deps ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        ip6tables \
        libpcap-dev \
        sqlite3 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ── non-root user (UID ≥ 1000) ─────────────────────────────────────────────
RUN groupadd -g 1001 netguard && \
    useradd -u 1001 -g netguard -m -s /bin/bash netguard

# ── working directory ──────────────────────────────────────────────────────
WORKDIR /app

# ── Python deps (install before copying source so layer is cached) ─────────
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ── copy source (no .env — never bake secrets into the image) ─────────────
COPY --chown=netguard:netguard . .

# ── directories that need write access at runtime ─────────────────────────
RUN mkdir -p /app/database /app/logs /app/backups && \
    chown -R netguard:netguard /app/database /app/logs /app/backups

# ── switch to non-root ─────────────────────────────────────────────────────
USER netguard

# ── environment defaults (override via docker-compose or -e flags) ─────────
ENV FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000 \
    LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

# HEALTHCHECK every 30 s, timeout 10 s (Req 12.1)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:${FLASK_PORT}/api/v1/health || exit 1

CMD ["python", "-m", "backend.main"]
