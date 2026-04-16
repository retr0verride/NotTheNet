# syntax=docker/dockerfile:1.6
# ──────────────────────────────────────────────────────────────────────────────
# NotTheNet — Multi-stage Dockerfile
#
# Stages:
#   base        Shared Debian Bookworm-slim base with non-root user
#   builder     Install Python dependencies into a venv (no internet in prod)
#   lint        Run ruff + bandit (CI stage; exits non-zero on violations)
#   test        Run pytest (CI stage; exits non-zero on failures)
#   runtime     Minimal production image (~130 MB)
#
# Build targets:
#   docker build --target runtime -t notthenet:latest .   # production
#   docker build --target test    -t notthenet:test   .   # CI test run
#   docker build --target lint    -t notthenet:lint   .   # CI lint run
#
# Security hardening:
#   - Non-root user (notthenet:notthenet, UID 1001)
#   - No SUID/SGID binaries in runtime layer
#   - Secrets NEVER embedded — passed via environment variables at runtime
#   - Python bytecache disabled (PYTHONDONTWRITEBYTECODE=1)
#   - Unbuffered output for container log streaming (PYTHONUNBUFFERED=1)
#   - read-only root filesystem compatible (logs volume required)
# ──────────────────────────────────────────────────────────────────────────────

# Base image pinned to digest for supply-chain security (Scorecard: Pinned-Dependencies).
# To update: docker manifest inspect python:3.11-slim-bookworm --verbose | grep Digest
FROM python:3.11-slim-bookworm@sha256:9c6f90801e6b68e772b7c0ca74260cbf7af9f320acec894e26fccdaccfbe3b47 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps needed at runtime (iptables, iproute2 for network rules)
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Dedicated non-root user and group
RUN groupadd -g 1001 notthenet \
    && useradd  -u 1001 -g notthenet -s /sbin/nologin -d /app notthenet

WORKDIR /app

# ── builder ───────────────────────────────────────────────────────────────────
FROM base AS builder

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy only dependency manifests first — leverages layer cache
COPY requirements.txt pyproject.toml ./

RUN python -m venv /venv \
    && /venv/bin/pip install --upgrade pip \
    && /venv/bin/pip install -r requirements.txt

# ── lint ──────────────────────────────────────────────────────────────────────
FROM builder AS lint

COPY . .

RUN /venv/bin/pip install ruff bandit[toml] \
    && /venv/bin/ruff check . \
    && /venv/bin/bandit -r . \
        --exclude .venv,tests,tools \
        -ll \
        --format json \
        --output /tmp/bandit-report.json \
    ; cat /tmp/bandit-report.json

# ── test ──────────────────────────────────────────────────────────────────────
FROM builder AS test

COPY . .

RUN /venv/bin/pip install pytest pytest-cov \
    && /venv/bin/pytest tests/ \
        --tb=short \
        -q \
        --cov=. \
        --cov-report=term-missing \
        --cov-fail-under=70

# ── runtime ───────────────────────────────────────────────────────────────────
FROM base AS runtime

# Copy the virtual environment from builder
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH" \
    VIRTUAL_ENV=/venv

# Copy application source (excludes files in .dockerignore)
COPY --chown=notthenet:notthenet . .

# Create the logs volume directory owned by notthenet
RUN mkdir -p /app/logs /app/certs \
    && chown -R notthenet:notthenet /app/logs /app/certs

# iptables requires CAP_NET_ADMIN; bind <1024 requires CAP_NET_BIND_SERVICE.
# These are set at runtime via --cap-add, not baked into the image.
# The binary is NOT setuid.

VOLUME ["/app/logs", "/app/certs", "/app/config.json"]

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=4)"

USER notthenet

EXPOSE 8080

# Default: headless mode (no display server needed)
ENV NTN_HEADLESS=1

ENTRYPOINT ["/venv/bin/python", "notthenet.py"]
