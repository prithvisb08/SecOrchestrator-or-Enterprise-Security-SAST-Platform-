# Stage 1: Build virtual environment and wheels
FROM python:3.12-slim-bookworm@sha256:d894819777eb6fc17ceac7dd3cf98eec28abdc704be704d2be734aa722b5e7d5 AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir=/build/wheels .

# Stage 2: Minimal hardened runtime image
FROM python:3.12-slim-bookworm@sha256:d894819777eb6fc17ceac7dd3cf98eec28abdc704be704d2be734aa722b5e7d5 AS runtime

WORKDIR /app

# Create unprivileged system user and group (UID/GID 65532)
RUN groupadd -g 65532 secuser && \
    useradd -u 65532 -g secuser -M -s /usr/sbin/nologin secuser && \
    mkdir -p /app /tmp/secorch && \
    chown -R secuser:secuser /app /tmp/secorch

COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Switch to non-root user
USER 65532:65532

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TMPDIR=/tmp/secorch

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

CMD ["uvicorn", "security_platform.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
