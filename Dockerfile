FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
RUN uv sync --all-extras --no-dev

COPY bugfinder/ bugfinder/
RUN uv build

FROM python:3.13-slim-bookworm

RUN groupadd -r bugfinder && useradd -r -g bugfinder -d /app -s /sbin/nologin bugfinder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/bugfinder /app/bugfinder
COPY pyproject.toml README.md ./

RUN mkdir -p /data /app/reports /app/cache && chown -R bugfinder:bugfinder /data /app

ENV PATH="/app/.venv/bin:$PATH"
ENV BF_DATABASE_URL="sqlite+aiosqlite:////data/bugfinder.db"
ENV BF_REPORTS_DIR="/app/reports"
ENV BF_CACHE_DIR="/app/cache"
ENV BF_WEB_HOST="0.0.0.0"
ENV BF_WEB_PORT=8080

VOLUME ["/data", "/app/reports"]

USER bugfinder

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8080/health', timeout=5)" || exit 1

ENTRYPOINT ["bf"]
CMD ["--help"]
