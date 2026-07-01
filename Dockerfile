FROM python:3.13-slim AS builder

WORKDIR /app

RUN pip install uv
COPY pyproject.toml README.md ./
RUN uv sync --all-extras --no-dev

COPY bugfinder/ bugfinder/
RUN uv build && uv pip install dist/*.whl


FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/bugfinder /app/bugfinder
COPY pyproject.toml README.md ./

ENV PATH="/app/.venv/bin:$PATH"
ENV BF_DATABASE_URL="sqlite+aiosqlite:////data/bugfinder.db"

VOLUME ["/data"]
ENTRYPOINT ["bf"]
CMD ["--help"]
