FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv fastapi uvicorn

COPY . .

RUN uv sync --frozen --no-dev || true

RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app && mkdir -p /data/credentials && \
    chown -R app:app /data

USER app

EXPOSE 8000
ARG PORT
EXPOSE ${PORT:-8000}

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${PORT:-8000}/health || exit 1

ENTRYPOINT ["uv", "run", "uvicorn", "serve:app", "--host", "0.0.0.0", "--port", "8000"]
