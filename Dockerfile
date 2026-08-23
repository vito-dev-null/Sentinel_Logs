FROM python:3.11-slim AS builder

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN python -m venv "$VIRTUAL_ENV"
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir .

FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="SentinelLogs" \
      org.opencontainers.image.description="Real-time log parser with JSONL sinks and alerting" \
      org.opencontainers.image.licenses="MIT"

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system appgroup && useradd --system --gid appgroup --create-home --home-dir /home/appuser appuser
COPY --from=builder /opt/venv /opt/venv

USER appuser

ENTRYPOINT ["sentinellogs"]
CMD ["--help"]
