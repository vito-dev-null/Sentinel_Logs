FROM python:3.11-slim AS builder

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

RUN python -m venv $VIRTUAL_ENV
COPY . .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir .

FROM python:3.11-slim AS runtime

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system appgroup && useradd --system --gid appgroup --create-home --home-dir /home/appuser appuser
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

RUN chown -R appuser:appgroup /app /home/appuser
USER appuser

ENTRYPOINT ["log-parser"]
CMD ["--help"]
