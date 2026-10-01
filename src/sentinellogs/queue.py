from __future__ import annotations

import json
import os
from typing import Callable

from .schema import LogRecord


class RedisQueue:
    def __init__(self, url: str | None = None, name: str | None = None) -> None:
        try:
            import redis  # type: ignore
        except ModuleNotFoundError as exc:
            raise RuntimeError("Install the redis optional dependency to use RedisQueue") from exc
        self.client = redis.Redis.from_url(url or os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
        self.name = name or os.environ.get("REDIS_QUEUE_NAME", "sentinellogs:events")

    def ping(self) -> bool:
        return bool(self.client.ping())

    def publish(self, record: LogRecord) -> None:
        self.client.rpush(self.name, record.to_json())

    def consume(self, handler: Callable[[LogRecord], None], *, timeout: int = 1) -> None:
        while True:
            item = self.client.blpop(self.name, timeout=timeout)
            if item is None:
                continue
            _, payload = item
            handler(record_from_payload(json.loads(payload)))


class InMemoryQueue:
    def __init__(self) -> None:
        self.items: list[LogRecord] = []

    def publish(self, record: LogRecord) -> None:
        self.items.append(record)

    def consume_once(self, handler: Callable[[LogRecord], None]) -> None:
        while self.items:
            handler(self.items.pop(0))


def record_from_payload(payload: dict[str, object]) -> LogRecord:
    return LogRecord(
        format=str(payload.get("format", "unknown")),
        timestamp=payload.get("timestamp"),
        event_time=payload.get("event_time"),
        delta_seconds=payload.get("delta_seconds"),
        host=payload.get("host"),
        process=payload.get("process"),
        pid=payload.get("pid"),
        level=payload.get("level"),
        message=payload.get("message"),
        ips=list(payload.get("ips") or []),
        parsed_at=payload.get("parsed_at"),
        raw=payload.get("raw"),
        raw_line=payload.get("raw_line"),
        matched_parser=payload.get("matched_parser"),
        parse_duration_ms=payload.get("parse_duration_ms"),
        source=payload.get("source"),
        tenant_id=payload.get("tenant_id"),
        agent_id=payload.get("agent_id"),
        source_type=payload.get("source_type"),
        source_ip=payload.get("source.ip"),
        user_name=payload.get("user.name"),
        user_target=payload.get("user.target"),
        host_hostname=payload.get("host.hostname"),
        event_action=payload.get("event.action"),
        event_outcome=payload.get("event.outcome"),
        event_category=payload.get("event.category"),
        mitre_techniques=list(payload.get("threat.technique.id") or []),
    )