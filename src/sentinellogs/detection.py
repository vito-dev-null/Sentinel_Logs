from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from math import asin, cos, radians, sin, sqrt
from typing import Callable, Protocol

from .schema import LogRecord


@dataclass(frozen=True)
class SecurityAlert:
    rule_id: str
    title: str
    severity: str
    message: str
    tenant_id: str | None
    source_ip: str | None
    mitre_technique: str
    details: dict[str, object] | None = None


class GeoIPProvider(Protocol):
    def locate(self, ip: str) -> tuple[float, float] | None:
        """Return latitude/longitude for a public IP, or None when unavailable."""


class MaxMindGeoIP:
    def __init__(self, database_path: str) -> None:
        try:
            import geoip2.database  # type: ignore
        except ModuleNotFoundError as exc:
            raise RuntimeError("Install the geoip optional dependency to use MaxMindGeoIP") from exc
        self._reader = geoip2.database.Reader(database_path)

    def locate(self, ip: str) -> tuple[float, float] | None:
        try:
            location = self._reader.city(ip).location
        except Exception:
            return None
        if location.latitude is None or location.longitude is None:
            return None
        return float(location.latitude), float(location.longitude)

    def close(self) -> None:
        self._reader.close()


def haversine_km(first: tuple[float, float], second: tuple[float, float]) -> float:
    latitude_one, longitude_one = map(radians, first)
    latitude_two, longitude_two = map(radians, second)
    delta_latitude = latitude_two - latitude_one
    delta_longitude = longitude_two - longitude_one
    value = sin(delta_latitude / 2) ** 2 + cos(latitude_one) * cos(latitude_two) * sin(delta_longitude / 2) ** 2
    return 6371.0088 * 2 * asin(sqrt(value))


def _event_time(record: LogRecord) -> float:
    value = record.event_time or record.timestamp or record.parsed_at
    if not value:
        return datetime.now(timezone.utc).timestamp()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return datetime.now(timezone.utc).timestamp()


class CorrelationEngine:
    def __init__(self, *, threshold: int = 10, window_seconds: int = 60, admin_users: set[str] | None = None, geoip: GeoIPProvider | None = None, impossible_speed_kmh: float = 900.0) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.admin_users = {user.lower() for user in (admin_users or set())}
        self._failed_logins: dict[tuple[str | None, str], deque[float]] = defaultdict(deque)
        self.geoip = geoip
        self.impossible_speed_kmh = impossible_speed_kmh
        self._last_logins: dict[tuple[str | None, str], tuple[float, str, tuple[float, float]]] = {}

    def observe(self, record: LogRecord) -> list[SecurityAlert]:
        alerts: list[SecurityAlert] = []
        if record.event_action == "authentication" and record.event_outcome == "success" and record.user_name and record.source_ip and self.geoip:
            location = self.geoip.locate(record.source_ip)
            if location is not None:
                key = (record.tenant_id, record.user_name.lower())
                now = _event_time(record)
                previous = self._last_logins.get(key)
                if previous is not None:
                    previous_time, previous_ip, previous_location = previous
                    elapsed_hours = max((now - previous_time) / 3600.0, 1 / 3600.0)
                    distance = haversine_km(previous_location, location)
                    speed = distance / elapsed_hours
                    if previous_ip != record.source_ip and speed > self.impossible_speed_kmh:
                        alerts.append(SecurityAlert(
                            rule_id="impossible-travel",
                            title="Impossible travel detected",
                            severity="high",
                            message=f"User {record.user_name} moved {distance:.0f} km in {elapsed_hours * 60:.0f} minutes ({speed:.0f} km/h)",
                            tenant_id=record.tenant_id,
                            source_ip=record.source_ip,
                            mitre_technique="T1078",
                            details={"previous_ip": previous_ip, "distance_km": round(distance, 2), "speed_kmh": round(speed, 2)},
                        ))
                self._last_logins[key] = (now, record.source_ip, location)
        if record.event_action == "authentication" and record.event_outcome == "failure" and record.source_ip:
            key = (record.tenant_id, record.source_ip)
            events = self._failed_logins[key]
            now = _event_time(record)
            events.append(now)
            while events and now - events[0] >= self.window_seconds:
                events.popleft()
            if len(events) == self.threshold + 1:
                alerts.append(SecurityAlert(
                    rule_id="brute-force-ssh",
                    title="Possible SSH brute force",
                    severity="high",
                    message=f"{len(events)} failed authentication attempts from {record.source_ip} in {self.window_seconds}s",
                    tenant_id=record.tenant_id,
                    source_ip=record.source_ip,
                    mitre_technique="T1110",
                ))
        if record.event_action == "sudo_command" and record.user_name and self.admin_users and record.user_name.lower() not in self.admin_users:
            alerts.append(SecurityAlert(
                rule_id="unexpected-sudo",
                title="Unexpected privileged command",
                severity="high",
                message=f"User {record.user_name} executed a sudo command outside the administrator allowlist",
                tenant_id=record.tenant_id,
                source_ip=record.source_ip,
                mitre_technique="T1548.003",
            ))
        return alerts


def correlate(record: LogRecord, engine: CorrelationEngine, emit: Callable[[SecurityAlert], None] | None = None) -> list[SecurityAlert]:
    alerts = engine.observe(record)
    if emit is not None:
        for alert in alerts:
            emit(alert)
    return alerts