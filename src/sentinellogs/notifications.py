from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable
from urllib.request import Request, urlopen

from .detection import SecurityAlert


@dataclass
class WebhookConnector:
    url: str
    sender: Callable[[Request], Any] | None = None

    def send(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = Request(self.url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        if self.sender:
            self.sender(request)
            return
        with urlopen(request, timeout=10) as response:
            response.read()


class SlackConnector(WebhookConnector):
    def payload(self, alert: SecurityAlert) -> dict[str, Any]:
        return {"text": f"[{alert.severity.upper()}] {alert.title}: {alert.message}"}

    def send_alert(self, alert: SecurityAlert) -> None:
        self.send(self.payload(alert))


class TeamsConnector(WebhookConnector):
    def payload(self, alert: SecurityAlert) -> dict[str, Any]:
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": alert.title, "text": f"{alert.severity.upper()}: {alert.message}"}

    def send_alert(self, alert: SecurityAlert) -> None:
        self.send(self.payload(alert))


class PagerDutyConnector(WebhookConnector):
    routing_key: str = ""

    def __init__(self, url: str, routing_key: str, sender: Callable[[Request], Any] | None = None) -> None:
        super().__init__(url, sender)
        self.routing_key = routing_key

    def payload(self, alert: SecurityAlert) -> dict[str, Any]:
        return {"routing_key": self.routing_key, "event_action": "trigger", "payload": {"summary": alert.message, "severity": alert.severity, "source": alert.source_ip or "sentinellogs", "custom_details": {"rule_id": alert.rule_id, "tenant_id": alert.tenant_id}}}

    def send_alert(self, alert: SecurityAlert) -> None:
        self.send(self.payload(alert))


class NotificationRouter:
    def __init__(self, connectors: list[WebhookConnector] | None = None) -> None:
        self.connectors = list(connectors or [])

    def dispatch(self, alert: SecurityAlert) -> int:
        sent = 0
        for connector in self.connectors:
            sender = getattr(connector, "send_alert", None)
            if sender is None:
                raise TypeError("notification connector must provide send_alert")
            sender(alert)
            sent += 1
        return sent