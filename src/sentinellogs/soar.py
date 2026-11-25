from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Callable

from .detection import SecurityAlert

logger = logging.getLogger(__name__)


def dry_run_block_ip(ip_address: str) -> str:
    ipaddress.ip_address(ip_address)
    logger.info("SOAR dry-run request accepted; no firewall changes made")
    return "dry-run"


@dataclass(frozen=True)
class Playbook:
    name: str
    rule_ids: frozenset[str]
    action: Callable[[SecurityAlert], None]
    allowed_ips: frozenset[str] = frozenset()
    allowed_tenants: frozenset[str] = frozenset()


class SoarEngine:
    def __init__(self, playbooks: list[Playbook] | None = None) -> None:
        self.playbooks = list(playbooks or [])

    def execute(self, alert: SecurityAlert) -> list[str]:
        executed: list[str] = []
        for playbook in self.playbooks:
            if alert.rule_id not in playbook.rule_ids or alert.severity not in {"high", "critical"}:
                continue
            if alert.source_ip in playbook.allowed_ips or alert.tenant_id in playbook.allowed_tenants:
                continue
            playbook.action(alert)
            executed.append(playbook.name)
        return executed