from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .audit import AuditLog
from .detection import SecurityAlert

COMPLIANCE_CONTROLS = {
    "ISO 27001": "A.8.15 logging and A.8.16 monitoring",
    "GDPR": "Art. 32 security of processing and Art. 33 breach response",
    "NIS2": "Art. 21 risk-management measures and incident handling",
    "PCI-DSS": "Requirement 10 audit logs and monitoring",
}


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def export_compliance_pdf(path: str | Path, *, metrics: dict[str, Any], incidents: Iterable[SecurityAlert | dict[str, Any]], audit_log: AuditLog | None = None) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    incident_rows = list(incidents)
    audit_verified = audit_log.verify() if audit_log is not None else False
    lines = [
        "SentinelLogs Enterprise Security Report",
        "",
        f"Processed events: {metrics.get('processed_lines', 0)}",
        f"Dropped events: {metrics.get('dropped_lines', 0)}",
        f"Alerts generated: {metrics.get('alerts_generated', len(incident_rows))}",
        f"Immutable audit chain verified: {'YES' if audit_verified else 'NO / NOT CONFIGURED'}",
        "",
        "Compliance coverage:",
    ]
    lines.extend(f"- {framework}: {control}" for framework, control in COMPLIANCE_CONTROLS.items())
    lines.extend(["", "Incident timeline:"])
    for incident in incident_rows:
        if isinstance(incident, SecurityAlert):
            lines.append(f"[{incident.severity}] {incident.rule_id}: {incident.message}")
        else:
            lines.append(f"[{incident.get('severity', 'unknown')}] {incident.get('rule_id', 'incident')}: {incident.get('message', '')}")
    if not incident_rows:
        lines.append("No incidents recorded.")
    lines = [line[:110] for line in lines]
    content = ["BT", "/F1 10 Tf", "50 770 Td"]
    for index, line in enumerate(lines):
        if index:
            content.append("0 -14 Td")
        content.append(f"({_pdf_escape(line)}) Tj")
    content.append("ET")
    stream = "\n".join(content).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    destination.write_bytes(pdf)
    return destination