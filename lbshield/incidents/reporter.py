"""Local incident report export."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from lbshield.models import Incident
from lbshield.utils.formatting import format_bps, format_duration, format_pps


def _json_default(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    return str(value)


def export_incident(incident: Incident, output: Path, fmt: str) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output.write_text(json.dumps(incident, default=_json_default, indent=2), encoding="utf-8")
    elif fmt == "csv":
        with output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["incident_id", "server_id", "status", "duration_seconds", "peak_pps", "peak_bps", "signatures"])
            writer.writerow([incident.incident_id, incident.server.server_id, incident.status.value, incident.duration_seconds, incident.peak_pps, incident.peak_bps, ";".join(s.name for s in incident.signatures)])
    elif fmt == "md":
        lines = [
            f"# Incident {incident.incident_id}",
            "",
            f"- Server: {incident.server.name} ({incident.server.server_id})",
            f"- Status: {incident.status.value}",
            f"- Duration: {format_duration(incident.duration_seconds)}",
        ]
        if incident.peak_pps is not None:
            lines.append(f"- Peak PPS: {format_pps(incident.peak_pps)}")
        if incident.peak_bps is not None:
            lines.append(f"- Peak Bandwidth: {format_bps(incident.peak_bps)}")
        lines.append("")
        lines.append("## Signatures")
        lines.extend(f"- {signature.name} ({signature.layer})" for signature in incident.signatures)
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        raise ValueError("format must be json, csv or md")
    return output

