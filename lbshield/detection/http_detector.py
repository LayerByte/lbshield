"""Layer 7 HTTP detection."""

from __future__ import annotations

from lbshield.config import WebserverConfig
from lbshield.models import AttackSignature


def http_signatures(summary: dict[str, object], config: WebserverConfig) -> list[AttackSignature]:
    requests = float(summary.get("requests") or 0)
    errors = float(summary.get("errors") or 0)
    signatures: list[AttackSignature] = []
    if requests >= config.request_warning_per_second:
        signatures.append(
            AttackSignature(
                name="HTTP Request Spike",
                layer="L7",
                protocol="HTTP",
                request_peak=requests,
                target=str(summary.get("top_path") or ""),
                confidence=0.55,
                evidence=[f"Recent access log request count elevated: {requests:.0f}"],
            )
        )
    if errors >= 20 or (requests > 0 and errors / requests >= 0.2):
        signatures.append(
            AttackSignature(
                name="HTTP Error Spike",
                layer="L7",
                protocol="HTTP",
                request_peak=requests,
                confidence=0.45,
                evidence=[f"HTTP error count elevated: {errors:.0f}"],
            )
        )
    return signatures
