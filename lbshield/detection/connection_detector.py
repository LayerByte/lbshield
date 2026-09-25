"""Connection anomaly detection."""

from __future__ import annotations

from lbshield.config import NetworkConfig
from lbshield.models import AttackSignature, ConnectionSummary


def connection_signatures(summary: ConnectionSummary, config: NetworkConfig, reliable_syn: bool = True) -> list[AttackSignature]:
    signatures: list[AttackSignature] = []
    if summary.syn_recv >= config.syn_recv_warning and reliable_syn:
        signatures.append(
            AttackSignature(
                name="TCP SYN",
                layer="L4",
                protocol="TCP",
                confidence=0.7,
                evidence=[f"SYN_RECV count elevated: {summary.syn_recv}"],
            )
        )
    elif summary.total >= config.connection_warning:
        signatures.append(
            AttackSignature(
                name="TCP Connection Spike",
                layer="L4",
                protocol="TCP",
                confidence=0.5,
                evidence=[f"Concurrent connections elevated: {summary.total}"],
            )
        )
    if summary.unique_remotes >= 500 and summary.total >= config.connection_warning:
        signatures.append(
            AttackSignature(
                name="Distributed Source Flood Pattern",
                layer="L4",
                protocol="TCP",
                confidence=0.65,
                evidence=[f"Unique observed sources elevated: {summary.unique_remotes}"],
            )
        )
    return signatures

