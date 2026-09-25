"""Incident lifecycle management."""

from __future__ import annotations

from datetime import UTC, datetime

from lbshield.models import AttackSignature, Incident, IncidentState, ServerMetadata
from lbshield.network.signatures import deduplicate_signatures


class IncidentManager:
    def __init__(self, server: ServerMetadata) -> None:
        self.server = server
        self.sequence = 0
        self.active: Incident | None = None

    def _next_id(self) -> str:
        self.sequence += 1
        return f"LB-{datetime.now(UTC).year}-{self.sequence:06d}"

    def create_or_update(
        self,
        signatures: list[AttackSignature],
        observed_pps: float | None = None,
        observed_bps: float | None = None,
        unique_sources: int | None = None,
        top_sources: list[tuple[str, float]] | None = None,
        target_ports: dict[int, int] | None = None,
    ) -> Incident:
        signatures = deduplicate_signatures(signatures)
        peak_pps = max((signature.peak_pps or 0 for signature in signatures), default=0) or observed_pps
        peak_bps = max((signature.peak_bps or 0 for signature in signatures), default=0) or observed_bps
        if self.active is None or self.active.status == IncidentState.RESOLVED:
            self.active = Incident(
                incident_id=self._next_id(),
                server=self.server,
                status=IncidentState.ACTIVE,
                signatures=signatures,
                peak_pps=peak_pps,
                peak_bps=peak_bps,
                observed_pps=observed_pps,
                observed_bps=observed_bps,
                unique_sources=unique_sources,
                top_sources=top_sources or [],
                target_ports=target_ports or {},
            )
            return self.active
        self.active.signatures = signatures
        self.active.updated_at = datetime.now(UTC)
        self.active.peak_pps = max(self.active.peak_pps or 0, peak_pps or 0) or None
        self.active.peak_bps = max(self.active.peak_bps or 0, peak_bps or 0) or None
        self.active.observed_pps = max(self.active.observed_pps or 0, observed_pps or 0) or None
        self.active.observed_bps = max(self.active.observed_bps or 0, observed_bps or 0) or None
        self.active.unique_sources = unique_sources
        self.active.top_sources = top_sources or self.active.top_sources
        self.active.target_ports = target_ports or self.active.target_ports
        return self.active

    def resolve(self) -> Incident | None:
        if not self.active or self.active.status == IncidentState.RESOLVED:
            return None
        self.active.status = IncidentState.RESOLVED
        self.active.ended_at = datetime.now(UTC)
        return self.active

