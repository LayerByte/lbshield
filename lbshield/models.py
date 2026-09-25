"""Shared domain models for LBShield."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentState(StrEnum):
    OBSERVING = "OBSERVING"
    ACTIVE = "ACTIVE"
    MITIGATING = "MITIGATING"
    RECOVERING = "RECOVERING"
    RESOLVED = "RESOLVED"


@dataclass(slots=True)
class ServerMetadata:
    server_id: str
    name: str
    public_ip: str | None
    hostname: str
    interface: str | None


@dataclass(slots=True)
class Event:
    key: str
    message: str
    severity: Severity = Severity.INFO
    created_at: datetime = field(default_factory=utc_now)
    details: dict[str, Any] = field(default_factory=dict)
    resolved: bool = False


@dataclass(slots=True)
class ProcessInfo:
    pid: int
    name: str
    executable: str | None
    user: str | None
    ppid: int | None
    cpu_percent: float
    memory_percent: float
    create_time: float | None
    cmdline: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DiskSample:
    path: str
    percent: float
    used_bytes: int
    free_bytes: int


@dataclass(slots=True)
class NetworkSample:
    interface: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    errin: int = 0
    errout: int = 0
    dropin: int = 0
    dropout: int = 0
    timestamp: datetime = field(default_factory=utc_now)


@dataclass(slots=True)
class NetworkRate:
    interface: str
    rx_bps: float = 0.0
    tx_bps: float = 0.0
    rx_pps: float = 0.0
    tx_pps: float = 0.0
    peak_bps: float = 0.0
    peak_pps: float = 0.0

    @property
    def total_bps(self) -> float:
        return max(self.rx_bps, self.tx_bps)

    @property
    def total_pps(self) -> float:
        return max(self.rx_pps, self.tx_pps)


@dataclass(slots=True)
class ConnectionSummary:
    total: int = 0
    established: int = 0
    syn_recv: int = 0
    time_wait: int = 0
    close_wait: int = 0
    listening: int = 0
    udp: int = 0
    unique_remotes: int = 0
    target_ports: dict[int, int] = field(default_factory=dict)
    top_sources: list[tuple[str, float]] = field(default_factory=list)


@dataclass(slots=True)
class AttackSignature:
    name: str
    layer: str
    protocol: str | None = None
    first_seen: datetime = field(default_factory=utc_now)
    last_seen: datetime = field(default_factory=utc_now)
    current_pps: float | None = None
    peak_pps: float | None = None
    current_bps: float | None = None
    peak_bps: float | None = None
    request_peak: float | None = None
    target: str | None = None
    confidence: float | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Incident:
    incident_id: str
    server: ServerMetadata
    status: IncidentState
    signatures: list[AttackSignature]
    started_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    ended_at: datetime | None = None
    baseline_pps: float | None = None
    peak_pps: float | None = None
    baseline_bps: float | None = None
    peak_bps: float | None = None
    observed_pps: float | None = None
    observed_bps: float | None = None
    unique_sources: int | None = None
    top_sources: list[tuple[str, float]] = field(default_factory=list)
    target_ports: dict[int, int] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        end = self.ended_at or utc_now()
        return max(0.0, (end - self.started_at).total_seconds())

