"""Process anomaly detection."""

from __future__ import annotations

from lbshield.config import ProcessesConfig
from lbshield.models import Event, ProcessInfo, Severity
from lbshield.monitors.processes import executable_deleted, suspicious_runtime_path


def process_events(processes: list[ProcessInfo], config: ProcessesConfig) -> list[Event]:
    events: list[Event] = []
    for proc in processes:
        if proc.name in config.trusted_processes:
            continue
        reason: str | None = None
        if suspicious_runtime_path(proc.executable):
            reason = "executable running from temporary memory-backed path"
        elif executable_deleted(proc.executable):
            reason = "deleted executable still running"
        elif proc.cpu_percent >= config.cpu_warning:
            reason = f"high CPU usage {proc.cpu_percent:.0f}%"
        elif proc.memory_percent >= config.memory_warning:
            reason = f"high RAM usage {proc.memory_percent:.0f}%"
        if reason:
            events.append(
                Event(
                    key=f"PROCESS_{proc.pid}",
                    message=f"Suspicious process needs review: {proc.name or proc.pid}",
                    severity=Severity.WARNING,
                    details={"pid": proc.pid, "reason": reason, "executable": proc.executable, "user": proc.user},
                )
            )
    return events

