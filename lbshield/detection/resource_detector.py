"""Resource threshold detection."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from lbshield.models import Event, Severity


@dataclass(slots=True)
class SustainedThreshold:
    warning: float
    critical: float
    minimum_duration: float = 0
    _started: dict[str, float] = field(default_factory=dict)

    def evaluate(self, key: str, value: float) -> Severity | None:
        target = None
        if value >= self.critical:
            target = Severity.CRITICAL
        elif value >= self.warning:
            target = Severity.WARNING
        else:
            self._started.pop(key, None)
            return None
        now = time.monotonic()
        self._started.setdefault(key, now)
        if now - self._started[key] < self.minimum_duration:
            return None
        return target


def cpu_event(value: float, threshold: SustainedThreshold) -> Event | None:
    severity = threshold.evaluate("cpu", value)
    if not severity:
        return None
    return Event(key="HIGH_CPU", message=f"High CPU usage: {value:.0f}%", severity=severity, details={"cpu_percent": value})


def memory_event(value: float, warning: float, critical: float) -> Event | None:
    if value >= critical:
        severity = Severity.CRITICAL
    elif value >= warning:
        severity = Severity.WARNING
    else:
        return None
    return Event(key="HIGH_RAM", message=f"High RAM usage: {value:.0f}%", severity=severity, details={"ram_percent": value})


def disk_events(samples: list[object], warning: float, critical: float) -> list[Event]:
    events: list[Event] = []
    for sample in samples:
        percent = float(getattr(sample, "percent"))
        path = str(getattr(sample, "path"))
        if percent >= critical:
            severity = Severity.CRITICAL
        elif percent >= warning:
            severity = Severity.WARNING
        else:
            continue
        events.append(Event(key=f"DISK_{path}", message=f"Disk usage reached {percent:.0f}% on {path}", severity=severity, details={"path": path, "percent": percent}))
    return events

