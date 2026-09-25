"""Authentication anomaly detection."""

from __future__ import annotations

from lbshield.models import Event, Severity


def auth_events(counts: dict[str, int], failure_warning: int) -> list[Event]:
    events: list[Event] = []
    if counts.get("failures", 0) >= failure_warning:
        events.append(Event(key="SSH_FAILURES", message="SSH authentication failures increased", severity=Severity.WARNING, details=counts))
    if counts.get("invalid_users", 0) >= failure_warning:
        events.append(Event(key="SSH_INVALID_USERS", message="SSH invalid-user failures increased", severity=Severity.WARNING, details=counts))
    return events

