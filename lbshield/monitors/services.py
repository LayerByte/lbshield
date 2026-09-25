"""Linux service monitoring."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(slots=True)
class ServiceState:
    name: str
    active: bool
    status: str


def service_status(name: str) -> ServiceState:
    try:
        result = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, check=False, timeout=3)
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError) as exc:
        return ServiceState(name=name, active=False, status=f"unavailable: {exc.__class__.__name__}")
    status = result.stdout.strip() or result.stderr.strip() or "unknown"
    return ServiceState(name=name, active=result.returncode == 0 and status == "active", status=status)


def collect_services(names: list[str]) -> list[ServiceState]:
    return [service_status(name) for name in names]

