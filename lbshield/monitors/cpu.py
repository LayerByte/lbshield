"""CPU monitoring."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import psutil


@dataclass(slots=True)
class CpuSample:
    percent: float
    per_core: list[float]
    load_average: tuple[float, float, float]
    timestamp: float


def collect_cpu(interval: float | None = None) -> CpuSample:
    percent = psutil.cpu_percent(interval=interval)
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    load_average = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    return CpuSample(percent=percent, per_core=per_core, load_average=load_average, timestamp=time.time())


def top_cpu_processes(limit: int = 5) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            rows.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name") or "",
                    "user": info.get("username") or "",
                    "cpu_percent": float(info.get("cpu_percent") or 0.0),
                    "memory_percent": float(info.get("memory_percent") or 0.0),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return sorted(rows, key=lambda item: float(item["cpu_percent"]), reverse=True)[:limit]

