"""Memory monitoring."""

from __future__ import annotations

from dataclasses import dataclass

import psutil


@dataclass(slots=True)
class MemorySample:
    ram_percent: float
    available: int
    used: int
    total: int
    swap_percent: float
    swap_used: int
    swap_total: int


def collect_memory() -> MemorySample:
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return MemorySample(
        ram_percent=float(memory.percent),
        available=int(memory.available),
        used=int(memory.used),
        total=int(memory.total),
        swap_percent=float(swap.percent),
        swap_used=int(swap.used),
        swap_total=int(swap.total),
    )


def top_memory_processes(limit: int = 5) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for proc in psutil.process_iter(["pid", "name", "username", "memory_percent"]):
        try:
            info = proc.info
            rows.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name") or "",
                    "user": info.get("username") or "",
                    "memory_percent": float(info.get("memory_percent") or 0.0),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return sorted(rows, key=lambda item: float(item["memory_percent"]), reverse=True)[:limit]

