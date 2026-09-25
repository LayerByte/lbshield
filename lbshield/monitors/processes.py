"""Process monitoring."""

from __future__ import annotations

import os

import psutil

from lbshield.models import ProcessInfo


def collect_processes(limit: int | None = None) -> list[ProcessInfo]:
    processes: list[ProcessInfo] = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "ppid", "cpu_percent", "memory_percent", "create_time", "cmdline"]):
        try:
            info = proc.info
            processes.append(
                ProcessInfo(
                    pid=int(info.get("pid") or proc.pid),
                    name=str(info.get("name") or ""),
                    executable=info.get("exe"),
                    user=info.get("username"),
                    ppid=info.get("ppid"),
                    cpu_percent=float(info.get("cpu_percent") or 0.0),
                    memory_percent=float(info.get("memory_percent") or 0.0),
                    create_time=info.get("create_time"),
                    cmdline=list(info.get("cmdline") or []),
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue
    processes.sort(key=lambda item: (item.cpu_percent, item.memory_percent), reverse=True)
    return processes[:limit] if limit else processes


def executable_deleted(path: str | None) -> bool:
    return bool(path and " (deleted)" in path)


def suspicious_runtime_path(path: str | None) -> bool:
    if not path:
        return False
    raw = path.replace(" (deleted)", "")
    if raw.startswith(("/tmp/", "/dev/shm/")):
        return True
    normalized = os.path.realpath(raw)
    return normalized.startswith(("/tmp/", "/dev/shm/"))
