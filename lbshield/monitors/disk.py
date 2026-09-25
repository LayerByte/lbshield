"""Disk monitoring."""

from __future__ import annotations

from pathlib import Path

import psutil

from lbshield.models import DiskSample


def collect_disk(paths: list[str]) -> list[DiskSample]:
    samples: list[DiskSample] = []
    for path in paths:
        if not Path(path).exists():
            continue
        try:
            usage = psutil.disk_usage(path)
        except (PermissionError, OSError):
            continue
        samples.append(DiskSample(path=path, percent=float(usage.percent), used_bytes=int(usage.used), free_bytes=int(usage.free)))
    return samples


def disk_io_rates(previous: tuple[int, int, float] | None = None) -> tuple[dict[str, float], tuple[int, int, float]]:
    import time

    counters = psutil.disk_io_counters()
    now = time.monotonic()
    if counters is None:
        return {"read_bps": 0.0, "write_bps": 0.0}, (0, 0, now)
    current = (int(counters.read_bytes), int(counters.write_bytes), now)
    if previous is None:
        return {"read_bps": 0.0, "write_bps": 0.0}, current
    elapsed = max(0.001, current[2] - previous[2])
    return {
        "read_bps": max(0, current[0] - previous[0]) / elapsed,
        "write_bps": max(0, current[1] - previous[1]) / elapsed,
    }, current

