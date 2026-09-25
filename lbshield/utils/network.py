"""Network utility helpers."""

from __future__ import annotations

import socket

import psutil


def default_interface() -> str | None:
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    for name, stat in stats.items():
        if stat.isup and not name.startswith(("lo", "Loopback")) and name in counters:
            return name
    return next(iter(counters), None)


def local_hostname() -> str:
    return socket.gethostname()

