"""Connection collection and summarization."""

from __future__ import annotations

from collections import Counter

import psutil

from lbshield.models import ConnectionSummary


def summarize_connections() -> ConnectionSummary:
    summary = ConnectionSummary()
    remotes: Counter[str] = Counter()
    ports: Counter[int] = Counter()
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError):
        return summary
    for conn in connections:
        status = conn.status or ""
        if conn.type.name == "SOCK_DGRAM":
            summary.udp += 1
        else:
            summary.total += 1
        if status == psutil.CONN_ESTABLISHED:
            summary.established += 1
        elif status == psutil.CONN_SYN_RECV:
            summary.syn_recv += 1
        elif status == psutil.CONN_TIME_WAIT:
            summary.time_wait += 1
        elif status == psutil.CONN_CLOSE_WAIT:
            summary.close_wait += 1
        elif status == psutil.CONN_LISTEN:
            summary.listening += 1
        if conn.raddr:
            remotes[str(conn.raddr.ip)] += 1
        if conn.laddr:
            ports[int(conn.laddr.port)] += 1
    summary.unique_remotes = len(remotes)
    summary.target_ports = dict(ports)
    summary.top_sources = [(source, float(count)) for source, count in remotes.most_common(5)]
    return summary

