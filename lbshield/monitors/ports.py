"""Listening port monitoring."""

from __future__ import annotations

from dataclasses import dataclass

import psutil


@dataclass(frozen=True, slots=True)
class ListeningPort:
    protocol: str
    address: str
    port: int
    pid: int | None = None
    process: str | None = None


def collect_listening_ports() -> list[ListeningPort]:
    ports: list[ListeningPort] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError):
        return ports
    for conn in connections:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        process_name = None
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_name = None
        ports.append(
            ListeningPort(
                protocol="tcp",
                address=str(conn.laddr.ip),
                port=int(conn.laddr.port),
                pid=conn.pid,
                process=process_name,
            )
        )
    return sorted(ports, key=lambda item: (item.port, item.address))

