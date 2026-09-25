"""Read-only Linux /proc network parsers."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def parse_tcp_state_lines(lines: list[str]) -> Counter[str]:
    states: Counter[str] = Counter()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        states[TCP_STATES.get(parts[3], parts[3])] += 1
    return states


def read_tcp_states(proc_root: str = "/proc") -> Counter[str]:
    states: Counter[str] = Counter()
    for name in ("net/tcp", "net/tcp6"):
        path = Path(proc_root) / name
        try:
            states.update(parse_tcp_state_lines(path.read_text(encoding="utf-8", errors="ignore").splitlines()))
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return states


def read_snmp(proc_root: str = "/proc") -> dict[str, dict[str, int]]:
    path = Path(proc_root) / "net/snmp"
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except (FileNotFoundError, PermissionError, OSError):
        return {}
    parsed: dict[str, dict[str, int]] = {}
    for header, values in zip(lines[0::2], lines[1::2], strict=False):
        header_parts = header.split()
        value_parts = values.split()
        if not header_parts or not value_parts:
            continue
        section = header_parts[0].rstrip(":")
        keys = [item.rstrip(":") for item in header_parts[1:]]
        numbers = [int(item) for item in value_parts[1:] if item.isdigit()]
        parsed[section] = dict(zip(keys, numbers, strict=False))
    return parsed

