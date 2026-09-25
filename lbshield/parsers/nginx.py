"""Nginx access log parser."""

from __future__ import annotations

import re

ACCESS_RE = re.compile(
    r'(?P<source>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" (?P<status>\d{3}) (?P<size>\S+)'
)


def parse_nginx_access(line: str) -> dict[str, object] | None:
    match = ACCESS_RE.search(line)
    if not match:
        return None
    return {
        "source": match.group("source"),
        "method": match.group("method"),
        "path": match.group("path"),
        "status": int(match.group("status")),
    }

