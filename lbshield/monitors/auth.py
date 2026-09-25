"""Authentication log monitoring."""

from __future__ import annotations

from pathlib import Path

from lbshield.parsers.auth import parse_auth_line


def scan_auth_logs(paths: list[str], max_lines: int = 500) -> dict[str, int]:
    counts = {"failures": 0, "invalid_users": 0, "successes": 0}
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[-max_lines:]
        except (PermissionError, OSError):
            continue
        for line in lines:
            event = parse_auth_line(line)
            if event:
                counts[event] += 1
    return counts

