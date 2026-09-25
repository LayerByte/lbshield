"""Linux authentication log parser."""

from __future__ import annotations


def parse_auth_line(line: str) -> str | None:
    lowered = line.lower()
    if "invalid user" in lowered:
        return "invalid_users"
    if "failed password" in lowered or "authentication failure" in lowered:
        return "failures"
    if "accepted password" in lowered or "accepted publickey" in lowered:
        return "successes"
    return None

