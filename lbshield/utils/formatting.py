"""Formatting helpers for terminal output and alerts."""

from __future__ import annotations


def format_bytes_per_second(bytes_per_second: float) -> str:
    units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
    value = float(bytes_per_second)
    for unit in units:
        if abs(value) < 1000 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "B/s" else f"{value:.0f} {unit}"
        value /= 1000
    return f"{value:.2f} TB/s"


def format_bps(bits_per_second: float) -> str:
    """Format bits/sec using decimal networking units."""
    units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]
    value = float(bits_per_second)
    for unit in units:
        if abs(value) < 1000 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "bps" else f"{value:.0f} {unit}"
        value /= 1000
    return f"{value:.2f} Tbps"


def format_pps(packets_per_second: float) -> str:
    units = ["PPS", "Kpps", "Mpps", "Gpps"]
    value = float(packets_per_second)
    for unit in units:
        if abs(value) < 1000 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "PPS" else f"{value:.0f} {unit}"
        value /= 1000
    return f"{value:.2f} Gpps"


def format_percent(value: float) -> str:
    return f"{value:.0f}%"


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def redact_secret(value: str | None) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"

