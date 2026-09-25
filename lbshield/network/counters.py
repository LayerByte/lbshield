"""Network counter calculations."""

from __future__ import annotations

from lbshield.models import NetworkRate


def calculate_pps(current_packets: int, previous_packets: int, elapsed_seconds: float) -> float:
    return max(0, current_packets - previous_packets) / max(0.001, elapsed_seconds)


def calculate_bps(current_bytes: int, previous_bytes: int, elapsed_seconds: float) -> float:
    return max(0, current_bytes - previous_bytes) * 8 / max(0.001, elapsed_seconds)


def total_observed_rate(rates: list[NetworkRate]) -> tuple[float, float]:
    """Return actual observed peak PPS/BPS, not summed overlapping signatures."""
    if not rates:
        return 0.0, 0.0
    return max(rate.total_pps for rate in rates), max(rate.total_bps for rate in rates)

