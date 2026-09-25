"""Network monitoring."""

from __future__ import annotations

import time

import psutil

from lbshield.models import NetworkRate, NetworkSample


def collect_interfaces(interface: str | None = None) -> list[NetworkSample]:
    counters = psutil.net_io_counters(pernic=True)
    samples: list[NetworkSample] = []
    for name, item in counters.items():
        if interface and name != interface:
            continue
        samples.append(
            NetworkSample(
                interface=name,
                rx_bytes=int(item.bytes_recv),
                tx_bytes=int(item.bytes_sent),
                rx_packets=int(item.packets_recv),
                tx_packets=int(item.packets_sent),
                errin=int(item.errin),
                errout=int(item.errout),
                dropin=int(item.dropin),
                dropout=int(item.dropout),
            )
        )
    return samples


class NetworkRateTracker:
    """Calculate PPS/BPS from interface counter deltas."""

    def __init__(self) -> None:
        self._previous: dict[str, tuple[NetworkSample, float]] = {}
        self._peaks: dict[str, tuple[float, float]] = {}

    def calculate(self, sample: NetworkSample) -> NetworkRate:
        now = time.monotonic()
        previous = self._previous.get(sample.interface)
        self._previous[sample.interface] = (sample, now)
        if previous is None:
            return NetworkRate(interface=sample.interface)
        old, old_time = previous
        elapsed = max(0.001, now - old_time)
        rx_bps = max(0, sample.rx_bytes - old.rx_bytes) * 8 / elapsed
        tx_bps = max(0, sample.tx_bytes - old.tx_bytes) * 8 / elapsed
        rx_pps = max(0, sample.rx_packets - old.rx_packets) / elapsed
        tx_pps = max(0, sample.tx_packets - old.tx_packets) / elapsed
        peak_bps, peak_pps = self._peaks.get(sample.interface, (0.0, 0.0))
        peak_bps = max(peak_bps, rx_bps, tx_bps)
        peak_pps = max(peak_pps, rx_pps, tx_pps)
        self._peaks[sample.interface] = (peak_bps, peak_pps)
        return NetworkRate(
            interface=sample.interface,
            rx_bps=rx_bps,
            tx_bps=tx_bps,
            rx_pps=rx_pps,
            tx_pps=tx_pps,
            peak_bps=peak_bps,
            peak_pps=peak_pps,
        )

