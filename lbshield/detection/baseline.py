"""Rolling baseline calculations."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


@dataclass(slots=True)
class RollingBaseline:
    maxlen: int = 450
    values: deque[float] = field(default_factory=lambda: deque(maxlen=450))

    def __post_init__(self) -> None:
        if self.values.maxlen != self.maxlen:
            self.values = deque(self.values, maxlen=self.maxlen)

    def add(self, value: float) -> None:
        self.values.append(float(value))

    @property
    def average(self) -> float:
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)

    @property
    def peak(self) -> float:
        return max(self.values, default=0.0)

    def above_multiplier(self, value: float, multiplier: float, absolute_floor: float = 0.0) -> bool:
        baseline = max(self.average, absolute_floor)
        if baseline <= 0:
            return value > absolute_floor > 0
        return value >= baseline * multiplier


@dataclass(slots=True)
class NetworkBaselines:
    rx_pps: RollingBaseline = field(default_factory=RollingBaseline)
    tx_pps: RollingBaseline = field(default_factory=RollingBaseline)
    rx_bps: RollingBaseline = field(default_factory=RollingBaseline)
    tx_bps: RollingBaseline = field(default_factory=RollingBaseline)
    connections: RollingBaseline = field(default_factory=RollingBaseline)
    requests: RollingBaseline = field(default_factory=RollingBaseline)

    def update_network(self, rx_pps: float, tx_pps: float, rx_bps: float, tx_bps: float, connections: float = 0) -> None:
        self.rx_pps.add(rx_pps)
        self.tx_pps.add(tx_pps)
        self.rx_bps.add(rx_bps)
        self.tx_bps.add(tx_bps)
        self.connections.add(connections)

