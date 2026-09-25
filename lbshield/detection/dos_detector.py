"""DoS/DDoS incident decision logic."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from time import monotonic

from lbshield.config import NetworkDetectionConfig
from lbshield.models import AttackSignature


@dataclass(slots=True)
class MultiSignalGate:
    config: NetworkDetectionConfig
    _first_seen: dict[str, float] = field(default_factory=lambda: defaultdict(monotonic))

    def active(self, signatures: list[AttackSignature]) -> bool:
        if len(signatures) < self.config.minimum_signals:
            self._first_seen.clear()
            return False
        key = "|".join(sorted(signature.name for signature in signatures))
        started = self._first_seen.setdefault(key, monotonic())
        return monotonic() - started >= self.config.minimum_duration

