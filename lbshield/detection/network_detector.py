"""Network anomaly detection."""

from __future__ import annotations

from lbshield.config import NetworkConfig
from lbshield.detection.baseline import NetworkBaselines
from lbshield.models import AttackSignature, NetworkRate


def network_signatures(rate: NetworkRate, baseline: NetworkBaselines, config: NetworkConfig) -> list[AttackSignature]:
    signatures: list[AttackSignature] = []
    rx_pps_anomaly = rate.rx_pps >= config.absolute_pps_warning or baseline.rx_pps.above_multiplier(rate.rx_pps, config.pps_warning_multiplier, 100)
    rx_bps_anomaly = rate.rx_bps >= config.absolute_bps_warning or baseline.rx_bps.above_multiplier(rate.rx_bps, config.bps_warning_multiplier, 1_000_000)
    if rx_pps_anomaly or rx_bps_anomaly:
        evidence: list[str] = []
        if rx_pps_anomaly:
            evidence.append("RX packet rate above baseline or threshold")
        if rx_bps_anomaly:
            evidence.append("RX bandwidth above baseline or threshold")
        signatures.append(
            AttackSignature(
                name="IP Traffic Spike",
                layer="L3",
                protocol="IP",
                current_pps=rate.rx_pps,
                peak_pps=rate.peak_pps or rate.rx_pps,
                current_bps=rate.rx_bps,
                peak_bps=rate.peak_bps or rate.rx_bps,
                confidence=0.45,
                evidence=evidence,
            )
        )
    return signatures

