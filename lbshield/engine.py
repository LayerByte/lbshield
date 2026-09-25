"""Main LBShield runtime engine."""

from __future__ import annotations

import logging
import time
from dataclasses import asdict
from pathlib import Path

from lbshield.alerts.manager import AlertManager
from lbshield.config import AppConfig, existing_disk_paths
from lbshield.detection.auth_detector import auth_events
from lbshield.detection.baseline import NetworkBaselines
from lbshield.detection.connection_detector import connection_signatures
from lbshield.detection.dos_detector import MultiSignalGate
from lbshield.detection.http_detector import http_signatures
from lbshield.detection.network_detector import network_signatures
from lbshield.detection.process_detector import process_events
from lbshield.detection.resource_detector import SustainedThreshold, cpu_event, disk_events, memory_event
from lbshield.incidents.manager import IncidentManager
from lbshield.models import Event, Severity
from lbshield.monitors.auth import scan_auth_logs
from lbshield.monitors.cpu import collect_cpu
from lbshield.monitors.disk import collect_disk
from lbshield.monitors.files import collect_hashes
from lbshield.monitors.memory import collect_memory
from lbshield.monitors.network import NetworkRateTracker, collect_interfaces
from lbshield.monitors.ports import collect_listening_ports
from lbshield.monitors.processes import collect_processes
from lbshield.monitors.services import collect_services
from lbshield.monitors.webserver import scan_access_logs
from lbshield.network.connections import summarize_connections
from lbshield.network.counters import total_observed_rate
from lbshield.storage.database import Database
from lbshield.storage.retention import prune_expired
from lbshield.utils.time import iso_now

LOGGER = logging.getLogger(__name__)


class LBShieldEngine:
    def __init__(self, config: AppConfig, database: Database | None = None, alerts: AlertManager | None = None) -> None:
        self.config = config
        self.server = config.server_metadata(discover_public_ip=False)
        self.db = database or Database(config.storage.database_path)
        self.alerts = alerts or AlertManager(config)
        self.rate_tracker = NetworkRateTracker()
        self.baselines = NetworkBaselines()
        self.cpu_threshold = SustainedThreshold(config.cpu.warning, config.cpu.critical, config.cpu.minimum_duration)
        self.incidents = IncidentManager(self.server)
        self.gate = MultiSignalGate(config.network_detection)
        self.recent_events: list[Event] = []

    def record_event(self, event: Event) -> None:
        self.recent_events.append(event)
        self.recent_events = self.recent_events[-100:]
        try:
            self.db.insert_event(event)
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            LOGGER.warning("failed to store event: %s", exc)
        self.alerts.send_event(event)

    def sample_once(self) -> dict[str, object]:
        events: list[Event] = []
        cpu = collect_cpu(interval=None)
        memory = collect_memory()
        disk_samples = collect_disk(existing_disk_paths(self.config.disk))
        disk_percent = max((sample.percent for sample in disk_samples), default=0.0)
        rates = []
        for sample in collect_interfaces(self.server.interface if self.server.interface else None):
            rate = self.rate_tracker.calculate(sample)
            rates.append(rate)
            self.baselines.update_network(rate.rx_pps, rate.tx_pps, rate.rx_bps, rate.tx_bps)
        connection_summary = summarize_connections()
        current_rate = rates[0] if rates else None
        observed_pps, observed_bps = total_observed_rate(rates)

        cpu_alert = cpu_event(cpu.percent, self.cpu_threshold)
        if cpu_alert:
            events.append(cpu_alert)
        ram_alert = memory_event(memory.ram_percent, self.config.memory.warning, self.config.memory.critical)
        if ram_alert:
            events.append(ram_alert)
        events.extend(disk_events(disk_samples, self.config.disk.warning, self.config.disk.critical))

        if self.config.processes.enabled:
            events.extend(process_events(collect_processes(limit=50), self.config.processes))
        if self.config.ports.enabled:
            for port in collect_listening_ports():
                if port.port not in self.config.ports.expected:
                    events.append(Event(key=f"PORT_{port.protocol}_{port.port}", message=f"New listening port detected: {port.port}", severity=Severity.WARNING, details=asdict(port)))
        if self.config.services.enabled:
            for service in collect_services(self.config.services.monitor):
                if not service.active:
                    events.append(Event(key=f"SERVICE_{service.name}", message=f"Critical service stopped: {service.name}", severity=Severity.WARNING, details={"status": service.status}))
        if self.config.auth.enabled:
            events.extend(auth_events(scan_auth_logs(self.config.auth.paths), self.config.auth.failure_warning))
        if self.config.files.enabled:
            for path, digest in collect_hashes(self.config.files.paths).items():
                old = self.db.get_file_hash(path)
                if old and old != digest:
                    events.append(Event(key=f"FILE_{path}", message=f"Monitored file changed: {Path(path).name}", severity=Severity.WARNING, details={"path": path}))
                self.db.upsert_file_hash(path, digest, iso_now())

        signatures = []
        if current_rate:
            signatures.extend(network_signatures(current_rate, self.baselines, self.config.network))
        signatures.extend(connection_signatures(connection_summary, self.config.network))
        if self.config.webserver.enabled:
            http_summary = scan_access_logs(self.config.webserver.nginx_access_logs + self.config.webserver.apache_access_logs)
            signatures.extend(http_signatures(http_summary, self.config.webserver))

        for event in events:
            self.record_event(event)

        if signatures and self.gate.active(signatures):
            incident = self.incidents.create_or_update(
                signatures,
                observed_pps=observed_pps,
                observed_bps=observed_bps,
                unique_sources=connection_summary.unique_remotes,
                top_sources=connection_summary.top_sources,
                target_ports=connection_summary.target_ports,
            )
            self.db.upsert_incident(incident)
            self.alerts.send_incident(incident)
        elif self.incidents.active:
            resolved = self.incidents.resolve()
            if resolved:
                self.db.upsert_incident(resolved)

        try:
            self.db.insert_metric("cpu_percent", cpu.percent, iso_now())
            self.db.insert_metric("ram_percent", memory.ram_percent, iso_now())
            self.db.insert_metric("disk_percent", disk_percent, iso_now())
            if current_rate:
                self.db.insert_metric("rx_pps", current_rate.rx_pps, iso_now(), {"interface": current_rate.interface})
                self.db.insert_metric("rx_bps", current_rate.rx_bps, iso_now(), {"interface": current_rate.interface})
            prune_expired(self.db, self.config.storage)
        except Exception as exc:  # pragma: no cover
            LOGGER.warning("failed to store metrics: %s", exc)

        return {
            "cpu": cpu,
            "memory": memory,
            "disk_percent": disk_percent,
            "rates": rates,
            "connections": connection_summary,
            "events": list(self.recent_events),
        }

    def run_forever(self) -> None:
        while True:
            started = time.monotonic()
            try:
                self.sample_once()
            except Exception as exc:  # pragma: no cover - runtime isolation
                LOGGER.exception("monitoring iteration failed: %s", exc)
            elapsed = time.monotonic() - started
            time.sleep(max(0.1, self.config.monitor.interval_seconds - elapsed))
