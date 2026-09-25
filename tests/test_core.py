from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from lbshield.alerts.discord import DiscordAlertProvider
from lbshield.alerts.formatter import (
    discord_incident_text,
    standard_alert,
    telegram_incident_text,
)
from lbshield.alerts.manager import AlertManager
from lbshield.alerts.telegram import TelegramAlertProvider
from lbshield.config import AppConfig, DiskConfig
from lbshield.detection.auth_detector import auth_events
from lbshield.detection.baseline import NetworkBaselines, RollingBaseline
from lbshield.detection.connection_detector import connection_signatures
from lbshield.detection.http_detector import http_signatures
from lbshield.detection.network_detector import network_signatures
from lbshield.detection.process_detector import process_events
from lbshield.detection.resource_detector import (
    SustainedThreshold,
    cpu_event,
    disk_events,
    memory_event,
)
from lbshield.incidents.manager import IncidentManager
from lbshield.models import (
    AttackSignature,
    ConnectionSummary,
    DiskSample,
    Event,
    NetworkRate,
    ProcessInfo,
    Severity,
)
from lbshield.monitors.files import sha256_file
from lbshield.monitors.services import service_status
from lbshield.network.counters import calculate_bps, calculate_pps, total_observed_rate
from lbshield.network.linux_proc import parse_tcp_state_lines
from lbshield.network.signatures import deduplicate_signatures
from lbshield.parsers.apache import parse_apache_access
from lbshield.parsers.auth import parse_auth_line
from lbshield.parsers.nginx import parse_nginx_access
from lbshield.storage.database import Database
from lbshield.storage.retention import prune_expired
from lbshield.utils.formatting import format_bps, format_duration, format_pps


def test_format_pps_units() -> None:
    assert format_pps(842) == "842 PPS"
    assert format_pps(14_320) == "14.32 Kpps"
    assert format_pps(367_970) == "367.97 Kpps"
    assert format_pps(1_240_000) == "1.24 Mpps"


def test_format_bps_units() -> None:
    assert format_bps(721_400) == "721.40 Kbps"
    assert format_bps(12_420_000) == "12.42 Mbps"
    assert format_bps(176_630_000) == "176.63 Mbps"
    assert format_bps(1_180_000_000) == "1.18 Gbps"


def test_pps_and_bps_calculations() -> None:
    assert calculate_pps(2000, 1000, 2) == 500
    assert calculate_bps(2000, 1000, 2) == 4000


def test_cpu_sustained_duration() -> None:
    threshold = SustainedThreshold(warning=80, critical=95, minimum_duration=10)
    assert cpu_event(96, threshold) is None
    threshold._started["cpu"] = time.monotonic() - 11
    event = cpu_event(96, threshold)
    assert event is not None
    assert event.severity == Severity.CRITICAL


def test_memory_thresholds() -> None:
    assert memory_event(70, 80, 92) is None
    assert memory_event(85, 80, 92).severity == Severity.WARNING
    assert memory_event(95, 80, 92).severity == Severity.CRITICAL


def test_disk_thresholds_and_path_handling() -> None:
    samples = [DiskSample("/", 91, 9, 1), DiskSample("/home", 20, 2, 8)]
    events = disk_events(samples, warning=80, critical=90)
    assert len(events) == 1
    assert "91%" in events[0].message


def test_rolling_baseline() -> None:
    baseline = RollingBaseline(maxlen=3)
    baseline.add(10)
    baseline.add(20)
    baseline.add(30)
    assert baseline.average == 20
    assert baseline.peak == 30
    assert baseline.above_multiplier(100, 4)


def test_network_signature_creation() -> None:
    baselines = NetworkBaselines()
    for _ in range(5):
        baselines.update_network(100, 50, 1_000_000, 100_000)
    rate = NetworkRate(interface="eth0", rx_pps=1000, rx_bps=10_000_000, peak_pps=1000, peak_bps=10_000_000)
    signatures = network_signatures(rate, baselines, AppConfig().network)
    assert signatures[0].name == "IP Traffic Spike"
    assert signatures[0].layer == "L3"


def test_connection_state_parsing_and_syn_recv_detection() -> None:
    states = parse_tcp_state_lines(["sl local_address rem_address st", "0: 00000000:0016 00000000:0000 03"])
    assert states["SYN_RECV"] == 1
    summary = ConnectionSummary(total=10, syn_recv=200)
    signatures = connection_signatures(summary, AppConfig().network, reliable_syn=True)
    assert signatures[0].name == "TCP SYN"


def test_connection_spike_when_syn_not_reliable() -> None:
    cfg = AppConfig().network
    cfg.connection_warning = 5
    summary = ConnectionSummary(total=10, syn_recv=200)
    signatures = connection_signatures(summary, cfg, reliable_syn=False)
    assert signatures[0].name == "TCP Connection Spike"


def test_signature_deduplication() -> None:
    one = AttackSignature(name="IP Traffic Spike", layer="L3", peak_pps=100, evidence=["a"])
    two = AttackSignature(name="IP Traffic Spike", layer="L3", peak_pps=200, evidence=["b"])
    result = deduplicate_signatures([one, two])
    assert len(result) == 1
    assert result[0].peak_pps == 200
    assert result[0].evidence == ["a", "b"]


def test_overlapping_signature_totals_are_not_added() -> None:
    rates = [NetworkRate(interface="eth0", rx_pps=367_970, rx_bps=176_630_000)]
    total_pps, total_bps = total_observed_rate(rates)
    manager = IncidentManager(AppConfig().server_metadata(discover_public_ip=False))
    incident = manager.create_or_update(
        [
            AttackSignature(name="IP Traffic Spike", layer="L3", peak_pps=367_970, peak_bps=176_630_000),
            AttackSignature(name="TCP SYN", layer="L4", peak_pps=367_970, peak_bps=176_630_000),
        ],
        observed_pps=total_pps,
        observed_bps=total_bps,
    )
    assert len(incident.signatures) == 2
    assert incident.peak_pps == 367_970
    assert incident.peak_bps == 176_630_000
    assert incident.observed_pps == 367_970
    assert incident.observed_bps == 176_630_000


def test_incident_recovery() -> None:
    manager = IncidentManager(AppConfig().server_metadata(discover_public_ip=False))
    manager.create_or_update([AttackSignature(name="TCP Connection Spike", layer="L4")])
    resolved = manager.resolve()
    assert resolved is not None
    assert resolved.status.value == "RESOLVED"
    assert resolved.ended_at is not None


def test_process_detection() -> None:
    proc = ProcessInfo(pid=1, name="weird", executable="/tmp/weird", user="www-data", ppid=0, cpu_percent=1, memory_percent=1, create_time=None)
    events = process_events([proc], AppConfig().processes)
    assert events
    assert "Suspicious process" in events[0].message


def test_port_config_defaults() -> None:
    assert DiskConfig().paths == ["/", "/home", "/var"]
    assert AppConfig().ports.expected == [22, 80, 443]


def test_auth_parser_and_detector() -> None:
    assert parse_auth_line("Failed password for invalid user admin from 1.2.3.4") == "invalid_users"
    events = auth_events({"failures": 9, "invalid_users": 0}, failure_warning=8)
    assert events[0].key == "SSH_FAILURES"


def test_nginx_and_apache_parsers_do_not_store_sensitive_headers() -> None:
    line = '203.0.113.1 - - [25/Sep/2026:18:00:00 +0000] "GET /login HTTP/1.1" 401 123 "-" "curl"'
    assert parse_nginx_access(line)["path"] == "/login"
    assert parse_apache_access(line)["status"] == 401


def test_http_detector() -> None:
    cfg = AppConfig().webserver
    cfg.request_warning_per_second = 10
    signatures = http_signatures({"requests": 20, "errors": 5, "top_path": "/login"}, cfg)
    assert {sig.name for sig in signatures} == {"HTTP Request Spike", "HTTP Error Spike"}


def test_alert_cooldown_and_dedup() -> None:
    cfg = AppConfig()
    cfg.alerts.console = False
    cfg.alerts.reminder_seconds = 999
    manager = AlertManager(cfg)
    event = Event(key="HIGH_RAM", message="High RAM usage: 94%", severity=Severity.WARNING)
    assert manager.should_send(event)
    assert not manager.should_send(event)
    event.resolved = True
    assert manager.should_send(event)


def test_standard_discord_and_telegram_formatting() -> None:
    event = Event(key="TEST", message="LBShield test alert", severity=Severity.WARNING)
    assert standard_alert(event) == "Warning ! [ LBShield test alert ]"
    manager = IncidentManager(AppConfig().server_metadata(discover_public_ip=False))
    incident = manager.create_or_update([AttackSignature(name="TCP SYN", layer="L4", peak_pps=1000, peak_bps=2_000_000)], observed_pps=1000, observed_bps=2_000_000)
    discord = discord_incident_text(incident)
    telegram = telegram_incident_text(incident)
    assert "Possible DDoS Attack Detected" in discord
    assert "TCP SYN" in telegram


def test_database_retention(tmp_path) -> None:
    db = Database(tmp_path / "lbshield.sqlite3")
    old = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    db.insert_metric("old", 1, old)
    cfg = AppConfig().storage
    cfg.metrics_days = 1
    prune_expired(db, cfg)
    row = db.conn.execute("SELECT COUNT(*) FROM metrics").fetchone()
    assert row[0] == 0


def test_incident_database_persistence(tmp_path) -> None:
    db = Database(tmp_path / "lbshield.sqlite3")
    manager = IncidentManager(AppConfig().server_metadata(discover_public_ip=False))
    incident = manager.create_or_update([AttackSignature(name="IP Traffic Spike", layer="L3", peak_pps=42, peak_bps=84)], observed_pps=42, observed_bps=84)
    db.upsert_incident(incident)
    row = db.conn.execute("SELECT incident_id, peak_pps, peak_bps FROM incidents").fetchone()
    assert row == (incident.incident_id, 42, 84)


def test_file_integrity_database(tmp_path) -> None:
    db = Database(tmp_path / "lbshield.sqlite3")
    db.upsert_file_hash("/etc/passwd", "abc", datetime.now(UTC).isoformat())
    assert db.get_file_hash("/etc/passwd") == "abc"


def test_file_sha256(tmp_path) -> None:
    target = tmp_path / "sshd_config"
    target.write_text("Port 22\n", encoding="utf-8")
    assert sha256_file(str(target)) == "01b8dc798db9c5f2da0690499b2885ab7f15833917a105df438416e709966791"


def test_config_validation() -> None:
    cfg = AppConfig.model_validate({"cpu": {"warning": 80, "critical": 95, "minimum_duration": 30}})
    assert cfg.cpu.warning == 80


def test_demo_incident_uses_synthetic_values_only() -> None:
    manager = IncidentManager(AppConfig().server_metadata(discover_public_ip=False))
    incident = manager.create_or_update(
        [
            AttackSignature(name="IP Traffic Spike", layer="L3", peak_pps=367_970, peak_bps=176_630_000),
            AttackSignature(name="TCP SYN", layer="L4", peak_pps=367_970, peak_bps=176_630_000),
        ],
        observed_pps=367_970,
        observed_bps=176_630_000,
    )
    text = discord_incident_text(incident)
    assert "367.97 Kpps" in text
    assert "176.63 Mbps" in text


def test_format_duration() -> None:
    assert format_duration(268) == "4m 28s"


def test_mock_discord_delivery(monkeypatch) -> None:
    calls = []

    class Response:
        def raise_for_status(self) -> None:
            return None

    def fake_post(url, json, timeout):
        calls.append((url, json, timeout))
        return Response()

    monkeypatch.setattr("lbshield.alerts.discord.httpx.post", fake_post)
    provider = DiscordAlertProvider("https://discord.example/webhook")
    assert provider.send_text("Warning ! [ LBShield test alert ]")
    assert calls[0][1]["content"] == "Warning ! [ LBShield test alert ]"


def test_mock_telegram_delivery(monkeypatch) -> None:
    calls = []

    class Response:
        def raise_for_status(self) -> None:
            return None

    def fake_post(url, json, timeout):
        calls.append((url, json, timeout))
        return Response()

    monkeypatch.setattr("lbshield.alerts.telegram.httpx.post", fake_post)
    provider = TelegramAlertProvider("token", "chat")
    assert provider.send_text("hello")
    assert "token" in calls[0][0]
    assert calls[0][1]["chat_id"] == "chat"


def test_service_monitoring_missing_systemctl(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("systemctl")

    monkeypatch.setattr("lbshield.monitors.services.subprocess.run", fake_run)
    state = service_status("nginx")
    assert not state.active
    assert "unavailable" in state.status
