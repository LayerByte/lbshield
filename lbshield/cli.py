"""Command line interface for LBShield."""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table

from lbshield import __version__
from lbshield.alerts.formatter import discord_incident_text, standard_alert
from lbshield.alerts.manager import AlertManager
from lbshield.config import AppConfig, load_config
from lbshield.engine import LBShieldEngine
from lbshield.incidents.manager import IncidentManager
from lbshield.models import AttackSignature, Event, Severity
from lbshield.monitors.cpu import collect_cpu
from lbshield.monitors.disk import collect_disk
from lbshield.monitors.memory import collect_memory
from lbshield.monitors.network import NetworkRateTracker, collect_interfaces
from lbshield.monitors.ports import collect_listening_ports
from lbshield.monitors.processes import collect_processes
from lbshield.monitors.services import collect_services
from lbshield.ui.dashboard import dashboard
from lbshield.utils.formatting import format_bps, format_pps

app = typer.Typer(help="LBShield - Linux Server Security & DDoS Monitor")


def _make_console() -> Console:
    encoding = (sys.stdout.encoding or "").lower()
    if encoding and "utf" not in encoding and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    return Console()


console = _make_console()


def _config(path: Path | None) -> AppConfig:
    return load_config(path)


@app.command()
def version() -> None:
    """Show LBShield version."""
    console.print(f"LBShield {__version__}")


@app.command()
def config_check(config: Path | None = typer.Option(None, "--config", "-c")) -> None:
    """Validate configuration."""
    cfg = _config(config)
    console.print("[green]Configuration valid[/green]")
    console.print(cfg.model_dump_json(indent=2))


@app.command()
def monitor(config: Path | None = typer.Option(None, "--config", "-c")) -> None:
    """Run the live dashboard."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = _config(config)
    engine = LBShieldEngine(cfg)
    with Live(console=console, refresh_per_second=1, screen=False) as live:
        while True:
            sample = engine.sample_once()
            cpu = sample["cpu"]
            memory = sample["memory"]
            rates = sample["rates"]
            rate = rates[0] if rates else None
            connections = sample["connections"]
            live.update(
                dashboard(
                    engine.server,
                    cpu.percent,
                    memory.ram_percent,
                    memory.swap_percent,
                    float(sample["disk_percent"]),
                    cpu.load_average[0],
                    rate.rx_bps if rate else 0,
                    rate.tx_bps if rate else 0,
                    rate.rx_pps if rate else 0,
                    rate.tx_pps if rate else 0,
                    connections.total,
                    connections.syn_recv,
                    sample["events"],
                )
            )
            time.sleep(cfg.monitor.interval_seconds)


@app.command()
def status(config: Path | None = typer.Option(None, "--config", "-c")) -> None:
    """Print a one-shot status snapshot."""
    engine = LBShieldEngine(_config(config))
    sample = engine.sample_once()
    cpu = sample["cpu"]
    memory = sample["memory"]
    console.print(f"CPU {cpu.percent:.0f}%  RAM {memory.ram_percent:.0f}%  DISK {float(sample['disk_percent']):.0f}%")


@app.command()
def events(config: Path | None = typer.Option(None, "--config", "-c")) -> None:
    """Collect and print current events."""
    engine = LBShieldEngine(_config(config))
    sample = engine.sample_once()
    for event in sample["events"]:
        console.print(standard_alert(event))


@app.command()
def processes(limit: int = 10) -> None:
    """Show top processes by CPU and RAM."""
    table = Table("PID", "Name", "User", "CPU %", "RAM %", "Executable")
    for proc in collect_processes(limit=limit):
        table.add_row(str(proc.pid), proc.name, proc.user or "", f"{proc.cpu_percent:.1f}", f"{proc.memory_percent:.1f}", proc.executable or "")
    console.print(table)


@app.command()
def network() -> None:
    """Show network interface counters and calculated rates."""
    tracker = NetworkRateTracker()
    samples = collect_interfaces()
    for sample in samples:
        tracker.calculate(sample)
    time.sleep(1)
    table = Table("Interface", "RX PPS", "TX PPS", "RX", "TX")
    for sample in collect_interfaces():
        rate = tracker.calculate(sample)
        table.add_row(rate.interface, format_pps(rate.rx_pps), format_pps(rate.tx_pps), format_bps(rate.rx_bps), format_bps(rate.tx_bps))
    console.print(table)


@app.command()
def ports() -> None:
    """Show listening ports."""
    table = Table("Protocol", "Address", "Port", "PID", "Process")
    for port in collect_listening_ports():
        table.add_row(port.protocol, port.address, str(port.port), str(port.pid or ""), port.process or "")
    console.print(table)


@app.command()
def services(config: Path | None = typer.Option(None, "--config", "-c")) -> None:
    """Show configured service states."""
    cfg = _config(config)
    table = Table("Service", "Active", "Status")
    for service in collect_services(cfg.services.monitor):
        table.add_row(service.name, "yes" if service.active else "no", service.status)
    console.print(table)


@app.command()
def baseline() -> None:
    """Explain baseline behavior."""
    console.print("LBShield uses rolling baselines for PPS, bandwidth, connections and HTTP request counts.")


@app.command()
def incidents() -> None:
    """Show incident storage location."""
    console.print("Incidents are stored in SQLite and can be exported from local reports.")


@app.command()
def test_alert(provider: str = typer.Argument("console"), config: Path | None = typer.Option(None, "--config", "-c")) -> None:
    """Send a test alert through the selected provider."""
    cfg = _config(config)
    if provider == "discord":
        cfg.alerts.discord = True
        cfg.alerts.console = False
    elif provider == "telegram":
        cfg.alerts.telegram = True
        cfg.alerts.console = False
    else:
        cfg.alerts.console = True
    AlertManager(cfg).send_event(Event(key="TEST_ALERT", message="LBShield test alert", severity=Severity.WARNING))


@app.command()
def demo() -> None:
    """Render synthetic defensive monitoring scenarios."""
    console.print("[bold yellow]SYNTHETIC DEMO DATA[/bold yellow]")
    cfg = AppConfig()
    cfg.server.id = "DEMO-GAME-01"
    cfg.server.name = "DEMO-GAME-01"
    cfg.server.public_ip = "203.0.113.25"
    cfg.server.hostname = "demo-game-01"
    cfg.server.interface = "eth0"
    server = cfg.server_metadata(discover_public_ip=False)
    manager = IncidentManager(server)
    signatures = [
        AttackSignature(name="IP Traffic Spike", layer="L3", protocol="IP", peak_pps=367_970, peak_bps=176_630_000, evidence=["synthetic PPS and bandwidth spike"]),
        AttackSignature(name="TCP SYN", layer="L4", protocol="TCP", peak_pps=367_970, peak_bps=176_630_000, evidence=["synthetic SYN_RECV elevation"]),
    ]
    incident = manager.create_or_update(signatures, observed_pps=367_970, observed_bps=176_630_000, unique_sources=1482, top_sources=[("203.0.113.41", 21_400), ("198.51.100.72", 18_700)])
    console.print(discord_incident_text(incident))
    console.print("\n[green]Demo scenarios:[/green] Normal Server, High CPU, High RAM, Disk Warning, Network Spike, Single Source Anomaly, Distributed Traffic Anomaly, TCP Connection Spike, HTTP Request Spike, Suspicious Process, Recovery")


@app.command("memory")
def memory_cmd() -> None:
    sample = collect_memory()
    console.print(f"RAM {sample.ram_percent:.0f}%  Swap {sample.swap_percent:.0f}%")


@app.command("disk")
def disk_cmd() -> None:
    for sample in collect_disk(["/", "/home", "/var"]):
        console.print(f"{sample.path}: {sample.percent:.0f}%")


@app.command("cpu")
def cpu_cmd() -> None:
    sample = collect_cpu(interval=0.1)
    console.print(f"CPU {sample.percent:.0f}%  Load {sample.load_average[0]:.2f}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
