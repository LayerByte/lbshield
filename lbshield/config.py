"""Configuration loading and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import httpx
import psutil
import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from lbshield.models import ServerMetadata
from lbshield.utils.network import default_interface, local_hostname


class ServerConfig(BaseModel):
    id: str = "LB-SERVER-01"
    name: str = "SERVER-01"
    public_ip: str = "auto"
    hostname: str = "auto"
    interface: str = "auto"


class MonitorConfig(BaseModel):
    interval_seconds: float = Field(default=2, gt=0)


class ThresholdConfig(BaseModel):
    warning: float
    critical: float
    minimum_duration: float = Field(default=0, ge=0)

    @field_validator("warning", "critical")
    @classmethod
    def percent_range(cls, value: float) -> float:
        if not 0 <= value <= 100:
            raise ValueError("must be between 0 and 100")
        return value


class DiskConfig(BaseModel):
    warning: float = Field(default=80, ge=0, le=100)
    critical: float = Field(default=90, ge=0, le=100)
    paths: list[str] = Field(default_factory=lambda: ["/", "/home", "/var"])


class NetworkConfig(BaseModel):
    enabled: bool = True
    baseline: bool = True
    pps_warning_multiplier: float = Field(default=5.0, gt=1)
    bps_warning_multiplier: float = Field(default=5.0, gt=1)
    absolute_pps_warning: float = Field(default=100_000, ge=0)
    absolute_bps_warning: float = Field(default=100_000_000, ge=0)
    connection_warning: int = Field(default=1000, ge=0)
    syn_recv_warning: int = Field(default=128, ge=0)


class NetworkDetectionConfig(BaseModel):
    minimum_duration: float = Field(default=5, ge=0)
    minimum_signals: int = Field(default=2, ge=1)


class ProcessesConfig(BaseModel):
    enabled: bool = True
    trusted_processes: list[str] = Field(default_factory=lambda: ["systemd", "sshd", "nginx"])
    trusted_paths: list[str] = Field(default_factory=lambda: ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"])
    trusted_users: list[str] = Field(default_factory=list)
    cpu_warning: float = Field(default=90, ge=0, le=100)
    memory_warning: float = Field(default=50, ge=0, le=100)


class PortsConfig(BaseModel):
    enabled: bool = True
    expected: list[int] = Field(default_factory=lambda: [22, 80, 443])


class ServicesConfig(BaseModel):
    enabled: bool = True
    monitor: list[str] = Field(default_factory=lambda: ["ssh", "nginx"])
    automatic_restart: bool = False


class AlertsConfig(BaseModel):
    cooldown_seconds: int = Field(default=300, ge=0)
    reminder_seconds: int = Field(default=1800, ge=0)
    console: bool = True
    discord: bool = False
    telegram: bool = False


class DiscordConfig(BaseModel):
    format: Literal["text", "embed"] = "text"


class StorageConfig(BaseModel):
    database_path: str = "data/lbshield.sqlite3"
    metrics_days: int = Field(default=7, ge=1)
    events_days: int = Field(default=30, ge=1)
    alert_days: int = Field(default=30, ge=1)


class AuthConfig(BaseModel):
    enabled: bool = True
    paths: list[str] = Field(default_factory=lambda: ["/var/log/auth.log", "/var/log/secure"])
    failure_warning: int = Field(default=8, ge=1)


class FilesConfig(BaseModel):
    enabled: bool = True
    paths: list[str] = Field(default_factory=lambda: ["/etc/ssh/sshd_config", "/etc/passwd", "/etc/group"])


class WebserverConfig(BaseModel):
    enabled: bool = True
    nginx_access_logs: list[str] = Field(default_factory=lambda: ["/var/log/nginx/access.log"])
    apache_access_logs: list[str] = Field(default_factory=lambda: ["/var/log/apache2/access.log", "/var/log/httpd/access_log"])
    request_warning_per_second: float = Field(default=500, ge=0)


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    cpu: ThresholdConfig = Field(default_factory=lambda: ThresholdConfig(warning=80, critical=95, minimum_duration=30))
    memory: ThresholdConfig = Field(default_factory=lambda: ThresholdConfig(warning=80, critical=92))
    disk: DiskConfig = Field(default_factory=DiskConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    network_detection: NetworkDetectionConfig = Field(default_factory=NetworkDetectionConfig)
    processes: ProcessesConfig = Field(default_factory=ProcessesConfig)
    ports: PortsConfig = Field(default_factory=PortsConfig)
    services: ServicesConfig = Field(default_factory=ServicesConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    files: FilesConfig = Field(default_factory=FilesConfig)
    webserver: WebserverConfig = Field(default_factory=WebserverConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    discord: DiscordConfig = Field(default_factory=DiscordConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)

    def server_metadata(self, discover_public_ip: bool = True) -> ServerMetadata:
        public_ip = self.server.public_ip
        if public_ip == "auto":
            public_ip = discover_ip() if discover_public_ip else None
        hostname = local_hostname() if self.server.hostname == "auto" else self.server.hostname
        interface = default_interface() if self.server.interface == "auto" else self.server.interface
        return ServerMetadata(
            server_id=self.server.id,
            name=self.server.name,
            public_ip=public_ip,
            hostname=hostname,
            interface=interface,
        )


def discover_ip() -> str | None:
    """Discover public IP with HTTPS, a short timeout and graceful failure."""
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.get("https://api.ipify.org")
            response.raise_for_status()
            value = response.text.strip()
            return value if value else None
    except httpx.HTTPError:
        return None


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path or "lbshield.yaml")
    if not config_path.exists():
        return AppConfig()
    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    try:
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def existing_disk_paths(config: DiskConfig) -> list[str]:
    return [path for path in config.paths if Path(path).exists()]


def known_interfaces() -> list[str]:
    return list(psutil.net_io_counters(pernic=True).keys())

