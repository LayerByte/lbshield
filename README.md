# LBShield

Linux Server Security & DDoS Monitor

LBShield is a lightweight Python security monitoring system for Linux servers that detects resource problems, suspicious processes, network anomalies and possible DoS/DDoS activity.

School Purpose Only.

## Overview

LBShield runs on a Linux server and observes host telemetry: CPU, RAM, swap, disks, disk I/O, network counters, packets per second, bandwidth, TCP connection states, listening ports, processes, authentication logs, important services, file integrity, and optional web server access logs.

It is defensive-only. It monitors and detects. It never generates attack traffic, floods, stress tests, bypasses controls, steals credentials, installs persistence, or attacks external systems.

## Features

- Rich terminal dashboard with clean dark-terminal friendly colors
- CPU, memory, swap and disk monitoring
- Process review for unusual runtime paths, deleted executables and high resource usage
- Network PPS and bandwidth calculations using decimal networking units
- Rolling traffic baselines for packet rate, bandwidth, connections and HTTP request volume
- Layer 3, Layer 4 and Layer 7 anomaly signatures where telemetry supports them
- Incident lifecycle tracking with local SQLite storage
- Discord webhook and Telegram Bot API alert providers
- Authentication, listening port, service and file integrity monitoring
- Synthetic demo mode that does not create packets, connections or load

## Screenshots / Preview

Run:

```bash
lbshield demo
lbshield monitor
```

The live dashboard shows server identity, system load, network counters, connection state, protection status and recent events.

## Architecture

LBShield separates collection from detection and alert delivery:

- `monitors/` collects local host telemetry.
- `detection/` evaluates thresholds, baselines and anomaly signals.
- `network/` contains counter calculations, connection summaries and Linux `/proc` parsers.
- `alerts/` formats and sends console, Discord and Telegram notifications.
- `incidents/` manages incident state and exports reports.
- `storage/` stores telemetry, events, baselines and incidents in SQLite.
- `ui/` renders Rich terminal components.

Detectors do not contain provider-specific Discord or Telegram logic. All alerts pass through `AlertManager`.

## Requirements

- Python 3.12+
- Linux for full telemetry
- Runtime dependencies are installed automatically from `pyproject.toml`.
- `pytest` is included by the optional `dev` dependency group.

Basic monitoring does not require root. Some process, service or connection details may be limited by OS permissions; LBShield continues running with reduced visibility.

## Installation

```bash
git clone https://github.com/layerbyte/lbshield.git
cd lbshield
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
cp config/lbshield.example.yaml lbshield.yaml
```

## Quick Start

```bash
lbshield config-check
lbshield status
lbshield monitor
```

## CLI

```bash
lbshield monitor
lbshield status
lbshield events
lbshield processes
lbshield network
lbshield ports
lbshield services
lbshield incidents
lbshield baseline
lbshield config-check
lbshield test-alert console
lbshield test-alert discord
lbshield demo
lbshield version
```

## Configuration

Configuration is read from `lbshield.yaml` by default and validated with Pydantic. Invalid values produce readable validation errors.

Server identity should be configured explicitly for multi-server alert destinations:

```yaml
server:
  id: "LB-GAME-01"
  name: "GAME-01"
  public_ip: "auto"
  hostname: "auto"
  interface: "auto"
```

`public_ip: auto` uses HTTPS with a short timeout and graceful failure. The result is not queried every monitoring interval.

## System Monitoring

LBShield samples CPU, RAM, swap, disk usage, disk I/O, network interfaces, processes, ports and services. One failed monitor does not stop other monitors.

## CPU Monitoring

CPU alerts use sustained-duration logic. A short spike is not enough to alert by default.

## Memory Monitoring

Memory alerts report high RAM or swap usage and record top memory-consuming processes where permissions allow. LBShield never kills processes automatically.

## Disk Monitoring

Only configured paths that exist are monitored. LBShield never deletes files automatically.

## Process Monitoring

Processes are reviewed for unusual conditions such as executables under `/tmp` or `/dev/shm`, deleted executables still running, high CPU/RAM usage, and allowlist mismatches. LBShield uses "Suspicious", "Unusual" and "Needs Review" terminology rather than claiming malware from weak signals.

## Network Monitoring

LBShield reads `psutil` counters and safe read-only Linux sources such as `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/snmp` and related files where available.

## PPS & Bandwidth

Packets per second:

```text
RX PPS = (current_rx_packets - previous_rx_packets) / elapsed_seconds
```

Bandwidth:

```text
RX BPS = (current_rx_bytes - previous_rx_bytes) * 8 / elapsed_seconds
```

Bandwidth is reported as bits per second with decimal units: Kbps, Mbps and Gbps.

## Network Baselines

Rolling baselines track normal PPS, bandwidth, connection count and request activity. Detections combine historical behavior with configurable absolute thresholds.

## DoS/DDoS Detection

LBShield detects combinations of defensive indicators that may suggest DoS/DDoS activity, such as PPS spikes, bandwidth spikes, connection spikes, SYN_RECV elevation, unique-source increases, HTTP request spikes and error spikes.

An anomaly is not automatically proof of an attack. LBShield cannot guarantee that a traffic spike is malicious.

Host-level software also cannot stop a volumetric DDoS attack after the server's upstream network connection is saturated. Large attacks normally require upstream mitigation from the hosting provider, ISP, CDN, or a dedicated DDoS protection provider.

## Layer 3 Monitoring

Layer 3 signatures include measurable IP traffic spikes, packet-rate anomalies and bandwidth anomalies.

## Layer 4 Monitoring

Layer 4 signatures use TCP state and connection telemetry. LBShield only labels `TCP SYN` when supporting SYN telemetry is available; otherwise it uses names such as `TCP Connection Spike`.

## Layer 7 Monitoring

Optional Nginx and Apache access-log parsing tracks request count, unique sources, methods, paths, status codes and errors. LBShield never stores Authorization headers, cookies, passwords, POST bodies or session tokens.

## Attack Signatures

Signatures include fields such as name, layer, protocol, first seen, last seen, current PPS, peak PPS, current bandwidth, peak bandwidth, confidence and evidence. Only measurable fields are populated.

## Incident Management

Incidents require multiple signals and configurable minimum duration. States include `OBSERVING`, `ACTIVE`, `MITIGATING`, `RECOVERING` and `RESOLVED`.

Overlapping signatures are not added together. If interface traffic is 367.97 Kpps and both `IP Traffic Spike` and `TCP SYN` refer to that same observed traffic, total PPS remains 367.97 Kpps.

## Discord Alerts

Discord webhook support is available through:

```bash
DISCORD_WEBHOOK_URL=
```

Normal alerts are compact:

```text
Warning ! [ High RAM usage: 94% ]
```

High-confidence network incidents use a detailed server-identified message. Webhook URLs are never logged or displayed.

## Telegram Alerts

Telegram Bot API support is available through:

```bash
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Bot tokens are never logged or displayed.

## Authentication Monitoring

LBShield supports common Linux authentication logs and detects repeated SSH failures, invalid-user spikes and successful login signals after many failures. It avoids overstating evidence.

## Port Monitoring

Configure expected ports. Newly opened listening sockets generate review events.

## Service Monitoring

Configure important services such as SSH, Nginx or Docker. Automatic restart is disabled by default and must be explicitly configured.

## File Integrity

Configured files are hashed with SHA-256. LBShield reports changes but never restores or sends file contents to external providers.

## Database

SQLite stores metrics, events, incidents, signatures, process events, network events, auth events, file integrity baselines, alert history and baselines. Queries use parameters.

## Data Retention

Retention is configurable:

```yaml
storage:
  metrics_days: 7
  events_days: 30
  alert_days: 30
```

Expired telemetry is pruned to prevent unlimited database growth.

## Demo Mode

`lbshield demo` uses synthetic internal metrics and clearly displays `SYNTHETIC DEMO DATA`. It does not generate network traffic, packets, connections, CPU exhaustion or RAM exhaustion.

## Running as a Linux Service

A sample unit is provided in `deploy/lbshield.service`.

```bash
sudo cp deploy/lbshield.service /etc/systemd/system/lbshield.service
sudo systemctl daemon-reload
sudo systemctl start lbshield
sudo systemctl status lbshield
sudo systemctl enable lbshield
sudo journalctl -u lbshield -f
sudo systemctl stop lbshield
sudo systemctl restart lbshield
```

The repository does not automatically install or enable the service.

## Security

LBShield is defensive-only and local-observation-only. It contains no attack mode, stress mode, flood mode, packet flooding, amplification, reflection, botnet, malware, credential theft, spoofing, bypass or exploit functionality.

## Privacy

LBShield should collect only information necessary for defensive monitoring. It does not store passwords, authentication tokens, cookies, HTTP request bodies, Discord webhook URLs or Telegram bot tokens.

## Limitations

LBShield detects indicators and anomalies, not absolute truth. Permissions, NAT, proxies, spoofing, sampling intervals and host visibility can affect what it sees.

## Testing

```bash
pytest
```

Tests cover formatting, thresholds, sustained CPU logic, disk handling, network baselines, connection state parsing, SYN_RECV detection, signature deduplication, overlapping totals, incident creation, alert cooldown, Discord and Telegram formatting, parsers, file integrity, database retention and demo safety assumptions.

## Contributing

Contributions should preserve the defensive-only scope, add tests for behavior changes, avoid storing secrets, and keep monitoring lightweight.