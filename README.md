# LBShield

**Linux Server Security & DDoS Monitor**

LBShield is a lightweight Python security monitoring tool for Linux servers. It detects resource problems, suspicious processes, network anomalies and possible DoS/DDoS activity.

> **School Purpose Only.** Defensive monitoring only — LBShield does not generate attack traffic.

---

## Features

* CPU, RAM, swap, disk and disk I/O monitoring
* Suspicious process detection
* PPS and bandwidth monitoring
* Network traffic baselines
* Layer 3 / 4 / 7 anomaly detection
* DoS/DDoS indicators
* TCP connection and SYN monitoring
* Authentication and port monitoring
* Service and file integrity monitoring
* Nginx / Apache log analysis
* SQLite incident storage
* Discord and Telegram alerts
* Safe synthetic demo mode

---

## Installation

```bash id="k5vw1j"
git clone https://github.com/layerbyte/lbshield.git
cd lbshield

python -m venv .venv
source .venv/bin/activate

pip install -e .[dev]
cp config/lbshield.example.yaml lbshield.yaml
```

Requires **Python 3.12+** and Linux for full telemetry.

---

## Quick Start

```bash id="z94v3p"
lbshield config-check
lbshield status
lbshield monitor
```

Demo mode:

```bash id="2vvslp"
lbshield demo
```

---

## CLI

| Command                 | Description            |
| ----------------------- | ---------------------- |
| `lbshield monitor`      | Start live monitoring  |
| `lbshield status`       | Server status          |
| `lbshield events`       | Recent events          |
| `lbshield processes`    | Process monitoring     |
| `lbshield network`      | Network statistics     |
| `lbshield ports`        | Listening ports        |
| `lbshield services`     | Service status         |
| `lbshield incidents`    | Security incidents     |
| `lbshield baseline`     | Traffic baselines      |
| `lbshield config-check` | Validate configuration |
| `lbshield demo`         | Synthetic demo         |
| `lbshield version`      | Version information    |

---

## Monitoring

LBShield monitors system and network activity without automatically modifying the server.

| Monitor       | Detection                                               |
| ------------- | ------------------------------------------------------- |
| **CPU**       | Sustained high CPU usage                                |
| **Memory**    | High RAM / swap usage                                   |
| **Disk**      | Disk usage and I/O                                      |
| **Processes** | High resource usage, unusual paths, deleted executables |
| **Network**   | PPS, bandwidth and connection anomalies                 |
| **Auth**      | SSH failures and suspicious login activity              |
| **Ports**     | Unexpected listening ports                              |
| **Services**  | Important service availability                          |
| **Files**     | SHA-256 integrity changes                               |

---

## Network Layers

|  Layer | Monitoring        | Examples                                           |
| :----: | ----------------- | -------------------------------------------------- |
| **L3** | IP / Network      | PPS spikes, bandwidth spikes, IP traffic anomalies |
| **L4** | TCP / Connections | SYN activity, `SYN_RECV`, connection spikes        |
| **L7** | HTTP / Web        | Request spikes, HTTP errors, unusual web activity  |

Layer 7 monitoring supports optional **Nginx and Apache access logs**.

---

## DoS / DDoS Detection

LBShield combines multiple defensive signals:

```text id="qetxvb"
PPS Spike
Bandwidth Spike
Connection Spike
SYN_RECV Spike
Unique Source Spike
HTTP Request Spike
HTTP Error Spike
```

Traffic is compared against rolling baselines and configurable thresholds.

> A traffic anomaly does not automatically mean an attack. Large volumetric attacks require upstream protection from the hosting provider, ISP, CDN or DDoS protection provider.

---

## Incident Lifecycle

```text id="k3zup5"
OBSERVING → ACTIVE → MITIGATING → RECOVERING → RESOLVED
```

Overlapping signatures are deduplicated to prevent the same traffic from being counted multiple times.

---

## Alerts

LBShield supports:

**Discord**

```bash id="c39hbu"
DISCORD_WEBHOOK_URL=
```

**Telegram**

```bash id="vvclmw"
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Example alert:

```text id="by01ny"
Warning ! [ High RAM usage: 94% ]
```

Webhook URLs and bot tokens are never logged or displayed.

---

## Configuration

Example `lbshield.yaml`:

```yaml id="fngnvs"
server:
  id: "LB-GAME-01"
  name: "GAME-01"
  public_ip: "auto"
  hostname: "auto"
  interface: "auto"
```

Configuration is validated using Pydantic.

---

## Architecture

```text id="nmqcb9"
monitors/    → Telemetry collection
detection/   → Thresholds & anomaly detection
network/     → Network analysis
alerts/      → Console, Discord & Telegram
incidents/   → Incident management
storage/     → SQLite database
ui/          → Terminal interface
```

---

## Linux Service

```bash id="gssjsa"
sudo cp deploy/lbshield.service /etc/systemd/system/lbshield.service
sudo systemctl daemon-reload
sudo systemctl enable --now lbshield
```

Check status:

```bash id="0v3r4q"
sudo systemctl status lbshield
```

View logs:

```bash id="oyjnb4"
sudo journalctl -u lbshield -f
```

---

## Security & Privacy

LBShield is **defensive-only**.

It does not perform flooding, amplification, exploitation, credential theft, spoofing or attack traffic generation.

Sensitive information such as passwords, authentication tokens, cookies, Discord webhook URLs and Telegram bot tokens is not stored.

---

## Testing

```bash id="t46mgv"
pytest
```

Tests cover monitoring, thresholds, network baselines, TCP states, incidents, alerts, file integrity, storage and demo safety.
