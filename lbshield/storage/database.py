"""SQLite storage for metrics, events and incidents."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from lbshield.models import Event, Incident


SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  name TEXT NOT NULL,
  value REAL NOT NULL,
  labels TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  key TEXT NOT NULL,
  severity TEXT NOT NULL,
  message TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  server_name TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  peak_pps REAL,
  peak_bps REAL,
  details TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS signatures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT NOT NULL,
  name TEXT NOT NULL,
  layer TEXT NOT NULL,
  protocol TEXT,
  peak_pps REAL,
  peak_bps REAL,
  evidence TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS process_events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS network_events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS file_integrity (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alert_history (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, key TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS baselines (name TEXT PRIMARY KEY, value REAL NOT NULL, updated_at TEXT NOT NULL);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def insert_metric(self, name: str, value: float, created_at: str, labels: dict[str, Any] | None = None) -> None:
        self.conn.execute(
            "INSERT INTO metrics (created_at, name, value, labels) VALUES (?, ?, ?, ?)",
            (created_at, name, float(value), json.dumps(labels or {})),
        )
        self.conn.commit()

    def insert_event(self, event: Event) -> None:
        self.conn.execute(
            "INSERT INTO events (created_at, key, severity, message, details) VALUES (?, ?, ?, ?, ?)",
            (event.created_at.isoformat(), event.key, event.severity.value, event.message, json.dumps(event.details)),
        )
        self.conn.commit()

    def upsert_file_hash(self, path: str, sha256: str, updated_at: str) -> None:
        self.conn.execute(
            "INSERT INTO file_integrity (path, sha256, updated_at) VALUES (?, ?, ?) ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256, updated_at=excluded.updated_at",
            (path, sha256, updated_at),
        )
        self.conn.commit()

    def get_file_hash(self, path: str) -> str | None:
        row = self.conn.execute("SELECT sha256 FROM file_integrity WHERE path = ?", (path,)).fetchone()
        return str(row[0]) if row else None

    def upsert_incident(self, incident: Incident) -> None:
        details = {
            "hostname": incident.server.hostname,
            "public_ip": incident.server.public_ip,
            "interface": incident.server.interface,
            "observed_pps": incident.observed_pps,
            "observed_bps": incident.observed_bps,
            "unique_sources": incident.unique_sources,
            "top_sources": incident.top_sources,
            "target_ports": incident.target_ports,
        }
        self.conn.execute(
            """
            INSERT INTO incidents (incident_id, server_id, server_name, status, started_at, ended_at, peak_pps, peak_bps, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET status=excluded.status, ended_at=excluded.ended_at, peak_pps=excluded.peak_pps, peak_bps=excluded.peak_bps, details=excluded.details
            """,
            (
                incident.incident_id,
                incident.server.server_id,
                incident.server.name,
                incident.status.value,
                incident.started_at.isoformat(),
                incident.ended_at.isoformat() if incident.ended_at else None,
                incident.peak_pps,
                incident.peak_bps,
                json.dumps(details),
            ),
        )
        self.conn.execute("DELETE FROM signatures WHERE incident_id = ?", (incident.incident_id,))
        self.conn.executemany(
            "INSERT INTO signatures (incident_id, name, layer, protocol, peak_pps, peak_bps, evidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (incident.incident_id, sig.name, sig.layer, sig.protocol, sig.peak_pps, sig.peak_bps, json.dumps(sig.evidence))
                for sig in incident.signatures
            ],
        )
        self.conn.commit()

