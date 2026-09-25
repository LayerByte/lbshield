"""SQLite retention pruning."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from lbshield.config import StorageConfig
from lbshield.storage.database import Database


def prune_expired(db: Database, config: StorageConfig) -> None:
    now = datetime.now(UTC)
    metric_cutoff = (now - timedelta(days=config.metrics_days)).isoformat()
    event_cutoff = (now - timedelta(days=config.events_days)).isoformat()
    alert_cutoff = (now - timedelta(days=config.alert_days)).isoformat()
    db.conn.execute("DELETE FROM metrics WHERE created_at < ?", (metric_cutoff,))
    db.conn.execute("DELETE FROM events WHERE created_at < ?", (event_cutoff,))
    db.conn.execute("DELETE FROM alert_history WHERE created_at < ?", (alert_cutoff,))
    db.conn.commit()

