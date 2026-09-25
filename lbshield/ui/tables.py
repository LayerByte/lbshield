"""Rich table helpers."""

from __future__ import annotations

from rich.table import Table

from lbshield.models import Event


def key_value_table(title: str, rows: list[tuple[str, str]], style: str = "cyan") -> Table:
    table = Table(title=title, show_header=False, box=None, expand=True)
    table.add_column("Key", style="dim white")
    table.add_column("Value", style=style)
    for key, value in rows:
        table.add_row(key, value)
    return table


def events_table(events: list[Event]) -> Table:
    table = Table(title="RECENT EVENTS", expand=True)
    table.add_column("Time", style="dim white")
    table.add_column("Severity")
    table.add_column("Message")
    for event in events[-10:]:
        style = {"INFO": "green", "WARNING": "yellow", "HIGH": "magenta", "CRITICAL": "red"}.get(event.severity.value, "white")
        table.add_row(event.created_at.strftime("%H:%M"), f"[{style}]{event.severity.value}[/{style}]", event.message)
    return table

