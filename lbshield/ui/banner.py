"""Banner rendering."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from lbshield import __version__
from lbshield.models import ServerMetadata


def banner(server: ServerMetadata, state: str = "PROTECTED") -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim white")
    table.add_column(style="cyan")
    table.add_row("Version", __version__)
    table.add_row("Hostname", server.hostname)
    table.add_row("Server", server.name)
    table.add_row("Monitoring", state)
    return Panel(table, title="[bold green]LBShield[/bold green]", subtitle="Linux Server Security & DDoS Monitor", border_style="cyan")

