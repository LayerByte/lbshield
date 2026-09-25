"""Small Rich components."""

from __future__ import annotations

from rich.panel import Panel


def status_panel(status: str, threat: str, events: int, warnings: int) -> Panel:
    style = "green" if threat == "NORMAL" else "yellow"
    return Panel(
        f"STATUS      [{style}]{status}[/{style}]\nTHREAT      [{style}]{threat}[/{style}]\nEVENTS      {events}\nWARNINGS    {warnings}",
        title="SECURITY",
        border_style=style,
    )

