"""Console alert provider."""

from __future__ import annotations

from rich.console import Console

from lbshield.alerts.formatter import standard_alert
from lbshield.models import Event, Incident, Severity


class ConsoleAlertProvider:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def send_event(self, event: Event) -> None:
        style = {
            Severity.INFO: "dim white",
            Severity.WARNING: "yellow",
            Severity.HIGH: "magenta",
            Severity.CRITICAL: "red bold",
        }[event.severity]
        self.console.print(standard_alert(event), style=style)

    def send_incident(self, incident: Incident, text: str) -> None:
        self.console.print(text, style="magenta")

