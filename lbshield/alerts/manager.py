"""Alert cooldown, deduplication and provider fan-out."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from lbshield.alerts.console import ConsoleAlertProvider
from lbshield.alerts.discord import DiscordAlertProvider
from lbshield.alerts.formatter import discord_incident_text, standard_alert, telegram_incident_text
from lbshield.alerts.telegram import TelegramAlertProvider
from lbshield.config import AppConfig
from lbshield.models import Event, Incident


@dataclass(slots=True)
class AlertState:
    active: bool = False
    last_sent: float = 0.0
    last_message: str = ""


class AlertManager:
    def __init__(
        self,
        config: AppConfig,
        console: ConsoleAlertProvider | None = None,
        discord: DiscordAlertProvider | None = None,
        telegram: TelegramAlertProvider | None = None,
    ) -> None:
        self.config = config
        self.console = console or ConsoleAlertProvider()
        self.discord = discord or DiscordAlertProvider(mode=config.discord.format)
        self.telegram = telegram or TelegramAlertProvider()
        self.states: dict[str, AlertState] = {}

    def should_send(self, event: Event) -> bool:
        now = time.monotonic()
        state = self.states.setdefault(event.key, AlertState())
        if event.resolved:
            state.active = False
            state.last_sent = now
            state.last_message = event.message
            return True
        if not state.active:
            state.active = True
            state.last_sent = now
            state.last_message = event.message
            return True
        elapsed = now - state.last_sent
        if elapsed >= self.config.alerts.reminder_seconds:
            state.last_sent = now
            state.last_message = event.message
            return True
        return False

    def send_event(self, event: Event) -> None:
        if not self.should_send(event):
            return
        text = standard_alert(event)
        if self.config.alerts.console:
            self.console.send_event(event)
        if self.config.alerts.discord:
            self.discord.send_text(text)
        if self.config.alerts.telegram:
            self.telegram.send_text(text)

    def send_incident(self, incident: Incident) -> None:
        discord_text = discord_incident_text(incident)
        if self.config.alerts.console:
            self.console.send_incident(incident, discord_text)
        if self.config.alerts.discord:
            self.discord.send_text(discord_text)
        if self.config.alerts.telegram:
            self.telegram.send_text(telegram_incident_text(incident))

