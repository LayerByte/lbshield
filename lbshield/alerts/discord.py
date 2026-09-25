"""Discord webhook alert provider."""

from __future__ import annotations

import os

import httpx


class DiscordAlertProvider:
    def __init__(self, webhook_url: str | None = None, mode: str = "text") -> None:
        self.webhook_url = webhook_url or os.getenv("DISCORD_WEBHOOK_URL")
        self.mode = mode

    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def send_text(self, text: str) -> bool:
        if not self.webhook_url:
            return False
        payload = {"content": text[:1900]}
        try:
            response = httpx.post(self.webhook_url, json=payload, timeout=5)
            response.raise_for_status()
            return True
        except httpx.HTTPError:
            return False

    def send_embed(self, title: str, description: str) -> bool:
        if not self.webhook_url:
            return False
        payload = {"embeds": [{"title": title[:256], "description": description[:3900]}]}
        try:
            response = httpx.post(self.webhook_url, json=payload, timeout=5)
            response.raise_for_status()
            return True
        except httpx.HTTPError:
            return False

