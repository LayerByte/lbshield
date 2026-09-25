"""Telegram Bot API alert provider."""

from __future__ import annotations

import os

import httpx


class TelegramAlertProvider:
    def __init__(self, token: str | None = None, chat_id: str | None = None) -> None:
        self.token = token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")

    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send_text(self, text: str) -> bool:
        if not self.enabled():
            return False
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        try:
            response = httpx.post(url, json={"chat_id": self.chat_id, "text": text[:4000]}, timeout=5)
            response.raise_for_status()
            return True
        except httpx.HTTPError:
            return False

