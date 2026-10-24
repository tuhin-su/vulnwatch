import json
import logging
from typing import Any

import requests

log = logging.getLogger("vulnwatch.telegram")


class TelegramNotifier:
    """Delivers alerts via the Telegram Bot API to a user ID or chat ID."""

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        app_name: str = "VulnWatch",
        session: requests.Session | None = None,
    ):
        self.bot_token = bot_token.strip().strip("'\"")
        self.chat_id = chat_id.strip().strip("'\"")
        self.app_name = app_name
        self.session = session or requests.Session()

    @property
    def is_configured(self) -> bool:
        """Check whether both bot token and recipient chat/user ID are provided."""
        return bool(self.bot_token and self.chat_id)

    def send_message(self, message: str) -> bool:
        """Send a plain text message to the configured Telegram recipient."""
        if not self.is_configured:
            log.warning("Telegram is not configured; message not sent")
            return False

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

        try:
            response = self.session.post(
                url,
                json={
                    "chat_id": self.chat_id,
                    "text": message[:3900],
                    "disable_web_page_preview": True,
                },
                timeout=(10, 30),
            )
            response.raise_for_status()

            if not response.json().get("ok"):
                log.error("Telegram API rejected the message: %s", response.text)
                return False

            return True

        except (requests.RequestException, ValueError) as exc:
            log.error("Telegram delivery failed: %s", exc)
            return False

    def format_alert(self, row: Any, reason: str) -> str:
        """Format vulnerability record into a readable Telegram alert message."""
        cve_id = row["cve_id"]

        try:
            refs = json.loads(row["refs"] or "[]")
        except (ValueError, TypeError):
            refs = []

        kev_info = ""
        if row["kev"]:
            kev_info = (
                "\nCISA KEV: YES"
                f"\nDate added: {row['kev_added'] or 'unknown'}"
                f"\nRemediation due: {row['kev_due'] or 'not listed'}"
                f"\nRansomware use: {row['ransomware'] or 'unknown'}"
            )

        return (
            f"🚨 {self.app_name} vulnerability alert\n"
            f"{cve_id} — {row['severity']}\n"
            f"Reason: {reason}\n"
            f"CVSS: {row['cvss'] if row['cvss'] is not None else 'unassigned'}\n"
            f"Published: {row['published'] or 'unknown'}\n"
            f"Modified: {row['modified'] or 'unknown'}\n"
            f"Products: {row['products']}\n"
            f"CWE: {row['cwe']}\n"
            f"{kev_info}\n\n"
            f"Description: {row['description']}\n\n"
            f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}\n"
            "References:\n"
            + ("\n".join(refs[:3]) if refs else "No references available")
            + "\n\nVerify affected versions against the vendor advisory."
        )

    def send_alert(self, row: Any, reason: str) -> bool:
        """Format and deliver a vulnerability alert to Telegram."""
        text = self.format_alert(row, reason)
        return self.send_message(text)
