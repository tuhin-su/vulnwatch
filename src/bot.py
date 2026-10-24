import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests

from .config import Config
from .database import Database
from .nvd import CVEParser, NVDClient
from .telegram import TelegramNotifier
from .utils import parse_date

log = logging.getLogger("vulnwatch.bot")


class TelegramBotListener:
    """
    Listens for incoming Telegram commands via long-polling and responds to authorized users.
    Supports interactive commands:
      /rating [all|medium|high|critical] - View or change alert rating threshold live
      /critical, /high, /medium, /low - Browse vulnerabilities by severity
      /date YYYY-MM-DD - Search vulnerabilities published on a specific date
      /cve CVE-YYYY-NNNN - Detailed lookup for a specific CVE
      /set <key> <value> - Update runtime settings directly from Telegram
      /status - System status, sync statistics, and database counts
      /settings - Display active configuration settings and overrides
      /latest - View most recently recorded vulnerabilities
      /kev - View recent CISA Known Exploited Vulnerabilities
      /start, /help - Show available commands
    """

    def __init__(
        self,
        config: Config,
        database: Database,
        nvd_client: NVDClient,
        telegram_notifier: TelegramNotifier,
    ):
        self.config = config
        self.db = database
        self.nvd = nvd_client
        self.notifier = telegram_notifier
        self.last_update_id = 0
        self.session = requests.Session()
        self.running = False
        self._thread: threading.Thread | None = None

    def setup_bot_commands(self) -> None:
        """
        Drop any stale pending updates from previous offline sessions
        and register current VulnWatch commands with Telegram Bot API.
        """
        token = self.config.telegram_bot_token
        if not token:
            return

        base_url = f"https://api.telegram.org/bot{token}"

        # 1. Clear any old pending messages from previous offline sessions
        try:
            res = self.session.post(
                f"{base_url}/deleteWebhook",
                json={"drop_pending_updates": True},
                timeout=10,
            )
            if res.status_code == 200:
                log.info("Cleared stale Telegram updates queue.")
        except Exception as exc:
            log.warning("Could not clear pending Telegram updates: %s", exc)

        # 2. Register fresh VulnWatch commands list
        commands = [
            {"command": "rating", "description": "View or set alert severity filter"},
            {"command": "critical", "description": "View latest Critical CVEs (CVSS 9.0+)"},
            {"command": "high", "description": "View latest High CVEs (CVSS 7.0+)"},
            {"command": "medium", "description": "View latest Medium CVEs (CVSS 4.0+)"},
            {"command": "watch_add", "description": "Add program/framework to watchlist (/watch_add php)"},
            {"command": "watch_delete", "description": "Remove program/framework from watchlist"},
            {"command": "watch_list", "description": "View active technology watchlist"},
            {"command": "date", "description": "Search CVEs by date (YYYY-MM-DD)"},
            {"command": "cve", "description": "Lookup details for a specific CVE ID"},
            {"command": "latest", "description": "Show 5 most recently published CVEs"},
            {"command": "kev", "description": "Show CISA Known Exploited Vulnerabilities"},
            {"command": "set", "description": "Configure settings on the fly"},
            {"command": "settings", "description": "View active configuration & overrides"},
            {"command": "status", "description": "View service health & database counts"},
            {"command": "help", "description": "Show command help menu"},
        ]

        try:
            res = self.session.post(
                f"{base_url}/setMyCommands",
                json={"commands": commands},
                timeout=10,
            )
            if res.status_code == 200 and res.json().get("ok"):
                log.info("Registered %d Telegram commands with Bot API.", len(commands))
            else:
                log.warning("Failed to register Telegram commands: %s", res.text)
        except Exception as exc:
            log.warning("Could not register Telegram commands: %s", exc)

    def start_in_background(self) -> None:
        """Launch the Telegram command polling loop in a background daemon thread."""
        if not self.notifier.is_configured:
            log.warning("Telegram Bot Token is not configured; command listener disabled.")
            return

        # Clear old updates & sync command menu on startup
        self.setup_bot_commands()

        self.running = True
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="TelegramBotListener",
            daemon=True,
        )
        self._thread.start()
        log.info("Telegram command listener started in background.")

    def stop(self) -> None:
        """Signal the polling loop to stop."""
        self.running = False

    def _poll_loop(self) -> None:
        """Continuous polling loop using getUpdates."""
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/getUpdates"

        while self.running:
            try:
                params = {
                    "timeout": 15,
                    "offset": self.last_update_id + 1 if self.last_update_id else 0,
                    "allowed_updates": ["message"],
                }
                response = self.session.get(url, params=params, timeout=25)
                if response.status_code != 200:
                    time.sleep(3)
                    continue

                data = response.json()
                if not data.get("ok"):
                    time.sleep(3)
                    continue

                updates = data.get("result", [])
                for update in updates:
                    update_id = update.get("update_id", 0)
                    if update_id > self.last_update_id:
                        self.last_update_id = update_id

                    message = update.get("message")
                    if not message or "text" not in message:
                        continue

                    self._handle_message(message)

            except Exception as exc:
                log.debug("Error in Telegram poll loop: %s", exc)
                time.sleep(3)

    def _is_authorized(self, user_id: int | str, chat_id: int | str) -> bool:
        """Verify that the sender matches the configured TELEGRAM_USER_ID or TELEGRAM_CHAT_ID."""
        expected = str(self.config.telegram_chat_id).strip()
        return str(user_id) == expected or str(chat_id) == expected

    def _reply(self, chat_id: int | str, text: str) -> None:
        """Send a reply to the specified chat."""
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        try:
            self.session.post(
                url,
                json={
                    "chat_id": chat_id,
                    "text": text[:4000],
                    "disable_web_page_preview": True,
                },
                timeout=15,
            )
        except Exception as exc:
            log.error("Failed to send Telegram reply: %s", exc)

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Parse incoming message and dispatch commands."""
        sender = message.get("from", {})
        user_id = sender.get("id")
        chat_id = message.get("chat", {}).get("id")
        text = message.get("text", "").strip()

        if not self._is_authorized(user_id, chat_id):
            log.warning("Received command from unauthorized user %s (chat %s)", user_id, chat_id)
            self._reply(chat_id, "🚫 Access denied: You are not authorized to use this bot.")
            return

        parts = text.split()
        if not parts:
            return

        raw_cmd = parts[0].lower()
        cmd = raw_cmd.split("@")[0]  # Strip bot handle if present (e.g. /status@bot)
        args = parts[1:]

        if cmd in ("/start", "/help"):
            self._cmd_help(chat_id)
        elif cmd in ("/rating", "/filter"):
            self._cmd_rating(chat_id, args)
        elif cmd in ("/watch_add", "/wach_add"):
            self._cmd_watch_add(chat_id, args)
        elif cmd in ("/watch_delete", "/wach_delete", "/watch_del", "/wach_del"):
            self._cmd_watch_delete(chat_id, args)
        elif cmd in ("/watch_list", "/wach_list", "/watchlist"):
            self._cmd_watch_list(chat_id)
        elif cmd in ("/watch_clear", "/wach_clear"):
            self._cmd_watch_clear(chat_id)
        elif cmd == "/critical":
            self._cmd_severity(chat_id, "CRITICAL", args)
        elif cmd == "/high":
            self._cmd_severity(chat_id, "HIGH", args)
        elif cmd == "/medium":
            self._cmd_severity(chat_id, "MEDIUM", args)
        elif cmd == "/low":
            self._cmd_severity(chat_id, "LOW", args)
        elif cmd == "/set":
            self._cmd_set(chat_id, args)
        elif cmd == "/date":
            self._cmd_date(chat_id, args)
        elif cmd == "/status":
            self._cmd_status(chat_id)
        elif cmd == "/settings":
            self._cmd_settings(chat_id)
        elif cmd == "/cve":
            self._cmd_cve(chat_id, args)
        elif cmd == "/latest":
            self._cmd_latest(chat_id)
        elif cmd == "/kev":
            self._cmd_kev(chat_id)
        else:
            self._reply(chat_id, f"Unknown command: {cmd}\nSend /help to see all available commands.")

    def _cmd_help(self, chat_id: int | str) -> None:
        text = (
            "🛡️ *VulnWatch Interactive Bot*\n\n"
            "🎯 *Alert Rating & Settings:*\n"
            "• `/rating [critical|high|medium|all]` — Set alert severity filter\n"
            "• `/set <key> <value>` — Update settings directly from Telegram\n"
            "• `/settings` — Inspect current active settings & overrides\n\n"
            "🎯 *Specific Technology Watchlist:*\n"
            "• `/watch_add <name>` — Watch only specific software (e.g. `/watch_add php`)\n"
            "• `/watch_delete <name>` — Remove software from watchlist\n"
            "• `/watch_list` — Show currently monitored technologies\n\n"
            "🔍 *Vulnerability Lookup:*\n"
            "• `/critical` — View latest Critical vulnerabilities\n"
            "• `/high` — View latest High vulnerabilities\n"
            "• `/medium` — View latest Medium vulnerabilities\n"
            "• `/date YYYY-MM-DD` — Search CVEs published on a specific date\n"
            "• `/cve CVE-YYYY-NNNN` — View detailed info for any CVE\n"
            "• `/latest` — View most recently recorded vulnerabilities\n"
            "• `/kev` — View recent CISA Known Exploited Vulnerabilities\n\n"
            "📊 *System:*\n"
            "• `/status` — View monitor health, sync cursor & statistics\n"
            "• `/help` — Display this command menu"
        )
        self._reply(chat_id, text)

    def _cmd_rating(self, chat_id: int | str, args: list[str]) -> None:
        """View or set the alert rating filter (all, medium, high, critical)."""
        valid_ratings = {
            "critical": ("CRITICAL ONLY", 9.0, "Only CVSS ≥ 9.0 or CISA KEV entries will trigger alerts."),
            "high": ("HIGH & CRITICAL", 7.0, "CVSS ≥ 7.0 and CISA KEV entries will trigger alerts."),
            "medium": ("MEDIUM, HIGH & CRITICAL", 4.0, "CVSS ≥ 4.0 and CISA KEV entries will trigger alerts."),
            "all": ("ALL SEVERITIES", 0.0, "All published vulnerabilities will trigger alerts."),
        }

        current_filter = (self.db.get_state("setting_rating_filter") or "high" if self.config.only_high_or_kev else "all").lower()

        if not args:
            label, min_score, desc = valid_ratings.get(current_filter, ("CUSTOM", 0.0, "Custom filter active."))
            text = (
                f"🎯 *Current Alert Rating Filter:* `{label}`\n"
                f"ℹ️ {desc}\n\n"
                "To change the alert threshold, send:\n"
                "• `/rating critical` — Critical only (CVSS 9.0 - 10.0)\n"
                "• `/rating high` — High & Critical (CVSS 7.0 - 10.0)\n"
                "• `/rating medium` — Medium, High & Critical (CVSS 4.0 - 10.0)\n"
                "• `/rating all` — All vulnerabilities (CVSS 0.0 - 10.0)"
            )
            self._reply(chat_id, text)
            return

        choice = args[0].strip().lower()
        if choice not in valid_ratings:
            self._reply(
                chat_id,
                f"❌ Invalid rating option: `{choice}`\n\n"
                "Valid options are:\n"
                "• `/rating critical` (CVSS ≥ 9.0)\n"
                "• `/rating high` (CVSS ≥ 7.0)\n"
                "• `/rating medium` (CVSS ≥ 4.0)\n"
                "• `/rating all` (All CVEs)"
            )
            return

        label, min_score, desc = valid_ratings[choice]
        self.db.set_state("setting_rating_filter", choice)
        self.db.set_state("setting_min_cvss", str(min_score))

        text = (
            f"✅ *Alert Rating Updated!*\n\n"
            f"• *New Setting:* `{label}`\n"
            f"• *Min CVSS Threshold:* `{min_score}`\n"
            f"• *Effect:* {desc}\n\n"
            "This setting is saved and applies immediately to all upcoming background sync cycles."
        )
        self._reply(chat_id, text)

    def _cmd_watch_add(self, chat_id: int | str, args: list[str]) -> None:
        """Add a software, framework, or vendor to the monitored watchlist."""
        if not args:
            self._reply(
                chat_id,
                "⚠️ *Usage:* `/watch_add <name>`\n"
                "Examples:\n"
                "• `/watch_add php`\n"
                "• `/watch_add laravel`\n"
                "• `/watch_add wordpress`\n"
                "• `/watch_add nginx`"
            )
            return

        name = " ".join(args).strip().lower()
        if len(name) < 2:
            self._reply(chat_id, "⚠️ Technology keyword must be at least 2 characters long.")
            return

        added = self.db.add_to_watchlist(name)
        watchlist = self.db.get_watchlist()

        if not added:
            self._reply(
                chat_id,
                f"ℹ️ `{name}` is already in your watchlist.\n\n"
                f"📋 *Active Watchlist ({len(watchlist)} items):*\n`{', '.join(watchlist)}`"
            )
            return

        text = (
            f"✅ *Added to Watchlist:* `{name}`\n\n"
            "🎯 *Watchlist Mode Active:*\n"
            "VulnWatch will now filter alerts to ONLY notify you when a vulnerability affects your watched technologies.\n\n"
            f"📋 *Currently Monitored ({len(watchlist)} items):*\n"
            + "\n".join(f"• 🔹 `{kw}`" for kw in watchlist)
            + "\n\nTo view list: `/watch_list` | To remove: `/watch_delete " + name + "`"
        )
        self._reply(chat_id, text)

    def _cmd_watch_delete(self, chat_id: int | str, args: list[str]) -> None:
        """Remove a software or framework from the watchlist."""
        if not args:
            self._reply(
                chat_id,
                "⚠️ *Usage:* `/watch_delete <name>`\n"
                "Example: `/watch_delete php`\n\n"
                "Send `/watch_list` to see all currently watched items."
            )
            return

        name = " ".join(args).strip().lower()
        removed = self.db.remove_from_watchlist(name)
        watchlist = self.db.get_watchlist()

        if not removed:
            self._reply(
                chat_id,
                f"❌ `{name}` was not found in your watchlist.\n\n"
                f"Active items: `{', '.join(watchlist) if watchlist else 'None'}`"
            )
            return

        if watchlist:
            text = (
                f"🗑️ *Removed from Watchlist:* `{name}`\n\n"
                f"📋 *Remaining Watched Technologies ({len(watchlist)}):*\n"
                + "\n".join(f"• 🔹 `{kw}`" for kw in watchlist)
            )
        else:
            text = (
                f"🗑️ *Removed from Watchlist:* `{name}`\n\n"
                "ℹ️ *Your Watchlist is now empty.*\n"
                "VulnWatch has reverted to alerting on all technologies based on your standard severity rating filter."
            )
        self._reply(chat_id, text)

    def _cmd_watch_list(self, chat_id: int | str) -> None:
        """Display all currently monitored technologies in the watchlist."""
        items = self.db.get_watchlist()
        if not items:
            text = (
                "📋 *Your Technology Watchlist is Empty.*\n\n"
                "Currently, VulnWatch monitors all technologies.\n\n"
                "To restrict alerts strictly to specific programs or frameworks, add them:\n"
                "• `/watch_add php`\n"
                "• `/watch_add laravel`\n"
                "• `/watch_add wordpress`\n"
                "• `/watch_add nginx`"
            )
            self._reply(chat_id, text)
            return

        lines = [f"{i}. 🔹 `{kw}`" for i, kw in enumerate(items, 1)]
        text = (
            f"📋 *Active Technology Watchlist* ({len(items)} monitored):\n\n"
            + "\n".join(lines)
            + "\n\n🎯 *Filter Status:* Active (Alerts will only trigger for CVEs affecting these technologies)\n\n"
            "• Add item: `/watch_add <name>`\n"
            "• Remove item: `/watch_delete <name>`\n"
            "• Clear all: `/watch_clear`"
        )
        self._reply(chat_id, text)

    def _cmd_watch_clear(self, chat_id: int | str) -> None:
        """Clear all items from the watchlist."""
        count = self.db.clear_watchlist()
        text = (
            f"🗑️ *Cleared Watchlist ({count} items removed).*\n\n"
            "ℹ️ VulnWatch will now monitor all software based on your severity rating filter."
        )
        self._reply(chat_id, text)

    def _cmd_set(self, chat_id: int | str, args: list[str]) -> None:
        """Dynamically configure settings via Telegram: /set <key> <value>."""
        if len(args) < 2:
            text = (
                "⚙️ *Configure Settings via Telegram*\n\n"
                "Usage: `/set <key> <value>`\n\n"
                "Supported settings:\n"
                "• `/set rating [critical|high|medium|all]` — Set rating filter\n"
                "• `/set cvss <score>` — e.g. `/set cvss 7.5`\n"
                "• `/set poll <seconds>` — e.g. `/set poll 600` (min: 60s)\n"
                "• `/set age <days>` — e.g. `/set age 3` (ignore CVEs older than X days)\n"
                "• `/set reset` — Revert all settings to .env defaults"
            )
            self._reply(chat_id, text)
            return

        key = args[0].strip().lower()
        value = args[1].strip()

        if key in ("rating", "severity", "filter"):
            self._cmd_rating(chat_id, [value])

        elif key in ("cvss", "min_cvss"):
            try:
                score = float(value)
                if not (0.0 <= score <= 10.0):
                    raise ValueError
                self.db.set_state("setting_min_cvss", str(score))
                self._reply(chat_id, f"✅ Minimum CVSS threshold updated to: `{score}`")
            except ValueError:
                self._reply(chat_id, "❌ Invalid CVSS score. Must be a number between 0.0 and 10.0 (e.g. `/set cvss 7.5`).")

        elif key in ("poll", "poll_seconds"):
            try:
                sec = int(value)
                if sec < 60:
                    self._reply(chat_id, "⚠️ Poll interval must be at least 60 seconds.")
                    return
                self.db.set_state("setting_poll_seconds", str(sec))
                self._reply(chat_id, f"✅ Polling frequency updated to: `{sec}s` ({sec // 60}m)")
            except ValueError:
                self._reply(chat_id, "❌ Invalid poll seconds. Must be an integer (e.g. `/set poll 300`).")

        elif key in ("age", "max_age", "max_cve_age_days"):
            try:
                days = int(value)
                if days < 0:
                    raise ValueError
                self.db.set_state("setting_max_cve_age_days", str(days))
                self._reply(chat_id, f"✅ Maximum CVE age updated to: `{days} days` (0 to disable).")
            except ValueError:
                self._reply(chat_id, "❌ Invalid age in days. Must be a positive integer (e.g. `/set age 7`).")

        elif key == "reset":
            for setting_key in ("setting_rating_filter", "setting_min_cvss", "setting_poll_seconds", "setting_max_cve_age_days"):
                with self.db.connect() as conn:
                    conn.execute("DELETE FROM state WHERE key=?", (setting_key,))
            self._reply(chat_id, "🔄 All dynamic overrides have been cleared. Restored to `.env` defaults.")

        else:
            self._reply(
                chat_id,
                f"❌ Unknown setting key: `{key}`\n\n"
                "Supported keys: `rating`, `cvss`, `poll`, `age`, `reset`."
            )

    def _cmd_severity(self, chat_id: int | str, severity: str, args: list[str]) -> None:
        """Browse vulnerabilities by severity: /critical, /high, /medium, /low."""
        limit = 5
        if args and args[0].isdigit():
            limit = max(1, min(20, int(args[0])))

        rows = self.db.get_vulnerabilities_by_severity(severity, limit=limit)
        if not rows:
            self._reply(
                chat_id,
                f"ℹ️ No vulnerabilities with severity *{severity}* found in local database yet."
            )
            return

        items = []
        for i, row in enumerate(rows, 1):
            cve_id = row["cve_id"]
            cvss = f"CVSS {row['cvss']:.1f}" if row["cvss"] is not None else "CVSS Unassigned"
            sev = row["severity"] or severity
            kev_badge = "🔥 [CISA KEV]" if row["kev"] else ""
            pub = (row["published"] or "")[:10]
            prod = (row["products"] or "Unknown")[:45]
            desc = (row["description"] or "")[:130].strip() + "..."
            items.append(
                f"{i}. *{cve_id}* — {sev} ({cvss}) {kev_badge} [{pub}]\n"
                f"   📦 *Product:* {prod}\n"
                f"   📝 {desc}\n"
                f"   🔗 https://nvd.nist.gov/vuln/detail/{cve_id}"
            )

        reply = f"🛡️ *Latest {severity} Vulnerabilities* (Top {len(rows)}):\n\n" + "\n\n".join(items)
        self._reply(chat_id, reply)

    def _cmd_status(self, chat_id: int | str) -> None:
        stats = self.db.get_stats()
        last_sync = stats["last_successful_sync"] or "Not yet synced"
        active_rating = (self.db.get_state("setting_rating_filter") or "high" if self.config.only_high_or_kev else "all").upper()
        min_cvss = self.db.get_state("setting_min_cvss") or str(self.config.min_cvss)
        watchlist = self.db.get_watchlist()
        watch_summary = f"{len(watchlist)} items ({', '.join(watchlist[:3]) + ('...' if len(watchlist) > 3 else '')})" if watchlist else "None (monitoring all technologies)"

        text = (
            "📊 *VulnWatch System Status*\n\n"
            f"• Status: Active 🟢\n"
            f"• Alert Rating Filter: `{active_rating}` (CVSS ≥ {min_cvss})\n"
            f"• Technology Watchlist: `{watch_summary}`\n"
            f"• Last Sync: {last_sync}\n"
            f"• Total Indexed CVEs: {stats['total_vulnerabilities']:,}\n"
            f"• CISA KEV Catalog: {stats['total_kev']:,}\n"
            f"• Total Alerts Sent: {stats['total_alerts']:,}\n"
            f"• Poll Frequency: Every {self.config.poll_seconds}s ({self.config.poll_seconds // 60}m)"
        )
        self._reply(chat_id, text)

    def _cmd_settings(self, chat_id: int | str) -> None:
        active_rating = (self.db.get_state("setting_rating_filter") or "high" if self.config.only_high_or_kev else "all").upper()
        min_cvss = self.db.get_state("setting_min_cvss") or str(self.config.min_cvss)
        poll_sec = self.db.get_state("setting_poll_seconds") or str(self.config.poll_seconds)
        max_age = self.db.get_state("setting_max_cve_age_days") or str(self.config.max_cve_age_days)
        watchlist = self.db.get_watchlist()
        watch_summary = f"{len(watchlist)} items (`{', '.join(watchlist)}`)" if watchlist else "Disabled (all technologies)"

        text = (
            "⚙️ *VulnWatch Active Settings*\n\n"
            f"• Alert Rating Filter: `{active_rating}`\n"
            f"• Min CVSS Alert Threshold: `{min_cvss}`\n"
            f"• Technology Watchlist: {watch_summary}\n"
            f"• Polling Interval: `{poll_sec}s`\n"
            f"• Max CVE Publication Age: `{max_age} days`\n"
            f"• Only Newly Published: `{self.config.only_newly_published}`\n"
            f"• Start From Now (Future Only): `{self.config.start_from_now}`\n"
            f"• NVD API Key: `{'Configured ✅' if self.config.nvd_api_key else 'None (Public limits)'}`\n"
            f"• MCP Server: `{'Online ✅ (Port ' + str(self.config.mcp_port) + ')' if self.config.mcp_enabled else 'Disabled'}`\n"
            f"• Recipient ID: `{self.config.telegram_chat_id}`\n\n"
            "💡 *Change Settings Live:*\n"
            "• `/watch_add <name>` / `/watch_delete <name>`\n"
            "• `/rating [critical | high | medium | all]`\n"
            "• `/set cvss <score>` (e.g. `/set cvss 8.0`)\n"
            "• `/set poll <seconds>` (e.g. `/set poll 300`)"
        )
        self._reply(chat_id, text)

    def _cmd_date(self, chat_id: int | str, args: list[str]) -> None:
        if not args:
            self._reply(
                chat_id,
                "⚠️ Please provide a date in `YYYY-MM-DD` format.\n"
                "Example: `/date 2026-10-24`"
            )
            return

        date_str = args[0].strip()
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_str):
            self._reply(
                chat_id,
                f"❌ Invalid date format: `{date_str}`\n"
                "Please use `YYYY-MM-DD` (e.g. `/date 2026-10-24`)."
            )
            return

        # 1. Search local SQLite database
        rows = self.db.search_by_date(date_str, limit=5)

        # 2. If nothing found locally, query NVD API directly for that date
        if not rows:
            self._reply(chat_id, f"🔍 Searching NVD for vulnerabilities published on {date_str}...")
            try:
                start_dt = datetime.fromisoformat(f"{date_str}T00:00:00+00:00")
                end_dt = datetime.fromisoformat(f"{date_str}T23:59:59+00:00")
                cves = self.nvd.fetch_cves(start=start_dt, end=end_dt, only_newly_published=True)

                for cve in cves:
                    cve_id = cve.get("id")
                    if not cve_id:
                        continue
                    score, severity = CVEParser.extract_cvss(cve)
                    self.db.save_cve_data(
                        cve_id=cve_id,
                        published=cve.get("published"),
                        modified=cve.get("lastModified"),
                        description=CVEParser.extract_description(cve),
                        cvss=score,
                        severity=severity,
                        products=CVEParser.extract_products(cve),
                        cwe=CVEParser.extract_cwes(cve),
                        refs=CVEParser.extract_refs(cve),
                    )

                rows = self.db.search_by_date(date_str, limit=5)

            except Exception as exc:
                log.warning("NVD search failed for %s: %s", date_str, exc)

        if not rows:
            self._reply(chat_id, f"ℹ️ No vulnerabilities found published on {date_str}.")
            return

        items = []
        for i, row in enumerate(rows, 1):
            cve_id = row["cve_id"]
            cvss = f"CVSS {row['cvss']:.1f}" if row["cvss"] is not None else "CVSS Unassigned"
            sev = row["severity"] or "UNKNOWN"
            kev_badge = "🔥 [CISA KEV]" if row["kev"] else ""
            desc = (row["description"] or "")[:150].strip()
            if len(row["description"] or "") > 150:
                desc += "..."
            product = row["products"] or "Unknown"

            items.append(
                f"{i}. 🚨 *{cve_id}* — {sev} ({cvss}) {kev_badge}\n"
                f"   📦 *Product:* {product}\n"
                f"   📝 {desc}\n"
                f"   🔗 https://nvd.nist.gov/vuln/detail/{cve_id}"
            )

        reply = (
            f"📅 *Vulnerabilities Published on {date_str}* (Top {len(rows)}):\n\n"
            + "\n\n".join(items)
        )
        self._reply(chat_id, reply)

    def _cmd_cve(self, chat_id: int | str, args: list[str]) -> None:
        if not args:
            self._reply(chat_id, "⚠️ Usage: `/cve CVE-YYYY-NNNN`\nExample: `/cve CVE-2026-115929`")
            return

        cve_id = args[0].strip().upper()
        row = self.db.get_vulnerability(cve_id)

        # If not in local DB, fetch directly from NVD
        if not row:
            self._reply(chat_id, f"🔍 Looking up {cve_id} in NVD...")
            cve_data = self.nvd.fetch_cve_by_id(cve_id)
            if cve_data:
                score, severity = CVEParser.extract_cvss(cve_data)
                self.db.save_cve_data(
                    cve_id=cve_id,
                    published=cve_data.get("published"),
                    modified=cve_data.get("lastModified"),
                    description=CVEParser.extract_description(cve_data),
                    cvss=score,
                    severity=severity,
                    products=CVEParser.extract_products(cve_data),
                    cwe=CVEParser.extract_cwes(cve_data),
                    refs=CVEParser.extract_refs(cve_data),
                )
                row = self.db.get_vulnerability(cve_id)

        if not row:
            self._reply(chat_id, f"❌ Vulnerability `{cve_id}` was not found in local database or NVD.")
            return

        cvss = f"{row['cvss']:.1f}" if row["cvss"] is not None else "Unassigned"
        kev_text = "YES 🔥 (Actively Exploited)" if row["kev"] else "No"
        desc = (row["description"] or "No description")[:600]

        try:
            refs = json.loads(row["refs"] or "[]")
        except Exception:
            refs = []

        reply = (
            f"🔍 *Vulnerability Details: {cve_id}*\n\n"
            f"• *Severity:* {row['severity']} (CVSS: {cvss})\n"
            f"• *Published:* {row['published'] or 'Unknown'}\n"
            f"• *Modified:* {row['modified'] or 'Unknown'}\n"
            f"• *CISA KEV:* {kev_text}\n"
            f"• *Products:* {row['products'] or 'Unknown'}\n"
            f"• *CWE:* {row['cwe'] or 'None'}\n\n"
            f"📝 *Description:*\n{desc}\n\n"
            f"🔗 *NVD:* https://nvd.nist.gov/vuln/detail/{cve_id}\n"
            + ("• " + "\n• ".join(refs[:2]) if refs else "")
        )
        self._reply(chat_id, reply)

    def _cmd_latest(self, chat_id: int | str) -> None:
        rows = self.db.get_latest_vulnerabilities(limit=5)
        if not rows:
            self._reply(chat_id, "ℹ️ No vulnerabilities recorded in local database yet.")
            return

        items = []
        for i, row in enumerate(rows, 1):
            cve_id = row["cve_id"]
            cvss = f"CVSS {row['cvss']:.1f}" if row["cvss"] is not None else "CVSS unassigned"
            sev = row["severity"] or "UNKNOWN"
            kev = "🔥 [KEV]" if row["kev"] else ""
            pub = (row["published"] or "")[:10]
            items.append(f"{i}. *{cve_id}* — {sev} ({cvss}) {kev} [{pub}]\n   🔗 https://nvd.nist.gov/vuln/detail/{cve_id}")

        reply = "🕒 *Latest Recorded Vulnerabilities:*\n\n" + "\n\n".join(items)
        self._reply(chat_id, reply)

    def _cmd_kev(self, chat_id: int | str) -> None:
        rows = self.db.get_latest_kev(limit=5)
        if not rows:
            self._reply(chat_id, "ℹ️ No CISA KEV entries indexed in database yet.")
            return

        items = []
        for i, row in enumerate(rows, 1):
            cve_id = row["cve_id"]
            added = row["kev_added"] or "Unknown"
            ransom = "⚠️ Ransomware" if row["ransomware"] and row["ransomware"].lower() == "known" else ""
            items.append(f"{i}. 🔥 *{cve_id}* (Added: {added}) {ransom}\n   📦 {row['products']}\n   🔗 https://nvd.nist.gov/vuln/detail/{cve_id}")

        reply = "🔥 *Recent CISA Known Exploited Vulnerabilities:*\n\n" + "\n\n".join(items)
        self._reply(chat_id, reply)
