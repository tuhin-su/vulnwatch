import logging
import time
from datetime import timedelta
from typing import Any

from .alerter import AlertEvaluator
from .config import Config
from .database import Database
from .kev import KEVClient
from .nvd import CVEParser, NVDClient
from .telegram import TelegramNotifier
from .utils import iso_utc, now_utc, parse_date

log = logging.getLogger("vulnwatch.service")


class VulnWatchService:
    """Orchestrates vulnerability syncing from NVD and CISA KEV and triggers alerts."""

    def __init__(
        self,
        config: Config,
        database: Database,
        nvd_client: NVDClient,
        kev_client: KEVClient,
        telegram_notifier: TelegramNotifier,
        alerter: AlertEvaluator,
    ):
        self.config = config
        self.db = database
        self.nvd = nvd_client
        self.kev = kev_client
        self.telegram = telegram_notifier
        self.alerter = alerter

    def send_alert(self, cve_id: str, reason: str) -> bool:
        """Fetch vulnerability from DB, deliver Telegram notification, and record it."""
        if self.db.is_alert_sent(cve_id):
            return False

        row = self.db.get_vulnerability(cve_id)
        if not row:
            return False

        if not self.telegram.send_alert(row, reason):
            return False

        self.db.record_alert_sent(cve_id, reason)
        log.info("Alert delivered: %s", cve_id)
        return True

    def process_kev(self, kev_catalog: dict[str, dict[str, Any]]) -> int:
        """
        Record KEV items in database. On initial bootstrap, baseline older entries
        and alert only for entries added within the cutoff window.
        """
        previous = parse_date(self.db.get_state("last_successful_sync"))
        cutoff = previous or (
            now_utc() - timedelta(hours=self.config.bootstrap_hours)
        )
        recorded = 0

        for cve_id, item in kev_catalog.items():
            is_new = self.db.update_or_insert_kev_entry(
                cve_id, item, self.config.kev_url
            )
            if is_new:
                recorded += 1

            added = parse_date(item.get("dateAdded"))
            if added and added >= cutoff:
                self.send_alert(
                    cve_id,
                    "CISA KEV: newly added known exploited vulnerability",
                )

        return recorded

    def run_cycle(self) -> None:
        """Execute one complete synchronization cycle."""
        now = now_utc()
        previous_str = self.db.get_state("last_successful_sync")
        previous = parse_date(previous_str)

        # If fresh start and start_from_now is configured:
        # initialize cursor to now so only FUTURE vulnerabilities alert.
        if not previous and self.config.start_from_now:
            log.info(
                "Fresh start with START_FROM_NOW enabled: initializing cursor to current time. "
                "Monitoring for latest / future vulnerabilities only."
            )
            kev_catalog = self.kev.fetch_kev()
            for cve_id, item in kev_catalog.items():
                self.db.update_or_insert_kev_entry(
                    cve_id, item, self.config.kev_url
                )
            self.db.set_state("last_successful_sync", iso_utc(now))
            log.info("Baseline complete (%d KEV entries indexed). Watching for new events.", len(kev_catalog))
            return

        start = (
            previous - timedelta(minutes=self.config.overlap_minutes)
            if previous
            else now - timedelta(hours=self.config.bootstrap_hours)
        )
        end = now - timedelta(seconds=5)

        if start > end:
            start = now - timedelta(hours=self.config.bootstrap_hours)

        date_mode = "pubDate" if self.config.only_newly_published else "lastModDate"
        log.info("Checking NVD (%s): %s through %s", date_mode, iso_utc(start), iso_utc(end))

        # Fetch from both sources before advancing cursor.
        kev_catalog = self.kev.fetch_kev()
        cves = self.nvd.fetch_cves(
            start=start,
            end=end,
            only_newly_published=self.config.only_newly_published,
        )
        log.info(
            "NVD returned %d CVE records; KEV has %d entries",
            len(cves), len(kev_catalog),
        )

        for cve in cves:
            cve_id = cve.get("id")
            if not cve_id:
                continue

            score, severity = CVEParser.extract_cvss(cve)
            kev_item = kev_catalog.get(cve_id)

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
                kev_item=kev_item,
            )

            row = self.db.get_vulnerability(cve_id)
            if not row:
                continue

            reason = self.alerter.evaluate_reason(
                score=row["cvss"],
                severity=row["severity"],
                is_kev=bool(row["kev"]),
                published_dt=parse_date(row["published"]),
            )
            if reason:
                self.send_alert(cve_id, reason)

        recorded = self.process_kev(kev_catalog)

        # Advance state cursor only after both stages finish cleanly.
        self.db.set_state("last_successful_sync", iso_utc(end))
        log.info("Sync complete; %d KEV entries newly recorded", recorded)

    def run_forever(self) -> None:
        """Run monitor loop continuously."""
        self.db.init_db()

        if not self.telegram.is_configured:
            log.warning("Telegram credentials missing or incomplete; alerts disabled.")

        while True:
            try:
                self.run_cycle()
            except Exception:
                log.exception("Sync failed; will retry on the next cycle")

            time.sleep(self.config.poll_seconds)
