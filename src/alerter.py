from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Optional

from .utils import now_utc

if TYPE_CHECKING:
    from .database import Database


class AlertEvaluator:
    """
    Evaluates whether a CVE meets the criteria to trigger an alert.
    Supports dynamic runtime settings and technology watchlists stored in the Database.
    """

    def __init__(
        self,
        min_cvss: float = 0.0,
        only_high_or_kev: bool = False,
        max_cve_age_days: int = 7,
        database: Optional["Database"] = None,
        rating_filter: str = "",
    ):
        self.default_min_cvss = min_cvss
        self.default_only_high_or_kev = only_high_or_kev
        self.default_max_cve_age_days = max_cve_age_days
        self.default_rating_filter = rating_filter.strip().lower()
        self.db = database

    def get_rating_filter(self) -> str:
        """
        Get the current severity rating filter:
        'critical', 'high', 'medium', or 'all'
        """
        if self.db:
            val = self.db.get_state("setting_rating_filter")
            if val:
                return val.lower().strip()

        if self.default_rating_filter in ("critical", "high", "medium", "all"):
            return self.default_rating_filter

        if self.default_only_high_or_kev or self.default_min_cvss >= 7.0:
            return "high"
        if self.default_min_cvss >= 9.0:
            return "critical"
        if self.default_min_cvss >= 4.0:
            return "medium"
        return "all"

    def get_min_cvss(self) -> float:
        """Get the effective minimum CVSS threshold (database override or default)."""
        if self.db:
            val = self.db.get_state("setting_min_cvss")
            if val is not None:
                try:
                    return float(val)
                except ValueError:
                    pass
        return self.default_min_cvss

    def get_max_cve_age_days(self) -> int:
        """Get the effective maximum CVE age in days."""
        if self.db:
            val = self.db.get_state("setting_max_cve_age_days")
            if val is not None:
                try:
                    return int(val)
                except ValueError:
                    pass
        return self.default_max_cve_age_days

    def evaluate_reason(
        self,
        score: float | None,
        severity: str,
        is_kev: bool,
        published_dt: Optional[datetime] = None,
        products: str = "",
        description: str = "",
    ) -> str | None:
        """
        Determine if an alert should be triggered and return the reason string,
        or None if criteria are not met.
        """
        # Watchlist filtering: if watchlist is configured, ONLY alert on matching items
        matched_kw = None
        if self.db:
            watchlist = self.db.get_watchlist()
            if watchlist:
                matched_kw = self.db.matches_watchlist(products, description)
                if not matched_kw:
                    # Does not match any watched technology -> skip alert!
                    return None

        watch_tag = f"🎯 Watchlist [{matched_kw}]: " if matched_kw else ""

        # CISA KEV additions always alert regardless of age or score
        if is_kev:
            return f"{watch_tag}CISA KEV: known exploited vulnerability"

        # Check maximum publication age (filters ancient re-indexed CVEs)
        max_age = self.get_max_cve_age_days()
        if max_age > 0 and published_dt:
            age = now_utc() - published_dt
            if age > timedelta(days=max_age):
                return None

        rating = self.get_rating_filter()
        sev_upper = (severity or "UNKNOWN").upper()

        if rating == "critical":
            if (score is not None and score >= 9.0) or sev_upper == "CRITICAL":
                return f"{watch_tag}CVSS {score:.1f} (CRITICAL)" if score is not None else f"{watch_tag}Severity CRITICAL; CVSS not assigned"
            return None

        elif rating == "high":
            if (score is not None and score >= 7.0) or sev_upper in ("HIGH", "CRITICAL"):
                return f"{watch_tag}CVSS {score:.1f} ({sev_upper})" if score is not None else f"{watch_tag}Severity {sev_upper}; CVSS not assigned"
            return None

        elif rating == "medium":
            if (score is not None and score >= 4.0) or sev_upper in ("MEDIUM", "HIGH", "CRITICAL"):
                return f"{watch_tag}CVSS {score:.1f} ({sev_upper})" if score is not None else f"{watch_tag}Severity {sev_upper}; CVSS not assigned"
            return None

        # rating == 'all'
        min_cvss = self.get_min_cvss()
        if score is not None and score >= min_cvss:
            return f"{watch_tag}CVSS {score:.1f} ({sev_upper})"

        if score is None and min_cvss <= 0:
            return f"{watch_tag}Severity {sev_upper}; CVSS not assigned"

        return None
