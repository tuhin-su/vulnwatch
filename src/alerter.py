from datetime import datetime, timedelta
from typing import Optional

from .utils import now_utc


class AlertEvaluator:
    """Evaluates whether a CVE meets the criteria to trigger an alert."""

    def __init__(
        self,
        min_cvss: float = 0.0,
        only_high_or_kev: bool = False,
        max_cve_age_days: int = 7,
    ):
        self.min_cvss = min_cvss
        self.only_high_or_kev = only_high_or_kev
        self.max_cve_age_days = max_cve_age_days

    def evaluate_reason(
        self,
        score: float | None,
        severity: str,
        is_kev: bool,
        published_dt: Optional[datetime] = None,
    ) -> str | None:
        """
        Determine if an alert should be triggered and return the reason string,
        or None if criteria are not met.
        """
        # CISA KEV additions always alert regardless of age because active exploitation is critical
        if is_kev:
            return "CISA KEV: known exploited vulnerability"

        # If publication date is too old (e.g. ancient CVE re-indexed), skip alert
        if self.max_cve_age_days > 0 and published_dt:
            age = now_utc() - published_dt
            if age > timedelta(days=self.max_cve_age_days):
                return None

        if self.only_high_or_kev:
            threshold = max(7.0, self.min_cvss)
            if score is not None and score >= threshold:
                return f"CVSS {score:.1f} ({severity})"
            return None

        if score is not None and score >= self.min_cvss:
            return f"CVSS {score:.1f} ({severity})"

        if score is None and self.min_cvss <= 0:
            return f"Severity {severity}; CVSS not assigned"

        return None
