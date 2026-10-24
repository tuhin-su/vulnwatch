import logging
import time
from typing import Any

import requests

log = logging.getLogger("vulnwatch.kev")


class KEVClient:
    """Client for querying CISA Known Exploited Vulnerabilities (KEV) catalog."""

    def __init__(
        self,
        url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        session: requests.Session | None = None,
    ):
        self.url = url
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnWatch/1.0 defensive security monitor",
            "Accept": "application/json",
        })

    def fetch_kev(self, retries: int = 5) -> dict[str, dict[str, Any]]:
        """Fetch and return KEV catalog mapped by cveID."""
        for attempt in range(retries):
            try:
                response = self.session.get(self.url, timeout=(10, 45))
                if response.status_code == 429 or response.status_code >= 500:
                    if attempt == retries - 1:
                        response.raise_for_status()
                    delay = min(60, 2 ** (attempt + 1))
                    log.warning("HTTP %s from CISA KEV; retrying in %ss", response.status_code, delay)
                    time.sleep(delay)
                    continue

                response.raise_for_status()
                payload = response.json()
                return {
                    item["cveID"]: item
                    for item in payload.get("vulnerabilities", [])
                    if item.get("cveID")
                }

            except (requests.RequestException, ValueError):
                if attempt == retries - 1:
                    raise
                time.sleep(min(60, 2 ** (attempt + 1)))

        raise RuntimeError("Failed to fetch CISA KEV catalog")
