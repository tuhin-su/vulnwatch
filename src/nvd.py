import logging
import time
from datetime import datetime
from typing import Any

import requests

from .utils import iso_utc

log = logging.getLogger("vulnwatch.nvd")


class CVEParser:
    """Parses CVE JSON structure returned by the NVD 2.0 API."""

    @staticmethod
    def extract_description(cve: dict[str, Any]) -> str:
        for item in cve.get("descriptions", []):
            if item.get("lang") == "en" and item.get("value"):
                return " ".join(item["value"].split())[:2500]
        return "No English description published yet."

    @staticmethod
    def extract_cvss(cve: dict[str, Any]) -> tuple[float | None, str]:
        metrics = cve.get("metrics", {})
        for name in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            items = metrics.get(name, [])
            if not items:
                continue

            item = items[0]
            data = item.get("cvssData", {})
            severity = (
                data.get("baseSeverity")
                or item.get("baseSeverity")
                or "UNKNOWN"
            )

            try:
                return float(data["baseScore"]), str(severity).upper()
            except (KeyError, TypeError, ValueError):
                return None, str(severity).upper()

        return None, "UNASSESSED"

    @staticmethod
    def extract_products(cve: dict[str, Any]) -> str:
        products: list[str] = []

        def walk(node: dict[str, Any]) -> None:
            if not isinstance(node, dict):
                return

            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4:
                    value = f"{parts[3]}:{parts[4]}"
                    if value not in products:
                        products.append(value)

            for child in node.get("children", []):
                walk(child)

        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                walk(node)

        return ", ".join(products[:20]) or "Not yet identified in NVD"

    @staticmethod
    def extract_cwes(cve: dict[str, Any]) -> str:
        values: list[str] = []
        for weakness in cve.get("weaknesses", []):
            for item in weakness.get("description", []):
                value = item.get("value")
                if value and value not in values:
                    values.append(value)
        return ", ".join(values[:10]) or "Not assigned"

    @staticmethod
    def extract_refs(cve: dict[str, Any]) -> list[str]:
        values: list[str] = []
        for item in cve.get("references", []):
            url = item.get("url")
            if url and url not in values:
                values.append(url)
        return values[:12]


class NVDClient:
    """Client for querying NIST National Vulnerability Database (NVD) API 2.0."""

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        session: requests.Session | None = None,
    ):
        self.api_key = api_key.strip().strip("'\"")
        self.base_url = base_url
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnWatch/1.0 defensive security monitor",
            "Accept": "application/json",
        })
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

    def request_json(self, params: dict[str, Any] | None = None, retries: int = 5) -> dict[str, Any]:
        """Perform an HTTP GET request to NVD with retries and rate limit handling."""
        for attempt in range(retries):
            try:
                response = self.session.get(
                    self.base_url, params=params, timeout=(10, 45)
                )

                if response.status_code == 429 or response.status_code >= 500:
                    if attempt == retries - 1:
                        response.raise_for_status()
                    delay = min(60, 2 ** (attempt + 1))
                    log.warning("HTTP %s; retrying in %ss", response.status_code, delay)
                    time.sleep(delay)
                    continue

                if response.status_code == 404 and "invalid apikey" in response.headers.get("message", "").lower():
                    raise RuntimeError(
                        "NVD API rejected your key (HTTP 404: Invalid apiKey). "
                        "Please leave NVD_API_KEY empty in .env to run without a key, "
                        "or get a valid key from https://nvd.nist.gov/developers/request-an-api-key"
                    )

                response.raise_for_status()
                return response.json()

            except (requests.RequestException, ValueError):
                if attempt == retries - 1:
                    raise
                time.sleep(min(60, 2 ** (attempt + 1)))

        raise RuntimeError("NVD request retries exhausted")

    def fetch_cves(
        self,
        start: datetime,
        end: datetime,
        only_newly_published: bool = True,
    ) -> list[dict[str, Any]]:
        """Fetch CVE records published or modified between start and end timestamps."""
        results: list[dict[str, Any]] = []
        index = 0

        start_param = "pubStartDate" if only_newly_published else "lastModStartDate"
        end_param = "pubEndDate" if only_newly_published else "lastModEndDate"

        while True:
            payload = self.request_json({
                start_param: iso_utc(start),
                end_param: iso_utc(end),
                "startIndex": index,
                "resultsPerPage": 2000,
            })

            batch = payload.get("vulnerabilities", [])
            results.extend(
                item["cve"] for item in batch
                if isinstance(item.get("cve"), dict)
            )

            total = int(payload.get("totalResults", 0))
            page_size = int(payload.get("resultsPerPage", len(batch)))

            if not batch or page_size <= 0:
                break

            index += page_size
            if index >= total:
                break

            # Respect NVD rate limits (public: ~5 per 30s; with key: ~50 per 30s)
            time.sleep(6 if not self.api_key else 0.7)

        return results

    def fetch_cve_by_id(self, cve_id: str) -> dict[str, Any] | None:
        """Fetch a specific CVE from NVD by its CVE ID."""
        try:
            payload = self.request_json({"cveId": cve_id.strip().upper()})
            vulnerabilities = payload.get("vulnerabilities", [])
            if vulnerabilities and isinstance(vulnerabilities[0].get("cve"), dict):
                return vulnerabilities[0]["cve"]
        except Exception as exc:
            log.warning("Could not fetch %s from NVD: %s", cve_id, exc)
        return None
