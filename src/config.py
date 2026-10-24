import os
import urllib.parse
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    app_name: str = "VulnWatch"
    db_path: str = "/data/vulnwatch.sqlite3"
    poll_seconds: int = 1800
    bootstrap_hours: int = 24
    overlap_minutes: int = 10
    min_cvss: float = 0.0
    only_high_or_kev: bool = False

    # Filter controls: watch future/new only
    start_from_now: bool = True
    only_newly_published: bool = True
    max_cve_age_days: int = 7
    watchlist: str = ""
    rating_filter: str = ""

    nvd_api_key: str = ""
    telegram_bot_enabled: bool = True
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    # MCP Server configuration
    mcp_enabled: bool = False
    mcp_url: str = "http://localhost:8080"
    mcp_auth_token: str = ""
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8080

    log_level: str = "INFO"
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        raw_mcp_url = os.getenv("MCP_URL", "http://localhost:8080").strip()
        parsed = urllib.parse.urlparse(raw_mcp_url)
        port = parsed.port or int(os.getenv("PORT", "8080"))

        return cls(
            app_name=os.getenv("APP_NAME", "VulnWatch").strip(),
            db_path=os.getenv("DB_PATH", "/data/vulnwatch.sqlite3").strip(),
            poll_seconds=max(60, int(os.getenv("POLL_SECONDS", "1800"))),
            bootstrap_hours=max(1, int(os.getenv("BOOTSTRAP_HOURS", "24"))),
            overlap_minutes=max(1, int(os.getenv("OVERLAP_MINUTES", "10"))),
            min_cvss=float(os.getenv("MIN_CVSS", "0")),
            only_high_or_kev=os.getenv("ONLY_HIGH_OR_KEV", "false").lower() in {
                "1", "true", "yes"
            },
            start_from_now=os.getenv("START_FROM_NOW", "true").lower() in {
                "1", "true", "yes"
            },
            only_newly_published=os.getenv("ONLY_NEWLY_PUBLISHED", "true").lower() in {
                "1", "true", "yes"
            },
            max_cve_age_days=max(0, int(os.getenv("MAX_CVE_AGE_DAYS", "7"))),
            watchlist=os.getenv("WATCHLIST", "").strip(),
            rating_filter=os.getenv("RATING_FILTER", "").strip().lower(),
            nvd_api_key=os.getenv("NVD_API_KEY", "").strip().strip("'\""),
            telegram_bot_enabled=os.getenv("TELEGRAM_BOT_ENABLED", "true").lower() in {
                "1", "true", "yes"
            },
            telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip().strip("'\""),
            telegram_chat_id=(
                os.getenv("TELEGRAM_USER_ID") or os.getenv("TELEGRAM_CHAT_ID") or ""
            ).strip().strip("'\""),
            mcp_enabled=os.getenv("MCP_ENABLED", "false").lower() in {
                "1", "true", "yes"
            },
            mcp_url=raw_mcp_url,
            mcp_auth_token=os.getenv("MCP_AUTH_TOKEN", "").strip().strip("'\""),
            mcp_host=os.getenv("MCP_HOST", "0.0.0.0").strip(),
            mcp_port=port,
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            nvd_url=os.getenv(
                "NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
            ).strip(),
            kev_url=os.getenv(
                "KEV_URL",
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            ).strip(),
        )
