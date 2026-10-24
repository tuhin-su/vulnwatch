import json
import logging
import os
import re
import sqlite3
from typing import Any

from .utils import iso_utc, now_utc

log = logging.getLogger("vulnwatch.db")


class Database:
    """Manages SQLite storage for vulnerabilities, state, and sent alerts."""

    def __init__(self, db_path: str = "/data/vulnwatch.sqlite3"):
        self.db_path = db_path

    def connect(self) -> sqlite3.Connection:
        """Create and configure a new SQLite connection."""
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init_db(self) -> None:
        """Initialize database schema if tables do not exist."""
        with self.connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    cve_id TEXT PRIMARY KEY,
                    published TEXT,
                    modified TEXT,
                    description TEXT,
                    cvss REAL,
                    severity TEXT,
                    products TEXT,
                    cwe TEXT,
                    refs TEXT,
                    kev INTEGER DEFAULT 0,
                    kev_added TEXT,
                    kev_due TEXT,
                    ransomware TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS sent_alerts (
                    cve_id TEXT PRIMARY KEY,
                    sent_at TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS watchlist (
                    keyword TEXT PRIMARY KEY,
                    added_at TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_vuln_cvss
                ON vulnerabilities(cvss)
            """)
        log.info("Database initialized at %s", self.db_path)

    def get_state(self, key: str) -> str | None:
        """Retrieve a string state value by key."""
        with self.connect() as db:
            row = db.execute(
                "SELECT value FROM state WHERE key=?", (key,)
            ).fetchone()
            return row["value"] if row else None

    def set_state(self, key: str, value: str) -> None:
        """Persist or update a string state value by key."""
        with self.connect() as db:
            db.execute("""
                INSERT INTO state(key,value) VALUES(?,?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, (key, value))

    def get_vulnerability(self, cve_id: str) -> sqlite3.Row | None:
        """Fetch a single vulnerability record by CVE ID."""
        with self.connect() as db:
            return db.execute(
                "SELECT * FROM vulnerabilities WHERE UPPER(cve_id)=UPPER(?)",
                (cve_id.strip(),),
            ).fetchone()

    def is_alert_sent(self, cve_id: str) -> bool:
        """Check if an alert has already been sent for the given CVE ID."""
        with self.connect() as db:
            row = db.execute(
                "SELECT 1 FROM sent_alerts WHERE cve_id=?",
                (cve_id,),
            ).fetchone()
            return row is not None

    def search_by_date(self, date_str: str, limit: int = 10) -> list[sqlite3.Row]:
        """Search vulnerabilities by publication date string (YYYY-MM-DD)."""
        with self.connect() as db:
            return db.execute("""
                SELECT cve_id, published, cvss, severity, description, products, kev
                FROM vulnerabilities
                WHERE published LIKE ? || '%'
                ORDER BY COALESCE(cvss, 0) DESC, published DESC
                LIMIT ?
            """, (date_str, limit)).fetchall()

    def get_latest_vulnerabilities(self, limit: int = 5) -> list[sqlite3.Row]:
        """Get the most recently published vulnerabilities."""
        with self.connect() as db:
            return db.execute("""
                SELECT cve_id, published, cvss, severity, description, products, kev
                FROM vulnerabilities
                ORDER BY published DESC
                LIMIT ?
            """, (limit,)).fetchall()

    def get_vulnerabilities_by_severity(
        self,
        severity: str,
        limit: int = 5,
    ) -> list[sqlite3.Row]:
        """Fetch latest vulnerabilities filtered by severity (CRITICAL, HIGH, MEDIUM, LOW)."""
        sev = severity.strip().upper()
        with self.connect() as db:
            return db.execute("""
                SELECT cve_id, published, cvss, severity, description, products, kev
                FROM vulnerabilities
                WHERE UPPER(severity) = ?
                ORDER BY COALESCE(cvss, 0) DESC, published DESC
                LIMIT ?
            """, (sev, limit)).fetchall()

    def get_latest_kev(self, limit: int = 5) -> list[sqlite3.Row]:
        """Get the most recently added CISA KEV entries."""
        with self.connect() as db:
            return db.execute("""
                SELECT cve_id, kev_added, kev_due, ransomware, description, products
                FROM vulnerabilities
                WHERE kev = 1
                ORDER BY kev_added DESC
                LIMIT ?
            """, (limit,)).fetchall()

    def get_stats(self) -> dict[str, Any]:
        """Retrieve overview statistics from database."""
        with self.connect() as db:
            total_vulns = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            total_kev = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE kev = 1").fetchone()[0]
            total_alerts = db.execute("SELECT COUNT(*) FROM sent_alerts").fetchone()[0]
            total_watchlist = db.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
            last_sync = self.get_state("last_successful_sync")
            return {
                "total_vulnerabilities": total_vulns,
                "total_kev": total_kev,
                "total_alerts": total_alerts,
                "total_watchlist": total_watchlist,
                "last_successful_sync": last_sync,
            }

    def add_to_watchlist(self, keyword: str) -> bool:
        """Add a technology, framework, or vendor keyword to the watchlist."""
        kw = keyword.strip().lower()
        if not kw:
            return False
        with self.connect() as db:
            try:
                db.execute(
                    "INSERT INTO watchlist (keyword, added_at) VALUES (?, ?)",
                    (kw, iso_utc(now_utc())),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def remove_from_watchlist(self, keyword: str) -> bool:
        """Remove a technology keyword from the watchlist."""
        kw = keyword.strip().lower()
        with self.connect() as db:
            cur = db.execute("DELETE FROM watchlist WHERE keyword = ?", (kw,))
            return cur.rowcount > 0

    def get_watchlist(self) -> list[str]:
        """Retrieve all active technology keywords in the watchlist."""
        with self.connect() as db:
            rows = db.execute("SELECT keyword FROM watchlist ORDER BY keyword ASC").fetchall()
            return [row["keyword"] for row in rows]

    def clear_watchlist(self) -> int:
        """Remove all keywords from the watchlist."""
        with self.connect() as db:
            cur = db.execute("DELETE FROM watchlist")
            return cur.rowcount

    def matches_watchlist(self, products: str = "", description: str = "") -> str | None:
        """
        Check if a vulnerability's products or description matches any watched keyword.
        Returns the matched keyword, or None if no match.
        """
        keywords = self.get_watchlist()
        if not keywords:
            return None

        p_lower = (products or "").lower()
        d_lower = (description or "").lower()

        for kw in keywords:
            if kw in p_lower:
                return kw
            pattern = rf"(?:\b|_){re.escape(kw)}(?:\b|_)"
            if re.search(pattern, d_lower):
                return kw

        return None

    def record_alert_sent(self, cve_id: str, reason: str) -> None:
        """Mark an alert as sent in the sent_alerts table."""
        with self.connect() as db:
            db.execute("""
                INSERT OR IGNORE INTO sent_alerts(cve_id,sent_at,reason)
                VALUES(?,?,?)
            """, (cve_id, iso_utc(now_utc()), reason))

    def save_cve_data(
        self,
        cve_id: str,
        published: str | None,
        modified: str | None,
        description: str,
        cvss: float | None,
        severity: str,
        products: str,
        cwe: str,
        refs: list[str],
        kev_item: dict[str, Any] | None = None,
    ) -> str:
        """Insert or update a CVE record in the vulnerabilities table."""
        now = iso_utc(now_utc())

        with self.connect() as db:
            old = db.execute(
                "SELECT first_seen, kev, kev_added, kev_due, ransomware FROM vulnerabilities WHERE cve_id=?",
                (cve_id,),
            ).fetchone()

            first_seen = old["first_seen"] if old else now
            is_kev = bool(kev_item) or bool(old and old["kev"])

            db.execute("""
                INSERT INTO vulnerabilities (
                    cve_id,published,modified,description,cvss,severity,
                    products,cwe,refs,kev,kev_added,kev_due,ransomware,
                    first_seen,last_seen
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    published=excluded.published,
                    modified=excluded.modified,
                    description=excluded.description,
                    cvss=excluded.cvss,
                    severity=excluded.severity,
                    products=excluded.products,
                    cwe=excluded.cwe,
                    refs=excluded.refs,
                    kev=excluded.kev,
                    kev_added=COALESCE(excluded.kev_added, vulnerabilities.kev_added),
                    kev_due=COALESCE(excluded.kev_due, vulnerabilities.kev_due),
                    ransomware=COALESCE(excluded.ransomware, vulnerabilities.ransomware),
                    last_seen=excluded.last_seen
            """, (
                cve_id,
                published,
                modified,
                description,
                cvss,
                severity,
                products,
                cwe,
                json.dumps(refs),
                int(is_kev),
                (kev_item or {}).get("dateAdded"),
                (kev_item or {}).get("dueDate"),
                (kev_item or {}).get("knownRansomwareCampaignUse"),
                first_seen,
                now,
            ))

        return cve_id

    def update_or_insert_kev_entry(
        self,
        cve_id: str,
        item: dict[str, Any],
        kev_url: str,
    ) -> bool:
        """
        Record or update a CISA KEV entry in the database.
        Returns True if newly recorded or updated to KEV, False if already active.
        """
        now = iso_utc(now_utc())

        with self.connect() as db:
            old = db.execute(
                "SELECT kev FROM vulnerabilities WHERE cve_id=?",
                (cve_id,),
            ).fetchone()

            if old and old["kev"]:
                return False

            if old:
                db.execute("""
                    UPDATE vulnerabilities
                    SET kev=1, kev_added=?, kev_due=?, ransomware=?, last_seen=?
                    WHERE cve_id=?
                """, (
                    item.get("dateAdded"),
                    item.get("dueDate"),
                    item.get("knownRansomwareCampaignUse"),
                    now,
                    cve_id,
                ))
            else:
                db.execute("""
                    INSERT OR IGNORE INTO vulnerabilities (
                        cve_id,description,severity,products,cwe,refs,
                        kev,kev_added,kev_due,ransomware,first_seen,last_seen
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    cve_id,
                    item.get("shortDescription") or "Listed in CISA KEV.",
                    "UNKNOWN",
                    f"{item.get('vendorProject', 'Unknown')}:{item.get('product', 'Unknown')}",
                    "Not assigned",
                    json.dumps([kev_url]),
                    1,
                    item.get("dateAdded"),
                    item.get("dueDate"),
                    item.get("knownRansomwareCampaignUse"),
                    now,
                    now,
                ))

            return True
