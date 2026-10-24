# VulnWatch 🛡️

**VulnWatch** is a lightweight, automated vulnerability intelligence and alerting service designed for security engineers, sysadmins, and DevOps teams.

It continuously monitors the **NIST National Vulnerability Database (NVD API 2.0)** and the **CISA Known Exploited Vulnerabilities (KEV)** catalog, filtering and delivering actionable security alerts directly to your **Telegram** (private chat or channel).

---

## ✨ Features

- **Real-Time & Future-Only Alerting:** Watches for newly published vulnerabilities (`pubStartDate`) without spamming you with thousands of re-indexed historical CVEs.
- **CISA KEV Prioritization:** Highlights actively exploited vulnerabilities and ransomware associations with high-priority notifications.
- **Customizable Filtering:**
  - Minimum CVSS score thresholds (`MIN_CVSS`).
  - High-severity & KEV-only modes (`ONLY_HIGH_OR_KEV`).
  - Publication age filters (`MAX_CVE_AGE_DAYS`).
- **Direct Telegram Notifications:** Supports sending alerts directly to individual Telegram User IDs or group/channel chats.
- **Robust Persistence:** SQLite database running in WAL mode to track state cursors and ensure zero duplicate alerts.
- **Modular & Class-Based:** Clean, typed Python architecture under [`src/`](file:///home/tuhin/Desktop/vulnwatch/src).
- **Container Hardening (Podman / Docker):**
  - Runs rootless as dedicated non-root user `app`.
  - Read-only root filesystem (`read_only: true`).
  - Drops all Linux capabilities (`cap_drop: ALL`).
  - Blocks privilege escalation (`no-new-privileges: true`).
  - Sandboxed `tmpfs` and bounded memory/CPU limits.

---

## 📁 Project Architecture

```text
vulnwatch/
├── src/
│   ├── __init__.py      # Package definitions & exports
│   ├── config.py        # Environment variables & typed settings
│   ├── database.py      # SQLite engine (schemas, state, CVE & alert storage)
│   ├── nvd.py           # NVD 2.0 API client & CVE parser (CVSS, CPE, CWE)
│   ├── kev.py           # CISA Known Exploited Vulnerabilities catalog client
│   ├── telegram.py      # Telegram Bot notifier & message formatter
│   ├── alerter.py       # Alert filter and qualification logic
│   ├── service.py       # Synchronization cycle & workflow orchestration
│   ├── utils.py         # UTC ISO 8601 formatting & parsing helpers
│   └── main.py          # Application bootstrapper
├── app.py               # Main entrypoint
├── Dockerfile           # Minimal Python 3.11 container image
├── docker-compose.yml   # Hardened compose configuration
├── .env.example         # Template environment configuration
└── requirements.txt     # Python dependencies (requests)
```

---

## 🚀 Quick Start

### 1. Prerequisites
- **Podman** (or **Docker**)
- **`podman-compose`** (or `docker-compose`)
- A **Telegram Bot Token** (created via [@BotFather](https://t.me/BotFather))

### 2. Configure Environment

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` with your settings:

```env
# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_USER_ID=USER_NUMERIC_ID_OR_CHAT_ID

# Optional NVD API Key (leave empty for public rate-limited access)
NVD_API_KEY=

# Filtering & Polling Controls
POLL_SECONDS=900
MIN_CVSS=7.0
ONLY_HIGH_OR_KEV=false
ONLY_NEWLY_PUBLISHED=true
START_FROM_NOW=true
MAX_CVE_AGE_DAYS=7
LOG_LEVEL=INFO
```

> **Tip:** If sending directly to your personal Telegram account, set `TELEGRAM_USER_ID` to your numeric ID (you can find it via bots like [@userinfobot](https://t.me/userinfobot)) and make sure you send `/start` to your bot first.

### 3. Build & Run

Launch the service in the background:

```bash
podman compose up -d --build
```

*(Or with Docker: `docker compose up -d --build`)*

### 4. Monitor Logs

Stream live logs:

```bash
podman compose logs -f
```

---

## ⚙️ Configuration Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `TELEGRAM_BOT_TOKEN` | *(Required)* | Telegram bot token from `@BotFather`. |
| `TELEGRAM_USER_ID` | *(Required)* | Recipient Telegram numeric user ID or chat ID. |
| `NVD_API_KEY` | *(Optional)* | NIST NVD API key. Increases rate limit from 5 req/30s to 50 req/30s. |
| `POLL_SECONDS` | `900` | Sync frequency in seconds (default: 15 minutes). Minimum: `60`. |
| `MIN_CVSS` | `0` | Minimum CVSS score required to trigger an alert (e.g. `7.0`). |
| `ONLY_HIGH_OR_KEV` | `false` | When `true`, alerts only for CVSS ≥ 7.0 or CISA KEV entries. |
| `ONLY_NEWLY_PUBLISHED`| `true` | When `true`, queries newly published CVEs (`pubStartDate`) instead of modified CVEs. |
| `START_FROM_NOW` | `true` | When `true`, starts monitoring from the current time forward (avoids past backlog). |
| `MAX_CVE_AGE_DAYS` | `7` | Maximum publication age in days for a CVE to trigger an alert. |
| `LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `DB_PATH` | `/data/vulnwatch.sqlite3` | SQLite database file location inside the container. |

---

## 📱 Sample Telegram Alert

```text
🚨 VulnWatch vulnerability alert
CVE-2026-115929 — HIGH
Reason: CVSS 7.6 (HIGH)
CVSS: 7.6
Published: 2026-10-24T01:17:08.250Z
Modified: 2026-10-24T01:17:08.250Z
Products: MongoDB, Inc.:Compass
CWE: CWE-295

Description: MongoDB Compass relies on Electron, a third-party runtime that carries its own TLS root certificate store...

NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-115929
References:
https://github.com/mongodb-js/compass/releases/tag/v1.53.1
https://blog.mozilla.org/security/...

Verify affected versions against the vendor advisory.
```

---

## 🤖 Interactive Telegram Commands

VulnWatch includes a built-in background bot listener that allows you to query vulnerabilities directly from Telegram:

| Command | Description | Example |
| :--- | :--- | :--- |
| `/date YYYY-MM-DD` | Search vulnerabilities published on a specific date (searches DB, then NVD). | `/date 2026-10-24` |
| `/cve CVE-ID` | Detailed lookup for any CVE (queries local DB or NVD). | `/cve CVE-2026-115929` |
| `/status` | View monitor health, last sync timestamp, and total indexed counts. | `/status` |
| `/settings` | Inspect current threshold & filter configuration. | `/settings` |
| `/latest` | List the 5 most recently published vulnerabilities. | `/latest` |
| `/kev` | List the 5 most recent CISA Known Exploited Vulnerabilities. | `/kev` |
| `/help` | Show available bot commands. | `/help` |

> 🔒 **Security:** The bot listener verifies message sender ID against `TELEGRAM_USER_ID` / `TELEGRAM_CHAT_ID` and rejects unauthorized users.

---

## 🛠️ Management Commands

| Action | Command |
| :--- | :--- |
| **Start Service** | `podman compose up -d` |
| **Rebuild & Start** | `podman compose up -d --build` |
| **Follow Logs** | `podman compose logs -f` |
| **Container Status** | `podman compose ps` |
| **Stop Service** | `podman compose down` |
| **Inspect DB Volume** | `podman volume inspect vulnwatch_vulnwach_data` |

---

## 📄 License

MIT License. Free for open-source and commercial use.
