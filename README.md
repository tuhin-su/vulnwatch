# VulnWatch 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Container](https://img.shields.io/badge/Container-Podman%20%7C%20Docker-purple.svg)](docker-compose.yml)

**VulnWatch** is a lightweight, automated vulnerability intelligence and alerting service designed for security engineers, sysadmins, and DevOps teams.

It continuously monitors the **NIST National Vulnerability Database (NVD API 2.0)** and the **CISA Known Exploited Vulnerabilities (KEV)** catalog, filtering and delivering actionable security alerts directly to your **Telegram** (private chat or channel).

---

## ✨ Features

- **Real-Time & Future-Only Alerting:** Watches for newly published vulnerabilities (`pubStartDate`) without spamming you with thousands of re-indexed historical CVEs.
- **CISA KEV Prioritization:** Highlights actively exploited vulnerabilities and ransomware associations with high-priority notifications.
- **Interactive Telegram Bot Commands:** Query vulnerabilities on-demand (`/date`, `/cve`, `/critical`, `/high`, `/medium`) and adjust severity thresholds (`/rating`, `/set`) live from chat.
- **Model Context Protocol (MCP) Server:** Allows AI assistants (Claude, Cursor, Antigravity, VS Code) to query your live vulnerability database and CVE intelligence.
- **Customizable Filtering:**
  - Dynamic severity rating thresholds (`/rating [critical|high|medium|all]`).
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
│   ├── bot.py           # Interactive Telegram bot listener & command dispatcher
│   ├── alerter.py       # Alert filter and dynamic qualification logic
│   ├── mcp_server.py    # Model Context Protocol (MCP) server for AI agents
│   ├── service.py       # Synchronization cycle & workflow orchestration
│   ├── utils.py         # UTC ISO 8601 formatting & parsing helpers
│   └── main.py          # Application bootstrapper
├── app.py               # Main entrypoint
├── Dockerfile           # Minimal Python 3.11 container image
├── docker-compose.yml   # Hardened compose configuration
├── .env.example         # Template environment configuration
├── requirements.txt     # Python dependencies (requests)
└── LICENSE              # MIT Open Source License
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
POLL_SECONDS=1800
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
| `TELEGRAM_BOT_ENABLED` | `true` | Master switch to enable or disable Telegram alerts and interactive bot listener (`true`/`false`). |
| `TELEGRAM_BOT_TOKEN` | *(Required)* | Telegram bot token from `@BotFather`. |
| `TELEGRAM_USER_ID` | *(Required)* | Recipient Telegram numeric user ID or chat ID. |
| `NVD_API_KEY` | *(Optional)* | NIST NVD API key. Increases rate limit from 5 req/30s to 50 req/30s. |
| `POLL_SECONDS` | `1800` | Sync frequency in seconds (default: 30 minutes). Minimum: `60`. |
| `MIN_CVSS` | `0` | Minimum CVSS score required to trigger an alert (e.g. `7.0`). |
| `ONLY_HIGH_OR_KEV` | `false` | When `true`, alerts only for CVSS ≥ 7.0 or CISA KEV entries. |
| `ONLY_NEWLY_PUBLISHED`| `true` | When `true`, queries newly published CVEs (`pubStartDate`) instead of modified CVEs. |
| `START_FROM_NOW` | `true` | When `true`, starts monitoring from the current time forward (avoids past backlog). |
| `MAX_CVE_AGE_DAYS` | `7` | Maximum publication age in days for a CVE to trigger an alert. |
| `WATCHLIST` | *(Empty)* | Comma-separated list of software/frameworks to watch exclusively (e.g. `php,laravel,wordpress`). |
| `RATING_FILTER` | *(Empty)* | Default severity rating filter (`critical`, `high`, `medium`, `all`). |
| `MCP_ENABLED` | `false` | Enable the Model Context Protocol (MCP) server for AI assistants. |
| `MCP_URL` | `http://localhost:8080` | External URL / port where the MCP server listens. |
| `MCP_AUTH_TOKEN` | *(Optional)* | Secret Bearer authentication token protecting the MCP server. |
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

VulnWatch includes a built-in background bot listener that allows you to manage alerts and query vulnerabilities directly in Telegram:

### Technology Watchlist (Targeted Software & Frameworks)
| Command | Description | Example |
| :--- | :--- | :--- |
| **`/watch_add <name>`** | **Add software, framework, or vendor to your watchlist.** When watchlist is active, VulnWatch **only** alerts on CVEs matching these technologies. | `/watch_add php` or `/watch_add laravel` |
| **`/watch_delete <name>`** | Remove a software or framework from the watchlist. | `/watch_delete php` |
| **`/watch_list`** | Display all currently monitored technologies in your watchlist. | `/watch_list` |
| **`/watch_clear`** | Clear all watched items (reverts to monitoring all technologies). | `/watch_clear` |

*(Note: `/wach_add`, `/wach_delete`, and `/wach_list` are also supported as aliases.)*

### Severity Ratings & Dynamic Settings
| Command | Description | Example |
| :--- | :--- | :--- |
| **`/rating [type]`** | **View or change alert severity threshold live.** Options: `critical`, `high`, `medium`, `all`. Applies immediately to upcoming sync cycles. | `/rating critical` |
| **`/set <key> <value>`** | **Update configuration on the fly.** Supported keys: `rating`, `cvss`, `poll`, `age`, `reset`. | `/set cvss 8.5` |
| **`/settings`** | Inspect current active configuration & runtime overrides. | `/settings` |

### Vulnerability Queries by Rating & Date
| Command | Description | Example |
| :--- | :--- | :--- |
| **`/critical`** | List the top recent **Critical** vulnerabilities (CVSS 9.0–10.0). | `/critical` |
| **`/high`** | List the top recent **High** vulnerabilities (CVSS 7.0–8.9). | `/high` |
| **`/medium`** | List the top recent **Medium** vulnerabilities (CVSS 4.0–6.9). | `/medium` |
| **`/date YYYY-MM-DD`** | Search vulnerabilities published on a specific date (searches DB, then NVD). | `/date 2026-10-24` |
| **`/cve CVE-ID`** | Detailed lookup for any CVE (queries local DB or NVD). | `/cve CVE-2026-115929` |
| **`/latest`** | List the 5 most recently published vulnerabilities. | `/latest` |
| **`/kev`** | List the 5 most recent CISA Known Exploited Vulnerabilities. | `/kev` |
| **`/status`** | View monitor health, active rating filter, last sync time, and total counts. | `/status` |
| **`/help`** | Show available bot commands. | `/help` |

> 🔒 **Security:** The bot listener verifies message sender ID against `TELEGRAM_USER_ID` / `TELEGRAM_CHAT_ID` and rejects unauthorized users.

---

## 🧠 Model Context Protocol (MCP) Server for AI

VulnWatch includes a built-in **MCP server** that implements the open [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) specification.

---

### What is the Model Context Protocol (MCP)?

The **Model Context Protocol (MCP)** is an open industry standard that enables AI models and autonomous coding agents (such as **Claude Desktop**, **Cursor**, **Google Antigravity**, **VS Code Roo/Cline**, and **ChatGPT**) to safely connect to external data sources and execution environments.

Think of MCP as a **standardized "USB-C" interface for AI applications**:
- Instead of building custom plugins or copy-pasting vulnerability data into chats, the AI client directly queries VulnWatch via MCP tools.
- It provides structured schema definitions so AI models know *what* questions they can ask and *how* to call functions.

---

### What Does the MCP Protocol Do in VulnWatch?

By running the MCP server, VulnWatch turns your vulnerability monitor into an **active intelligence backend for your AI assistant**:

1. **Eliminates AI Hallucinations on Security Data**
   - AI models have a fixed knowledge training cutoff and cannot reliably remember newly published zero-days or recent CVE details.
   - With VulnWatch MCP, when you ask your AI *"Is there an active exploit or ransomware campaign for CVE-2026-115929?"*, the AI calls `get_cve_details` or `get_cisa_kev_catalog` to retrieve verified, real-time facts from your local database and NIST NVD.

2. **Automated Vulnerability Triage in Codebases**
   - An AI coding assistant analyzing your project's dependencies can query VulnWatch directly to check whether a specific library version has any CVEs published today or this week.

3. **Standardized Protocol Flow (JSON-RPC 2.0)**
   - **Handshake (`initialize`)**: When the AI client connects, VulnWatch reports its server capabilities and metadata.
   - **Tool Discovery (`tools/list`)**: VulnWatch presents its tools with strict JSON input schemas.
   - **Execution (`tools/call`)**: When you ask a security question in natural language, the AI autonomously decides which tool to call, executes it against VulnWatch, and uses the returned structured context to formulate an accurate answer.

---

### Available MCP Tools for AI

| Tool | Purpose | Parameters |
| :--- | :--- | :--- |
| **`search_cves_by_date`** | Search CVEs published on a specific date (`YYYY-MM-DD`). | `date` (string, required), `limit` (int) |
| **`get_cve_details`** | Lookup comprehensive intelligence for a specific CVE ID. | `cve_id` (string, required) |
| **`get_latest_vulnerabilities`** | Retrieve the most recent vulnerabilities. | `limit` (int, default 5) |
| **`get_vulnerabilities_by_severity`** | Filter vulnerabilities by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). | `severity` (string, required), `limit` (int) |
| **`get_cisa_kev_catalog`** | Query CISA Known Exploited Vulnerabilities catalog. | `limit` (int), `ransomware_only` (bool) |
| **`get_watchlist`** | Retrieve all currently monitored software and framework keywords. | *None* |
| **`add_to_watchlist`** | Add a technology to the monitored watchlist (e.g. `php`, `laravel`). | `keyword` (string, required) |
| **`remove_from_watchlist`** | Remove a technology from the watchlist. | `keyword` (string, required) |
| **`clear_watchlist`** | Clear all watchlist items (reverts to monitoring all software). | *None* |
| **`set_rating_filter`** | Update alert severity threshold (`critical`, `high`, `medium`, `all`). | `rating` (string, required) |
| **`get_settings`** | Retrieve all active configuration settings, thresholds, and overrides. | *None* |
| **`set_setting`** | Update runtime setting (`min_cvss`, `poll_seconds`, `max_cve_age_days`, `rating`). | `key` (string), `value` (string) |
| **`trigger_sync`** | Trigger an on-demand vulnerability synchronization cycle in the background. | *None* |
| **`get_vulnwatch_status`** | Retrieve system sync cursor and statistics. | *None* |

---

### Configuration (`.env`)

```env
# Enable MCP Server
MCP_ENABLED=true
MCP_URL=http://localhost:8080
MCP_AUTH_TOKEN="6adec69a0c7752f93dfacf468e9ef208fb72883b88dad7b97e39f03be68d05d0"
```

---

### How to Connect Your AI Assistant

#### Claude Desktop / Cursor / VS Code
Add VulnWatch to your AI client's configuration file (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vulnwatch": {
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer 6adec69a0c7752f93dfacf468e9ef208fb72883b88dad7b97e39f03be68d05d0"
      }
    }
  }
}
```

#### Test with cURL
```bash
# 1. Server Health
curl http://localhost:8080/health

# 2. List Tools via MCP JSON-RPC
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer 6adec69a0c7752f93dfacf468e9ef208fb72883b88dad7b97e39f03be68d05d0" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'

# 3. Call a Tool (e.g. search date)
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer 6adec69a0c7752f93dfacf468e9ef208fb72883b88dad7b97e39f03be68d05d0" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "search_cves_by_date",
      "arguments": {"date": "2026-10-24", "limit": 5}
    }
  }'
```

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

## 📄 Open Source License

This project is open-source software licensed under the **[MIT License](LICENSE)**.

```text
MIT License - Copyright (c) 2026 VulnWatch Contributors
```

### Key Permissions & Conditions:
- ✅ **Commercial Use:** Allowed for personal, commercial, and enterprise applications.
- ✅ **Modification:** Allowed to freely modify, adapt, and rewrite the code.
- ✅ **Distribution:** Allowed to redistribute the original or modified source code and binaries.
- ✅ **Private Use:** Allowed to run, modify, and host privately without mandatory source disclosure.
- ℹ️ **Notice Required:** Retain the original copyright and permission notice in all copies or substantial portions of the software.

For full license terms and conditions, see the [LICENSE](LICENSE) file.
