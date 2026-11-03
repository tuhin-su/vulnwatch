#!/usr/bin/env bash
# ==============================================================================
# VulnWatch System-Wide Native Installer (No Docker Required)
# Supported Distributions:
#   - Debian & Ubuntu (and derivatives: Linux Mint, Pop!_OS, Kali, etc.)
#   - RHEL-based (RHEL 8/9/10, CentOS, Rocky Linux, AlmaLinux, Fedora, Oracle)
#   - Arch Linux (and derivatives: Manjaro, EndeavourOS, etc.)
#   - openSUSE / SLES
#
# Storage directory: /opt/vulnwatch
# Configuration:     /etc/vulnwatch/vulnwatch.env
# Database & State:  /var/lib/vulnwatch/
# Service Unit:      /etc/systemd/system/vulnwatch.service
# CLI Management:    /usr/local/bin/vulnwatch
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Constants & Defaults
# ------------------------------------------------------------------------------
APP_NAME="VulnWatch"
INSTALL_DIR="/opt/vulnwatch"
CONFIG_DIR="/etc/vulnwatch"
CONFIG_FILE="${CONFIG_DIR}/vulnwatch.env"
DATA_DIR="/var/lib/vulnwatch"
DB_PATH="${DATA_DIR}/vulnwatch.sqlite3"
LOG_DIR="/var/log/vulnwatch"
APP_LOG_FILE="${LOG_DIR}/vulnwatch.log"
LOGROTATE_DIR="/etc/logrotate.d"
LOGROTATE_FILE="${LOGROTATE_DIR}/vulnwatch"
SERVICE_NAME="vulnwatch.service"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_FILE="${SYSTEMD_DIR}/${SERVICE_NAME}"
CLI_BIN="/usr/local/bin/vulnwatch"
SERVICE_USER="vulnwatch"
SERVICE_GROUP="vulnwatch"

NON_INTERACTIVE=0
NO_START=0
DO_UNINSTALL=0
PURGE_ON_UNINSTALL=0
CHECK_ONLY=0

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------------------
# Terminal Colors & Logging
# ------------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

log_info() {
    echo -e "${CYAN}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} ${BOLD}$1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-] Error:${NC} $1" >&2
}

log_step() {
    echo -e "\n${BLUE}==>${NC} ${BOLD}$1${NC}"
}

# ------------------------------------------------------------------------------
# Help & Usage
# ------------------------------------------------------------------------------
show_help() {
    cat <<EOF
VulnWatch Native System-Wide Installer

Usage:
  sudo bash install.sh [OPTIONS]

Options:
  -y, --non-interactive    Run non-interactively without user prompts
      --no-start           Do not start the systemd service after installation
      --check, --dry-run   Check system compatibility and pre-requisites without making changes
      --uninstall          Uninstall VulnWatch from the system
      --purge              When used with --uninstall, removes config and database files
  -h, --help               Show this help message and exit

File Layout:
  Application:    ${INSTALL_DIR}
  Configuration:  ${CONFIG_FILE}
  Database:       ${DATA_DIR}
  Logs:           ${LOG_DIR}
  Logrotate:      ${LOGROTATE_FILE}
  Service:        ${SERVICE_FILE}
  CLI Tool:       ${CLI_BIN}

Supported OS:
  - Debian 11+, Ubuntu 20.04+
  - RHEL 8+, CentOS Stream, Rocky Linux, AlmaLinux, Fedora
  - Arch Linux, Manjaro, EndeavourOS
  - openSUSE / SLES

EOF
}

# ------------------------------------------------------------------------------
# Parse Arguments
# ------------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -y|--non-interactive|--yes)
                NON_INTERACTIVE=1
                shift
                ;;
            --check|--dry-run)
                CHECK_ONLY=1
                shift
                ;;
            --no-start)
                NO_START=1
                shift
                ;;
            --uninstall)
                DO_UNINSTALL=1
                shift
                ;;
            --purge)
                PURGE_ON_UNINSTALL=1
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Privilege Check
# ------------------------------------------------------------------------------
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This installer must be run as root (or using sudo)."
        echo "Example: sudo bash install.sh"
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Distribution Detection
# ------------------------------------------------------------------------------
DISTRO_ID=""
DISTRO_ID_LIKE=""
DISTRO_NAME=""

detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID:-}"
        DISTRO_ID_LIKE="${ID_LIKE:-}"
        DISTRO_NAME="${PRETTY_NAME:-$NAME}"
    elif [ -f /etc/redhat-release ]; then
        DISTRO_ID="rhel"
        DISTRO_ID_LIKE="rhel fedora"
        DISTRO_NAME="$(cat /etc/redhat-release)"
    elif [ -f /etc/debian_version ]; then
        DISTRO_ID="debian"
        DISTRO_ID_LIKE="debian"
        DISTRO_NAME="Debian $(cat /etc/debian_version)"
    elif [ -f /etc/arch-release ]; then
        DISTRO_ID="arch"
        DISTRO_ID_LIKE="arch"
        DISTRO_NAME="Arch Linux"
    else
        DISTRO_ID="unknown"
        DISTRO_ID_LIKE="unknown"
        DISTRO_NAME="Unknown Linux"
    fi
}

is_debian_family() {
    case "$DISTRO_ID" in
        debian|ubuntu|linuxmint|pop|kali|raspbian|elementary|zorin|parrot) return 0 ;;
    esac
    for like in $DISTRO_ID_LIKE; do
        if [ "$like" = "debian" ] || [ "$like" = "ubuntu" ]; then
            return 0
        fi
    done
    return 1
}

is_rhel_family() {
    case "$DISTRO_ID" in
        rhel|centos|fedora|rocky|almalinux|ol|amzn|scientific) return 0 ;;
    esac
    for like in $DISTRO_ID_LIKE; do
        if [ "$like" = "rhel" ] || [ "$like" = "fedora" ] || [ "$like" = "centos" ]; then
            return 0
        fi
    done
    return 1
}

is_arch_family() {
    case "$DISTRO_ID" in
        arch|manjaro|endeavouros|artix|garuda|arcolinux|cachyos) return 0 ;;
    esac
    for like in $DISTRO_ID_LIKE; do
        if [ "$like" = "arch" ]; then
            return 0
        fi
    done
    return 1
}

is_suse_family() {
    case "$DISTRO_ID" in
        opensuse*|sles*|suse) return 0 ;;
    esac
    for like in $DISTRO_ID_LIKE; do
        if [ "$like" = "suse" ] || [ "$like" = "opensuse" ]; then
            return 0
        fi
    done
    return 1
}

# ------------------------------------------------------------------------------
# Install System Dependencies
# ------------------------------------------------------------------------------
install_system_packages() {
    log_step "Checking and installing OS dependencies for ${DISTRO_NAME}..."

    if is_debian_family; then
        log_info "Detected Debian/Ubuntu family (APT package manager)."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y python3 python3-venv python3-pip curl ca-certificates
    elif is_rhel_family; then
        local PKG_MGR="dnf"
        if ! command -v dnf >/dev/null 2>&1; then
            PKG_MGR="yum"
        fi
        log_info "Detected RHEL family (${PKG_MGR} package manager)."

        # Check if installed default python3 is >= 3.10
        local PY_MODERN=0
        if command -v python3 >/dev/null 2>&1; then
            if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
                PY_MODERN=1
            fi
        fi

        if [ "$PY_MODERN" -eq 1 ]; then
            $PKG_MGR install -y python3 python3-pip curl ca-certificates
        else
            # On RHEL 8 / 9, python3.11 or python3.12 is available in AppStream
            if $PKG_MGR info python3.11 >/dev/null 2>&1; then
                log_info "Installing Python 3.11 from AppStream..."
                $PKG_MGR install -y python3.11 python3.11-pip curl ca-certificates
            elif $PKG_MGR info python3.12 >/dev/null 2>&1; then
                log_info "Installing Python 3.12 from AppStream..."
                $PKG_MGR install -y python3.12 python3.12-pip curl ca-certificates
            else
                $PKG_MGR install -y python3 python3-pip curl ca-certificates
            fi
        fi
    elif is_arch_family; then
        log_info "Detected Arch Linux family (pacman package manager)."
        pacman -Sy --noconfirm --needed python python-pip curl ca-certificates
    elif is_suse_family; then
        log_info "Detected SUSE family (zypper package manager)."
        zypper --non-interactive refresh
        zypper --non-interactive install -y python3 python3-pip python3-virtualenv curl ca-certificates
    else
        log_warn "Unknown Linux distribution. Attempting fallback package manager detection..."
        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y python3 python3-venv python3-pip curl ca-certificates
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y python3 python3-pip curl ca-certificates
        elif command -v yum >/dev/null 2>&1; then
            yum install -y python3 python3-pip curl ca-certificates
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm --needed python python-pip curl ca-certificates
        elif command -v zypper >/dev/null 2>&1; then
            zypper --non-interactive install -y python3 python3-pip curl ca-certificates
        else
            log_error "No supported package manager found (apt, dnf, yum, pacman, zypper)."
            log_error "Please ensure Python >= 3.10, venv, and pip are installed manually."
            exit 1
        fi
    fi
}

# ------------------------------------------------------------------------------
# Locate Supported Python Binary
# ------------------------------------------------------------------------------
find_python_bin() {
    local candidates=(
        python3.14
        python3.13
        python3.12
        python3.11
        python3.10
        python3
        python
    )

    for cmd in "${candidates[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            local full_path
            full_path="$(command -v "$cmd")"
            if "$full_path" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
                echo "$full_path"
                return 0
            fi
        fi
    done
    return 1
}

# ------------------------------------------------------------------------------
# Create Dedicated System Service User
# ------------------------------------------------------------------------------
create_system_user() {
    log_step "Setting up dedicated system user '${SERVICE_USER}'..."

    if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
        log_info "Creating system group '${SERVICE_GROUP}'..."
        groupadd --system "${SERVICE_GROUP}" 2>/dev/null || groupadd "${SERVICE_GROUP}" 2>/dev/null || true
    fi

    if ! getent passwd "${SERVICE_USER}" >/dev/null 2>&1; then
        log_info "Creating system user '${SERVICE_USER}'..."
        local NOLOGIN_SHELL="/usr/sbin/nologin"
        if [ ! -x "$NOLOGIN_SHELL" ]; then
            if [ -x "/sbin/nologin" ]; then
                NOLOGIN_SHELL="/sbin/nologin"
            else
                NOLOGIN_SHELL="/bin/false"
            fi
        fi

        useradd \
            --system \
            --gid "${SERVICE_GROUP}" \
            --home-dir "${INSTALL_DIR}" \
            --no-create-home \
            --shell "$NOLOGIN_SHELL" \
            --comment "VulnWatch Daemon User" \
            "${SERVICE_USER}"
    else
        log_info "System user '${SERVICE_USER}' already exists."
    fi
}

# ------------------------------------------------------------------------------
# Setup Directories
# ------------------------------------------------------------------------------
setup_directories() {
    log_step "Creating system directories..."

    # Application folder: /opt/vulnwatch
    mkdir -p "${INSTALL_DIR}"
    chmod 0755 "${INSTALL_DIR}"

    # Configuration directory: /etc/vulnwatch
    mkdir -p "${CONFIG_DIR}"
    chown root:"${SERVICE_GROUP}" "${CONFIG_DIR}"
    chmod 0750 "${CONFIG_DIR}"

    # Data directory: /var/lib/vulnwatch
    mkdir -p "${DATA_DIR}"
    chown "${SERVICE_USER}":"${SERVICE_GROUP}" "${DATA_DIR}"
    chmod 0750 "${DATA_DIR}"

    # Log directory: /var/log/vulnwatch
    mkdir -p "${LOG_DIR}"
    chown "${SERVICE_USER}":"${SERVICE_GROUP}" "${LOG_DIR}"
    chmod 0750 "${LOG_DIR}"

    log_success "Created /opt/vulnwatch, /etc/vulnwatch, /var/lib/vulnwatch, and /var/log/vulnwatch."
}

# ------------------------------------------------------------------------------
# Copy Project Files
# ------------------------------------------------------------------------------
copy_application_files() {
    log_step "Installing VulnWatch files into ${INSTALL_DIR}..."

    local SOURCE_DIR="$SCRIPT_DIR"

    # If app.py is missing from script directory (e.g. running via raw curl pipe), clone repo
    if [ ! -f "${SOURCE_DIR}/app.py" ] || [ ! -d "${SOURCE_DIR}/src" ]; then
        log_warn "Source files not found in ${SOURCE_DIR}. Cloning from GitHub repository..."
        local TEMP_CLONE
        TEMP_CLONE="$(mktemp -d /tmp/vulnwatch-install-XXXXXX)"
        git clone https://github.com/tuhin-su/vulnwatch.git "${TEMP_CLONE}"
        SOURCE_DIR="${TEMP_CLONE}"
    fi

    # Copy core application files
    cp -f "${SOURCE_DIR}/app.py" "${INSTALL_DIR}/app.py"
    cp -f "${SOURCE_DIR}/requirements.txt" "${INSTALL_DIR}/requirements.txt"
    [ -f "${SOURCE_DIR}/LICENSE" ] && cp -f "${SOURCE_DIR}/LICENSE" "${INSTALL_DIR}/LICENSE"
    [ -f "${SOURCE_DIR}/README.md" ] && cp -f "${SOURCE_DIR}/README.md" "${INSTALL_DIR}/README.md"
    [ -f "${SOURCE_DIR}/.env.example" ] && cp -f "${SOURCE_DIR}/.env.example" "${INSTALL_DIR}/.env.example"
    [ -f "${SOURCE_DIR}/uninstall.sh" ] && cp -f "${SOURCE_DIR}/uninstall.sh" "${INSTALL_DIR}/uninstall.sh"

    # Copy src directory
    rm -rf "${INSTALL_DIR}/src"
    cp -r "${SOURCE_DIR}/src" "${INSTALL_DIR}/src"

    # Clean any local pycache from source copy
    find "${INSTALL_DIR}/src" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "${INSTALL_DIR}/src" -type f -name "*.pyc" -delete 2>/dev/null || true

    # Ownership and permissions for application files
    chown -R root:"${SERVICE_GROUP}" "${INSTALL_DIR}"
    chmod -R u=rwX,go=rX "${INSTALL_DIR}"
    chmod 0755 "${INSTALL_DIR}/app.py"
    [ -f "${INSTALL_DIR}/uninstall.sh" ] && chmod 0755 "${INSTALL_DIR}/uninstall.sh"

    log_success "Application files copied to ${INSTALL_DIR}."
}

# ------------------------------------------------------------------------------
# Setup Python Virtual Environment
# ------------------------------------------------------------------------------
setup_virtualenv() {
    local PY_BIN="$1"
    local VENV_DIR="${INSTALL_DIR}/venv"

    log_step "Setting up Python virtual environment in ${VENV_DIR}..."

    # If venv already exists but is corrupt or uses different python, recreate it
    if [ -d "$VENV_DIR" ] && [ ! -x "${VENV_DIR}/bin/python" ]; then
        rm -rf "$VENV_DIR"
    fi

    local venv_ok=0
    if [ ! -d "$VENV_DIR" ]; then
        log_info "Creating virtualenv using ${PY_BIN}..."
        if "$PY_BIN" -m venv "$VENV_DIR" 2>/dev/null; then
            venv_ok=1
        else
            log_warn "Standard python -m venv failed; falling back to --without-pip..."
            rm -rf "$VENV_DIR"
            if "$PY_BIN" -m venv --without-pip "$VENV_DIR"; then
                venv_ok=1
            fi
        fi
    else
        log_info "Reusing existing virtual environment at ${VENV_DIR}."
        venv_ok=1
    fi

    if [ "$venv_ok" -ne 1 ] || [ ! -x "${VENV_DIR}/bin/python" ]; then
        log_error "Unable to create Python virtual environment in ${VENV_DIR}."
        exit 1
    fi

    # Ensure pip is present inside venv
    if [ ! -x "${VENV_DIR}/bin/pip" ]; then
        log_info "Bootstrapping pip inside virtual environment..."
        curl -fsSL https://bootstrap.pypa.io/get-pip.py | "${VENV_DIR}/bin/python"
    fi

    # Install Python requirements
    log_info "Installing Python dependencies from ${INSTALL_DIR}/requirements.txt..."
    "${VENV_DIR}/bin/pip" install --quiet --no-cache-dir -r "${INSTALL_DIR}/requirements.txt"

    # Precompile bytecode for faster boot and compatibility with read-only root
    log_info "Precompiling Python bytecode..."
    "${VENV_DIR}/bin/python" -m compileall -q "${INSTALL_DIR}/src" "${INSTALL_DIR}/app.py" 2>/dev/null || true

    # Set proper permissions for the venv
    chown -R root:"${SERVICE_GROUP}" "${VENV_DIR}"
    chmod -R u=rwX,go=rX "${VENV_DIR}"

    log_success "Virtual environment configured with Python $("${VENV_DIR}/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')."
}

# ------------------------------------------------------------------------------
# Setup Configuration File (/etc/vulnwatch/vulnwatch.env)
# ------------------------------------------------------------------------------
setup_configuration() {
    log_step "Configuring environment settings in ${CONFIG_FILE}..."

    local IS_NEW_CONFIG=0

    if [ ! -f "${CONFIG_FILE}" ]; then
        IS_NEW_CONFIG=1
        cat <<'EOF' > "${CONFIG_FILE}"
# ==============================================================================
# VulnWatch System Configuration
# File: /etc/vulnwatch/vulnwatch.env
# Permissions: 0640 (root:vulnwatch)
# ==============================================================================

# --- Telegram Bot Alerting & Commands ---
TELEGRAM_BOT_ENABLED=true
TELEGRAM_BOT_TOKEN=
TELEGRAM_USER_ID=
TELEGRAM_CHAT_ID=

# --- NIST NVD API Key (Optional, increases rate limit 10x) ---
NVD_API_KEY=

# --- Polling & Interval Controls ---
POLL_SECONDS=1800
BOOTSTRAP_HOURS=24
OVERLAP_MINUTES=10
LOG_LEVEL=INFO
# Persistent daemon log file path
LOG_FILE=/var/log/vulnwatch/vulnwatch.log

# --- Vulnerability Filtering Rules ---
# Minimum CVSS score threshold (0.0 to 10.0)
MIN_CVSS=0
# Alert only on CVSS >= 7.0 or CISA KEV entries
ONLY_HIGH_OR_KEV=false
# Filter controls: watch only newly published CVEs
ONLY_NEWLY_PUBLISHED=true
START_FROM_NOW=true
MAX_CVE_AGE_DAYS=7

# Technology Watchlist: comma-separated list of software/frameworks (e.g. php,laravel,wordpress)
# Leave empty to monitor all technologies
WATCHLIST=

# Initial severity rating filter: all, medium, high, critical
RATING_FILTER=

# --- SQLite Database Storage (Native System Path) ---
DB_PATH=/var/lib/vulnwatch/vulnwatch.sqlite3

# --- Model Context Protocol (MCP) Server for AI Assistants ---
MCP_ENABLED=false
MCP_URL=http://localhost:8080
MCP_AUTH_TOKEN=your_secure_mcp_auth_token_here

# --- Alternative Webhook Channel ---
ALTER_CHANNEL_ENABLED=false
ALTER_CHANNEL_URL=http://localhost:8080/alter-channel-endpoint
ALTER_CHANNEL_AUTH_TOKEN=your_secure_alter_channel_auth_token_here
EOF
        chown root:"${SERVICE_GROUP}" "${CONFIG_FILE}"
        chmod 0640 "${CONFIG_FILE}"
        log_success "Created initial configuration at ${CONFIG_FILE} (permissions: 0640)."
    else
        log_info "Existing configuration detected at ${CONFIG_FILE}. Preserving user settings."
        # Ensure DB_PATH is properly set for native installation if missing
        if ! grep -q "^DB_PATH=" "${CONFIG_FILE}"; then
            echo "DB_PATH=/var/lib/vulnwatch/vulnwatch.sqlite3" >> "${CONFIG_FILE}"
        fi
        if ! grep -q "^LOG_FILE=" "${CONFIG_FILE}"; then
            echo "LOG_FILE=/var/log/vulnwatch/vulnwatch.log" >> "${CONFIG_FILE}"
        fi
        chown root:"${SERVICE_GROUP}" "${CONFIG_FILE}"
        chmod 0640 "${CONFIG_FILE}"
    fi

    # Symlink /opt/vulnwatch/.env -> /etc/vulnwatch/vulnwatch.env for convenience
    ln -sf "${CONFIG_FILE}" "${INSTALL_DIR}/.env"

    echo "$IS_NEW_CONFIG"
}

# ------------------------------------------------------------------------------
# Install Systemd Service Unit
# ------------------------------------------------------------------------------
setup_systemd_service() {
    log_step "Installing systemd service unit (${SERVICE_FILE})..."

    cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=VulnWatch Security Intelligence & Alerting Service
Documentation=https://github.com/tuhin-su/vulnwatch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-${CONFIG_FILE}
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=${INSTALL_DIR}/venv/bin/python -u ${INSTALL_DIR}/app.py
Restart=always
RestartSec=10s

# Sandboxing and security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
RuntimeDirectory=vulnwatch
LogsDirectory=vulnwatch
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true

# Logging
StandardOutput=journal
StandardError=journal

# Capabilities: allow binding to low ports if MCP server is used on port 80/443
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Resource limitations
LimitNOFILE=65535
MemoryMax=512M
TasksMax=256

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "${SERVICE_FILE}"

    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable "${SERVICE_NAME}"
        log_success "Enabled ${SERVICE_NAME} to start automatically on system boot."
    fi
}

# ------------------------------------------------------------------------------
# Install Logrotate Configuration (/etc/logrotate.d/vulnwatch)
# ------------------------------------------------------------------------------
setup_logrotate() {
    log_step "Configuring logrotate policy at ${LOGROTATE_FILE}..."

    mkdir -p "${LOGROTATE_DIR}"
    cat <<EOF > "${LOGROTATE_FILE}"
${LOG_DIR}/*.log {
    weekly
    missingok
    rotate 12
    compress
    delaycompress
    notifempty
    copytruncate
    create 0640 ${SERVICE_USER} ${SERVICE_GROUP}
}
EOF

    chmod 0644 "${LOGROTATE_FILE}"
    log_success "Created logrotate policy at ${LOGROTATE_FILE}."
}

# ------------------------------------------------------------------------------
# Install Management CLI Utility (/usr/local/bin/vulnwatch)
# ------------------------------------------------------------------------------
install_cli_utility() {
    log_step "Installing CLI management utility at ${CLI_BIN}..."

    cat <<'EOF' > "${CLI_BIN}"
#!/usr/bin/env bash
# ==============================================================================
# VulnWatch CLI Utility
# ==============================================================================

SERVICE_NAME="vulnwatch.service"
CONFIG_FILE="/etc/vulnwatch/vulnwatch.env"
INSTALL_DIR="/opt/vulnwatch"
SERVICE_USER="vulnwatch"

show_help() {
    cat <<HELP
VulnWatch Management Utility

Usage:
  vulnwatch <command> [options]

Commands:
  status         Show systemd service status (default)
  start          Start the VulnWatch service
  stop           Stop the VulnWatch service
  restart        Restart the VulnWatch service
  logs [-f]      Inspect service journal logs (systemd)
  log-file [-f]  View or tail /var/log/vulnwatch/vulnwatch.log
  config         Edit configuration in /etc/vulnwatch/vulnwatch.env
  run            Run VulnWatch interactively in the foreground
  version        Display version and system installation paths
  uninstall      Uninstall VulnWatch completely from system
  help           Show this help message

Examples:
  vulnwatch status
  vulnwatch logs -f
  vulnwatch config
HELP
}

CMD="${1:-status}"

case "$CMD" in
    status)
        systemctl status "$SERVICE_NAME"
        ;;
    start)
        systemctl start "$SERVICE_NAME"
        echo "VulnWatch service started."
        systemctl status "$SERVICE_NAME" --no-pager
        ;;
    stop)
        systemctl stop "$SERVICE_NAME"
        echo "VulnWatch service stopped."
        ;;
    restart)
        systemctl restart "$SERVICE_NAME"
        echo "VulnWatch service restarted."
        systemctl status "$SERVICE_NAME" --no-pager
        ;;
    reload)
        systemctl reload-or-restart "$SERVICE_NAME"
        ;;
    logs|log)
        shift 2>/dev/null || true
        if [ "${1:-}" = "file" ] || [ "${1:-}" = "--file" ]; then
            shift 2>/dev/null || true
            LOG_PATH="/var/log/vulnwatch/vulnwatch.log"
            if [ -f "$LOG_PATH" ]; then
                tail -n 50 "$@" "$LOG_PATH"
            else
                echo "Log file $LOG_PATH not found or not created yet."
            fi
        elif [ $# -eq 0 ]; then
            journalctl -u "$SERVICE_NAME" -n 50 --no-pager
        else
            journalctl -u "$SERVICE_NAME" "$@"
        fi
        ;;
    log-file|logfile)
        shift 2>/dev/null || true
        LOG_PATH="/var/log/vulnwatch/vulnwatch.log"
        if [ -f "$LOG_PATH" ]; then
            if [ $# -eq 0 ]; then
                tail -n 50 "$LOG_PATH"
            else
                tail "$@" "$LOG_PATH"
            fi
        else
            echo "Log file $LOG_PATH not found or not created yet."
        fi
        ;;
    config|edit)
        EDITOR_BIN="${EDITOR:-nano}"
        if ! command -v "$EDITOR_BIN" >/dev/null 2>&1; then
            EDITOR_BIN="vi"
        fi
        "$EDITOR_BIN" "$CONFIG_FILE"
        echo
        read -r -p "Do you want to restart VulnWatch now to apply changes? [Y/n]: " reply
        if [[ ! "$reply" =~ ^[Nn] ]]; then
            systemctl restart "$SERVICE_NAME"
            echo "VulnWatch service restarted."
        fi
        ;;
    run)
        shift 2>/dev/null || true
        echo "Running VulnWatch in foreground under user '${SERVICE_USER}' (press Ctrl+C to stop)..."
        if [ -f "$CONFIG_FILE" ]; then
            set -a
            # shellcheck disable=SC1090
            . "$CONFIG_FILE"
            set +a
        fi
        cd "$INSTALL_DIR" || exit 1
        exec su -s /bin/bash "$SERVICE_USER" -c "${INSTALL_DIR}/venv/bin/python -u ${INSTALL_DIR}/app.py $*"
        ;;
    version|-v|--version)
        echo "VulnWatch (Native System-Wide Installation)"
        echo "Install Directory: ${INSTALL_DIR}"
        echo "Configuration:     ${CONFIG_FILE}"
        echo "Database Path:     /var/lib/vulnwatch/vulnwatch.sqlite3"
        if [ -x "${INSTALL_DIR}/venv/bin/python" ]; then
            echo "Python runtime:    $("${INSTALL_DIR}/venv/bin/python" --version)"
        fi
        ;;
    uninstall)
        shift 2>/dev/null || true
        if [ -x "${INSTALL_DIR}/uninstall.sh" ]; then
            exec "${INSTALL_DIR}/uninstall.sh" "$@"
        elif [ -x "/opt/vulnwatch/uninstall.sh" ]; then
            exec "/opt/vulnwatch/uninstall.sh" "$@"
        else
            echo "Error: Uninstaller not found. Run 'sudo bash install.sh --uninstall'." >&2
            exit 1
        fi
        ;;
    help|-h|--help)
        show_help
        ;;
    *)
        echo "Error: Unknown command '$CMD'" >&2
        show_help
        exit 1
        ;;
esac
EOF

    chmod 0755 "${CLI_BIN}"
    log_success "Created management CLI: ${CLI_BIN}"
}

# ------------------------------------------------------------------------------
# Interactive Telegram Setup Prompt
# ------------------------------------------------------------------------------
prompt_telegram_setup() {
    local is_new="$1"

    if [ "$NON_INTERACTIVE" -eq 1 ] || [ ! -t 0 ]; then
        return
    fi

    # Check if Telegram token is currently empty in config
    local current_token
    current_token="$(grep -E "^TELEGRAM_BOT_TOKEN=" "${CONFIG_FILE}" | cut -d'=' -f2- | tr -d ' "')"

    if [ -z "$current_token" ] || [ "$current_token" = "YOUR_BOT_TOKEN" ]; then
        echo
        echo -e "${YELLOW}==================================================================${NC}"
        echo -e "${BOLD} VulnWatch Configuration Setup${NC}"
        echo -e "${YELLOW}==================================================================${NC}"
        echo "To receive alerts and use bot commands, VulnWatch needs your"
        echo "Telegram Bot Token and User ID (from @BotFather & @userinfobot)."
        echo
        read -r -p "Would you like to configure your Telegram Bot credentials now? [y/N]: " configure_now

        if [[ "$configure_now" =~ ^[Yy] ]]; then
            read -r -p "Enter Telegram Bot Token: " input_token
            read -r -p "Enter Telegram User/Chat ID: " input_uid

            if [ -n "$input_token" ]; then
                sed -i "s|^TELEGRAM_BOT_TOKEN=.*|TELEGRAM_BOT_TOKEN=${input_token}|" "${CONFIG_FILE}"
            fi
            if [ -n "$input_uid" ]; then
                sed -i "s|^TELEGRAM_USER_ID=.*|TELEGRAM_USER_ID=${input_uid}|" "${CONFIG_FILE}"
            fi
            log_success "Credentials saved to ${CONFIG_FILE}."
        else
            log_info "Skipping Telegram setup. You can configure it anytime by running:"
            echo -e "    ${BOLD}sudo vulnwatch config${NC}"
        fi
    fi
}

# ------------------------------------------------------------------------------
# Start or Restart Service
# ------------------------------------------------------------------------------
start_or_restart_service() {
    if [ "$NO_START" -eq 1 ]; then
        log_info "Skipping service start (--no-start specified)."
        return
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        return
    fi

    local current_token
    current_token="$(grep -E "^TELEGRAM_BOT_TOKEN=" "${CONFIG_FILE}" | cut -d'=' -f2- | tr -d ' "')"

    if [ -n "$current_token" ] && [ "$current_token" != "YOUR_BOT_TOKEN" ]; then
        log_step "Starting ${SERVICE_NAME}..."
        systemctl restart "${SERVICE_NAME}"
        sleep 1
        if systemctl is-active --quiet "${SERVICE_NAME}"; then
            log_success "${SERVICE_NAME} is active and running!"
        else
            log_warn "${SERVICE_NAME} started but might need attention. Check logs with 'vulnwatch logs'."
        fi
    else
        log_warn "Telegram Bot Token is not configured yet."
        log_info "To start VulnWatch, edit your configuration:"
        echo -e "    ${BOLD}vulnwatch config${NC}"
        echo -e "And start the service:"
        echo -e "    ${BOLD}vulnwatch start${NC}"
    fi
}

# ------------------------------------------------------------------------------
# Final Summary Banner
# ------------------------------------------------------------------------------
print_summary() {
    echo
    echo -e "${GREEN}==================================================================${NC}"
    echo -e "${BOLD}       VulnWatch Installation Completed Successfully! 🛡️${NC}"
    echo -e "${GREEN}==================================================================${NC}"
    echo -e "  ${BOLD}Application Folder:${NC} ${INSTALL_DIR}"
    echo -e "  ${BOLD}Configuration File:${NC} ${CONFIG_FILE}"
    echo -e "  ${BOLD}Database Location:${NC}  ${DB_PATH}"
    echo -e "  ${BOLD}Daemon Log File:${NC}    ${APP_LOG_FILE}"
    echo -e "  ${BOLD}Logrotate Policy:${NC}   ${LOGROTATE_FILE}"
    echo -e "  ${BOLD}Systemd Service:${NC}    ${SERVICE_NAME}"
    echo -e "  ${BOLD}CLI Helper Utility:${NC} ${CLI_BIN}"
    echo
    echo -e "${BOLD}Quick Management Commands:${NC}"
    echo -e "  - View service status:   ${CYAN}vulnwatch status${NC}  (or systemctl status ${SERVICE_NAME})"
    echo -e "  - Start service:         ${CYAN}vulnwatch start${NC}"
    echo -e "  - Stop service:          ${CYAN}vulnwatch stop${NC}"
    echo -e "  - Restart service:       ${CYAN}vulnwatch restart${NC}"
    echo -e "  - Follow journal logs:   ${CYAN}vulnwatch logs -f${NC}"
    echo -e "  - Follow file logs:      ${CYAN}vulnwatch log-file -f${NC} (or tail -f ${APP_LOG_FILE})"
    echo -e "  - Edit configuration:    ${CYAN}vulnwatch config${NC}"
    echo -e "  - Debug foreground run:  ${CYAN}vulnwatch run${NC}"
    echo -e "  - Uninstall:             ${CYAN}vulnwatch uninstall${NC}"
    echo -e "${GREEN}==================================================================${NC}"
    echo
}

# ------------------------------------------------------------------------------
# Main Routine
# ------------------------------------------------------------------------------
main() {
    parse_args "$@"

    if [ "$CHECK_ONLY" -eq 1 ]; then
        echo -e "${BOLD}==================================================================${NC}"
        echo -e "${BOLD}           VulnWatch Compatibility & Pre-Flight Check            ${NC}"
        echo -e "${BOLD}==================================================================${NC}"
        detect_distro
        log_info "Detected OS: ${DISTRO_NAME} (ID: ${DISTRO_ID}, ID_LIKE: ${DISTRO_ID_LIKE})"
        
        local FAMILY="unknown"
        if is_debian_family; then FAMILY="Debian / Ubuntu"; fi
        if is_rhel_family; then FAMILY="RHEL / Fedora / CentOS / Rocky / AlmaLinux"; fi
        if is_arch_family; then FAMILY="Arch Linux"; fi
        if is_suse_family; then FAMILY="SUSE / openSUSE"; fi
        log_info "OS Family Classification: ${FAMILY}"

        local PY_BIN
        if PY_BIN="$(find_python_bin)"; then
            log_success "Compatible Python runtime found: ${PY_BIN} ($("$PY_BIN" --version))"
        else
            log_warn "Python >= 3.10 was not found. The installer will install it via package manager."
        fi

        log_info "Target Application Directory: ${INSTALL_DIR}"
        log_info "Target Configuration File:    ${CONFIG_FILE}"
        log_info "Target Database Directory:    ${DATA_DIR}"
        log_info "Target Log Directory:         ${LOG_DIR}"
        log_info "Target Log File:              ${APP_LOG_FILE}"
        log_info "Target Logrotate Policy:      ${LOGROTATE_FILE}"
        log_info "Target Systemd Service:       ${SERVICE_FILE}"
        log_info "Target CLI Utility:           ${CLI_BIN}"
        log_success "System is ready for VulnWatch installation."
        exit 0
    fi

    check_root

    # Handle uninstallation request
    if [ "$DO_UNINSTALL" -eq 1 ]; then
        if [ -x "${SCRIPT_DIR}/uninstall.sh" ]; then
            exec bash "${SCRIPT_DIR}/uninstall.sh" $([ "$PURGE_ON_UNINSTALL" -eq 1 ] && echo "--purge")
        elif [ -x "${INSTALL_DIR}/uninstall.sh" ]; then
            exec bash "${INSTALL_DIR}/uninstall.sh" $([ "$PURGE_ON_UNINSTALL" -eq 1 ] && echo "--purge")
        else
            log_error "Uninstaller script not found."
            exit 1
        fi
    fi

    echo -e "${BOLD}==================================================================${NC}"
    echo -e "${BOLD}            VulnWatch Native System-Wide Installer               ${NC}"
    echo -e "${BOLD}==================================================================${NC}"

    detect_distro
    log_info "Detected OS: ${DISTRO_NAME} (${DISTRO_ID})"

    install_system_packages

    local PYTHON_BIN
    if ! PYTHON_BIN="$(find_python_bin)"; then
        log_error "Python >= 3.10 is required by VulnWatch but was not found."
        log_error "Please install Python 3.10 or newer and re-run this script."
        exit 1
    fi
    log_info "Using Python runtime: ${PYTHON_BIN} ($("$PYTHON_BIN" --version))"

    create_system_user
    setup_directories
    copy_application_files
    setup_virtualenv "${PYTHON_BIN}"
    
    local IS_NEW_CONFIG
    IS_NEW_CONFIG="$(setup_configuration)"
    
    setup_systemd_service
    setup_logrotate
    install_cli_utility

    prompt_telegram_setup "${IS_NEW_CONFIG}"
    start_or_restart_service
    print_summary
}

main "$@"
