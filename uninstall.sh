#!/usr/bin/env bash
# ==============================================================================
# VulnWatch System-Wide Uninstaller
# Cleanly removes VulnWatch system service, binaries, and optionally data.
# ==============================================================================

set -euo pipefail

INSTALL_DIR="/opt/vulnwatch"
CONFIG_DIR="/etc/vulnwatch"
DATA_DIR="/var/lib/vulnwatch"
LOG_DIR="/var/log/vulnwatch"
LOGROTATE_FILE="/etc/logrotate.d/vulnwatch"
SERVICE_NAME="vulnwatch.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
CLI_BIN="/usr/local/bin/vulnwatch"
SERVICE_USER="vulnwatch"
SERVICE_GROUP="vulnwatch"

PURGE=0
NON_INTERACTIVE=0

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    BOLD=''
    NC=''
fi

log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} ${BOLD}$1${NC}"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-] Error:${NC} $1" >&2; }

show_help() {
    cat <<EOF
VulnWatch Uninstaller

Usage:
  sudo bash uninstall.sh [OPTIONS]

Options:
      --purge              Purge all configuration files and database (/var/lib/vulnwatch)
  -y, --non-interactive    Do not prompt for confirmation
  -h, --help               Show this help message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --purge)
            PURGE=1
            shift
            ;;
        -y|--non-interactive|--yes)
            NON_INTERACTIVE=1
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

if [ "$(id -u)" -ne 0 ]; then
    log_error "This uninstaller must be run as root (or using sudo)."
    exit 1
fi

echo -e "${BOLD}==================================================================${NC}"
echo -e "${BOLD}                  VulnWatch System Uninstaller                    ${NC}"
echo -e "${BOLD}==================================================================${NC}"

# Ask for confirmation if running interactively
if [ "$NON_INTERACTIVE" -eq 0 ] && [ -t 0 ]; then
    read -r -p "Are you sure you want to uninstall VulnWatch from this system? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        log_info "Uninstallation aborted."
        exit 0
    fi

    if [ "$PURGE" -eq 0 ]; then
        echo
        read -r -p "Do you also want to purge data and configuration (/var/lib/vulnwatch, /etc/vulnwatch)? [y/N]: " purge_confirm
        if [[ "$purge_confirm" =~ ^[Yy] ]]; then
            PURGE=1
        fi
    fi
fi

# 1. Stop and disable systemd service
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log_info "Stopping ${SERVICE_NAME}..."
        systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    fi

    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log_info "Disabling ${SERVICE_NAME}..."
        systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    fi
fi

# 2. Remove systemd service file
if [ -f "${SERVICE_FILE}" ]; then
    log_info "Removing systemd unit ${SERVICE_FILE}..."
    rm -f "${SERVICE_FILE}"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl reset-failed 2>/dev/null || true
    fi
fi

# 3. Remove CLI helper utility
if [ -f "${CLI_BIN}" ]; then
    log_info "Removing CLI utility ${CLI_BIN}..."
    rm -f "${CLI_BIN}"
fi

# 4. Remove application directory
if [ -d "${INSTALL_DIR}" ]; then
    log_info "Removing application directory ${INSTALL_DIR}..."
    rm -rf "${INSTALL_DIR}"
fi

# 5. Handle purge of data and config
if [ "$PURGE" -eq 1 ]; then
    log_info "Purging configuration directory ${CONFIG_DIR}..."
    rm -rf "${CONFIG_DIR}"

    log_info "Purging database and state directory ${DATA_DIR}..."
    rm -rf "${DATA_DIR}"

    log_info "Purging log directory ${LOG_DIR}..."
    rm -rf "${LOG_DIR}"

    if [ -f "${LOGROTATE_FILE}" ]; then
        log_info "Removing logrotate configuration ${LOGROTATE_FILE}..."
        rm -f "${LOGROTATE_FILE}"
    fi

    if getent passwd "${SERVICE_USER}" >/dev/null 2>&1; then
        log_info "Removing system user '${SERVICE_USER}'..."
        userdel "${SERVICE_USER}" 2>/dev/null || true
    fi

    if getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
        log_info "Removing system group '${SERVICE_GROUP}'..."
        groupdel "${SERVICE_GROUP}" 2>/dev/null || true
    fi
    log_success "All application files, logs, database records, and configurations have been purged."
else
    log_info "Preserving user configuration at ${CONFIG_DIR}."
    log_info "Preserving database records at ${DATA_DIR}."
    log_info "Preserving log files at ${LOG_DIR}."
    echo -e "${YELLOW}[!] Note:${NC} To completely remove remaining data and logs, run:"
    echo "    sudo rm -rf ${CONFIG_DIR} ${DATA_DIR} ${LOG_DIR} ${LOGROTATE_FILE}"
fi

log_success "VulnWatch has been successfully uninstalled."
EOF
