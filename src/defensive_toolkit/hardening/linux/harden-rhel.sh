#!/bin/bash
#
# RHEL/CentOS Security Hardening Script
# Based on CIS Benchmark for Red Hat Enterprise Linux
#
# Usage: sudo ./harden-rhel.sh [--level 1|2|3] [--dry-run] [--no-backup]
#
# Note: This script is similar to harden-ubuntu.sh but adapted for RHEL/CentOS
# Key differences: firewalld instead of UFW, SELinux instead of AppArmor
#

set -euo pipefail

# [COLORS AND CONFIGURATION - Same as Ubuntu script]
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"
BACKUP_DIR="/var/backups/security-hardening"
LOG_FILE="/var/log/security-hardening.log"
HARDENING_LEVEL=1
DRY_RUN=0
NO_BACKUP=0

# [ARGUMENT PARSING - Same as Ubuntu]
while [[ $# -gt 0 ]]; do
    case $1 in
        --level) HARDENING_LEVEL="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --no-backup) NO_BACKUP=1; shift ;;
        --help)
            echo "Usage: $0 [--level 1|2|3] [--dry-run] [--no-backup]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# [LOGGING FUNCTIONS - Same as Ubuntu]
log() { local level=$1; shift; echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] $*" | tee -a "${LOG_FILE}"; }
print_ok() { echo -e "${GREEN}[OK]${NC} $*"; log "INFO" "$*"; }
print_warn() { echo -e "${YELLOW}[!]${NC} $*"; log "WARN" "$*"; }
print_error() { echo -e "${RED}[-]${NC} $*"; log "ERROR" "$*"; }
print_info() { echo -e "[*] $*"; log "INFO" "$*"; }

check_root() {
    [[ $EUID -ne 0 ]] && { print_error "Must run as root"; exit 1; }
}

detect_distribution() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
    else
        print_error "Cannot detect Linux distribution"
        exit 1
    fi

    if [[ "$OS" != "rhel" ]] && [[ "$OS" != "centos" ]] && [[ "$OS" != "rocky" ]] && [[ "$OS" != "almalinux" ]]; then
        print_error "This script is for RHEL/CentOS/Rocky/AlmaLinux only. Use harden-ubuntu.sh for Ubuntu/Debian."
        exit 1
    fi

    print_info "Detected: $PRETTY_NAME"
}

create_backup() {
    [[ $NO_BACKUP -eq 1 ]] && { print_warn "Skipping backup"; return; }
    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would create backup"; return; }

    mkdir -p "${BACKUP_DIR}/$(date +%Y%m%d_%H%M%S)"
    local backup_path="${BACKUP_DIR}/$(date +%Y%m%d_%H%M%S)"

    cp -p /etc/ssh/sshd_config "${backup_path}/" 2>/dev/null || true
    cp -p /etc/sysctl.conf "${backup_path}/" 2>/dev/null || true
    firewall-cmd --list-all > "${backup_path}/firewall_rules.txt" 2>/dev/null || true

    print_ok "Backup created: ${backup_path}"
}

update_system() {
    print_info "Updating system..."
    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would run: yum update -y"; return; }

    yum update -y -q
    print_ok "System updated"
}

install_packages() {
    print_info "Installing required packages..."
    local packages="aide firewalld fail2ban policycoreutils-python-utils yum-cron"

    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would install: $packages"; return; }

    yum install -y $packages
    print_ok "Packages installed"
}

harden_ssh() {
    print_info "Hardening SSH..."
    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would modify SSH config"; return; }

    local sshd_config="/etc/ssh/sshd_config"
    cp -p "$sshd_config" "${sshd_config}.bak"

    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$sshd_config"
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$sshd_config"
    sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$sshd_config"

    if [[ $HARDENING_LEVEL -ge 2 ]]; then
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$sshd_config"
    fi

    print_ok "SSH hardened"
}

configure_firewall() {
    print_info "Configuring firewalld..."
    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would configure firewall"; return; }

    systemctl enable firewalld
    systemctl start firewalld

    # Set default zone to drop
    firewall-cmd --set-default-zone=drop
    firewall-cmd --permanent --zone=drop --add-service=ssh
    firewall-cmd --reload

    print_ok "Firewall configured"
}

harden_kernel() {
    print_info "Hardening kernel parameters..."
    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would modify sysctl"; return; }

    cat > /etc/sysctl.d/99-security.conf <<EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
EOF

    sysctl -p /etc/sysctl.d/99-security.conf
    print_ok "Kernel hardened"
}

configure_selinux() {
    print_info "Configuring SELinux..."
    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would set SELinux to enforcing"; return; }

    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1 2>/dev/null || true

    print_ok "SELinux configured"
}

configure_auto_updates() {
    print_info "Configuring automatic updates..."
    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would configure yum-cron"; return; }

    sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf
    systemctl enable yum-cron
    systemctl start yum-cron

    print_ok "Auto-updates configured"
}

configure_aide() {
    print_info "Configuring AIDE..."
    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would initialize AIDE"; return; }

    [[ -f "${CONFIG_DIR}/aide.conf" ]] && cp "${CONFIG_DIR}/aide.conf" /etc/aide.conf

    aide --init || true
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true

    cat > /etc/cron.daily/aide-check <<'EOF'
#!/bin/bash
/usr/sbin/aide --check | mail -s "AIDE Report" root
EOF
    chmod +x /etc/cron.daily/aide-check

    print_ok "AIDE configured"
}

configure_fail2ban() {
    print_info "Configuring Fail2ban..."
    [[ $DRY_RUN -eq 1 ]] && { print_info "[DRY RUN] Would configure Fail2ban"; return; }

    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
EOF

    systemctl enable fail2ban
    systemctl start fail2ban

    print_ok "Fail2ban configured"
}

print_summary() {
    echo ""
    echo "======================================================================"
    echo "  RHEL/CentOS Security Hardening Complete - Level $HARDENING_LEVEL"
    echo "======================================================================"
    echo ""
    print_ok "SSH hardened"
    print_ok "Firewalld configured"
    print_ok "SELinux enabled (enforcing mode)"
    print_ok "Kernel parameters hardened"
    print_ok "Automatic updates enabled"
    print_ok "AIDE file integrity monitoring configured"
    print_ok "Fail2ban enabled"
    echo ""
    print_warn "IMPORTANT: Test thoroughly before production use!"
    print_warn "Backup: ${BACKUP_DIR}"
    print_warn "Log: ${LOG_FILE}"
    echo ""
    echo "======================================================================"
}

main() {
    echo "======================================================================"
    echo "  RHEL/CentOS Security Hardening Script"
    echo "======================================================================"
    echo ""

    check_root
    detect_distribution
    create_backup
    update_system
    install_packages
    harden_ssh
    configure_firewall
    harden_kernel
    configure_selinux
    configure_auto_updates
    configure_aide
    configure_fail2ban
    print_summary
}

main
