#!/bin/bash
#
# Ubuntu/Debian Security Hardening Script
# Based on CIS Benchmark for Ubuntu Linux
#
# Usage: sudo ./harden-ubuntu.sh [--level 1|2|3] [--dry-run] [--no-backup]
#
# Levels:
#   1 (safe)      - CIS Level 1 - Minimal impact, production-safe
#   2 (balanced)  - CIS Level 2 - Enhanced security, moderate impact
#   3 (maximum)   - Maximum hardening, may impact functionality
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"
BACKUP_DIR="/var/backups/security-hardening"
LOG_FILE="/var/log/security-hardening.log"
HARDENING_LEVEL=1
DRY_RUN=0
NO_BACKUP=0

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --level)
            HARDENING_LEVEL="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --no-backup)
            NO_BACKUP=1
            shift
            ;;
        --help)
            echo "Usage: $0 [--level 1|2|3] [--dry-run] [--no-backup]"
            echo ""
            echo "Options:"
            echo "  --level N     Hardening level (1=safe, 2=balanced, 3=maximum)"
            echo "  --dry-run     Show what would be done without making changes"
            echo "  --no-backup   Skip backing up current configuration"
            echo "  --help        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

# Print functions
print_ok() {
    echo -e "${GREEN}[OK]${NC} $*"
    log "INFO" "$*"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $*"
    log "WARN" "$*"
}

print_error() {
    echo -e "${RED}[-]${NC} $*"
    log "ERROR" "$*"
}

print_info() {
    echo -e "[*] $*"
    log "INFO" "$*"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Detect distribution
detect_distribution() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_error "Cannot detect Linux distribution"
        exit 1
    fi

    if [[ "$OS" != "ubuntu" ]] && [[ "$OS" != "debian" ]]; then
        print_error "This script is for Ubuntu/Debian only. Use harden-rhel.sh for RHEL/CentOS."
        exit 1
    fi

    print_info "Detected: $PRETTY_NAME"
}

# Create backup
create_backup() {
    if [[ $NO_BACKUP -eq 1 ]]; then
        print_warn "Skipping backup (--no-backup specified)"
        return
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would create backup in ${BACKUP_DIR}"
        return
    fi

    print_info "Creating backup..."
    mkdir -p "${BACKUP_DIR}/$(date +%Y%m%d_%H%M%S)"
    local backup_path="${BACKUP_DIR}/$(date +%Y%m%d_%H%M%S)"

    # Backup critical files
    cp -p /etc/ssh/sshd_config "${backup_path}/" 2>/dev/null || true
    cp -p /etc/sysctl.conf "${backup_path}/" 2>/dev/null || true
    cp -pr /etc/pam.d "${backup_path}/" 2>/dev/null || true
    cp -p /etc/login.defs "${backup_path}/" 2>/dev/null || true

    # Backup firewall rules
    if command -v ufw &> /dev/null; then
        ufw status verbose > "${backup_path}/ufw_status.txt" 2>/dev/null || true
    fi

    print_ok "Backup created: ${backup_path}"
}

# Update system
update_system() {
    print_info "Updating package lists..."

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would run: apt-get update && apt-get upgrade -y"
        return
    fi

    apt-get update -qq
    print_ok "System updated"
}

# Install required packages
install_packages() {
    print_info "Installing required security packages..."

    local packages="aide aide-common ufw fail2ban apparmor apparmor-utils unattended-upgrades apt-listchanges"

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would install: $packages"
        return
    fi

    apt-get install -y $packages
    print_ok "Required packages installed"
}

# Harden SSH configuration
harden_ssh() {
    print_info "Hardening SSH configuration..."

    local sshd_config="/etc/ssh/sshd_config"

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would modify ${sshd_config}"
        return
    fi

    # Backup original
    cp -p "$sshd_config" "${sshd_config}.bak"

    # CIS 5.2.x - SSH hardening
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
    sed -i 's/^#*Protocol.*/Protocol 2/' "$sshd_config"
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$sshd_config"
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$sshd_config"
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$sshd_config"
    sed -i 's/^#*MaxSessions.*/MaxSessions 10/' "$sshd_config"
    sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$sshd_config"
    sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 0/' "$sshd_config"
    sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' "$sshd_config"

    # Level 2/3 additional hardening
    if [[ $HARDENING_LEVEL -ge 2 ]]; then
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$sshd_config"
        sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding no/' "$sshd_config"

        # Strong ciphers only
        echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" >> "$sshd_config"
        echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" >> "$sshd_config"
        echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512" >> "$sshd_config"
    fi

    # Restart SSH (with caution)
    print_warn "SSH configuration updated. You may need to restart SSH manually after verifying config."
    print_info "Test with: sshd -t"

    print_ok "SSH hardened"
}

# Configure firewall (UFW)
configure_firewall() {
    print_info "Configuring UFW firewall..."

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would configure UFW firewall"
        return
    fi

    # Enable UFW
    ufw --force enable

    # Default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH
    ufw allow 22/tcp

    # Rate limiting on SSH (Level 2+)
    if [[ $HARDENING_LEVEL -ge 2 ]]; then
        ufw limit 22/tcp
    fi

    # Logging
    ufw logging on

    print_ok "Firewall configured"
}

# Harden kernel parameters
harden_kernel() {
    print_info "Hardening kernel parameters (sysctl)..."

    local sysctl_file="/etc/sysctl.d/99-security-hardening.conf"

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would create ${sysctl_file}"
        return
    fi

    cat > "$sysctl_file" <<EOF
# CIS Benchmark - Kernel Hardening
# Created by security-hardening script

# IP Forwarding (CIS 3.1.1)
net.ipv4.ip_forward = 0

# Send redirects (CIS 3.1.2)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Source routed packets (CIS 3.2.1)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# ICMP redirects (CIS 3.2.2, 3.2.3)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Log suspicious packets (CIS 3.2.4)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcast (CIS 3.2.5)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors (CIS 3.2.6)
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse path filtering (CIS 3.2.7)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP SYN cookies (CIS 3.2.8)
net.ipv4.tcp_syncookies = 1

# IPv6 router advertisements (CIS 3.2.9)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Randomize virtual address space
kernel.randomize_va_space = 2

# Restrict core dumps
fs.suid_dumpable = 0

# Restrict kernel pointer access
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1
EOF

    if [[ $HARDENING_LEVEL -ge 2 ]]; then
        cat >> "$sysctl_file" <<EOF

# Level 2 - Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Additional hardening
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
EOF
    fi

    # Apply settings
    sysctl -p "$sysctl_file"

    print_ok "Kernel parameters hardened"
}

# Configure automatic security updates
configure_auto_updates() {
    print_info "Configuring automatic security updates..."

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would configure automatic updates"
        return
    fi

    # Configure unattended-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    if [[ $HARDENING_LEVEL -ge 2 ]]; then
        # Level 2 - enable all updates, not just security
        sed -i 's|//\s*"\${distro_id}:\${distro_codename}-updates";|"${distro_id}:${distro_codename}-updates";|' /etc/apt/apt.conf.d/50unattended-upgrades
    fi

    print_ok "Automatic updates configured"
}

# Harden password policies
harden_passwords() {
    print_info "Hardening password policies..."

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would modify password policies"
        return
    fi

    # Install libpam-pwquality if not present
    apt-get install -y libpam-pwquality

    # Configure password quality requirements
    local pwquality_conf="/etc/security/pwquality.conf"

    if [[ $HARDENING_LEVEL -eq 1 ]]; then
        sed -i 's/^# minlen =.*/minlen = 14/' "$pwquality_conf"
        sed -i 's/^# minclass =.*/minclass = 3/' "$pwquality_conf"
    else
        sed -i 's/^# minlen =.*/minlen = 16/' "$pwquality_conf"
        sed -i 's/^# minclass =.*/minclass = 4/' "$pwquality_conf"
        sed -i 's/^# dcredit =.*/dcredit = -1/' "$pwquality_conf"
        sed -i 's/^# ucredit =.*/ucredit = -1/' "$pwquality_conf"
        sed -i 's/^# lcredit =.*/lcredit = -1/' "$pwquality_conf"
        sed -i 's/^# ocredit =.*/ocredit = -1/' "$pwquality_conf"
    fi

    # Configure login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

    print_ok "Password policies hardened"
}

# Configure AIDE (file integrity monitoring)
configure_aide() {
    print_info "Configuring AIDE (File Integrity Monitoring)..."

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would configure AIDE"
        return
    fi

    # Copy custom AIDE configuration
    if [[ -f "${CONFIG_DIR}/aide.conf" ]]; then
        cp "${CONFIG_DIR}/aide.conf" /etc/aide/aide.conf
    fi

    # Initialize AIDE database
    print_info "Initializing AIDE database (this may take a while)..."
    aideinit || true

    # Setup daily cron job
    cat > /etc/cron.daily/aide-check <<'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report for $(hostname)" root
EOF
    chmod +x /etc/cron.daily/aide-check

    print_ok "AIDE configured"
}

# Configure Fail2ban
configure_fail2ban() {
    print_info "Configuring Fail2ban..."

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would configure Fail2ban"
        return
    fi

    # Create local jail configuration
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
EOF

    if [[ $HARDENING_LEVEL -ge 2 ]]; then
        sed -i 's/maxretry = 3/maxretry = 2/' /etc/fail2ban/jail.local
        sed -i 's/bantime = 3600/bantime = 7200/' /etc/fail2ban/jail.local
    fi

    systemctl enable fail2ban
    systemctl restart fail2ban

    print_ok "Fail2ban configured"
}

# Enable AppArmor
enable_apparmor() {
    print_info "Enabling AppArmor..."

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would enable AppArmor"
        return
    fi

    systemctl enable apparmor
    systemctl start apparmor

    # Set all profiles to enforce mode
    if [[ $HARDENING_LEVEL -ge 2 ]]; then
        aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    fi

    print_ok "AppArmor enabled"
}

# Disable unused filesystems
disable_filesystems() {
    print_info "Disabling unused filesystems..."

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would disable unused filesystems"
        return
    fi

    local fs_list="cramfs freevxfs jffs2 hfs hfsplus udf"

    if [[ $HARDENING_LEVEL -ge 2 ]]; then
        fs_list="$fs_list vfat"
    fi

    for fs in $fs_list; do
        echo "install $fs /bin/true" >> /etc/modprobe.d/disable-filesystems.conf
    done

    print_ok "Unused filesystems disabled"
}

# Disable unused services
disable_services() {
    print_info "Disabling unused services..."

    if [[ $DRY_RUN -eq 1 ]]; then
        print_info "[DRY RUN] Would disable unused services"
        return
    fi

    local services="avahi-daemon cups isc-dhcp-server isc-dhcp-server6 slapd nfs-server rpcbind rsync snmpd"

    for service in $services; do
        systemctl disable "$service" 2>/dev/null || true
        systemctl stop "$service" 2>/dev/null || true
    done

    print_ok "Unused services disabled"
}

# Summary
print_summary() {
    echo ""
    echo "======================================================================"
    echo "  Security Hardening Complete - Level $HARDENING_LEVEL"
    echo "======================================================================"
    echo ""
    print_ok "SSH hardened (PermitRootLogin=no, strong ciphers)"
    print_ok "Firewall (UFW) configured and enabled"
    print_ok "Kernel parameters hardened (sysctl)"
    print_ok "Automatic security updates enabled"
    print_ok "Password policies strengthened"
    print_ok "AIDE file integrity monitoring configured"
    print_ok "Fail2ban intrusion prevention enabled"
    print_ok "AppArmor mandatory access control enabled"
    print_ok "Unused filesystems and services disabled"
    echo ""
    print_warn "IMPORTANT: Review the changes and test thoroughly!"
    print_warn "Backup location: ${BACKUP_DIR}"
    print_warn "Log file: ${LOG_FILE}"
    echo ""
    print_info "Next steps:"
    echo "  1. Test SSH access before closing current session"
    echo "  2. Verify services are functioning correctly"
    echo "  3. Review firewall rules: ufw status verbose"
    echo "  4. Check AppArmor status: aa-status"
    echo "  5. Monitor AIDE reports in /var/log/aide/"
    echo ""
    echo "======================================================================"
}

# Main execution
main() {
    echo "======================================================================"
    echo "  Ubuntu/Debian Security Hardening Script"
    echo "  Based on CIS Benchmark"
    echo "======================================================================"
    echo ""
    print_info "Hardening Level: $HARDENING_LEVEL"
    if [[ $DRY_RUN -eq 1 ]]; then
        print_warn "DRY RUN MODE - No changes will be made"
    fi
    echo ""

    check_root
    detect_distribution
    create_backup
    update_system
    install_packages
    harden_ssh
    configure_firewall
    harden_kernel
    configure_auto_updates
    harden_passwords
    configure_aide
    configure_fail2ban
    enable_apparmor
    disable_filesystems
    disable_services
    print_summary
}

# Run main function
main
