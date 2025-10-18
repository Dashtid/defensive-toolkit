#!/bin/bash
#
# Backup Security Settings
# Creates timestamped backup of critical security configuration
#

set -euo pipefail

BACKUP_DIR="/var/backups/security-hardening"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"

[[ $EUID -ne 0 ]] && { echo "Must run as root"; exit 1; }

echo "[*] Creating backup directory: ${BACKUP_PATH}"
mkdir -p "${BACKUP_PATH}"

echo "[*] Backing up SSH configuration..."
cp -p /etc/ssh/sshd_config "${BACKUP_PATH}/"

echo "[*] Backing up sysctl configuration..."
cp -p /etc/sysctl.conf "${BACKUP_PATH}/" 2>/dev/null || true
cp -pr /etc/sysctl.d/ "${BACKUP_PATH}/" 2>/dev/null || true

echo "[*] Backing up PAM configuration..."
cp -pr /etc/pam.d/ "${BACKUP_PATH}/"

echo "[*] Backing up firewall rules..."
if command -v ufw &>/dev/null; then
    ufw status verbose > "${BACKUP_PATH}/ufw_status.txt"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --list-all > "${BACKUP_PATH}/firewall_rules.txt"
fi

echo "[*] Backing up login configuration..."
cp -p /etc/login.defs "${BACKUP_PATH}/"

echo "[*] Creating backup manifest..."
cat > "${BACKUP_PATH}/manifest.txt" <<EOF
Backup created: ${TIMESTAMP}
Hostname: $(hostname)
OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2)
Kernel: $(uname -r)
EOF

echo "[OK] Backup complete: ${BACKUP_PATH}"
echo "[*] To restore: sudo ./restore-security-settings.sh ${TIMESTAMP}"
