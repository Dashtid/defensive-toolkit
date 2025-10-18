#!/bin/bash
#
# Restore Security Settings
# Restores configuration from backup
#
# Usage: sudo ./restore-security-settings.sh [TIMESTAMP]
#

set -euo pipefail

BACKUP_DIR="/var/backups/security-hardening"

[[ $EUID -ne 0 ]] && { echo "Must run as root"; exit 1; }

if [[ $# -eq 0 ]]; then
    echo "Available backups:"
    ls -1 "$BACKUP_DIR" 2>/dev/null || echo "No backups found"
    echo ""
    echo "Usage: $0 TIMESTAMP"
    exit 1
fi

TIMESTAMP=$1
BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"

if [[ ! -d "$BACKUP_PATH" ]]; then
    echo "[-] Backup not found: $BACKUP_PATH"
    exit 1
fi

echo "[!] WARNING: This will restore configuration from backup"
echo "[*] Backup location: $BACKUP_PATH"
echo ""
read -p "Continue? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    echo "Aborted"
    exit 0
fi

echo "[*] Restoring SSH configuration..."
cp -p "${BACKUP_PATH}/sshd_config" /etc/ssh/sshd_config

echo "[*] Restoring sysctl configuration..."
[[ -f "${BACKUP_PATH}/sysctl.conf" ]] && cp -p "${BACKUP_PATH}/sysctl.conf" /etc/

echo "[*] Restoring PAM configuration..."
cp -pr "${BACKUP_PATH}/pam.d/"* /etc/pam.d/

echo "[*] Restoring login configuration..."
cp -p "${BACKUP_PATH}/login.defs" /etc/login.defs

echo "[OK] Restore complete"
echo "[!] Restart services for changes to take effect"
echo "    SSH: systemctl restart sshd"
echo "    Firewall: systemctl restart ufw (or firewalld)"
