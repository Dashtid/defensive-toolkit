#!/bin/bash
#
# Security Posture Audit Script
# Audits current security configuration against CIS Benchmarks
#
# Usage: sudo ./audit-security-posture.sh [--output json|html]
#

set -euo pipefail

OUTPUT_FORMAT="text"
REPORT_FILE="/tmp/security-audit-$(date +%Y%m%d_%H%M%S).txt"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output) OUTPUT_FORMAT="$2"; shift 2 ;;
        *) shift ;;
    esac
done

# Check if root
[[ $EUID -ne 0 ]] && { echo "Must run as root"; exit 1; }

# Scoring
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

check_test() {
    local test_name="$1"
    local test_command="$2"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if eval "$test_command" &>/dev/null; then
        echo "[OK] $test_name"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        echo "[FAIL] $test_name"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

echo "======================================================================"
echo "  Security Posture Audit"
echo "  $(date)"
echo "======================================================================"
echo ""

# SSH Checks
echo "=== SSH Configuration ==="
check_test "SSH: PermitRootLogin disabled" "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config"
check_test "SSH: Protocol 2 only" "grep -q '^Protocol 2' /etc/ssh/sshd_config"
check_test "SSH: X11Forwarding disabled" "grep -q '^X11Forwarding no' /etc/ssh/sshd_config"
echo ""

# Firewall Checks
echo "=== Firewall Configuration ==="
if command -v ufw &>/dev/null; then
    check_test "UFW: Firewall active" "ufw status | grep -q 'Status: active'"
elif command -v firewall-cmd &>/dev/null; then
    check_test "firewalld: Firewall running" "firewall-cmd --state | grep -q running"
fi
echo ""

# Kernel Parameters
echo "=== Kernel Parameters ==="
check_test "Kernel: IP forwarding disabled" "sysctl net.ipv4.ip_forward | grep -q '= 0'"
check_test "Kernel: SYN cookies enabled" "sysctl net.ipv4.tcp_syncookies | grep -q '= 1'"
check_test "Kernel: Source routing disabled" "sysctl net.ipv4.conf.all.accept_source_route | grep -q '= 0'"
echo ""

# AIDE
echo "=== File Integrity Monitoring ==="
check_test "AIDE: Installed" "command -v aide"
check_test "AIDE: Database exists" "[ -f /var/lib/aide/aide.db* ]"
echo ""

# Automatic Updates
echo "=== Automatic Updates ==="
if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
    check_test "Auto-updates: Enabled" "grep -q 'APT::Periodic::Unattended-Upgrade \"1\"' /etc/apt/apt.conf.d/20auto-upgrades"
elif [[ -f /etc/yum/yum-cron.conf ]]; then
    check_test "Auto-updates: Enabled" "grep -q 'apply_updates = yes' /etc/yum/yum-cron.conf"
fi
echo ""

# Mandatory Access Control
echo "=== Mandatory Access Control ==="
if command -v aa-status &>/dev/null; then
    check_test "AppArmor: Enabled" "systemctl is-active apparmor"
elif command -v getenforce &>/dev/null; then
    check_test "SELinux: Enforcing" "getenforce | grep -q Enforcing"
fi
echo ""

# Summary
echo "======================================================================"
echo "  Audit Summary"
echo "======================================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
SCORE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
echo "Score: ${SCORE}%"
echo ""

if [[ $SCORE -ge 80 ]]; then
    echo "[OK] Good security posture"
elif [[ $SCORE -ge 60 ]]; then
    echo "[!] Moderate security posture - improvements recommended"
else
    echo "[-] Weak security posture - immediate action required"
fi

echo "======================================================================"
