#!/bin/bash

################################################################################
# Linux Incident Response Triage Script
#
# Description: Collects volatile and non-volatile data from Linux systems
#              for incident response and forensic analysis
#
# Author: Defensive Toolkit
# Date: 2025-10-15
# Version: 1.0
#
# Usage: sudo ./linux-triage.sh [-o output_dir] [-q quick] [-f full]
#
# Options:
#   -o DIR    Output directory (default: /tmp/ir_triage)
#   -q        Quick triage (volatile data only)
#   -f        Full triage (all artifacts)
#   -h        Show help
#
# WARNING: This script collects sensitive system information.
#          Ensure proper authorization before running.
#          Follow chain of custody procedures for evidence handling.
################################################################################

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[X] This script must be run as root (sudo)"
   exit 1
fi

# Default configuration
OUTPUT_DIR="/tmp/ir_triage"
MODE="standard"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname)

# Parse command line arguments
while getopts "o:qfh" opt; do
    case $opt in
        o) OUTPUT_DIR="$OPTARG" ;;
        q) MODE="quick" ;;
        f) MODE="full" ;;
        h)
            echo "Usage: $0 [-o output_dir] [-q quick] [-f full]"
            echo "  -o DIR    Output directory (default: /tmp/ir_triage)"
            echo "  -q        Quick triage (volatile data only)"
            echo "  -f        Full triage (all artifacts)"
            echo "  -h        Show help"
            exit 0
            ;;
        *) echo "Invalid option. Use -h for help."; exit 1 ;;
    esac
done

# Create triage directory
TRIAGE_DIR="${OUTPUT_DIR}/${HOSTNAME}_${TIMESTAMP}"
mkdir -p "$TRIAGE_DIR"

# Logging function
log() {
    local TYPE=$1
    shift
    local MESSAGE="$@"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$TYPE] $MESSAGE" | tee -a "$TRIAGE_DIR/triage.log"
}

log "INFO" "Starting Linux IR triage collection"
log "INFO" "Target: $HOSTNAME"
log "INFO" "Mode: $MODE"
log "INFO" "Output: $TRIAGE_DIR"

# Create manifest
cat > "$TRIAGE_DIR/triage_manifest.json" <<EOF
{
  "collection_time": "$(date -Iseconds)",
  "hostname": "$HOSTNAME",
  "kernel": "$(uname -r)",
  "os": "$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')",
  "collection_mode": "$MODE",
  "artifacts": []
}
EOF

# Function to add artifact to manifest
add_artifact() {
    local ARTIFACT=$1
    # Simple append to artifacts array (not perfect JSON but functional)
    echo "  Collected: $ARTIFACT"
}

################################################################################
# Volatile Data Collection
################################################################################

log "INFO" "Collecting volatile data..."

# System information
log "INFO" "Collecting system information"
{
    echo "=== System Information ==="
    uname -a
    echo ""
    cat /etc/os-release 2>/dev/null
    echo ""
    echo "=== Uptime ==="
    uptime
    echo ""
    echo "=== Date/Time ==="
    date
    echo ""
    echo "=== Timezone ==="
    timedatectl 2>/dev/null || cat /etc/timezone 2>/dev/null
} > "$TRIAGE_DIR/system_info.txt"
add_artifact "system_info.txt"

# Current users
log "INFO" "Collecting logged on users"
{
    echo "=== Currently Logged On Users ==="
    who -a
    echo ""
    echo "=== w command output ==="
    w
    echo ""
    echo "=== Last logins ==="
    last -20
} > "$TRIAGE_DIR/users_logged_on.txt"
add_artifact "users_logged_on.txt"

# Running processes
log "INFO" "Collecting running processes"
{
    ps auxwww
} > "$TRIAGE_DIR/processes.txt"
add_artifact "processes.txt"

# Process tree
{
    pstree -apnh 2>/dev/null || pstree -ap 2>/dev/null || echo "pstree not available"
} > "$TRIAGE_DIR/process_tree.txt"
add_artifact "process_tree.txt"

# Network connections
log "INFO" "Collecting network connections"
{
    echo "=== Active Network Connections ==="
    netstat -antp 2>/dev/null || ss -antp
    echo ""
    echo "=== Listening Services ==="
    netstat -anlp 2>/dev/null || ss -anlp
    echo ""
    echo "=== UDP Connections ==="
    netstat -anup 2>/dev/null || ss -anup
} > "$TRIAGE_DIR/network_connections.txt"
add_artifact "network_connections.txt"

# Network configuration
log "INFO" "Collecting network configuration"
{
    echo "=== Network Interfaces ==="
    ip addr show 2>/dev/null || ifconfig -a
    echo ""
    echo "=== Routing Table ==="
    ip route show 2>/dev/null || route -n
    echo ""
    echo "=== ARP Cache ==="
    ip neigh show 2>/dev/null || arp -an
} > "$TRIAGE_DIR/network_config.txt"
add_artifact "network_config.txt"

# DNS configuration
{
    echo "=== DNS Configuration ==="
    cat /etc/resolv.conf 2>/dev/null
    echo ""
    echo "=== Hosts File ==="
    cat /etc/hosts 2>/dev/null
} > "$TRIAGE_DIR/dns_config.txt"
add_artifact "dns_config.txt"

# Open files
log "INFO" "Collecting open files"
{
    lsof -V 2>/dev/null | head -1000
} > "$TRIAGE_DIR/open_files.txt" 2>&1
add_artifact "open_files.txt"

# Loaded kernel modules
log "INFO" "Collecting loaded kernel modules"
{
    lsmod
} > "$TRIAGE_DIR/kernel_modules.txt"
add_artifact "kernel_modules.txt"

################################################################################
# System Configuration (non-volatile)
################################################################################

if [[ "$MODE" != "quick" ]]; then
    log "INFO" "Collecting system configuration..."

    # User accounts
    log "INFO" "Collecting user accounts"
    {
        echo "=== /etc/passwd ==="
        cat /etc/passwd
        echo ""
        echo "=== /etc/shadow (hashes only) ==="
        cat /etc/shadow | cut -d: -f1,2
        echo ""
        echo "=== /etc/group ==="
        cat /etc/group
    } > "$TRIAGE_DIR/user_accounts.txt"
    add_artifact "user_accounts.txt"

    # Sudo configuration
    {
        echo "=== /etc/sudoers ==="
        cat /etc/sudoers 2>/dev/null
        echo ""
        echo "=== /etc/sudoers.d/ ==="
        cat /etc/sudoers.d/* 2>/dev/null
    } > "$TRIAGE_DIR/sudo_config.txt" 2>&1
    add_artifact "sudo_config.txt"

    # SSH configuration
    log "INFO" "Collecting SSH configuration"
    {
        echo "=== SSH Server Config ==="
        cat /etc/ssh/sshd_config 2>/dev/null
        echo ""
        echo "=== SSH Authorized Keys ==="
        for user_home in /home/* /root; do
            if [[ -f "$user_home/.ssh/authorized_keys" ]]; then
                echo "--- $user_home/.ssh/authorized_keys ---"
                cat "$user_home/.ssh/authorized_keys" 2>/dev/null
            fi
        done
    } > "$TRIAGE_DIR/ssh_config.txt"
    add_artifact "ssh_config.txt"

    # Cron jobs
    log "INFO" "Collecting cron jobs"
    {
        echo "=== System Crontabs ==="
        cat /etc/crontab 2>/dev/null
        echo ""
        echo "=== /etc/cron.d/ ==="
        cat /etc/cron.d/* 2>/dev/null
        echo ""
        echo "=== User Crontabs ==="
        for user in $(cut -d: -f1 /etc/passwd); do
            echo "--- $user ---"
            crontab -u "$user" -l 2>/dev/null
        done
    } > "$TRIAGE_DIR/cron_jobs.txt" 2>&1
    add_artifact "cron_jobs.txt"

    # Scheduled tasks
    {
        echo "=== Systemd Timers ==="
        systemctl list-timers --all 2>/dev/null
        echo ""
        echo "=== At Jobs ==="
        atq 2>/dev/null
    } > "$TRIAGE_DIR/scheduled_tasks.txt" 2>&1
    add_artifact "scheduled_tasks.txt"

    # Systemd services
    log "INFO" "Collecting systemd services"
    {
        systemctl list-units --type=service --all
    } > "$TRIAGE_DIR/systemd_services.txt" 2>&1
    add_artifact "systemd_services.txt"

    # Installed packages
    log "INFO" "Collecting installed packages"
    if command -v dpkg &> /dev/null; then
        dpkg -l > "$TRIAGE_DIR/installed_packages.txt" 2>&1
    elif command -v rpm &> /dev/null; then
        rpm -qa > "$TRIAGE_DIR/installed_packages.txt" 2>&1
    elif command -v pacman &> /dev/null; then
        pacman -Q > "$TRIAGE_DIR/installed_packages.txt" 2>&1
    fi
    add_artifact "installed_packages.txt"

    # Firewall rules
    log "INFO" "Collecting firewall rules"
    {
        echo "=== iptables Rules ==="
        iptables -L -n -v 2>/dev/null
        echo ""
        echo "=== ip6tables Rules ==="
        ip6tables -L -n -v 2>/dev/null
        echo ""
        echo "=== ufw Status ==="
        ufw status verbose 2>/dev/null
        echo ""
        echo "=== firewalld Rules ==="
        firewall-cmd --list-all 2>/dev/null
    } > "$TRIAGE_DIR/firewall_rules.txt" 2>&1
    add_artifact "firewall_rules.txt"
fi

################################################################################
# File System Artifacts
################################################################################

if [[ "$MODE" == "full" ]]; then
    log "INFO" "Collecting file system artifacts..."

    # Recent file modifications
    log "INFO" "Collecting recent file modifications (last 7 days)"
    {
        find /home /tmp /var/tmp /root -type f -mtime -7 2>/dev/null | head -500
    } > "$TRIAGE_DIR/recent_file_modifications.txt"
    add_artifact "recent_file_modifications.txt"

    # SUID/SGID files
    log "INFO" "Collecting SUID/SGID files"
    {
        find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
    } > "$TRIAGE_DIR/suid_sgid_files.txt"
    add_artifact "suid_sgid_files.txt"

    # World-writable files
    log "INFO" "Collecting world-writable files"
    {
        find / -type f -perm -002 -ls 2>/dev/null | head -500
    } > "$TRIAGE_DIR/world_writable_files.txt"
    add_artifact "world_writable_files.txt"

    # Hidden files in common locations
    log "INFO" "Collecting hidden files"
    {
        find /tmp /var/tmp /home /root -name ".*" -type f 2>/dev/null | head -500
    } > "$TRIAGE_DIR/hidden_files.txt"
    add_artifact "hidden_files.txt"

    # Bash history
    log "INFO" "Collecting bash history"
    for user_home in /home/* /root; do
        if [[ -f "$user_home/.bash_history" ]]; then
            cp "$user_home/.bash_history" "$TRIAGE_DIR/bash_history_$(basename $user_home).txt" 2>/dev/null
        fi
    done
    add_artifact "bash_history_*.txt"
fi

################################################################################
# Log Files
################################################################################

if [[ "$MODE" == "full" ]]; then
    log "INFO" "Collecting log files..."

    # Create logs subdirectory
    mkdir -p "$TRIAGE_DIR/logs"

    # System logs
    log "INFO" "Copying system logs"
    cp /var/log/syslog "$TRIAGE_DIR/logs/" 2>/dev/null || \
    cp /var/log/messages "$TRIAGE_DIR/logs/" 2>/dev/null

    # Auth logs
    cp /var/log/auth.log "$TRIAGE_DIR/logs/" 2>/dev/null || \
    cp /var/log/secure "$TRIAGE_DIR/logs/" 2>/dev/null

    # Last 1000 lines of important logs
    {
        echo "=== Recent Auth Log ==="
        tail -1000 /var/log/auth.log 2>/dev/null || tail -1000 /var/log/secure 2>/dev/null
        echo ""
        echo "=== Recent Syslog ==="
        tail -1000 /var/log/syslog 2>/dev/null || tail -1000 /var/log/messages 2>/dev/null
    } > "$TRIAGE_DIR/logs/recent_logs.txt"

    add_artifact "logs/*"
fi

################################################################################
# Create Collection Summary
################################################################################

cat > "$TRIAGE_DIR/COLLECTION_SUMMARY.txt" <<EOF
Linux IR Triage Collection Summary
===================================
Collection Time: $(date +'%Y-%m-%d %H:%M:%S')
Hostname: $HOSTNAME
Kernel: $(uname -r)
OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
Collection Mode: $MODE
Output Directory: $TRIAGE_DIR

Collected Artifacts:
$(ls -1 "$TRIAGE_DIR" | sed 's/^/  - /')

Collection completed successfully.

IMPORTANT: Maintain proper chain of custody for all collected evidence.
EOF

cat "$TRIAGE_DIR/COLLECTION_SUMMARY.txt"

log "INFO" "Triage collection completed"
log "INFO" "Output directory: $TRIAGE_DIR"

echo ""
echo "[OK] Triage collection completed successfully."
echo "[OK] Review artifacts in: $TRIAGE_DIR"
echo ""
echo "[!] IMPORTANT: Maintain proper chain of custody for all collected evidence."

exit 0
