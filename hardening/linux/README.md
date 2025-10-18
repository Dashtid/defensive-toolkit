# Linux Security Hardening

Automated security hardening scripts for Ubuntu/Debian and RHEL/CentOS systems based on CIS Benchmarks.

---

## Overview

This directory contains production-ready bash scripts for hardening Linux systems according to industry best practices and CIS Benchmarks. The scripts provide three levels of hardening to balance security and functionality.

### Key Features

- **CIS Benchmark Aligned**: Based on CIS Benchmark for Ubuntu Linux and Red Hat Enterprise Linux
- **Three Hardening Levels**: Safe, Balanced, Maximum security configurations
- **Multi-Distribution**: Supports Ubuntu/Debian and RHEL/CentOS/Rocky/AlmaLinux
- **Backup & Restore**: Automatic backup before changes with restore capability
- **Dry-Run Mode**: Test changes before applying them
- **Compliance Checking**: Automated security posture auditing

### Hardening Levels

| Level | Name | Description | Use Case |
|-------|------|-------------|----------|
| 1 | Safe | CIS Level 1 - Minimal impact | Production servers, general use |
| 2 | Balanced | CIS Level 2 - Enhanced security | Security-focused environments |
| 3 | Maximum | Maximum hardening | High-security environments, DMZ |

---

## Quick Start

### Ubuntu/Debian

```bash
# 1. Backup current configuration
sudo ./backup-security-settings.sh

# 2. Run hardening (Level 1 - Safe)
sudo ./harden-ubuntu.sh --level 1

# 3. Audit security posture
sudo ./audit-security-posture.sh
```

### RHEL/CentOS

```bash
# 1. Backup current configuration
sudo ./backup-security-settings.sh

# 2. Run hardening (Level 1 - Safe)
sudo ./harden-rhel.sh --level 1

# 3. Audit security posture
sudo ./audit-security-posture.sh
```

---

## Scripts

### harden-ubuntu.sh

Comprehensive hardening for Ubuntu/Debian systems.

**Usage**:
```bash
sudo ./harden-ubuntu.sh [OPTIONS]

Options:
  --level N      Hardening level (1=safe, 2=balanced, 3=maximum)
  --dry-run      Show what would be done without making changes
  --no-backup    Skip backing up current configuration
  --help         Show help message
```

**What it hardens**:
- SSH configuration (disable root login, strong ciphers)
- UFW firewall (default deny, rate limiting)
- Kernel parameters (sysctl hardening)
- Automatic security updates (unattended-upgrades)
- Password policies (PAM, pwquality)
- AIDE file integrity monitoring
- Fail2ban intrusion prevention
- AppArmor mandatory access control
- Disable unused filesystems and services

**Examples**:
```bash
# Dry-run to see changes
sudo ./harden-ubuntu.sh --level 1 --dry-run

# Apply Level 1 hardening
sudo ./harden-ubuntu.sh --level 1

# Apply Level 2 hardening (requires SSH keys, no password auth)
sudo ./harden-ubuntu.sh --level 2

# Maximum hardening
sudo ./harden-ubuntu.sh --level 3
```

---

### harden-rhel.sh

Comprehensive hardening for RHEL/CentOS/Rocky/AlmaLinux systems.

**Usage**:
```bash
sudo ./harden-rhel.sh [OPTIONS]

Options:
  --level N      Hardening level (1=safe, 2=balanced, 3=maximum)
  --dry-run      Show what would be done without making changes
  --no-backup    Skip backing up current configuration
  --help         Show help message
```

**What it hardens**:
- SSH configuration
- Firewalld (replaces UFW)
- Kernel parameters (sysctl)
- Automatic updates (yum-cron)
- SELinux (replaces AppArmor) - enforcing mode
- AIDE file integrity monitoring
- Fail2ban intrusion prevention
- Disable unused services

**Examples**:
```bash
# Apply Level 1 hardening
sudo ./harden-rhel.sh --level 1

# Level 2 with dry-run
sudo ./harden-rhel.sh --level 2 --dry-run
```

---

### audit-security-posture.sh

Audits current security configuration and generates compliance report.

**Usage**:
```bash
sudo ./audit-security-posture.sh [--output text|json|html]
```

**Checks performed**:
- SSH configuration compliance
- Firewall status and rules
- Kernel security parameters
- AIDE installation and database
- Automatic updates configuration
- Mandatory access control (AppArmor/SELinux)

**Output**:
```
======================================================================
  Security Posture Audit
======================================================================

=== SSH Configuration ===
[OK] SSH: PermitRootLogin disabled
[OK] SSH: Protocol 2 only
[OK] SSH: X11Forwarding disabled

=== Firewall Configuration ===
[OK] UFW: Firewall active

...

======================================================================
  Audit Summary
======================================================================
Total Checks: 15
Passed: 13
Failed: 2
Score: 87%

[OK] Good security posture
======================================================================
```

---

### backup-security-settings.sh

Creates timestamped backup of critical security configuration.

**Usage**:
```bash
sudo ./backup-security-settings.sh
```

**What is backed up**:
- SSH configuration (`/etc/ssh/sshd_config`)
- Kernel parameters (`/etc/sysctl.conf`, `/etc/sysctl.d/`)
- PAM configuration (`/etc/pam.d/`)
- Firewall rules (UFW or firewalld)
- Login policies (`/etc/login.defs`)

**Backup location**: `/var/backups/security-hardening/YYYYMMDD_HHMMSS/`

---

### restore-security-settings.sh

Restores configuration from a previous backup.

**Usage**:
```bash
# List available backups
sudo ./restore-security-settings.sh

# Restore specific backup
sudo ./restore-security-settings.sh 20251018_140530
```

**Safety**:
- Prompts for confirmation before restoring
- Shows backup location and timestamp
- Requires manual service restarts

---

### check-compliance.sh

Automated CIS compliance checking.

**Usage**:
```bash
sudo ./check-compliance.sh
```

**Features**:
- Integrates with Lynis (if installed)
- Provides OpenSCAP usage instructions
- Runs basic compliance audit

**Installing Lynis** (recommended):
```bash
# Ubuntu/Debian
sudo apt-get install lynis

# RHEL/CentOS
sudo yum install lynis

# Manual installation
git clone https://github.com/CISOfy/lynis
cd lynis && sudo ./lynis audit system
```

---

## Hardening Details

### SSH Hardening (All Levels)

**Level 1**:
- Disable root login
- Protocol 2 only
- Max auth tries: 3
- Disable X11 forwarding
- Client alive interval: 300 seconds
- Password authentication: YES (still allowed)

**Level 2**:
- All Level 1 settings
- **Password authentication: NO** (keys only)
- Strong ciphers only (ChaCha20, AES-GCM)
- Strong MACs (SHA2-512, SHA2-256)
- Modern key exchange algorithms

**Level 3**:
- All Level 2 settings
- Reduced max sessions
- Additional restrictions

---

### Firewall Configuration

**Ubuntu/Debian (UFW)**:
```bash
# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow 22/tcp

# Level 2+: Rate limiting
ufw limit 22/tcp
```

**RHEL/CentOS (firewalld)**:
```bash
# Default zone: drop
firewall-cmd --set-default-zone=drop

# Allow SSH only
firewall-cmd --permanent --zone=drop --add-service=ssh
```

---

### Kernel Hardening (sysctl)

Key parameters hardened:
```bash
# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0

# Enable SYN cookies (DDoS protection)
net.ipv4.tcp_syncookies = 1

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1

# Randomize address space (ASLR)
kernel.randomize_va_space = 2

# Restrict core dumps
fs.suid_dumpable = 0
```

---

### Password Policies

**Level 1**:
- Minimum length: 14 characters
- Minimum days between changes: 7
- Maximum days before change required: 90
- Warning days before expiration: 7
- Remember last 5 passwords

**Level 2**:
- Minimum length: 16 characters
- Maximum days: 60
- Remember last 10 passwords
- Complexity requirements enforced

---

### AIDE (File Integrity Monitoring)

**Configuration**:
- Monitors critical system files and directories
- Daily automated checks via cron
- Email alerts for changes

**Monitored locations**:
- `/boot`, `/bin`, `/sbin`, `/lib`, `/lib64`
- `/etc` (configuration files)
- `/usr/bin`, `/usr/sbin`, `/usr/lib`
- Critical files: `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`

**Manual AIDE operations**:
```bash
# Update database after legitimate changes
sudo aideinit

# Manual check
sudo aide --check

# View report
sudo cat /var/log/aide/aide.log
```

---

### Fail2ban (Intrusion Prevention)

**Default configuration**:
- Ban time: 1 hour (3600 seconds)
- Find time: 10 minutes (600 seconds)
- Max retry: 3 attempts

**Level 2** increases security:
- Ban time: 2 hours
- Max retry: 2 attempts

**Check Fail2ban status**:
```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

---

## Post-Hardening Steps

### 1. Test SSH Access

**CRITICAL**: Test SSH access before logging out!

```bash
# Open a new SSH session in a different terminal
ssh user@server

# If successful, proceed
# If failed, restore from backup using existing session
```

### 2. Verify Services

```bash
# Check SSH
sudo systemctl status sshd

# Check firewall
sudo ufw status verbose    # Ubuntu
sudo firewall-cmd --list-all    # RHEL

# Check AppArmor/SELinux
sudo aa-status    # Ubuntu
sudo getenforce   # RHEL
```

### 3. Review Logs

```bash
# Hardening log
sudo cat /var/log/security-hardening.log

# System logs
sudo journalctl -xe
sudo tail -f /var/log/syslog    # Ubuntu
sudo tail -f /var/log/messages  # RHEL
```

### 4. Monitor AIDE

```bash
# Check AIDE reports daily
sudo cat /var/log/aide/aide.log

# Update AIDE database after legitimate changes
sudo aideinit
```

---

## Rollback Procedure

If hardening causes issues:

### Option 1: Restore from Backup

```bash
# List backups
sudo ./restore-security-settings.sh

# Restore specific backup
sudo ./restore-security-settings.sh 20251018_140530

# Restart services
sudo systemctl restart sshd
sudo systemctl restart ufw  # or firewalld
```

### Option 2: Manual Rollback

```bash
# SSH
sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
sudo systemctl restart sshd

# Firewall
sudo ufw disable    # Ubuntu
sudo systemctl stop firewalld    # RHEL

# Kernel parameters
sudo sysctl -p /etc/sysctl.conf
```

---

## Integration with Other Tools

### OpenSCAP (SCAP Compliance)

For enterprise SCAP-compliant auditing:

**Ubuntu**:
```bash
sudo apt-get install libopenscap8 scap-security-guide

oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results results.xml \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```

**RHEL**:
```bash
sudo yum install openscap-scanner scap-security-guide

oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results results.xml \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
```

### Lynis Security Auditing

```bash
# Install Lynis
sudo apt-get install lynis    # Ubuntu
sudo yum install lynis         # RHEL

# Run comprehensive audit
sudo lynis audit system

# View report
sudo cat /var/log/lynis.log
```

---

## Troubleshooting

### SSH Connection Refused After Hardening

**Problem**: Cannot connect via SSH after hardening

**Solutions**:
1. Check if SSH service is running: `sudo systemctl status sshd`
2. Verify firewall allows SSH: `sudo ufw status` or `sudo firewall-cmd --list-all`
3. Check SSH config syntax: `sudo sshd -t`
4. Restore from backup if necessary

### Password Authentication Disabled (Level 2+)

**Problem**: Cannot login with password after Level 2 hardening

**Solution**: Level 2+ requires SSH key authentication

```bash
# On your local machine, generate SSH key
ssh-keygen -t ed25519

# Copy to server (before hardening)
ssh-copy-id user@server

# Test key-based auth
ssh user@server
```

### Services Not Starting After Hardening

**Problem**: Critical services fail to start

**Solutions**:
1. Check SELinux/AppArmor is not blocking: `sudo aa-status` or `getenforce`
2. Review kernel parameters: `sudo sysctl -a | grep <parameter>`
3. Check service logs: `sudo journalctl -u <service>`

### AIDE Database Initialization Takes Forever

**Problem**: `aideinit` runs for hours

**Solution**: This is normal for large filesystems. Run in background:

```bash
sudo nohup aideinit &
# Check progress
sudo tail -f /var/log/aide/aide.log
```

---

## Best Practices

1. **Always Backup First**: Run `backup-security-settings.sh` before hardening
2. **Test in Lab**: Test hardening scripts on non-production systems first
3. **Use Dry-Run**: Always use `--dry-run` to preview changes
4. **Start with Level 1**: Begin with Level 1, verify functionality, then increase
5. **Monitor Logs**: Review `/var/log/security-hardening.log` after hardening
6. **Keep Sessions Open**: Don't close existing SSH sessions until new ones work
7. **Document Changes**: Note any custom modifications for future reference
8. **Regular Audits**: Run `audit-security-posture.sh` weekly

---

## CIS Benchmark Mapping

| CIS Control | Description | Script Coverage |
|-------------|-------------|-----------------|
| 1.1.x | Filesystem Configuration | Disable unused filesystems |
| 1.3.x | Filesystem Integrity Checking | AIDE configuration |
| 1.6.x | Mandatory Access Control | AppArmor/SELinux |
| 1.8.x | Software Updates | Automatic updates |
| 3.x | Network Configuration | Kernel parameters, firewall |
| 4.x | Logging and Auditing | rsyslog, auditd |
| 5.2.x | SSH Server Configuration | SSH hardening |
| 5.4.x | User Accounts and Environment | Password policies, PAM |

---

## Additional Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Ubuntu Security Guide](https://ubuntu.com/security/certifications/docs/usg)
- [RHEL Security Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/)
- [OpenSCAP](https://www.open-scap.org/)
- [Lynis](https://cisofy.com/lynis/)

---

**Security is a journey, not a destination. Regularly audit and update your hardening configuration!**
