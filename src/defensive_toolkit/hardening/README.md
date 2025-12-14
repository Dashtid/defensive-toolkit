# Security Hardening

Automated security hardening scripts for Windows and Linux systems based on industry best practices and CIS Benchmarks.

---

## Overview

This directory contains production-ready hardening scripts for both Windows and Linux operating systems. Each platform has comprehensive scripts with multiple hardening levels to balance security and functionality.

---

## Platforms

### Windows Security Hardening

**Location**: [windows-security/](windows-security/)

**Scripts**:
- 3 hardening levels (safe, balanced, maximum)
- Audit, backup, and restore capabilities
- Health checks and specific fixes
- PowerShell-based automation

**Quick Start**:
```powershell
cd hardening/windows-security
.\backup-security-settings.ps1
.\audit-security-posture.ps1
.\harden-level1-safe.ps1
```

**Documentation**: See [windows-security/README.md](windows-security/README.md)

---

### Linux Security Hardening

**Location**: [linux/](linux/)

**Distribution Support**:
- Ubuntu/Debian (harden-ubuntu.sh)
- RHEL/CentOS/Rocky/AlmaLinux (harden-rhel.sh)

**Scripts**:
- 3 hardening levels (safe, balanced, maximum)
- Audit, backup, and restore capabilities
- CIS compliance checking
- Bash-based automation

**Quick Start**:
```bash
cd hardening/linux
sudo ./backup-security-settings.sh
sudo ./audit-security-posture.sh
sudo ./harden-ubuntu.sh --level 1
```

**Documentation**: See [linux/README.md](linux/README.md)

---

## Hardening Levels

Both Windows and Linux hardening scripts provide three levels:

| Level | Name | Description | Impact | Use Case |
|-------|------|-------------|--------|----------|
| 1 | **Safe** | CIS Level 1 - Basic hardening | Minimal | Production systems, general use |
| 2 | **Balanced** | CIS Level 2 - Enhanced security | Moderate | Security-focused environments |
| 3 | **Maximum** | Maximum hardening | High | High-security environments, DMZ |

---

## Features Comparison

| Feature | Windows | Linux |
|---------|---------|-------|
| **CIS Benchmark** | ✅ CIS Windows 10/11 | ✅ CIS Ubuntu/RHEL |
| **Multiple Levels** | ✅ 3 levels | ✅ 3 levels |
| **Backup/Restore** | ✅ Yes | ✅ Yes |
| **Dry-Run Mode** | ✅ Yes | ✅ Yes |
| **Audit Script** | ✅ Yes | ✅ Yes |
| **Firewall** | ✅ Windows Firewall | ✅ UFW/firewalld |
| **Access Control** | ✅ UAC, Policies | ✅ AppArmor/SELinux |
| **File Integrity** | ⚠️ Manual | ✅ AIDE automated |
| **Intrusion Prevention** | ⚠️ Defender only | ✅ Fail2ban |
| **Auto Updates** | ✅ Windows Update | ✅ unattended-upgrades/yum-cron |

---

## Common Security Controls

Both platforms implement these CIS controls:

### Network Security
- Firewall enabled with default deny
- Unused network services disabled
- Secure network protocols only

### Access Control
- Strong password policies
- Account lockout policies
- Principle of least privilege

### System Hardening
- Disable unused features and services
- Secure system configuration
- Regular security updates

### Logging & Auditing
- Comprehensive audit logging
- Log retention policies
- Security event monitoring

### Application Security
- Latest security patches
- Secure default configurations
- Unnecessary software removed

---

## Quick Comparison

### Windows Hardening

**Strengths**:
- Group Policy automation
- BitLocker drive encryption
- Windows Defender integration
- Active Directory integration

**Best For**:
- Windows workstations
- Windows servers
- Domain environments
- Office productivity systems

### Linux Hardening

**Strengths**:
- Mandatory access control (SELinux/AppArmor)
- AIDE file integrity monitoring
- Fail2ban intrusion prevention
- OpenSCAP compliance scanning

**Best For**:
- Web servers
- Database servers
- Cloud infrastructure
- Container hosts

---

## Usage Workflows

### Initial Deployment

**Windows**:
```powershell
# 1. Audit current posture
.\windows-security\audit-security-posture.ps1

# 2. Backup current settings
.\windows-security\backup-security-settings.ps1

# 3. Apply hardening
.\windows-security\harden-level1-safe.ps1

# 4. Verify and test
.\windows-security\health-check.ps1
```

**Linux**:
```bash
# 1. Audit current posture
sudo ./linux/audit-security-posture.sh

# 2. Backup current settings
sudo ./linux/backup-security-settings.sh

# 3. Apply hardening
sudo ./linux/harden-ubuntu.sh --level 1

# 4. Check compliance
sudo ./linux/check-compliance.sh
```

### Progressive Hardening

Start with Level 1, verify functionality, then increase:

```bash
# Level 1: Safe (minimal impact)
sudo ./linux/harden-ubuntu.sh --level 1
# Test for 1-2 weeks

# Level 2: Balanced (requires SSH keys)
sudo ./linux/harden-ubuntu.sh --level 2
# Test for 1-2 weeks

# Level 3: Maximum (high security)
sudo ./linux/harden-ubuntu.sh --level 3
```

### Maintenance

Regular security maintenance:

```bash
# Monthly audit
sudo ./linux/audit-security-posture.sh

# Weekly compliance check
sudo ./linux/check-compliance.sh

# Review AIDE reports (Linux)
sudo cat /var/log/aide/aide.log

# Update AIDE database after legitimate changes
sudo aideinit
```

---

## Integration with Defensive Toolkit

These hardening scripts integrate with other toolkit components:

**Compliance Module**:
- CIS checker validates hardening effectiveness
- Policy validation against security baselines
- Drift detection for configuration changes

**Monitoring Module**:
- SIEM integration for security events
- Log forwarding configuration
- Health check dashboards

**Vulnerability Management**:
- Scanners verify hardening effectiveness
- Prioritize vulnerabilities based on hardening level
- Track remediation progress

---

## Best Practices

1. **Always Backup First**
   - Run backup scripts before any hardening
   - Verify backups are complete
   - Test restore procedure

2. **Test in Non-Production**
   - Lab/dev environment first
   - Test all critical functionality
   - Document any issues

3. **Use Dry-Run Mode**
   - Preview changes before applying
   - Verify expected modifications
   - Identify potential issues

4. **Progressive Hardening**
   - Start with Level 1
   - Verify functionality
   - Increase level gradually

5. **Document Changes**
   - Note custom modifications
   - Track exceptions
   - Maintain runbooks

6. **Regular Audits**
   - Weekly/monthly audits
   - Compliance checking
   - Drift detection

7. **Stay Updated**
   - Review CIS Benchmark updates
   - Apply security patches
   - Update scripts as needed

---

## Troubleshooting

### Common Issues

**Locked Out After Hardening**:
- Windows: Boot to Safe Mode, restore from backup
- Linux: Use console access, run restore script

**Services Not Working**:
- Check firewall rules
- Review security policies
- Consult application logs

**Performance Impact**:
- Reduce hardening level
- Disable specific controls
- Monitor resource usage

### Getting Help

1. Check platform-specific README
2. Review log files
3. Run audit scripts to identify issues
4. Consult CIS Benchmark documentation
5. Open GitHub issue with details

---

## Resources

### CIS Benchmarks
- [CIS Windows 10 Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [CIS Windows Server Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [CIS Ubuntu Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [CIS Red Hat Benchmark](https://www.cisecurity.org/benchmark/red_hat_linux)

### Tools
- [Lynis](https://cisofy.com/lynis/) - Linux security auditing
- [OpenSCAP](https://www.open-scap.org/) - SCAP compliance
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

### Documentation
- [Windows Security Hardening](windows-security/README.md)
- [Linux Security Hardening](linux/README.md)
- [Main Toolkit README](../README.md)

---

**Security hardening is an ongoing process. Regular auditing and updates are essential for maintaining a strong security posture.**
