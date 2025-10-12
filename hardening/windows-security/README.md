# Windows Security Hardening Scripts

Security hardening scripts for Windows systems based on industry best practices and security benchmarks.

## Overview

This directory contains PowerShell scripts to harden Windows systems at various security levels, audit security posture, and manage security configurations.

## Scripts

### Hardening Levels

**harden-level1-safe.ps1** - Safe hardening (minimal disruption)
- Basic security improvements
- Safe for most environments
- Minimal impact on functionality
- Recommended for all systems

**harden-level2-balanced.ps1** - Balanced hardening (moderate security)
- Enhanced security controls
- Some functionality trade-offs
- Suitable for business workstations
- May require testing before deployment

**harden-level3-maximum.ps1** - Maximum hardening (high security)
- Aggressive security controls
- Significant functionality restrictions
- For high-security environments only
- Extensive testing required

### Security Management

**audit-security-posture.ps1** - Audit current security settings
- Comprehensive security assessment
- Compliance checking
- Generates detailed reports
- Identifies security gaps

**backup-security-settings.ps1** - Backup security configuration
- Backs up registry settings
- Saves Group Policy settings
- Creates restore points
- Exports firewall rules

**restore-security-settings.ps1** - Restore from backup
- Restores previous security state
- Rollback hardening changes
- Recovers from misconfigurations

**complete-system-setup.ps1** - Complete security setup
- Applies recommended hardening
- Configures security features
- Sets up monitoring
- End-to-end security configuration

### Specific Fixes

**fix-netbios.ps1** - NetBIOS security hardening
- Disables NetBIOS over TCP/IP
- Reduces attack surface
- Prevents NetBIOS-based attacks

**system-health-check.ps1** - System health and security check
- Monitors system security
- Checks for vulnerabilities
- Validates security controls
- Generates health reports

## Usage

### Before Running

1. **Backup your system**
   ```powershell
   .\backup-security-settings.ps1
   ```

2. **Audit current state**
   ```powershell
   .\audit-security-posture.ps1
   ```

### Apply Hardening

**Level 1 (Recommended for most systems):**
```powershell
.\harden-level1-safe.ps1
```

**Level 2 (Business workstations):**
```powershell
.\harden-level2-balanced.ps1
```

**Level 3 (High security environments):**
```powershell
.\harden-level3-maximum.ps1
```

### Rollback if Needed

```powershell
.\restore-security-settings.ps1
```

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+ (PowerShell 7+ recommended)
- Administrator privileges
- System backup recommended

## Security Areas Covered

- User Account Control (UAC)
- Windows Defender configuration
- Firewall rules and profiles
- BitLocker encryption
- Security policies
- Registry hardening
- Service hardening
- Network security
- SMB hardening
- NetBIOS security
- PowerShell security
- Audit logging

## Testing Recommendations

1. **Test in non-production environment first**
2. **Review script contents before execution**
3. **Create system restore point**
4. **Document baseline configuration**
5. **Test application compatibility**
6. **Verify business functionality**

## Compliance Frameworks

Scripts align with:
- CIS Microsoft Windows Benchmarks
- DISA STIGs
- NIST Cybersecurity Framework
- Microsoft Security Baselines

## Monitoring

After hardening, monitor:
- Event Viewer (Security logs)
- Windows Defender logs
- Firewall logs
- Application functionality
- User reported issues

## Troubleshooting

If issues occur after hardening:
1. Check Event Viewer for errors
2. Review changed settings in audit report
3. Restore from backup if needed
4. Apply lower security level
5. Whitelist affected applications

## Support

For issues or questions:
- Review script comments and documentation
- Check logs in `backups/` directory
- Open GitHub issue with details
- Include audit report output

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Microsoft Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [DISA STIGs](https://public.cyber.mil/stigs/)

---

**Always test security hardening in non-production environments first!**
