# Ransomware Incident Response Playbook

**Severity**: CRITICAL
**MITRE ATT&CK**: T1486 - Data Encrypted for Impact
**Last Updated**: 2025-10-15

## Overview

This playbook provides step-by-step procedures for responding to ransomware incidents, from initial detection through recovery.

## Incident Phases

### Phase 1: Detection and Initial Response (0-15 minutes)

#### Indicators of Ransomware

- [!] Mass file encryption across multiple systems
- [!] File extensions changed to random/unknown extensions
- [!] Ransom notes appearing on desktops or in directories
- [!] Unusual disk I/O activity
- [!] Disabled security tools or backup solutions
- [!] Shadow copy deletion (vssadmin delete shadows)

#### Immediate Actions

**Priority 1 - Contain the Threat:**

1. **Isolate Affected Systems**
   ```bash
   # Disconnect from network immediately
   # DO NOT shut down - evidence may be lost
   - Disable network adapters (unplug Ethernet, disable WiFi)
   - Document system state before any changes
   - Take photos/screenshots of ransom notes
   ```

2. **Identify Patient Zero**
   - Check SIEM for first encryption events
   - Review authentication logs for initial access
   - Identify potential infection vector

3. **Alert Stakeholders**
   - Notify incident response team
   - Alert management/executives
   - Contact legal counsel
   - Engage cyber insurance provider

**Priority 2 - Prevent Spread:**

4. **Network Segmentation**
   ```bash
   # At firewall/switch level
   - Block lateral movement from affected segments
   - Isolate critical systems and backups
   - Monitor for additional encryption activity
   ```

5. **Disable Compromised Accounts**
   ```powershell
   # Disable user account
   Disable-ADAccount -Identity username

   # Reset passwords for affected accounts
   Set-ADAccountPassword -Identity username -Reset
   ```

6. **Protect Backups**
   - Verify backup integrity
   - Isolate backup systems from network
   - Ensure offline/immutable backups are safe

### Phase 2: Investigation and Analysis (15 minutes - 2 hours)

#### Evidence Collection

1. **Memory Dump (Before System Reboot)**
   ```powershell
   # Using DumpIt or similar tool
   .\DumpIt.exe /O memory_dump.raw

   # Analyze memory dump for malware
   python forensics\memory\hunt-malware.py memory_dump.raw --output analysis\memory
   ```

2. **Collect System Artifacts**
   ```powershell
   # Run triage script
   .\incident-response\scripts\windows-triage.ps1 -OutputDir C:\IR\evidence

   # Collect registry artifacts
   .\forensics\artifacts\registry\extract-registry-artifacts.ps1 -OutputDir C:\IR\evidence\registry

   # Hunt for persistence mechanisms
   .\forensics\artifacts\persistence\hunt-persistence.ps1 -OutputDir C:\IR\evidence\persistence

   # Extract browser history (if relevant)
   python forensics\artifacts\browser\extract-browser-history.py --user-profile C:\Users\target_user --output C:\IR\evidence\browser

   # Collect:
   - Event logs (System, Security, Application)
   - Prefetch files
   - Registry hives
   - File system timeline
   - Network connections
   ```

3. **Identify Ransomware Variant**
   ```bash
   # Analyze ransom note
   - Note payment amount and cryptocurrency address
   - Check file extensions used
   - Search ID Ransomware (https://id-ransomware.malwarehunterteam.com/)

   # Sample encrypted file
   - Upload sample to VirusTotal (after isolating)
   - Check for decryption tools availability
   ```

#### Root Cause Analysis

4. **Determine Initial Access Vector**
   - Review email logs for phishing attempts
   - Check VPN/RDP logs for suspicious logins
   - Examine web proxy logs for drive-by downloads
   - Review vulnerability scan results

5. **Timeline Development**
   ```bash
   # Generate comprehensive timeline
   python forensics\timeline\generate-timeline.py --source C:\IR\evidence --output timeline.csv

   # Analyze timeline for suspicious patterns
   python forensics\timeline\analyze-timeline.py --timeline timeline.csv --output analysis\timeline --detect-anomalies

   # Establish timeline:
   - Initial compromise time
   - Lateral movement activities
   - Privilege escalation events
   - Encryption start time
   - Detection time
   ```

6. **Scope Assessment**
   - Number of affected systems
   - Types of data encrypted
   - Critical systems impacted
   - Data exfiltration indicators

### Phase 3: Containment and Eradication (2-8 hours)

#### Full Containment

1. **Complete Network Isolation**
   - Segment affected network zones
   - Block command-and-control (C2) communications
   - Monitor for additional infections

2. **Hunt for Persistence Mechanisms**
   ```powershell
   # Check scheduled tasks
   Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"}

   # Check registry run keys
   Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

   # Check services
   Get-Service | Where-Object {$_.DisplayName -notlike "*Microsoft*"}
   ```

3. **Remove Malware Components**
   ```powershell
   # Terminate malicious processes
   Stop-Process -Name malware_process -Force

   # Remove persistence
   Unregister-ScheduledTask -TaskName malicious_task

   # Clean registry entries
   Remove-ItemProperty -Path "HKLM:\Software\BadActor\*"
   ```

#### Credential Reset

4. **Password Resets**
   ```powershell
   # Reset all potentially compromised accounts
   # Force password change at next logon
   Get-ADUser -Filter * | Set-ADUser -ChangePasswordAtLogon $true

   # Reset service accounts
   # Update application configurations
   ```

5. **Revoke Active Sessions**
   ```powershell
   # Kill active sessions
   query user
   logoff <session_id>
   ```

### Phase 4: Recovery (8 hours - several days)

#### Decision: Pay Ransom or Restore?

**DO NOT PAY RANSOM IF:**
- ✓ Clean, verified backups are available
- ✓ Decryption tools exist for the variant
- ✓ Legal/compliance prohibits payment

**CONSIDER (WITH CAUTION) IF:**
- ✗ No backups available
- ✗ Critical systems with irreplaceable data
- ✗ Business continuity at severe risk
- ✗ Legal counsel and management approve

**WARNING**: Paying ransom does not guarantee:
- Decryption key will work
- All files will be recovered
- Attackers won't strike again
- Attackers won't sell your data

#### Recovery from Backup

1. **Verify Backup Integrity**
   ```bash
   # Test backup restoration in isolated environment
   # Verify files are not encrypted
   # Check backup timestamps pre-incident
   ```

2. **Clean System Rebuild**
   ```powershell
   # Recommended: Rebuild from gold images
   # Install OS from known-good media
   # Apply security patches
   # Reinstall applications
   # Restore data from backups
   ```

3. **Restore Data**
   ```bash
   # Restore from backup in order of priority:
   1. Critical business systems
   2. Database servers
   3. File servers
   4. User workstations
   5. Non-critical systems
   ```

4. **Validation**
   - Test application functionality
   - Verify data integrity
   - Check for residual malware
   - Run full antivirus scans

### Phase 5: Post-Incident Activities (Ongoing)

#### Lessons Learned

1. **Conduct Post-Incident Review**
   - What worked well?
   - What could be improved?
   - Were response times adequate?
   - Was communication effective?

2. **Update Documentation**
   - Update this playbook with lessons learned
   - Document new TTPs observed
   - Share IOCs with community

#### Security Improvements

3. **Implement Security Enhancements**
   - Deploy EDR if not present
   - Enable email filtering improvements
   - Implement application whitelisting
   - Deploy network segmentation
   - Enable MFA on all accounts
   - Implement privileged access management

4. **Backup Strategy Review**
   - Test backup restoration regularly
   - Implement 3-2-1 backup rule
   - Ensure offline/immutable backups
   - Verify backup monitoring

5. **User Awareness Training**
   - Conduct phishing awareness training
   - Security hygiene best practices
   - Incident reporting procedures

#### Compliance and Reporting

6. **Regulatory Notification**
   - GDPR: 72 hours for personal data breaches
   - HIPAA: 60 days for healthcare data
   - State breach notification laws
   - Industry-specific requirements

7. **Document Everything**
   - Detailed incident timeline
   - Actions taken and by whom
   - Evidence collected and chain of custody
   - Financial impact assessment
   - Recovery costs

## Communication Templates

### Initial Alert (Critical Systems)

```
SUBJECT: CRITICAL - Ransomware Incident Detected

SEVERITY: CRITICAL
TIME DETECTED: [TIMESTAMP]
SYSTEMS AFFECTED: [LIST]

IMMEDIATE ACTIONS REQUIRED:
- All users disconnect from network
- Do not shut down systems
- Do not access shared drives
- Contact IR team at [CONTACT]

STATUS: Active incident response in progress
UPDATES: Every 30 minutes
```

### Management Briefing Template

```
INCIDENT: Ransomware Attack
DETECTION TIME: [TIME]
CURRENT STATUS: [Containment/Eradication/Recovery]

IMPACT:
- Systems affected: [NUMBER]
- Business operations: [STATUS]
- Data loss: [ASSESSMENT]
- Estimated recovery time: [ETA]

ACTIONS TAKEN:
1. [Action 1]
2. [Action 2]

NEXT STEPS:
1. [Next step 1]
2. [Next step 2]

RESOURCES NEEDED:
- [Resource 1]
- [Resource 2]
```

## Tools and Resources

### Detection Tools
- YARA rules: `detection-rules/yara/ransomware.yar`
- Sigma rules: `detection-rules/sigma/impact/`
- ID Ransomware: https://id-ransomware.malwarehunterteam.com/

### Triage Scripts
- Windows: `incident-response/scripts/windows-triage.ps1`
- Linux: `incident-response/scripts/linux-triage.sh`

### Forensics Tools
- Memory analysis: `forensics/memory/volatility-auto-analyze.py`, `forensics/memory/hunt-malware.py`
- Disk analysis: `forensics/disk/extract-mft.py`, `forensics/disk/carve-files.py`
- Artifact collection: `forensics/artifacts/registry/`, `forensics/artifacts/browser/`, `forensics/artifacts/persistence/`
- Timeline: `forensics/timeline/generate-timeline.py`, `forensics/timeline/analyze-timeline.py`

### Decryption Resources
- No More Ransom: https://www.nomoreransom.org/
- Emsisoft Decryptors: https://www.emsisoft.com/ransomware-decryption-tools/

## Checklist

### Initial Response
- [ ] Isolate affected systems
- [ ] Alert incident response team
- [ ] Protect backups
- [ ] Take photos of ransom notes
- [ ] Disable compromised accounts

### Investigation
- [ ] Collect memory dumps
- [ ] Gather system artifacts
- [ ] Identify ransomware variant
- [ ] Determine initial access vector
- [ ] Assess scope of impact

### Containment
- [ ] Complete network segmentation
- [ ] Hunt for persistence mechanisms
- [ ] Remove malware components
- [ ] Reset credentials
- [ ] Revoke active sessions

### Recovery
- [ ] Verify backup integrity
- [ ] Rebuild systems from clean images
- [ ] Restore data from backups
- [ ] Validate restored systems
- [ ] Resume business operations

### Post-Incident
- [ ] Conduct lessons learned session
- [ ] Update security controls
- [ ] Test backup procedures
- [ ] Provide user training
- [ ] Complete regulatory notifications
- [ ] Document incident fully

---

**REMEMBER: Time is critical in ransomware incidents. Act decisively but carefully.**

**DO NOT:**
- Pay ransom without executive approval and legal counsel
- Shut down systems (evidence loss)
- Access encrypted files (spread infection)
- Delete ransom notes (needed for identification)

**DO:**
- Isolate immediately
- Preserve evidence
- Follow chain of custody
- Document everything
- Communicate clearly
