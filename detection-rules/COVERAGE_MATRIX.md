# MITRE ATT&CK Detection Coverage Matrix

This document provides a visual representation of detection coverage mapped to the MITRE ATT&CK framework. The defensive-toolkit provides comprehensive detection across all major attack phases.

## Coverage Summary

| Metric | Count |
|--------|-------|
| **Total Sigma Rules** | 39 |
| **Total YARA Rules** | 22 |
| **ATT&CK Tactics Covered** | 11/14 (79%) |
| **ATT&CK Techniques Covered** | 45+ |
| **2025 Threat Coverage** | Infostealers, RaaS, APT, Loaders, C2 |

## Sigma Rule Coverage by Tactic

```
                    MITRE ATT&CK Coverage Heatmap
    +------------------------------------------------------------------+
    | Tactic              | Rules | Techniques              | Coverage |
    +------------------------------------------------------------------+
    | Execution           |   6   | T1059, T1218, T1204     | [####]   |
    | Persistence         |   5   | T1547, T1053, T1546     | [####]   |
    | Privilege Escalation|   4   | T1134, T1068, T1574     | [###]    |
    | Defense Evasion     |   5   | T1562, T1055, T1070     | [####]   |
    | Credential Access   |   5   | T1003, T1558, T1555     | [####]   |
    | Discovery           |   3   | T1087, T1046, T1526     | [###]    |
    | Lateral Movement    |   4   | T1021, T1569, T1563     | [###]    |
    | Collection          |   2   | T1056, T1113            | [##]     |
    | Exfiltration        |   2   | T1048, T1567            | [##]     |
    | Command & Control   |   4   | T1071, T1095, T1568     | [###]    |
    | Impact              |   2   | T1490, T1489            | [##]     |
    +------------------------------------------------------------------+

    Legend: [#] = 1-2 rules, [##] = 2-3 rules, [###] = 3-4 rules, [####] = 5+ rules
```

## YARA Rule Coverage by Threat Type

```
    +------------------------------------------------------------------+
    | Threat Category     | Rules | Families Detected       | Severity |
    +------------------------------------------------------------------+
    | Infostealers        |   5   | LummaC2, Vidar, RedLine | Critical |
    |                     |       | StrelaStealer, Generic  |          |
    | Ransomware (2025)   |   5   | LockBit 4.0, BlackCat   | Critical |
    |                     |       | Qilin, RansomHub        |          |
    | Malware Loaders     |   5   | HijackLoader, SocGholish| High     |
    |                     |       | BatLoader, GootLoader   |          |
    | C2 Frameworks       |   6   | Cobalt Strike, Sliver   | Critical |
    |                     |       | Brute Ratel, Generic    |          |
    | Webshells           |   3   | PHP, ASPX, JSP          | High     |
    | Suspicious Scripts  |   3   | PowerShell, VBS, JS     | Medium   |
    +------------------------------------------------------------------+
```

## Detailed Technique Coverage

### Execution (TA0002)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1059.001 | PowerShell | suspicious_powershell_execution.yml | [OK] |
| T1047 | WMI | suspicious_wmi_execution.yml | [OK] |
| T1218.005 | MSHTA | mshta_execution.yml | [OK] |
| T1218.010 | Regsvr32 | regsvr32_execution.yml | [OK] |
| T1218 | LOLBAS | lolbas_execution.yml | [OK] |
| T1204.002 | Paste-and-Run | paste_and_run_attack.yml | [OK] |

### Persistence (TA0003)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1547.001 | Registry Run Keys | registry_run_keys.yml | [OK] |
| T1053 | Scheduled Task | scheduled_task_creation.yml | [OK] |
| T1546.003 | WMI Subscription | wmi_event_subscription.yml | [OK] |
| T1574.001 | DLL Hijacking | dll_search_order_hijacking.yml | [OK] |
| T1547.001 | Startup Folder | startup_folder_modification.yml | [OK] |

### Privilege Escalation (TA0004)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1134 | Token Manipulation | token_manipulation.yml | [OK] |
| T1134.001 | Named Pipe Impersonation | named_pipe_impersonation.yml | [OK] |
| T1068 | PrintNightmare | print_spooler_exploitation.yml | [OK] |

### Defense Evasion (TA0005)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1070.001 | Event Log Clearing | clear_event_logs.yml | [OK] |
| T1562.001 | AMSI Bypass | amsi_bypass.yml | [OK] |
| T1055.012 | Process Hollowing | process_hollowing.yml | [OK] |
| T1070.006 | Timestomping | timestomping.yml | [OK] |
| T1562.006 | ETW Tampering | etw_tampering.yml | [OK] |

### Credential Access (TA0006)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1003.001 | LSASS Dumping | credential_dumping_lsass.yml | [OK] |
| T1003.006 | DCSync | dcsync_attack.yml | [OK] |
| T1558.003 | Kerberoasting | kerberoasting.yml | [OK] |
| T1003.002 | SAM Dumping | sam_database_access.yml | [OK] |
| T1555.003 | Browser Credentials | browser_credential_theft.yml | [OK] |

### Discovery (TA0007)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1087.002 | AD Enumeration | ad_enumeration.yml | [OK] |
| T1046 | Network Scanning | network_scanning.yml | [OK] |
| T1526 | Cloud Discovery | cloud_discovery.yml | [OK] |

### Lateral Movement (TA0008)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1569.002 | PsExec | psexec_execution.yml | [OK] |
| T1021.006 | WinRM | winrm_lateral_movement.yml | [OK] |
| T1563.002 | RDP Hijacking | rdp_hijacking.yml | [OK] |

### Collection (TA0009)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1056.001 | Keylogging | keylogging_detection.yml | [OK] |
| T1113 | Screen Capture | screen_capture.yml | [OK] |

### Exfiltration (TA0010)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1048.003 | DNS Tunneling | dns_tunneling.yml | [OK] |
| T1567.002 | Cloud Exfiltration | cloud_exfiltration.yml | [OK] |

### Command and Control (TA0011)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1071.001 | Cobalt Strike HTTP | cobalt_strike_detection.yml | [OK] |
| T1095 | Sliver C2 | sliver_c2_detection.yml | [OK] |
| T1071.004 | DNS C2 | dns_beaconing.yml | [OK] |

### Impact (TA0040)

| Technique ID | Technique Name | Rule File | Status |
|--------------|----------------|-----------|--------|
| T1490 | Shadow Copy Deletion | shadow_copy_deletion.yml | [OK] |
| T1489 | Service Stop | service_stop.yml | [OK] |

## 2025 Threat Landscape Coverage

### Trending Threats Detected

| Threat | Type | Detection Method | Reference |
|--------|------|------------------|-----------|
| LummaC2 | Infostealer | YARA + Sigma | Red Canary 2025 Report |
| Vidar | Infostealer | YARA | IBM X-Force 2025 |
| RedLine | Infostealer | YARA | ENISA 2025 |
| StrelaStealer | Infostealer | YARA | VMRay 2025 |
| LockBit 4.0 | Ransomware | YARA + Sigma | Darktrace 2025 |
| BlackCat/ALPHV | Ransomware | YARA | CISA Advisory |
| Qilin | Ransomware | YARA | Moonstone Sleet |
| RansomHub | Ransomware | YARA | CYFIRMA 2025 |
| HijackLoader | Loader | YARA + Sigma | Red Canary 2025 |
| SocGholish | Loader | YARA | Red Canary 2025 |
| Cobalt Strike | C2 | YARA + Sigma | DFIR Report |
| Sliver | C2 | YARA + Sigma | NCSC Advisory |

### Attack Techniques Trending in 2025

| Technique | Detection | Notes |
|-----------|-----------|-------|
| Paste-and-Run | Sigma | Fake CAPTCHA attacks delivering LummaC2 |
| Identity Attacks | Sigma | 4x increase - Kerberoasting, DCSync |
| AMSI Bypass | Sigma | LockBit 4.0 uses AMSI bypass |
| Browser Credential Theft | Sigma + YARA | Infostealers targeting 84% increase |
| RaaS Operations | YARA | 46% surge in industrial targets |

## Integration Guide

### Converting to SIEM Platforms

```bash
# Splunk
sigma convert -t splunk detection-rules/sigma/**/*.yml > splunk_rules.spl

# Elastic
sigma convert -t elasticsearch detection-rules/sigma/**/*.yml > elastic_rules.json

# Azure Sentinel
sigma convert -t sentinel detection-rules/sigma/**/*.yml > sentinel_rules.kql

# QRadar
sigma convert -t qradar detection-rules/sigma/**/*.yml > qradar_rules.aql
```

### Scanning with YARA

```bash
# Scan directory with all rules
yara -r detection-rules/yara/*.yar /path/to/scan/

# Scan with specific ruleset
yara detection-rules/yara/infostealers.yar /path/to/suspicious/file

# Scan with metadata output
yara -m detection-rules/yara/ransomware_2025.yar /path/to/scan/
```

## Maintenance Schedule

| Activity | Frequency | Last Updated |
|----------|-----------|--------------|
| Rule Review | Monthly | 2025-11-26 |
| Threat Intel Update | Weekly | 2025-11-26 |
| False Positive Tuning | As needed | 2025-11-26 |
| Coverage Gap Analysis | Quarterly | 2025-11-26 |

## Contributing

To add new detection rules:

1. Map to MITRE ATT&CK technique
2. Follow rule templates in existing files
3. Include references to threat intelligence
4. Test for false positives
5. Update this coverage matrix

---

**Last Updated**: 2025-11-26
**Version**: 2.0.0
**Maintainer**: Defensive Toolkit Project
