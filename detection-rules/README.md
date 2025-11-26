# Detection Rules

Enterprise-grade detection rules covering the complete MITRE ATT&CK framework for threat detection, incident response, and security monitoring.

## Quick Stats

| Metric | Count |
|--------|-------|
| Sigma Rules | 39 |
| YARA Rules | 22 |
| ATT&CK Tactics Covered | 11/14 (79%) |
| ATT&CK Techniques | 45+ |
| 2025 Threat Coverage | Infostealers, RaaS, APT, Loaders, C2 |

## 2025 Threat Landscape Coverage

This ruleset is designed to detect the most prevalent threats identified in 2025 threat intelligence reports:

| Threat Category | Detection Method | Examples |
|-----------------|------------------|----------|
| **Infostealers** (+84% in 2025) | Sigma + YARA | LummaC2, Vidar, RedLine, StrelaStealer |
| **RaaS Operations** (+46%) | Sigma + YARA | LockBit 4.0, BlackCat, Qilin, RansomHub |
| **Identity Attacks** (4x increase) | Sigma | DCSync, Kerberoasting, Credential Theft |
| **Paste-and-Run** (emerging) | Sigma | Fake CAPTCHA, HijackLoader delivery |
| **C2 Frameworks** | Sigma + YARA | Cobalt Strike, Sliver, Brute Ratel |

**Sources**: [Red Canary 2025](https://redcanary.com/blog/threat-detection/2025-threat-detection-report/), [IBM X-Force 2025](https://www.ibm.com/thought-leadership/institute-business-value/en-us/report/2025-threat-intelligence-index), [Darktrace 2025](https://www.darktrace.com/blog/2025-cyber-threat-landscape-darktraces-mid-year-review)

## Directory Structure

```text
detection-rules/
├── sigma/                        # 39 Sigma rules (MITRE ATT&CK organized)
│   ├── execution/               # MSHTA, Regsvr32, LOLBAS, Paste-and-Run
│   ├── persistence/             # WMI subscriptions, DLL hijacking, Startup
│   ├── privilege-escalation/    # Token manipulation, PrintNightmare
│   ├── defense-evasion/         # AMSI bypass, Process hollowing, ETW
│   ├── credential-access/       # DCSync, Kerberoasting, Browser theft
│   ├── discovery/               # AD enumeration, Network scan, Cloud
│   ├── lateral-movement/        # PsExec, WinRM, RDP hijacking
│   ├── collection/              # Keylogging, Screen capture
│   ├── exfiltration/            # DNS tunneling, Cloud exfil
│   ├── command-and-control/     # Cobalt Strike, Sliver, DNS C2
│   └── impact/                  # Shadow copy deletion, Service stop
├── yara/                        # 22 YARA rules
│   ├── infostealers.yar        # LummaC2, Vidar, RedLine, StrelaStealer
│   ├── ransomware.yar          # Generic ransomware patterns
│   ├── ransomware_2025.yar     # LockBit 4.0, BlackCat, Qilin, RansomHub
│   ├── loaders.yar             # HijackLoader, SocGholish, BatLoader
│   ├── c2_frameworks.yar       # Cobalt Strike, Sliver, Brute Ratel
│   ├── webshells.yar           # PHP, ASPX, JSP webshells
│   └── suspicious_scripts.yar  # Obfuscated PowerShell, VBS, JS
├── COVERAGE_MATRIX.md          # Full MITRE ATT&CK coverage map
└── README.md                   # This file
```

## MITRE ATT&CK Coverage

```text
Tactic                  | Rules | Key Techniques
------------------------|-------|------------------------------------
Execution               |   6   | T1059, T1218, T1204
Persistence             |   5   | T1547, T1053, T1546, T1574
Privilege Escalation    |   4   | T1134, T1068
Defense Evasion         |   5   | T1562, T1055, T1070
Credential Access       |   5   | T1003, T1558, T1555
Discovery               |   3   | T1087, T1046, T1526
Lateral Movement        |   4   | T1021, T1569, T1563
Collection              |   2   | T1056, T1113
Exfiltration            |   2   | T1048, T1567
Command & Control       |   4   | T1071, T1095, T1568
Impact                  |   2   | T1490, T1489
```

See [COVERAGE_MATRIX.md](COVERAGE_MATRIX.md) for detailed technique-level coverage.

## Quick Start

### Sigma Rules

```bash
# Install Sigma CLI
pip install sigma-cli pyyaml

# Convert to Splunk
sigma convert -t splunk detection-rules/sigma/execution/*.yml

# Convert to Elastic
sigma convert -t elasticsearch detection-rules/sigma/**/*.yml

# Convert to Azure Sentinel
sigma convert -t sentinel detection-rules/sigma/**/*.yml

# Batch convert all rules
for tactic in execution persistence privilege-escalation defense-evasion credential-access discovery lateral-movement collection exfiltration command-and-control impact; do
    sigma convert -t splunk detection-rules/sigma/$tactic/*.yml >> splunk_rules.spl
done
```

### YARA Rules

```bash
# Install YARA
# Linux: sudo apt-get install yara
# macOS: brew install yara
# Windows: choco install yara

# Scan for infostealers
yara detection-rules/yara/infostealers.yar /path/to/scan/

# Scan for 2025 ransomware families
yara detection-rules/yara/ransomware_2025.yar /path/to/suspicious/

# Scan for C2 implants
yara detection-rules/yara/c2_frameworks.yar /path/to/scan/

# Full threat scan with all rules
yara -r detection-rules/yara/*.yar /path/to/scan/
```

### Validation

```bash
# Validate all detection rules
python scripts/validate_detection_rules.py

# Run unit tests
pytest tests/unit/test_detection_rules/ -v

# Export validation report
python scripts/validate_detection_rules.py --json validation_report.json
```

## Rule Highlights

### Sigma: Paste-and-Run Attack Detection

```yaml
title: Paste and Run Attack - Fake CAPTCHA Technique
description: |
    Detects the "Paste and Run" attack technique where users are tricked
    by fake CAPTCHA pages to execute malicious commands. Delivers LummaC2,
    HijackLoader, and other malware. Top threat in 2025 reports.
tags:
    - attack.execution
    - attack.t1204.002
    - threat.lummac2
    - threat.hijackloader
```

### YARA: LummaC2 Infostealer

```yara
rule LummaC2_Stealer
{
    meta:
        description = "Detects LummaC2 infostealer - top threat in 2025"
        severity = "critical"
        mitre_attack = "T1555, T1539, T1552"

    strings:
        $browser1 = "\\Google\\Chrome\\User Data\\Default\\Login Data"
        $wallet1 = "\\Exodus\\exodus.wallet"
        // ... additional patterns

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        (2 of ($browser*) and 2 of ($wallet*))
}
```

### Sigma: DCSync Attack Detection

```yaml
title: DCSync Attack Detection
description: |
    Detects DCSync attacks where attackers use replication privileges
    to request password hashes from Active Directory. Used by APT groups
    and ransomware operators.
tags:
    - attack.credential_access
    - attack.t1003.006
level: critical
```

## Integration Examples

### Splunk

```spl
# Import converted Sigma rule
index=windows sourcetype=WinEventLog:Security EventCode=4662
| search Properties IN ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
| where NOT match(SubjectUserName, ".*\$$")
| table _time, SubjectUserName, ObjectName
```

### Elastic SIEM

```json
{
  "rule": {
    "name": "Potential DCSync Attack",
    "query": "event.code:4662 AND winlog.event_data.Properties:*1131f6aa*"
  }
}
```

### Azure Sentinel

```kql
SecurityEvent
| where EventID == 4662
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
| where SubjectUserName !endswith "$"
| project TimeGenerated, Computer, SubjectUserName, ObjectName
```

## Rule Quality

All rules are validated for:

- [x] Valid YAML/YARA syntax
- [x] Required metadata (title, ID, description, author, date)
- [x] MITRE ATT&CK technique mapping
- [x] Severity classification
- [x] False positive documentation
- [x] References to threat intelligence

Run validation:

```bash
pytest tests/unit/test_detection_rules/ -v --tb=short
```

## Detection Engineering Workflow

```text
1. Threat Intelligence
   - Monitor 2025 threat reports
   - Track CISA KEV catalog
   - Follow vendor advisories
         |
         v
2. Rule Development
   - Map to ATT&CK technique
   - Write Sigma/YARA rule
   - Add comprehensive metadata
         |
         v
3. Testing & Validation
   - Syntax validation
   - Lab testing with Atomic Red Team
   - False positive assessment
         |
         v
4. Deployment
   - Convert to SIEM format
   - Deploy in monitoring mode
   - Tune based on environment
         |
         v
5. Maintenance
   - Quarterly rule review
   - Update for new variants
   - Track detection metrics
```

## Resources

### Official Documentation

- [Sigma Specification](https://sigmahq.io/docs/guide/about)
- [YARA Documentation](https://yara.readthedocs.io/)
- [MITRE ATT&CK](https://attack.mitre.org/)

### Community Rules

- [SigmaHQ](https://github.com/SigmaHQ/sigma) - 3000+ community Sigma rules
- [Yara-Rules](https://github.com/Yara-Rules/rules) - Community YARA rules
- [Elastic Detection Rules](https://github.com/elastic/detection-rules)

### Threat Intelligence

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/)
- [MITRE ATT&CK Updates](https://attack.mitre.org/resources/updates/)

## Contributing

1. Create rule following existing templates
2. Map to MITRE ATT&CK technique
3. Include threat intelligence references
4. Document false positives
5. Run validation tests
6. Submit pull request

---

**Version**: 2.0.0 | **Last Updated**: 2025-11-26 | **Maintainer**: Defensive Toolkit
