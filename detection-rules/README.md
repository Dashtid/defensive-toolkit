# Detection Rules

Comprehensive detection rules for SIEM platforms, endpoint detection, and file analysis.

## Overview

This directory contains detection rules in multiple formats:
- **Sigma Rules**: SIEM-agnostic detection logic (YAML format)
- **YARA Rules**: File-based malware and threat detection
- **Snort/Suricata**: Network intrusion detection rules
- **EDR Logic**: Endpoint detection and response queries

## Directory Structure

```
detection-rules/
├── sigma/                    # Sigma detection rules (MITRE ATT&CK organized)
│   ├── execution/           # T1059 - Command and Scripting Interpreter
│   ├── persistence/         # T1547 - Boot or Logon Autostart
│   ├── privilege-escalation/
│   ├── defense-evasion/
│   ├── credential-access/   # T1003 - Credential Dumping
│   ├── discovery/
│   ├── lateral-movement/
│   ├── collection/
│   ├── exfiltration/
│   ├── command-and-control/
│   └── impact/
├── yara/                    # YARA rules for file analysis
│   ├── webshells.yar       # Web application backdoors
│   ├── ransomware.yar      # Ransomware detection
│   ├── suspicious_scripts.yar
│   └── malware_families.yar
├── snort/                   # Network IDS rules
└── edr/                     # EDR-specific queries
```

## Sigma Rules

### What are Sigma Rules?

Sigma is an open-source, generic signature format for SIEM systems. Rules are written once in YAML and can be converted to any SIEM query language.

**Supported SIEM Platforms:**
- Splunk (SPL)
- Elastic (EQL/KQL)
- Azure Sentinel (KQL)
- QRadar (AQL)
- ArcSight
- LogRhythm
- Sumo Logic

### Using Sigma Rules

#### 1. Install Sigma CLI

```bash
pip install sigma-cli
```

#### 2. Convert Rules to Your SIEM

```bash
# Convert to Splunk SPL
sigma convert -t splunk detection-rules/sigma/execution/*.yml

# Convert to Elastic EQL
sigma convert -t elasticsearch detection-rules/sigma/persistence/*.yml

# Convert to Azure Sentinel KQL
sigma convert -t sentinel detection-rules/sigma/credential-access/*.yml
```

#### 3. Deploy to SIEM

```bash
# Example: Deploy all execution rules to Splunk
for file in detection-rules/sigma/execution/*.yml; do
    sigma convert -t splunk "$file" >> splunk_alerts.txt
done
```

### Sigma Rule Structure

```yaml
title: Rule Name
id: unique-uuid
status: stable|testing|experimental
description: What this rule detects
references:
    - https://attack.mitre.org/techniques/T1234/
author: Your Name
date: YYYY-MM-DD
tags:
    - attack.tactic
    - attack.technique_id
logsource:
    category: process_creation|registry_set|network_connection
    product: windows|linux|macos
detection:
    selection:
        FieldName: value
    condition: selection
falsepositives:
    - Known benign scenarios
level: low|medium|high|critical
```

### Tuning Sigma Rules

1. **Reduce False Positives**: Add filters for known legitimate processes
2. **Adjust Sensitivity**: Modify `level` field based on environment
3. **Add Context**: Include additional log fields for investigation
4. **Test Thoroughly**: Deploy in monitoring mode before alerting

## YARA Rules

### What are YARA Rules?

YARA is a pattern-matching tool for identifying and classifying malware samples and suspicious files.

### Using YARA Rules

#### 1. Install YARA

```bash
# Ubuntu/Debian
sudo apt-get install yara

# Windows (via Chocolatey)
choco install yara

# macOS
brew install yara
```

#### 2. Scan Files

```bash
# Scan a single file
yara detection-rules/yara/webshells.yar /path/to/suspicious/file.php

# Scan a directory recursively
yara -r detection-rules/yara/ransomware.yar /path/to/scan/

# Scan with all rules
yara -r detection-rules/yara/*.yar /path/to/scan/
```

#### 3. Integration with EDR

```bash
# Generate alerts on matches
yara -r -w detection-rules/yara/*.yar /path/to/monitor/ | tee -a yara_alerts.log
```

### YARA Rule Structure

```yara
rule RuleName
{
    meta:
        description = "What this detects"
        author = "Your Name"
        date = "YYYY-MM-DD"
        severity = "low|medium|high|critical"

    strings:
        $str1 = "suspicious string"
        $str2 = /regex pattern/
        $hex = { 4D 5A 90 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        2 of ($str*)
}
```

## Detection Rule Best Practices

### Development

1. **Map to MITRE ATT&CK**: Tag rules with appropriate tactics/techniques
2. **Include Context**: Add references and descriptions
3. **Version Control**: Use Git to track rule changes
4. **Peer Review**: Have rules reviewed before production deployment

### Testing

1. **Lab Testing**: Test in isolated environment first
2. **Baseline Environment**: Understand normal behavior
3. **False Positive Testing**: Run against known-good files/events
4. **Performance Testing**: Ensure rules don't impact SIEM performance

### Deployment

1. **Staged Rollout**: Deploy to test group first
2. **Monitoring Mode**: Run in alert-only mode initially
3. **Tune Iteratively**: Adjust based on real-world feedback
4. **Document Changes**: Log all modifications and reasoning

### Maintenance

1. **Regular Updates**: Review rules quarterly
2. **Threat Intelligence**: Update based on new IOCs
3. **Remove Obsolete Rules**: Clean up outdated detections
4. **Performance Monitoring**: Track rule execution time

## Detection Engineering Workflow

```
1. Threat Research
   ↓
2. Write Detection Logic
   ↓
3. Test in Lab
   ↓
4. Peer Review
   ↓
5. Deploy to Monitoring
   ↓
6. Tune for False Positives
   ↓
7. Enable Alerting
   ↓
8. Document and Maintain
```

## Integration with SIEM

### Splunk

```spl
# Import Sigma rule as Splunk alert
index=windows EventCode=4688
| eval CommandLine=lower(CommandLine)
| search CommandLine="*-encodedcommand*" OR CommandLine="*-enc*"
| search (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
```

### Elastic

```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"event.category": "process"}},
        {"match": {"process.name": "powershell.exe"}},
        {"wildcard": {"process.command_line": "*-enc*"}}
      ]
    }
  }
}
```

### Azure Sentinel

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has_any ("powershell.exe", "pwsh.exe")
| where CommandLine has_any ("-enc", "-encodedcommand")
| project TimeGenerated, Computer, Account, CommandLine
```

## Contributing Detection Rules

When contributing new rules:

1. **Use Templates**: Follow existing rule structure
2. **Test Thoroughly**: Include test cases
3. **Document FPs**: List known false positives
4. **Provide Context**: Explain detection logic
5. **Add Examples**: Include sample logs/files that trigger

## Resources

### Sigma Resources
- [SigmaHQ Repository](https://github.com/SigmaHQ/sigma) - 3000+ community rules
- [Sigma Specification](https://sigmahq.io/docs/guide/about)
- [Sigma Converter](https://uncoder.io/) - Web-based rule converter

### YARA Resources
- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA Rules Repository](https://github.com/Yara-Rules/rules)
- [YARA Best Practices](https://yara.readthedocs.io/en/stable/writingrules.html)

### MITRE ATT&CK
- [ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

### Detection Engineering
- [Florian Roth's Detection Rules](https://github.com/Neo23x0/signature-base)
- [Elastic Detection Rules](https://github.com/elastic/detection-rules)
- [Splunk Security Content](https://github.com/splunk/security_content)

---

**Detect Early. Detect Often. Detect Everything.**
