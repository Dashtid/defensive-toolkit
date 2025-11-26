# Threat Hunting

**100% Open Source** threat hunting queries and methodologies for proactive security analysis.

## Overview

Threat hunting is the proactive search for threats that evade automated detection systems. This directory contains pre-built hunting queries for open-source SIEM platforms.

**Query Types:**
- **EQL (Event Query Language)**: For Elastic and OpenSearch
- **KQL (Kibana Query Language)**: For Elastic/OpenSearch Kibana/Dashboards
- **Wazuh Query Language**: For Wazuh SIEM
- **Lucene**: Universal query syntax for Elastic/OpenSearch/Graylog

## Directory Structure

```
threat-hunting/
├── queries/
│   ├── eql/              # Elastic/OpenSearch Event Query Language
│   ├── kql/              # Kibana Query Language (Elastic/OpenSearch)
│   ├── wazuh/            # Wazuh-specific queries
│   └── lucene/           # Lucene query syntax (universal)
├── methodologies/
│   ├── mitre-hunting.md  # MITRE ATT&CK-based hunting
│   ├── hypothesis-driven.md
│   └── anomaly-detection.md
└── playbooks/
    ├── ransomware-hunt.md
    ├── insider-threat-hunt.md
    └── c2-detection-hunt.md
```

## Supported Open Source SIEM Platforms

| Platform | Query Languages | Location |
|----------|----------------|----------|
| **Wazuh** | Wazuh QL, Lucene | `queries/wazuh/`, `queries/lucene/` |
| **Elastic** | EQL, KQL, Lucene | `queries/eql/`, `queries/kql/`, `queries/lucene/` |
| **OpenSearch** | EQL, KQL, Lucene | `queries/eql/`, `queries/kql/`, `queries/lucene/` |
| **Graylog** | Lucene, Graylog QL | `queries/lucene/` |

## Quick Start

### 1. Choose Your SIEM Platform

**Wazuh:**
```bash
# Access Wazuh web UI
https://your-wazuh-server:443

# Navigate to: Security events > Events
# Use query bar for hunting
```

**Elastic / OpenSearch:**
```bash
# Access Kibana/OpenSearch Dashboards
https://your-elastic-server:5601

# Navigate to: Discover
# Select appropriate data view (logs-*)
```

**Graylog:**
```bash
# Access Graylog web UI
https://your-graylog-server:9000

# Navigate to: Search
```

### 2. Run Pre-Built Hunting Queries

**Example: Hunt for Encoded PowerShell Commands (EQL)**
```eql
process where process.name in ("powershell.exe", "pwsh.exe") and
  process.command_line : "*-enc*" or process.command_line : "*-encodedcommand*"
```

**Example: Hunt for Suspicious Registry Persistence (KQL)**
```kql
event.category: "registry" and registry.path: (*\\CurrentVersion\\Run* or *\\CurrentVersion\\RunOnce*)
  and not process.executable: ("C:\\Program Files\\*" or "C:\\Windows\\System32\\*")
```

**Example: Hunt for Lateral Movement (Lucene)**
```
event_id:4624 AND logon_type:3 AND NOT source_ip:(127.0.0.1 OR fe80\:\:*)
```

### 3. Analyze Results

Look for:
- Unusual process execution patterns
- Anomalous network connections
- Unexpected privilege escalations
- Suspicious file modifications
- Abnormal authentication events

## Threat Hunting Methodologies

### 1. Hypothesis-Driven Hunting

**Process:**
1. Develop hypothesis based on threat intelligence (e.g., "Attackers may be using LOLBins for defense evasion")
2. Create queries to test hypothesis
3. Analyze results for anomalies
4. Document findings and refine detections

**Example Hypothesis:**
> "Attackers are using certutil.exe to download payloads"

**Query (Lucene):**
```
process_name:certutil.exe AND command_line:(*-urlcache* OR *-split* OR *http*)
```

### 2. MITRE ATT&CK-Based Hunting

Hunt by tactic and technique:

**Execution (T1059) - Command and Scripting Interpreter:**
```eql
process where process.name : ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
  and process.parent.name : ("winword.exe", "excel.exe", "outlook.exe")
```

**Persistence (T1547) - Boot or Logon Autostart Execution:**
```kql
registry.path: (*\\Run* or *\\RunOnce* or *\\Startup*)
  and not process.code_signature.trusted: true
```

**Credential Access (T1003) - OS Credential Dumping:**
```
process_name:(lsass.exe OR mimikatz.exe OR procdump.exe) AND (command_line:*lsass* OR event_id:10)
```

### 3. Anomaly-Based Hunting

Look for statistical outliers:

**Rare Process-Parent Relationships:**
```kql
process.parent.name: * and process.name: *
| rare process.parent.name, process.name by host.name
```

**Unusual Network Connections:**
```
destination_port NOT (80 OR 443 OR 53) AND NOT destination_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
```

**Abnormal User Activity:**
```eql
authentication where user.name : "*"
  and event.outcome : "success"
| stats count by user.name, source.ip
| where count > 100
```

## Query Examples by Threat Type

### Ransomware Hunting

**Mass File Encryption Activity (EQL):**
```eql
file where file.extension in ("encrypted", "locked", "crypto", "crypt")
| stats count by process.name, host.name
| where count > 50
```

**Shadow Copy Deletion (KQL):**
```kql
process.name: "vssadmin.exe" and process.command_line: (*delete* and *shadows* and *all*)
```

### Lateral Movement Hunting

**Remote Service Creation (Lucene):**
```
event_id:7045 AND service_name:* AND NOT service_name:(Windows* OR Microsoft*)
```

**WMI Lateral Movement (EQL):**
```eql
process where process.name : "wmic.exe" and
  process.command_line : ("*/node:*", "*process*call*create*")
```

### Command & Control Hunting

**Beaconing Detection (KQL):**
```kql
network.direction: "outbound" and destination.port: *
| stats count by source.ip, destination.ip, destination.port
| where count > 100
```

**DNS Tunneling (Lucene):**
```
dns.question.type:(TXT OR NULL) OR dns.question.name.length:>50
```

### Insider Threat Hunting

**Unusual Data Exfiltration (EQL):**
```eql
network where destination.port in (21, 22, 25, 80, 443, 8080)
  and network.bytes_sent > 10000000
| stats sum(network.bytes_sent) by user.name, destination.ip
```

**After-Hours Access (KQL):**
```kql
event.category: "authentication" and event.outcome: "success"
  and @timestamp > now-1d and @timestamp.hour: (0 or 1 or 2 or 3 or 4 or 5 or 22 or 23)
```

## Advanced Hunting Techniques

### Stacking Analysis

Find outliers by frequency:

```kql
# Rare parent-child process relationships
process.parent.name: * and process.name: *
| stats count by process.parent.name, process.name
| sort count asc
| head 20
```

### Timeline Analysis

Reconstruct attack timeline:

```eql
sequence by host.name
  [process where process.name : "cmd.exe"]
  [network where destination.port : 4444]
  [file where file.path : "C:\\Windows\\Temp\\*"]
```

### Behavioral Analytics

Detect abnormal user behavior:

```kql
authentication.successful: true
| stats dc(source.ip) as unique_ips by user.name
| where unique_ips > 5
```

## Threat Hunting Best Practices

### Planning
1. **Define Objectives**: What threats are you hunting for?
2. **Gather Intelligence**: Use threat intel to inform hypotheses
3. **Select Data Sources**: Ensure relevant logs are available
4. **Create Queries**: Develop hunting queries in advance

### Execution
1. **Start Broad**: Begin with wide queries, narrow based on findings
2. **Use Time Windows**: Focus on specific time periods
3. **Correlate Events**: Link related events across data sources
4. **Document Everything**: Record queries, findings, and insights

### Analysis
1. **Baseline Normal**: Understand what's normal in your environment
2. **Look for Anomalies**: Identify deviations from baseline
3. **Investigate Findings**: Deep-dive into suspicious activity
4. **Create Detections**: Turn findings into automated detection rules

### Continuous Improvement
1. **Update Queries**: Refine based on false positives
2. **Share Findings**: Document and share with team
3. **Automate Detections**: Convert successful hunts to alerts
4. **Track Metrics**: Measure hunting effectiveness

## Integration with Defensive Toolkit

### Convert Hunts to Detection Rules

Found something suspicious? Convert to Sigma rule:

```yaml
title: Suspicious Process Created by Office Application
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\winword.exe'
            - '*\excel.exe'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
    condition: selection
level: medium
```

Save to `detection-rules/sigma/` and deploy to your SIEM.

### Automate Response with SOAR

Trigger playbooks on hunt findings:

```yaml
# automation/playbooks/examples/hunt-response.yaml
name: "Threat Hunt Response"
tasks:
  - name: "Isolate affected host"
    action: isolate_host
    parameters:
      hostname: ${hunt_finding_host}

  - name: "Create incident ticket"
    action: create_ticket
    parameters:
      title: "Threat Hunt Finding: ${hunt_finding_type}"
```

## Hunting Playbooks

### Weekly Hunting Cadence

**Monday: Execution Techniques**
- Hunt for suspicious process execution
- Focus on Office applications spawning scripts

**Tuesday: Persistence Mechanisms**
- Search for registry persistence
- Check scheduled tasks and services

**Wednesday: Credential Access**
- Look for LSASS access
- Monitor for Kerberos anomalies

**Thursday: Lateral Movement**
- Hunt for RDP/SMB anomalies
- Check for WMI/PSExec usage

**Friday: Data Exfiltration**
- Monitor for unusual network traffic
- Check for large file transfers

## Resources

### Threat Hunting Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [TaHiTI (Targeted Hunting integrating Threat Intelligence)](https://www.betaalvereniging.nl/wp-content/uploads/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf)

### Open Source SIEM Documentation
- [Wazuh Query Language](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [Elastic EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html)
- [Kibana Query Language (KQL)](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- [Lucene Query Syntax](https://lucene.apache.org/core/2_9_4/queryparsersyntax.html)
- [OpenSearch Query DSL](https://opensearch.org/docs/latest/query-dsl/)
- [Graylog Query Language](https://go2docs.graylog.org/5-0/making_sense_of_your_log_data/writing_search_queries.html)

### Threat Intelligence
- [MISP Threat Intelligence](https://www.misp-project.org/)
- [OpenCTI](https://www.opencti.io/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

### Community Resources
- [Elastic Detection Rules](https://github.com/elastic/detection-rules)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [ThreatHunter-Playbook](https://threathunterplaybook.com/)

---

**Hunt Proactively. Find Threats Early. Defend Continuously.**
