# Defensive Toolkit - Architecture Documentation

**Version**: 1.0.0
**Last Updated**: 2025-10-18
**Status**: ✅ Production-Ready

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [System Architecture](#system-architecture)
- [Module Categories](#module-categories)
- [Data Flow](#data-flow)
- [Integration Points](#integration-points)
- [Technology Stack](#technology-stack)
- [Security Architecture](#security-architecture)
- [Deployment Models](#deployment-models)
- [Future Roadmap](#future-roadmap)

---

## Executive Summary

The Defensive Toolkit is a **comprehensive, enterprise-grade defensive security suite** designed for Security Operations Centers (SOCs), incident response teams, compliance teams, and security engineers. The toolkit provides production-ready tools for detection, incident response, threat hunting, hardening, monitoring, forensics, vulnerability management, automation, compliance, and log analysis.

### Key Characteristics

- **10 Security Categories**: Complete coverage of defensive security operations
- **35+ Production Tools**: Python and PowerShell scripts for automated security operations
- **14,000+ Lines of Code**: Well-structured, documented, and tested
- **400+ Tests**: Comprehensive test suite with 80%+ coverage
- **Multi-Platform**: Windows and Linux support
- **MITRE ATT&CK Aligned**: All detection rules mapped to ATT&CK framework
- **Compliance-Ready**: CIS, NIST, ISO 27001, PCI-DSS, SOC2 support

### Design Principles

1. **Modular Architecture**: Each category is self-contained and independently usable
2. **Integration-First**: Designed to integrate with existing SIEM, SOAR, and ticketing platforms
3. **Production-Ready**: Comprehensive error handling, logging, and documentation
4. **Security by Default**: Never commits credentials, validates inputs, follows least privilege
5. **Extensibility**: Easy to add new rules, playbooks, queries, and integrations

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Defensive Toolkit Core                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │  Detection   │  │   Incident   │  │    Threat    │             │
│  │    Rules     │  │   Response   │  │   Hunting    │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │  Hardening   │  │  Monitoring  │  │  Forensics   │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │Vulnerability │  │  Automation  │  │  Compliance  │             │
│  │  Management  │  │     SOAR     │  │              │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
│                                                                     │
│  ┌──────────────────────────────────────────────────┐             │
│  │           Log Analysis & Anomaly Detection       │             │
│  └──────────────────────────────────────────────────┘             │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                    Integration Layer                                │
├─────────────────────────────────────────────────────────────────────┤
│  SIEM  │  SOAR  │  Ticketing  │  Email  │  EDR  │  Scanners       │
└─────────────────────────────────────────────────────────────────────┘
```

### Directory Structure

```
defensive-toolkit/
├── detection-rules/              # Security detection rules
│   ├── sigma/                    # SIEM-agnostic Sigma rules
│   │   ├── execution/           # T1059 - Command execution
│   │   ├── persistence/         # T1547, T1053 - Persistence
│   │   ├── credential-access/   # T1003 - Credential dumping
│   │   └── defense-evasion/     # T1070 - Log clearing
│   └── yara/                    # Malware detection rules
│       ├── webshells.yar        # Web shell detection
│       ├── ransomware.yar       # Ransomware patterns
│       └── suspicious_scripts.yar
│
├── incident-response/            # IR playbooks and scripts
│   ├── playbooks/               # Step-by-step procedures
│   │   ├── ransomware_response.md
│   │   └── malware_infection.md
│   └── scripts/                 # Evidence collection
│       ├── windows-triage.ps1   # Windows triage script
│       └── linux-triage.sh      # Linux triage script
│
├── threat-hunting/               # Proactive hunting queries
│   └── queries/                 # SIEM platform queries
│       ├── kql/                 # Azure Sentinel/Defender
│       ├── spl/                 # Splunk
│       └── eql/                 # Elastic Security
│
├── hardening/                    # Security hardening
│   └── windows-security/        # Windows hardening scripts
│       ├── harden-level1-safe.ps1
│       ├── harden-level2-balanced.ps1
│       ├── harden-level3-maximum.ps1
│       ├── audit-security-posture.ps1
│       ├── backup-security-settings.ps1
│       └── restore-security-settings.ps1
│
├── monitoring/                   # Security monitoring
│   ├── siem-integration/        # SIEM connectors
│   ├── log-forwarding/          # Log collection
│   ├── dashboards/              # Visualization templates
│   └── health-checks/           # System health monitoring
│
├── forensics/                    # Digital forensics
│   ├── memory/                  # Memory analysis
│   │   └── volatility_automation.py
│   ├── disk/                    # Disk forensics
│   │   └── mft_extractor.py
│   ├── artifacts/               # Artifact collection
│   │   ├── browser/
│   │   ├── windows/
│   │   └── linux/
│   └── timeline/                # Timeline generation
│       └── generate_timeline.py
│
├── vulnerability-mgmt/           # Vulnerability management
│   ├── scanners/                # Vulnerability scanners
│   │   ├── openvas_scan.py      # OpenVAS integration
│   │   ├── nmap_nse.py          # Nmap NSE scripts
│   │   ├── trivy_scan.py        # Container scanning
│   │   └── sbom_generator.py    # SBOM generation
│   ├── prioritization/          # Risk prioritization
│   │   └── risk_scorer.py       # Multi-factor risk scoring
│   ├── remediation/             # Remediation tracking
│   └── reporting/               # Report generation
│       └── generate_report.py
│
├── automation/                   # SOAR automation
│   ├── playbooks/               # YAML playbooks
│   │   ├── playbook_engine.py   # Orchestration engine
│   │   └── examples/            # Example workflows
│   ├── actions/                 # Automation actions
│   │   ├── containment_actions.py
│   │   ├── enrichment_actions.py
│   │   └── notification_actions.py
│   └── integrations/            # Platform integrations
│       ├── siem_connector.py
│       ├── ticket_connector.py
│       ├── email_connector.py
│       └── toolkit_connector.py
│
├── compliance/                   # Compliance automation
│   ├── frameworks/              # Framework checkers
│   │   ├── cis_checker.py       # CIS Controls v8
│   │   ├── nist_checker.py      # NIST 800-53 Rev 5
│   │   └── framework_mapper.py  # Multi-framework mapping
│   ├── policy/                  # Policy validation
│   │   ├── policy_checker.py
│   │   └── drift_detector.py
│   └── reporting/               # Compliance reporting
│       └── dashboard.py
│
├── log-analysis/                 # Log analysis
│   ├── parsers/                 # Log parsers
│   │   └── universal_parser.py  # Multi-format parsing
│   └── analysis/                # Analysis tools
│       └── anomaly_detector.py  # Statistical anomaly detection
│
├── scripts/                      # Utility scripts
│   ├── cleanup.py               # Project cleanup
│   ├── validate_project.py      # Structure validation
│   └── generate_docs.py         # Documentation generation
│
├── tests/                        # Test suite (400+ tests)
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   ├── fixtures/                # Test data
│   └── conftest.py              # Shared fixtures
│
└── docs/                         # Documentation
    ├── GETTING_STARTED.md       # Quick start guide
    ├── ARCHITECTURE.md          # This file
    ├── TESTING.md               # Testing documentation
    ├── DEPLOYMENT.md            # Deployment guide
    ├── API_REFERENCE.md         # API documentation
    ├── TROUBLESHOOTING.md       # Common issues
    └── CHANGELOG.md             # Version history
```

---

## Module Categories

### 1. Detection Rules

**Purpose**: Detect malicious activity across endpoints, networks, and applications

**Components**:
- **Sigma Rules** (6 rules): SIEM-agnostic detection logic
- **YARA Rules** (3 rulesets): Malware and suspicious file detection
- **Coverage**: Execution, Persistence, Credential Access, Defense Evasion

**MITRE ATT&CK Mapping**:
- T1059 - Command and Scripting Interpreter
- T1547 - Boot or Logon Autostart Execution
- T1053 - Scheduled Task/Job
- T1003 - OS Credential Dumping
- T1070 - Indicator Removal

**Integration**: Converts to Splunk, Sentinel, Elastic, QRadar via Sigma CLI

### 2. Incident Response

**Purpose**: Structured playbooks and evidence collection for incident handling

**Components**:
- **Playbooks**: Step-by-step procedures (ransomware, malware)
- **Triage Scripts**: Windows (PowerShell) and Linux (Bash) evidence collection
- **Features**: Chain of custody, manifest generation, multiple collection modes

**Workflow**:
```
Incident Detection → Playbook Selection → Evidence Collection →
Analysis → Containment → Eradication → Recovery → Lessons Learned
```

### 3. Threat Hunting

**Purpose**: Proactive hunting for threats that evaded automated detection

**Components**:
- **KQL Queries** (7): Azure Sentinel/Defender for Endpoint
- **SPL Queries** (10): Splunk lateral movement detection
- **EQL Queries** (20): Elastic Security credential access hunting

**Hunt Categories**:
- PowerShell obfuscation and suspicious execution
- Lateral movement (pass-the-hash, remote execution)
- Credential access (LSASS dumping, registry extraction)
- Persistence mechanisms

### 4. Security Hardening

**Purpose**: Apply security baselines to Windows systems

**Components**:
- **Level 1 (Safe)**: CIS Benchmark Level 1, minimal impact
- **Level 2 (Balanced)**: Enhanced security with moderate impact
- **Level 3 (Maximum)**: Maximum security for high-risk environments
- **Audit**: Security posture assessment
- **Backup/Restore**: Configuration management

**Areas Covered**: UAC, Windows Defender, Firewall, BitLocker, SMB, security policies

### 5. Monitoring

**Purpose**: Continuous security and health monitoring

**Components**:
- **SIEM Integration**: Syslog forwarder, WEF configuration
- **Log Forwarding**: Rsyslog, WinRM setup
- **Dashboards**: Grafana and Splunk templates
- **Health Checks**: System, security, performance monitoring

### 6. Forensics

**Purpose**: Digital forensics for incident investigation

**Components**:
- **Memory Analysis**: Volatility automation, malware hunting
- **Disk Forensics**: MFT extraction, file carving, timeline generation
- **Artifact Collection**: Browser history, Windows artifacts, Linux artifacts
- **Timeline Generation**: Comprehensive forensic timelines

**Workflows**:
```
Memory Analysis: Dump → Parse → Hunt (processes, network, malware) → Report
Disk Forensics: Image → Extract (MFT, artifacts) → Timeline → Analysis
```

### 7. Vulnerability Management

**Purpose**: Continuous vulnerability assessment and prioritization

**Components**:
- **Scanners**: OpenVAS/GVM, Nmap NSE, Trivy (containers)
- **SBOM Generation**: Syft-based Software Bill of Materials
- **Risk Scoring**: Multi-factor (CVSS, KEV, exploitability, asset criticality)
- **Reporting**: HTML/Markdown/JSON reports

**Risk Scoring Formula**:
```python
risk_score = (
    cvss_score * cvss_weight +
    kev_factor * kev_weight +
    asset_criticality * asset_weight +
    exploitability * exploit_weight +
    environment_factor * env_weight
) / total_weight
```

### 8. Automation & SOAR

**Purpose**: Orchestrate incident response workflows

**Components**:
- **Playbook Engine**: YAML-based orchestration (400+ lines)
- **Actions**: Containment, enrichment, notification modules
- **Integrations**: SIEM, ticketing, email, toolkit connectors
- **Example Workflows**: Phishing response, malware containment, vuln remediation

**Workflow Example**:
```yaml
name: "Phishing Response"
tasks:
  - name: "Extract IOCs"
    action: "analyze_email"
  - name: "Enrich IOCs"
    action: "enrich_ioc"
  - name: "Block malicious URLs"
    action: "block_url"
  - name: "Create incident ticket"
    action: "create_ticket"
```

### 9. Compliance

**Purpose**: Automated compliance checking and reporting

**Components**:
- **Framework Checkers**: CIS Controls v8, NIST 800-53 Rev 5
- **Multi-Framework Mapper**: Cross-walk between CIS/NIST/ISO/PCI-DSS/SOC2
- **Policy Validation**: YAML-based security policy checker
- **Drift Detection**: Configuration change monitoring
- **Dashboards**: HTML compliance visualization

**Supported Frameworks**:
- CIS Controls v8 (7 controls implemented)
- NIST 800-53 Rev 5 (6 families, 3 impact levels)
- ISO 27001, PCI-DSS, SOC2 (via mapper)

### 10. Log Analysis

**Purpose**: Universal log parsing and anomaly detection

**Components**:
- **Universal Parser**: Syslog, JSON, Apache, Nginx, Windows Event Log
- **Anomaly Detection**: Statistical, pattern-based, frequency, rate analysis
- **Baseline Management**: Historical baseline creation
- **Reporting**: Text/JSON anomaly reports with severity classification

**Detection Methods**:
- **Frequency**: Event count spikes (> 2 std deviations)
- **Pattern**: Regex matching for attack signatures (SQLi, XSS)
- **Statistical**: Mean, standard deviation analysis
- **Rate**: Events per second anomalies

---

## Data Flow

### Detection Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Log Sources (Endpoints, Network, Applications)             │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Log Collection (Syslog, WEF, Agents)                        │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Log Parser (Universal Parser - Syslog/JSON/Apache/WinEvt)  │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Detection Rules (Sigma/YARA) + Anomaly Detection            │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. SIEM Alerting + Ticket Creation                             │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. SOAR Orchestration (Playbook Engine)                        │
│     - IOC Enrichment                                            │
│     - Containment Actions                                       │
│     - Notification                                              │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  7. Incident Response (Manual + Automated)                      │
└─────────────────────────────────────────────────────────────────┘
```

### Vulnerability Management Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Asset Discovery + Inventory                                 │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Vulnerability Scanning (OpenVAS, Nmap, Trivy)               │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. SBOM Generation (for containers/applications)               │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Risk Scoring Engine                                         │
│     - CVSS Scoring                                              │
│     - KEV Catalog Check (CISA)                                  │
│     - Exploitability Assessment (EPSS)                          │
│     - Asset Criticality                                         │
│     - Environment Factors                                       │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. Vulnerability Prioritization (sorted by risk score)         │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. Remediation Workflow (ticketing, tracking, verification)    │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  7. Compliance Reporting (NIST, CIS, ISO)                       │
└─────────────────────────────────────────────────────────────────┘
```

### Forensic Investigation Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Evidence Collection (Triage Scripts)                        │
│     - Memory dumps                                              │
│     - Disk images                                               │
│     - Artifacts (browser, registry, logs)                       │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Memory Analysis (Volatility)                                │
│     - Process listing                                           │
│     - Network connections                                       │
│     - Malware hunting (malfind, code injection)                 │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Disk Forensics (MFT Analysis)                               │
│     - MFT extraction                                            │
│     - Suspicious file detection                                 │
│     - Timestomping detection                                    │
│     - ADS detection                                             │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Artifact Analysis                                           │
│     - Browser history (Chrome, Firefox, Edge)                   │
│     - Windows artifacts (prefetch, registry, event logs)        │
│     - Linux artifacts (auth logs, bash history)                 │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. Timeline Generation (chronological event ordering)          │
└─────────────────┬───────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. Report Generation (JSON/HTML/Markdown)                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Integration Points

### SIEM Platforms

**Supported Platforms**:
- Splunk
- Azure Sentinel
- Elastic Security
- QRadar
- Generic Syslog

**Integration Methods**:
- Sigma rule conversion (via Sigma CLI)
- Syslog forwarding (UDP/TCP/TLS)
- Windows Event Forwarding (WEF)
- REST API connectors

### SOAR Platforms

**Integration via REST APIs**:
- Generic REST connector for major SOAR platforms
- Playbook export/import (YAML format)
- Action modules can be called from external SOAR

### Ticketing Systems

**Supported**:
- Jira
- ServiceNow
- Any REST API-based ticketing system

**Features**:
- Automated ticket creation
- Status updates
- Priority assignment
- Custom field mapping

### EDR Solutions

**Integration**:
- Host isolation commands
- Process termination
- File quarantine
- Network blocking

### Vulnerability Scanners

**Supported**:
- OpenVAS/GVM (full integration)
- Nmap NSE scripts
- Trivy (containers)
- SBOM tools (Syft)

---

## Technology Stack

### Languages

| Language | Usage | Lines of Code |
|----------|-------|---------------|
| Python 3.10+ | Primary automation | ~10,500 |
| PowerShell 7+ | Windows automation | ~1,500 |
| Bash | Linux automation | ~800 |
| YAML | Configurations, playbooks, policies | ~1,200 |

### Python Libraries

**Core Dependencies**:
- `yara-python` - YARA rule execution
- `sigma-cli` - Sigma rule conversion
- `scapy` - Network packet analysis
- `psutil` - System and process utilities
- `requests` - HTTP/REST API calls
- `pyyaml` - YAML parsing
- `python-dotenv` - Environment management
- `gvm-tools` - OpenVAS/GVM integration

**Development Dependencies**:
- `pytest` - Testing framework
- `pytest-cov` - Coverage reporting
- `bandit` - Security linting
- `ruff` - Fast linting
- `black` - Code formatting
- `mypy` - Type checking

### External Tools

**Forensics**:
- Volatility 3 (memory analysis)
- analyzeMFT (MFT parsing)
- bulk_extractor (artifact extraction)

**Vulnerability Scanning**:
- OpenVAS/GVM
- Nmap with NSE scripts
- Trivy
- Syft

### Package Management

- **uv** (recommended): 10-100x faster than pip, deterministic builds
- **pip**: Traditional fallback option

---

## Security Architecture

### Security Principles

1. **Least Privilege**: Tools request only necessary permissions
2. **Input Validation**: All user inputs validated before processing
3. **Credential Management**: No hardcoded credentials, use environment variables
4. **Logging**: Comprehensive audit logging for all actions
5. **Error Handling**: Graceful error handling, no sensitive data in errors
6. **Code Security**: Regular Bandit scans, secure coding practices

### Authentication & Authorization

**Credentials**:
- Environment variables (.env files, never committed)
- Secure credential stores (OS keychains)
- API tokens with limited scope

**Authorization**:
- Role-based access control (RBAC) where applicable
- Audit logs for privileged operations
- Approval workflows for destructive actions

### Data Protection

**At Rest**:
- Sensitive data encrypted (forensic artifacts, evidence)
- Proper file permissions (600 for sensitive files)
- Secure deletion when appropriate

**In Transit**:
- TLS for all network communications
- Certificate validation
- Encrypted syslog (TLS)

### Compliance

**Standards Met**:
- CIS Controls v8
- NIST 800-53 Rev 5
- GDPR considerations (data handling)
- Chain of custody for evidence
- Audit logging

---

## Deployment Models

### 1. Standalone Deployment

**Use Case**: Single analyst workstation or jump box

```
┌──────────────────────────┐
│  Analyst Workstation     │
│  - Defensive Toolkit     │
│  - Python 3.10+          │
│  - uv package manager    │
│  - All tools installed   │
└──────────────────────────┘
```

**Pros**: Simple setup, full control
**Cons**: Single point of failure, not scalable

### 2. Distributed Deployment

**Use Case**: SOC team with multiple analysts

```
┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│  Analyst Station 1   │  │  Analyst Station 2   │  │  Analyst Station N   │
│  - Toolkit installed │  │  - Toolkit installed │  │  - Toolkit installed │
└──────────┬───────────┘  └──────────┬───────────┘  └──────────┬───────────┘
           │                         │                         │
           └─────────────────────────┴─────────────────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   Shared SIEM       │
                          │   Shared Ticketing  │
                          │   Shared Scanners   │
                          └─────────────────────┘
```

**Pros**: Team collaboration, shared infrastructure
**Cons**: Requires centralized services

### 3. Enterprise SOC Deployment

**Use Case**: Large SOC with automation requirements

```
┌─────────────────────────────────────────────────────────────────┐
│                        SOAR Platform                            │
│  - Defensive Toolkit Playbooks                                  │
│  - Automated Workflows                                          │
└─────────────┬───────────────────────────────────────────────────┘
              │
    ┌─────────┼─────────┬─────────────┬──────────────┐
    │         │         │             │              │
┌───▼──┐  ┌───▼──┐  ┌───▼───┐  ┌─────▼────┐  ┌──────▼──────┐
│ SIEM │  │ EDR  │  │ Ticket│  │ Scanners │  │ Forensics   │
│      │  │      │  │ System│  │          │  │ Workstation │
└──────┘  └──────┘  └───────┘  └──────────┘  └─────────────┘
```

**Pros**: Full automation, scalable, integrated
**Cons**: Complex setup, requires SOAR platform

### 4. Cloud Deployment (Future)

**Use Case**: Cloud-native SOC operations

```
┌──────────────────────────────────────────────────┐
│           Cloud Platform (AWS/Azure/GCP)         │
├──────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────┐  │
│  │  Container Orchestration (Kubernetes)      │  │
│  │  - Toolkit containers                      │  │
│  │  - Auto-scaling                            │  │
│  │  - High availability                       │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  ┌────────────┐  ┌────────────┐  ┌───────────┐  │
│  │  Cloud     │  │  Cloud     │  │  Cloud    │  │
│  │  SIEM      │  │  Storage   │  │  Functions│  │
│  └────────────┘  └────────────┘  └───────────┘  │
└──────────────────────────────────────────────────┘
```

**Pros**: Elastic scaling, high availability, cloud-native
**Cons**: Not yet implemented, requires containerization

---

## Future Roadmap

### Short-Term (Next Release)

- [ ] Docker containerization
- [ ] REST API for toolkit access
- [ ] Web dashboard for monitoring
- [ ] Additional Snort/Suricata rules
- [ ] Cloud-specific detection rules (AWS, Azure, GCP)

### Medium-Term

- [ ] Kubernetes threat hunting queries
- [ ] Machine learning anomaly models
- [ ] Mobile device forensics
- [ ] Advanced persistent threat (APT) playbooks
- [ ] Threat intelligence feed integration

### Long-Term

- [ ] Full SOAR platform (not just integrations)
- [ ] Community-contributed content
- [ ] Marketplace for custom modules
- [ ] SaaS offering
- [ ] AI-powered threat hunting

---

## Repository Metrics

| Metric | Value |
|--------|-------|
| **Total Lines of Code** | ~14,000+ |
| **Python Scripts** | 35+ |
| **PowerShell Scripts** | 12 |
| **Detection Rules** | 9 files |
| **Playbooks** | 6 |
| **Query Files** | 3 |
| **Documentation Files** | 15+ |
| **Test Files** | 23 |
| **Test Coverage** | 80%+ |
| **Categories Complete** | 10/10 |

---

**For deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md)**
**For API reference, see [API_REFERENCE.md](API_REFERENCE.md)**
**For troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)**
