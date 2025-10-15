# Defensive Toolkit

Blue team security tools for detection, monitoring, incident response, and threat hunting.

## Overview
n## Implementation Status

| Category | Status | Contents |
|----------|--------|----------|
| **Detection Rules** | [OK] Implemented | 6 Sigma rules, 3 YARA rulesets, organized by MITRE ATT&CK |
| **Incident Response** | [OK] Implemented | 2 playbooks (ransomware, malware), 2 triage scripts |
| **Threat Hunting** | [OK] Implemented | KQL, SPL, and EQL queries for major SIEM platforms |
| **Hardening** | [OK] Implemented | Windows security hardening (3 levels + audit/backup) |
| **Monitoring** | [OK] Implemented | SIEM integration, log forwarding, dashboards, health checks |
| **Forensics** | [OK] Implemented | Memory analysis, disk forensics, artifact collection, timelines |
| **Vulnerability Mgmt** | [OK] Implemented | OpenVAS/Nmap/Trivy scanners, SBOM, risk scoring, reporting |
| **Log Analysis** | [*] Planned | Log parsing and analysis tools |
| **Automation** | [*] Planned | Security automation workflows |
| **Compliance** | [*] Planned | Compliance checking tools |


This repository contains defensive security tools, detection rules, hardening scripts, and incident response playbooks for protecting systems and detecting threats.

## Repository Structure

```
defensive-toolkit/
├── detection-rules/       # SIEM rules, Sigma, Yara, Snort
├── hardening/            # Security hardening scripts
├── incident-response/    # IR playbooks and scripts
├── threat-hunting/       # Threat hunting queries and tools
├── monitoring/           # System and security monitoring
├── forensics/           # Digital forensics tools
├── vulnerability-mgmt/  # Vulnerability scanning and management
├── log-analysis/        # Log parsing and analysis tools
├── automation/          # Security automation scripts
└── compliance/          # Compliance checking tools
```

## Tools Categories

### Detection Rules
- Sigma rules (SIEM-agnostic)
- Yara rules (malware detection)
- Snort/Suricata IDS rules
- EDR detection logic
- Custom detection scripts

### Security Hardening
- CIS Benchmark scripts
- Windows hardening (GPO, registry)
- Linux hardening (SELinux, AppArmor)
- Network device hardening
- Application security configs

### Incident Response
- IR playbooks and runbooks
- Evidence collection scripts
- Memory forensics tools
- Network traffic analysis
- Timeline analysis tools

### Threat Hunting
- KQL queries (Azure Sentinel)
- Splunk SPL queries
- Elastic EQL queries
- PowerShell hunting scripts
- Behavioral analytics

### Monitoring & Alerting
- System health monitoring
- Security event monitoring
- Performance monitoring
- Custom alert logic
- Dashboard configurations

## Prerequisites

- Python 3.x
- PowerShell 7+
- SIEM platform (Splunk, ELK, Sentinel, etc.)
- EDR solution (optional)
- Network monitoring tools

## Installation

```bash
git clone https://github.com/yourusername/defensive-toolkit.git
cd defensive-toolkit
pip install -r requirements.txt
```

## Quick Start

### Deploy Detection Rules
```bash
# Deploy Sigma rules to your SIEM
cd detection-rules/sigma
python deploy-sigma-rules.py --target splunk

# Deploy Yara rules
cd detection-rules/yara
./deploy-yara.sh
```

### Run Security Hardening
```powershell
# Windows hardening
cd hardening/windows
.\CIS-Windows-Hardening.ps1 -Level 1

# Linux hardening
cd hardening/linux
sudo ./harden-ubuntu.sh
```

### Incident Response
```bash
# Quick triage
cd incident-response/triage
./quick-triage.sh

# Memory dump analysis
cd incident-response/forensics
./analyze-memory-dump.py dump.raw
```

## Detection Rule Categories

### Endpoint Detection
- Process monitoring
- Registry monitoring
- File integrity monitoring
- User behavior analytics

### Network Detection
- Anomalous network traffic
- C2 communication patterns
- Data exfiltration
- Port scanning detection

### Application Detection
- Web application attacks
- SQL injection attempts
- XSS detection
- API abuse

## Compliance Frameworks

Includes tools for:
- CIS Benchmarks
- NIST Cybersecurity Framework
- ISO 27001
- PCI-DSS
- HIPAA
- GDPR

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test your changes
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Yara Rules Collection](https://github.com/Yara-Rules/rules)
- [Blue Team Handbook](https://www.amazon.com/Blue-Team-Handbook-Condensed-Operations/dp/1500734756)

## License

MIT License - See [LICENSE](LICENSE) for details

## Support

For questions or issues:
- Open a GitHub issue
- Check documentation in `/docs`
- Review examples in `/examples`

---

**Defend Forward. Hunt Threats. Secure Systems.**
