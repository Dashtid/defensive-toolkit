# Changelog

All notable changes to the Defensive Toolkit project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] - 2025-11-26

### Added
- **Enhanced Detection Rules** (2025 Threat Landscape):
  - 33 new Sigma rules across 11 MITRE ATT&CK tactics (39 total)
  - 22 new YARA rules for modern malware detection
  - 79% MITRE ATT&CK technique coverage
- **2025 Threat-Specific YARA Rules**:
  - Infostealers: LummaC2, Vidar, RedLine, StrelaStealer, Raccoon v2
  - Ransomware: LockBit 4.0, BlackCat/ALPHV, Qilin, RansomHub
  - Loaders: HijackLoader, SocGholish, BatLoader, GootLoader
  - C2 Frameworks: Cobalt Strike, Sliver, Brute Ratel C4
- **New Sigma Detection Categories**:
  - Execution: MSHTA, Regsvr32, LOLBAS, Paste-and-Run attacks
  - Credential Access: DCSync, Kerberoasting, Browser credential theft
  - Defense Evasion: AMSI bypass, ETW tampering, Process hollowing
  - Lateral Movement: PsExec, WinRM, RDP hijacking
  - Command & Control: Cobalt Strike, Sliver, DNS beaconing
- **Detection Validation Infrastructure**:
  - `scripts/validate_detection_rules.py` - Comprehensive rule validator
  - Unit tests for Sigma and YARA rule syntax/structure
  - JSON export for CI/CD integration
- **Portfolio Documentation**:
  - `COVERAGE_MATRIX.md` - Full MITRE ATT&CK coverage map
  - Updated README with 2025 threat statistics
  - Detection engineering workflow documentation

### Changed
- Updated pyproject.toml to modern dependency-groups format
- Added hatch build targets for wheel packaging
- Improved YARA rule extraction with proper brace matching

### Fixed
- YARA rule syntax errors (unreferenced strings in conditions)
- Validation script brace matching for nested rule structures

---

## [1.2.0] - 2025-11-26

### Added
- **Linux Hardening Suite** (CIS Benchmark L1/L2/L3):
  - Comprehensive Linux security hardening scripts
  - Audit mode for compliance checking
  - Backup and restore capabilities
- **Hardening Test Suite**:
  - Unit tests for hardening configuration validation
  - Cross-platform test coverage

---

## [1.1.0] - 2025-10-18

### Added
- **Comprehensive Test Suite**: 400+ tests across all 10 security categories
  - Unit tests for automation, compliance, forensics, log analysis, vulnerability management
  - Integration tests for SOAR workflows
  - 80%+ code coverage achieved
- **Modern Dependency Management**: uv package manager integration (10-100x faster than pip)
- **CI/CD Pipeline**: GitHub Actions workflows for automated testing
  - Multi-OS testing (Ubuntu, Windows)
  - Multi-version testing (Python 3.10, 3.11, 3.12)
  - Security scanning with Bandit
  - Code quality checks (Ruff, Black, mypy)
- **Utility Scripts**:
  - `scripts/cleanup.py` - Deep project cleanup utility
  - `scripts/validate_project.py` - Project structure validation
  - `scripts/generate_docs.py` - API documentation generator
- **Comprehensive Documentation**:
  - `docs/TESTING.md` - Complete testing guide
  - `docs/ARCHITECTURE.md` - System architecture documentation
  - `docs/DEPLOYMENT.md` - Enterprise deployment guide
  - `docs/API_REFERENCE.md` - Auto-generated API documentation
  - `docs/TROUBLESHOOTING.md` - Troubleshooting guide
  - `docs/CHANGELOG.md` - This file
  - `scripts/README.md` - Utility scripts documentation
- **Test Infrastructure**:
  - 50+ shared fixtures in `conftest.py`
  - Test markers for categorization (unit, integration, slow, platform-specific)
  - Parametrized tests for data variations
  - Performance benchmarks
- **Code Quality Tools**:
  - Bandit for security linting (SAST)
  - Black for code formatting
  - Ruff for fast linting
  - mypy for type checking
  - pytest-cov for coverage reporting

### Changed
- Reorganized project structure with proper `__init__.py` files (31 total)
- Updated main README.md with testing section and uv installation instructions
- Updated CONTRIBUTING.md with test requirements
- Updated .gitignore for uv and testing artifacts
- Modernized pyproject.toml with PEP 621 compliance and tool configurations
- Improved error handling across all modules

### Fixed
- Import path inconsistencies (hyphens vs underscores)
- Module structure for proper Python packaging
- Cross-platform compatibility issues

---

## [1.0.0] - 2025-10-15

### Added
- **Initial Release**: Complete 10-category defensive security toolkit
- **Detection Rules** (6 Sigma rules, 3 YARA rulesets):
  - Execution (T1059): PowerShell, WMI execution
  - Persistence (T1547, T1053): Registry run keys, scheduled tasks
  - Credential Access (T1003): LSASS dumping
  - Defense Evasion (T1070): Event log clearing
  - Webshell detection (PHP, ASPX, JSP, China Chopper)
  - Ransomware detection (WannaCry, generic patterns)
  - Suspicious script detection (PowerShell, VBScript, obfuscation)
- **Incident Response**:
  - 2 comprehensive playbooks (ransomware, malware infection)
  - Windows triage script (PowerShell, 400+ lines)
  - Linux triage script (Bash, 350+ lines)
  - Chain of custody and manifest generation
- **Threat Hunting**:
  - 7 KQL queries (Azure Sentinel/Defender)
  - 10 SPL queries (Splunk lateral movement detection)
  - 20 EQL queries (Elastic Security credential access)
  - PowerShell obfuscation detection
  - Lateral movement hunting
- **Security Hardening**:
  - 9 PowerShell hardening scripts
  - 3 hardening levels (safe, balanced, maximum)
  - Audit, backup, and restore capabilities
  - Coverage: UAC, Defender, Firewall, BitLocker, SMB, policies
- **Monitoring**:
  - SIEM integration (Syslog forwarder, WEF configuration)
  - Log forwarding (Rsyslog, WinRM)
  - Dashboards (Grafana, Splunk templates)
  - Health checks (system, security, performance)
- **Forensics**:
  - Memory analysis with Volatility automation
  - MFT extraction and analysis
  - Artifact collection (browser, Windows, Linux)
  - Timeline generation
  - Master evidence collector
- **Vulnerability Management**:
  - OpenVAS/GVM integration
  - Nmap NSE scripting
  - Trivy container scanning
  - SBOM generation (Syft, CISA 2025 compliant)
  - Multi-factor risk scoring (CVSS, KEV, exploitability, asset criticality)
  - KEV catalog integration (CISA Known Exploited Vulnerabilities)
  - HTML/Markdown/JSON reporting
- **Automation & SOAR**:
  - YAML-based playbook engine (400+ lines)
  - Containment actions (host isolation, IP blocking, file quarantine)
  - Enrichment actions (IOC enrichment, threat intel, geolocation)
  - Notification actions (email, ticketing)
  - SIEM, ticketing, and email integrations
  - 4 example workflows (phishing, malware, vuln remediation, alert enrichment)
- **Compliance**:
  - CIS Controls v8 checker (7 controls, Windows/Linux)
  - NIST 800-53 Rev 5 checker (6 families, 3 impact levels)
  - Multi-framework mapper (CIS, NIST, ISO 27001, PCI-DSS, SOC2)
  - YAML-based policy validation
  - Configuration drift detection (SHA256-based)
  - HTML compliance dashboards
- **Log Analysis**:
  - Universal log parser (Syslog, JSON, Apache, Nginx, Windows Event Log)
  - Auto-format detection
  - Statistical anomaly detection (frequency, pattern, statistical, rate)
  - Baseline management (create from historical data)
  - Text/JSON anomaly reports with severity classification

### Documentation
- Comprehensive README.md with overview and quick start
- PROJECT_STATUS.md with implementation summary
- CONTRIBUTING.md with contribution guidelines
- SECURITY.md with security policy and reporting
- GETTING_STARTED.md with detailed setup instructions
- Category-specific README files (10 categories)
- Example configurations and workflows
- LICENSE (MIT)

### Infrastructure
- Python 3.8+ support
- Multi-platform (Windows, Linux)
- Git repository structure
- requirements.txt for dependencies
- .gitignore for common patterns
- GitHub repository ready for CI/CD

---

## Future Releases

### [1.2.0] - Planned
- Docker containerization
- REST API for toolkit access
- Web dashboard for monitoring
- Additional cloud platform detection rules (AWS, Azure, GCP)
- Kubernetes threat hunting queries

### [2.0.0] - Future
- Full SOAR platform (not just integrations)
- Machine learning anomaly models
- Mobile device forensics
- SaaS offering
- AI-powered threat hunting

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.3.0 | 2025-11-26 | Enhanced detection rules with 2025 threat coverage |
| 1.2.0 | 2025-11-26 | Linux hardening suite with CIS Benchmark support |
| 1.1.0 | 2025-10-18 | Comprehensive testing, documentation, modernization |
| 1.0.0 | 2025-10-15 | Initial release with 10 complete categories |

---

## Contributors

Thank you to all contributors who have helped build the Defensive Toolkit!

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to contribute.

---

## Support

For questions, issues, or feature requests:
- GitHub Issues: https://github.com/yourusername/defensive-toolkit/issues
- Documentation: https://github.com/yourusername/defensive-toolkit/tree/main/docs
- Security Issues: See [SECURITY.md](../SECURITY.md)

---

**Defend Forward. Hunt Threats. Secure Systems.**
