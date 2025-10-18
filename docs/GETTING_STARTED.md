# Getting Started with Defensive Toolkit

Welcome to the Defensive Toolkit! This guide will help you get up and running quickly with the tools and resources in this repository.

## Prerequisites

### Required Skills
- Basic understanding of security concepts
- Command-line proficiency (PowerShell, Bash)
- Familiarity with your SIEM platform (if deploying detection rules)
- System administration experience (for hardening scripts)

### Required Access
- **Authorization**: Only use these tools on systems you own or have explicit permission to test
- **Administrative privileges**: Many scripts require admin/root access
- **Lab environment**: Recommended for testing before production deployment

### Software Requirements

**All Platforms:**
- Git
- Python 3.8+ (for analysis scripts)
- Text editor or IDE

**Windows:**
- PowerShell 5.1+ (PowerShell 7+ recommended)
- Windows 10/11 or Windows Server 2016+

**Linux:**
- Bash shell
- Standard utilities (grep, awk, sed)
- Root/sudo access

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/defensive-toolkit.git
cd defensive-toolkit
```

### 2. Install Dependencies

**Using uv (Recommended - 10-100x faster)**:
```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh  # macOS/Linux
# or: powershell -c "irm https://astral.sh/uv/install.ps1 | iex"  # Windows

# Install dependencies
uv sync --all-extras --dev
```

**Using pip (Traditional)**:
```bash
pip install -r requirements.txt
```

### 3. Verify Installation

```bash
# Check Python packages
pip list | grep -E "yara|sigma"

# On Windows: Check PowerShell version
pwsh --version

# On Linux: Check bash version
bash --version
```

## Quick Start Guides

### Deploy Detection Rules

**Option A: Sigma Rules to Your SIEM**

```bash
# Install Sigma CLI
pip install sigma-cli

# Convert rules to Splunk
sigma convert -t splunk detection-rules/sigma/execution/*.yml

# Convert rules to Azure Sentinel
sigma convert -t sentinel detection-rules/sigma/credential-access/*.yml

# Convert rules to Elastic
sigma convert -t elasticsearch detection-rules/sigma/persistence/*.yml
```

**Option B: YARA Rules for File Scanning**

```bash
# Install YARA
# Ubuntu/Debian:
sudo apt-get install yara

# macOS:
brew install yara

# Windows (Chocolatey):
choco install yara

# Scan a file
yara detection-rules/yara/webshells.yar /path/to/suspicious/file.php

# Scan a directory
yara -r detection-rules/yara/*.yar /path/to/scan/
```

### Run Security Hardening

**Windows Hardening (Level 1 - Safe):**

```powershell
# Open PowerShell as Administrator
cd hardening/windows-security

# Backup current settings first
.\backup-security-settings.ps1

# Audit current posture
.\audit-security-posture.ps1

# Apply Level 1 hardening
.\harden-level1-safe.ps1
```

**Important:** Always backup and audit before hardening!

### Incident Response Triage

**Windows System:**

```powershell
# Run as Administrator
.\incident-response\scripts\windows-triage.ps1 -OutputDir C:\Evidence -Quick
```

**Linux System:**

```bash
# Run as root
sudo ./incident-response/scripts/linux-triage.sh -o /tmp/evidence -q
```

### Threat Hunting

**Azure Sentinel/Defender:**

1. Open Azure Portal > Sentinel > Logs
2. Copy query from `threat-hunting/queries/kql/`
3. Paste into query editor
4. Adjust time range
5. Run query

**Splunk:**

1. Open Splunk > Search & Reporting
2. Copy query from `threat-hunting/queries/spl/`
3. Paste into search bar
4. Adjust time range and index
5. Run search

**Elastic Security:**

1. Open Kibana > Security > Timelines
2. Select "Event Correlation (EQL)"
3. Copy query from `threat-hunting/queries/eql/`
4. Paste and run

## Directory Guide

### Core Directories

| Directory | Purpose | Start Here |
|-----------|---------|------------|
| **detection-rules/** | Sigma, YARA, Snort rules | `detection-rules/README.md` |
| **incident-response/** | IR playbooks and scripts | `incident-response/playbooks/` |
| **threat-hunting/** | SIEM queries (KQL, SPL, EQL) | `threat-hunting/queries/` |
| **hardening/** | Security hardening scripts | `hardening/windows-security/README.md` |
| **monitoring/** | Security monitoring scripts | `monitoring/README.md` |
| **forensics/** | Forensics tools | `forensics/README.md` |
| **examples/** | Practical examples | `examples/README.md` |
| **docs/** | Documentation | This file! |

### Key Files

- `README.md` - Project overview
- `SECURITY.md` - Security policy and reporting
- `CONTRIBUTING.md` - How to contribute
- `requirements.txt` - Python dependencies

## Common Use Cases

### Use Case 1: Set Up Detection Rules

**Goal:** Deploy detection rules to your SIEM for automated alerting

**Steps:**
1. Review `detection-rules/README.md`
2. Select rules relevant to your environment
3. Test rules in non-production first
4. Convert to your SIEM format using Sigma CLI
5. Deploy and tune for false positives
6. Enable alerting

**Time:** 1-2 hours (initial setup)

### Use Case 2: Respond to Security Incident

**Goal:** Collect forensic data from potentially compromised system

**Steps:**
1. Review appropriate playbook in `incident-response/playbooks/`
2. Isolate affected system (if required)
3. Run triage script to collect evidence
4. Follow playbook procedures
5. Document all actions

**Time:** 30 minutes - several hours (depending on incident)

### Use Case 3: Proactive Threat Hunting

**Goal:** Hunt for threats that may have evaded automated detection

**Steps:**
1. Select hunting queries from `threat-hunting/queries/`
2. Understand what each query detects
3. Run queries against your SIEM logs
4. Analyze results and investigate anomalies
5. Update detection rules based on findings

**Time:** 1-4 hours (per hunting session)

### Use Case 4: Harden New System

**Goal:** Apply security hardening to new Windows/Linux system

**Steps:**
1. Review hardening README for your OS
2. Create system backup or snapshot
3. Run audit script to baseline current state
4. Run appropriate hardening level
5. Test system functionality
6. Document changes

**Time:** 1-2 hours (per system)

## Best Practices

### Testing First
- **Always** test in lab environment before production
- **Never** deploy untested rules or scripts
- **Always** have a rollback plan

### Documentation
- Document all changes made using these tools
- Keep audit logs of hardening activities
- Maintain chain of custody for IR evidence

### Tuning
- Detection rules require tuning for your environment
- Start with monitoring mode before enabling alerts
- Track and reduce false positives iteratively

### Updates
- Regularly pull latest rules and scripts
- Review changelogs for breaking changes
- Contribute improvements back to the project

### Security
- Never commit credentials or sensitive data
- Follow your organization's security policies
- Maintain proper authorization for all activities

## Troubleshooting

### Sigma Rules Not Converting

**Problem:** Sigma CLI errors or incorrect output

**Solutions:**
- Update sigma-cli: `pip install --upgrade sigma-cli`
- Verify rule syntax: Check YAML formatting
- Check supported backends: `sigma list targets`

### YARA Rules Not Matching

**Problem:** YARA rules don't detect known malware

**Solutions:**
- Verify file is actually malicious (use VirusTotal)
- Check file format matches rule expectations
- Test with simplified rule conditions
- Ensure YARA version is up to date

### Script Permission Denied

**Problem:** Scripts fail with permission errors

**Solutions:**
- Run as Administrator (Windows) or root (Linux)
- Check file permissions: `chmod +x script.sh` (Linux)
- Set execution policy: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process` (Windows)

### SIEM Query Timeout

**Problem:** Hunting queries timeout or take too long

**Solutions:**
- Reduce time range
- Add filters to narrow scope
- Check index/sourcetype is correct
- Optimize query (avoid wildcards at start of strings)

## Next Steps

### Beginner Path
1. Start with detection rules (easiest to deploy)
2. Explore threat hunting queries
3. Review incident response playbooks
4. Test triage scripts in lab

### Intermediate Path
1. Deploy comprehensive detection rules
2. Conduct regular threat hunting sessions
3. Customize hardening scripts for your environment
4. Practice incident response procedures

### Advanced Path
1. Develop custom detection rules
2. Automate threat hunting
3. Integrate with SOAR platforms
4. Contribute to the project

## Getting Help

### Documentation
- Check `docs/` directory for detailed guides
- Review README files in each directory
- Read inline code comments

### Issues
- Search existing issues on GitHub
- Open new issue with detailed description
- Include error messages and environment details

### Community
- Follow project discussions
- Share findings and improvements
- Help others in issue threads

## Resources

### External Learning
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [YARA Documentation](https://yara.readthedocs.io/)
- [Blue Team Handbook](https://www.blueteamhandbook.com/)

### Training
- [SANS Blue Team Courses](https://www.sans.org/cybersecurity-courses/)
- [Cybrary Defensive Security](https://www.cybrary.it/)
- [HTB Academy - Defensive Security](https://academy.hackthebox.com/)

---

**Ready to defend? Pick a use case above and start securing your environment!**

For detailed documentation on specific tools, see the README in each directory.
