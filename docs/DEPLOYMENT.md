# Defensive Toolkit - Deployment Guide

**Version**: 1.0.0
**Last Updated**: 2025-10-18

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
- [Configuration](#configuration)
- [Deployment Scenarios](#deployment-scenarios)
- [SIEM Integration](#siem-integration)
- [SOAR Integration](#soar-integration)
- [Production Hardening](#production-hardening)
- [Monitoring & Maintenance](#monitoring--maintenance)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Hardware**:
- CPU: 2+ cores recommended
- RAM: 4GB minimum, 8GB recommended
- Disk: 10GB minimum for installation + logs/artifacts
- Network: Outbound HTTPS for updates, scanners, threat intel

**Operating Systems**:
- Windows 10/11 or Windows Server 2016+
- Ubuntu 20.04+, Debian 11+, RHEL 8+, or equivalent Linux

**Software**:
- Python 3.10, 3.11, or 3.12
- Git
- PowerShell 7+ (for Windows tools)
- Administrative/root privileges (for many tools)

### Access Requirements

- Permission to install software on target systems
- Network access to SIEM, ticketing, and scanning infrastructure
- API credentials for integrated services (SIEM, ticketing, threat intel)
- Authorization to perform security operations on target systems

---

## Installation Methods

### Method 1: uv (Recommended - 10-100x Faster)

```bash
# 1. Install uv package manager
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# 2. Clone repository
git clone https://github.com/yourusername/defensive-toolkit.git
cd defensive-toolkit

# 3. Install dependencies
uv sync --all-extras --dev

# 4. Verify installation
uv run python -c "import yaml; print('Success!')"
```

### Method 2: pip (Traditional)

```bash
# 1. Clone repository
git clone https://github.com/yourusername/defensive-toolkit.git
cd defensive-toolkit

# 2. Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install in editable mode
pip install -e .

# 5. Verify installation
python -c "import yaml; print('Success!')"
```

### Method 3: System-Wide Installation

```bash
# Not recommended for production
# Only use for dedicated security appliances

pip install -r requirements.txt
pip install .
```

---

## Configuration

### Environment Variables

Create `.env` file in project root (never commit to Git):

```bash
# SIEM Configuration
SIEM_TYPE=splunk  # splunk, sentinel, elastic, qradar
SIEM_HOST=splunk.example.com
SIEM_PORT=8089
SIEM_API_KEY=your-api-key-here

# Ticketing System
TICKET_SYSTEM=jira  # jira, servicenow
TICKET_URL=https://jira.example.com
TICKET_API_TOKEN=your-token-here
TICKET_PROJECT_KEY=SEC

# Email Notifications
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=security@example.com
SMTP_PASSWORD=your-password-here
SMTP_FROM=security@example.com
SMTP_TO=soc@example.com

# Threat Intelligence
VIRUSTOTAL_API_KEY=your-vt-api-key
ABUSEIPDB_API_KEY=your-abuse-api-key

# OpenVAS/GVM Scanner
OPENVAS_HOST=scanner.example.com
OPENVAS_PORT=9390
OPENVAS_USER=admin
OPENVAS_PASSWORD=your-password-here

# General Settings
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
ENVIRONMENT=production  # development, staging, production
```

### Configuration Files

**Playbook Configuration** (`automation/playbooks/config.yml`):

```yaml
# SOAR Configuration
dry_run: false  # Set true for testing
timeout: 3600  # Task timeout in seconds
max_retries: 3

# Containment Actions
containment:
  isolation_method: firewall  # firewall, edr, vlan
  block_duration: 3600  # seconds
  quarantine_dir: /quarantine

# Enrichment Settings
enrichment:
  max_iocs_per_request: 100
  cache_duration: 86400  # 24 hours
```

**Compliance Configuration** (`compliance/policy/security_policy.yml`):

```yaml
# Security Policies
password_policy:
  min_length: 14
  complexity: true
  max_age_days: 90

logging_policy:
  retention_days: 365
  syslog_enabled: true

firewall_policy:
  default_deny: true
  allowed_ports: [22, 443, 3389]
```

---

## Deployment Scenarios

### Scenario 1: Analyst Workstation

**Use Case**: Single security analyst performing investigations

```bash
# 1. Install on analyst workstation
cd /opt
git clone https://github.com/yourusername/defensive-toolkit.git
cd defensive-toolkit
uv sync --all-extras --dev

# 2. Configure
cp .env.example .env
nano .env  # Add credentials

# 3. Verify
uv run pytest tests/ -m "not slow" -v

# 4. Create alias for convenience
echo 'alias toolkit="cd /opt/defensive-toolkit && uv run"' >> ~/.bashrc
```

**Tools Primarily Used**:
- Threat hunting queries
- Forensic analysis tools
- Log parsing and anomaly detection
- Manual playbook execution

### Scenario 2: SOC Team Deployment

**Use Case**: Multiple analysts with shared infrastructure

**Installation** (on each analyst workstation):
```bash
# Use shared network location for consistency
git clone https://github.com/yourusername/defensive-toolkit.git /shared/toolkit
cd /shared/toolkit
uv sync --all-extras --dev
```

**Shared Configuration**:
- Central .env file on network share (secured with proper permissions)
- Shared SIEM credentials
- Common ticketing system
- Centralized logging

**Tools Primarily Used**:
- All detection rules deployed to SIEM
- Shared threat hunting queries
- Coordinated incident response
- Compliance dashboards

### Scenario 3: Automated SOAR Integration

**Use Case**: Automated incident response in enterprise SOC

**Server Installation**:
```bash
# On dedicated SOAR server
useradd -m -s /bin/bash soar
su - soar

git clone https://github.com/yourusername/defensive-toolkit.git
cd defensive-toolkit
uv sync --all-extras

# Create systemd service (as root)
sudo cat > /etc/systemd/system/toolkit-soar.service <<EOF
[Unit]
Description=Defensive Toolkit SOAR Engine
After=network.target

[Service]
Type=simple
User=soar
WorkingDirectory=/home/soar/defensive-toolkit
ExecStart=/home/soar/.local/bin/uv run python automation/playbooks/playbook_engine.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable toolkit-soar
sudo systemctl start toolkit-soar
```

**Tools Primarily Used**:
- Automated playbook execution
- API integrations (SIEM, ticketing, email)
- Containment actions
- IOC enrichment

### Scenario 4: Scanning Server

**Use Case**: Dedicated vulnerability scanning server

**Installation**:
```bash
# Install toolkit
git clone https://github.com/yourusername/defensive-toolkit.git /opt/toolkit
cd /opt/toolkit
uv sync

# Install OpenVAS (Ubuntu/Debian)
sudo apt update
sudo apt install -y openvas
sudo gvm-setup
sudo gvm-start

# Install Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update
sudo apt install trivy

# Schedule daily scans (crontab)
crontab -e
# Add: 0 2 * * * cd /opt/toolkit && uv run python vulnerability-mgmt/scanners/openvas_scan.py --targets production
```

---

## SIEM Integration

### Integration

**Deploy Detection Rules**:
```bash
# Convert Sigma rules to SPL
uv run sigma convert -t splunk detection-rules/sigma/execution/*.yml > splunk-detections.spl

# Upload to Splunk
# Via Web UI: Settings > Searches, reports, and alerts > New Alert
# Or via API:
curl -k -u admin:password https://splunk.example.com:8089/services/saved/searches \
  -d name="Suspicious PowerShell Execution" \
  -d search="index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine=*bypass*" \
  -d actions="email"
```

**Deploy Threat Hunting Queries**:
```bash
# Copy SPL queries
cat threat-hunting/queries/spl/lateral_movement.spl

# Create saved searches in Splunk
# Each query becomes a saved search for ad-hoc hunting
```

### Azure Sentinel Integration

**Deploy Detection Rules**:
```bash
# Convert Sigma to KQL
uv run sigma convert -t sentinel detection-rules/sigma/persistence/*.yml > sentinel-analytics.kql

# Deploy via Azure Portal:
# Sentinel > Analytics > Create > Scheduled query rule
# Or via ARM template/PowerShell
```

**Deploy Hunting Queries**:
```bash
# Hunting queries go to Sentinel > Hunting
# Copy KQL from threat-hunting/queries/kql/
```

### Elastic Security Integration

**Deploy Detection Rules**:
```bash
# Convert Sigma to EQL
uv run sigma convert -t elasticsearch detection-rules/sigma/credential-access/*.yml > elastic-rules.json

# Import to Elastic:
# Security > Rules > Import rules
```

### Log Forwarding

**Syslog Forwarding (Linux)**:
```bash
# Install and configure rsyslog
sudo apt install rsyslog
sudo cat > /etc/rsyslog.d/50-defensive-toolkit.conf <<EOF
# Forward security logs to SIEM
*.* @@siem.example.com:514
EOF

sudo systemctl restart rsyslog
```

**Windows Event Forwarding**:
```powershell
# Configure WEF on Windows
# Run as Administrator

# Set Event Collector service to auto-start
wecutil qc

# Create subscription
wecutil cs /c:config.xml
```

---

## SOAR Integration

### Generic REST API Integration

Most SOAR platforms support REST APIs. Configure the toolkit to call your SOAR:

**Example - Trigger Playbook via REST**:
```python
# automation/integrations/soar_connector.py
import requests

def trigger_playbook(playbook_name, incident_data):
    soar_url = os.getenv("SOAR_URL")
    api_key = os.getenv("SOAR_API_KEY")

    response = requests.post(
        f"{soar_url}/api/playbooks/{playbook_name}/execute",
        headers={"Authorization": f"Bearer {api_key}"},
        json=incident_data
    )

    return response.json()
```

### Playbook Export

Export playbooks in YAML format compatible with most SOAR platforms:

```bash
# Export all playbooks
cp automation/playbooks/examples/*.yml /path/to/soar/import/
```

---

## Production Hardening

### Security Hardening

**1. Restrict File Permissions**:
```bash
# Secure credentials
chmod 600 .env

# Secure scripts
chmod 750 automation/ compliance/ forensics/ -R
chown -R securityteam:securityteam .
```

**2. Use Secrets Management**:
```bash
# Instead of .env, use HashiCorp Vault, AWS Secrets Manager, etc.
# Example with AWS Secrets Manager:
aws secretsmanager get-secret-value --secret-id defensive-toolkit/siem --query SecretString --output text
```

**3. Enable Audit Logging**:
```python
# All tools should log to syslog
import logging.handlers

handler = logging.handlers.SysLogHandler(address='/dev/log')
logger.addHandler(handler)
logger.info("Playbook executed by user %s", os.getenv("USER"))
```

**4. Network Segmentation**:
- Deploy toolkit on management network
- Restrict outbound connections to known IPs (SIEM, scanners, APIs)
- Use firewall rules to limit access

**5. Regular Updates**:
```bash
# Weekly updates
cd /opt/defensive-toolkit
git pull
uv sync --upgrade
```

### High Availability

**Load Balancing** (for SOAR automation):
```
┌────────────────┐
│  Load Balancer │
└────┬──────┬────┘
     │      │
┌────▼──┐ ┌─▼─────┐
│ SOAR1 │ │ SOAR2 │
└───────┘ └───────┘
```

**Database Backend** (for state management):
```bash
# Use PostgreSQL or MySQL for playbook state tracking
# Store: execution logs, IOC cache, baseline data
```

---

## Monitoring & Maintenance

### Health Checks

**Daily Health Check Script**:
```bash
#!/bin/bash
# health-check.sh

cd /opt/defensive-toolkit

# Check Python dependencies
uv run python -c "import yaml, requests, psutil" || echo "ALERT: Dependencies missing"

# Check SIEM connectivity
uv run python -c "import requests; r=requests.get('https://siem.example.com'); assert r.status_code==200" || echo "ALERT: SIEM unreachable"

# Check scanner connectivity
uv run python -c "from gvm.connections import TLSConnection; conn=TLSConnection(hostname='scanner.example.com')" || echo "ALERT: Scanner unreachable"

# Check log rotation
LOG_SIZE=$(du -sm logs/ | cut -f1)
[ $LOG_SIZE -gt 10000 ] && echo "ALERT: Logs exceed 10GB, rotate now"

echo "Health check complete"
```

**Schedule via cron**:
```bash
0 */6 * * * /opt/defensive-toolkit/health-check.sh | mail -s "Toolkit Health Check" soc@example.com
```

### Log Rotation

```bash
# /etc/logrotate.d/defensive-toolkit
/opt/defensive-toolkit/logs/*.log {
    daily
    rotate 90
    compress
    delaycompress
    notifempty
    create 0640 securityteam securityteam
}
```

### Backup Strategy

**What to Backup**:
- Configuration files (.env, YAML configs)
- Custom playbooks and rules
- Forensic artifacts and evidence
- Baseline data for anomaly detection

**Backup Script**:
```bash
#!/bin/bash
# backup.sh

BACKUP_DIR=/backups/defensive-toolkit
DATE=$(date +%Y%m%d)

tar czf $BACKUP_DIR/toolkit-config-$DATE.tar.gz \
  .env \
  automation/playbooks/examples/*.yml \
  compliance/policy/*.yml \
  detection-rules/

# Retain 30 days of backups
find $BACKUP_DIR -name "toolkit-config-*.tar.gz" -mtime +30 -delete
```

---

## Troubleshooting

### Common Issues

**1. "ModuleNotFoundError"**:
```bash
# Solution: Reinstall dependencies
uv sync --all-extras --dev
```

**2. "Permission Denied" during scans**:
```bash
# Solution: Run with sudo or check SELinux/AppArmor
sudo uv run python vulnerability-mgmt/scanners/openvas_scan.py
```

**3. "SIEM connection timeout"**:
```bash
# Solution: Check firewall, DNS, API key validity
curl -v https://siem.example.com
```

**4. "Playbook execution failed"**:
```bash
# Solution: Enable dry-run mode first
export DRY_RUN=true
uv run python automation/playbooks/playbook_engine.py phishing_response.yml
```

### Getting Support

- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed issues
- Review logs in `logs/` directory
- Enable DEBUG logging: `export LOG_LEVEL=DEBUG`
- Open GitHub issue with full error details

---

**For more information**:
- [Architecture Documentation](ARCHITECTURE.md)
- [Getting Started Guide](GETTING_STARTED.md)
- [Testing Documentation](TESTING.md)
- [API Reference](API_REFERENCE.md)
