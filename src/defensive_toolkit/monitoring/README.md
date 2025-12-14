# Security Monitoring & Alerting

Comprehensive security monitoring infrastructure for SIEM integration, log collection, dashboards, and health checks.

## Overview

This directory contains tools and configurations for:
- **SIEM Integration**: Deploy detection rules to Splunk, Azure Sentinel, Elastic
- **Log Collection**: Automated forwarding from Windows and Linux systems
- **Dashboards**: Pre-built security operation dashboards (Grafana, Kibana)
- **Health Monitoring**: Monitor security tool status and health
- **Alerting**: Configure automated alerts for security events

## Directory Structure

```
monitoring/
├── siem/                    # SIEM integration scripts
│   ├── splunk/             Splunk deployment automation
│   ├── sentinel/           Azure Sentinel deployment
│   ├── elastic/            Elastic Security deployment
│   └── wazuh/              Wazuh SIEM integration
├── collectors/              # Log collection & forwarding
│   ├── windows/            Windows Event Log forwarding
│   └── linux/              Linux syslog forwarding
├── dashboards/              # Security dashboards
│   ├── grafana/            Grafana JSON dashboards
│   └── kibana/             Kibana dashboard configs
├── health/                  # Health monitoring scripts
└── alerts/                  # Alert configurations
```

## Quick Start

### 1. Deploy Detection Rules to SIEM

**Splunk:**
```bash
cd siem/splunk
pip install -r requirements.txt

# Edit configuration
nano splunk_config.yml

# Deploy rules
python deploy_sigma_rules.py --config splunk_config.yml
```

**Azure Sentinel:**
```bash
cd siem/sentinel
pip install -r requirements.txt

# Configure Azure credentials
az login

# Edit configuration
nano sentinel_config.yml

# Deploy rules
python deploy_sigma_rules.py --config sentinel_config.yml
```

### 2. Configure Log Forwarding

**Windows (Splunk Universal Forwarder):**
```powershell
cd collectors/windows

# Forward logs to Splunk
.\forward-logs-splunk.ps1 -IndexerHost splunk.example.com -IndexerPort 9997 -EnableSysmon
```

**Linux (rsyslog):**
```bash
cd collectors/linux

# Forward logs via TCP
sudo ./forward-logs-rsyslog.sh -h siem.example.com -p 514 -t tcp

# Forward logs via TCP with TLS
sudo ./forward-logs-rsyslog.sh -h siem.example.com -p 6514 -t tcp -s
```

### 3. Import Security Dashboard

**Grafana:**
```bash
# Import dashboard JSON
cp dashboards/grafana/security-overview.json /etc/grafana/dashboards/

# Or via UI: Configuration > Data Sources > Import
```

### 4. Monitor Security Tool Health

**Windows:**
```powershell
cd health

# Run health check
.\check-security-tools.ps1

# Generate HTML report
.\check-security-tools.ps1 -OutputFormat HTML > health-report.html

# Schedule via Task Scheduler
schtasks /create /tn "Security Health Check" /tr "powershell.exe -File C:\path\to\check-security-tools.ps1" /sc hourly
```

## SIEM Integration

### Supported Platforms

| SIEM Platform | Status | Deployment Script | Configuration |
|---------------|--------|-------------------|---------------|
| **Splunk** | [OK] Implemented | `siem/splunk/deploy_sigma_rules.py` | `splunk_config.yml` |
| **Azure Sentinel** | [OK] Implemented | `siem/sentinel/deploy_sigma_rules.py` | `sentinel_config.yml` |
| **Elastic Security** | [*] Planned | - | - |
| **Wazuh** | [*] Planned | - | - |

### Features

- **Automated Deployment**: Convert and deploy Sigma rules automatically
- **Rule Management**: Update and manage detection rules from code
- **Scheduling**: Configure alert schedules and thresholds
- **Filtering**: Deploy only specific rules based on level or tags

### Prerequisites

**All Platforms:**
- Python 3.8+
- sigma-cli: `pip install sigma-cli`
- PyYAML: `pip install pyyaml`

**Splunk:**
- Splunk instance with API access
- Admin credentials
- `pip install splunk-sdk`

**Azure Sentinel:**
- Azure subscription
- Log Analytics workspace
- `pip install azure-mgmt-securityinsight azure-identity`
- Azure CLI: `az login`

### Configuration

Edit the relevant `*_config.yml` file for your SIEM platform:

**Splunk Example:**
```yaml
splunk:
  host: splunk.example.com
  port: 8089
  username: admin
  password: ${SPLUNK_PASSWORD}  # Use environment variable

  alert:
    email_to: security@example.com
    schedule: "*/15 * * * *"  # Every 15 minutes
```

**Azure Sentinel Example:**
```yaml
sentinel:
  subscription_id: your-subscription-id
  resource_group: rg-security
  workspace_name: law-sentinel

  analytics:
    query_frequency: PT15M
    query_period: PT15M
```

## Log Collection

### Windows Event Log Forwarding

The `forward-logs-splunk.ps1` script configures Splunk Universal Forwarder to collect:

**Standard Logs:**
- Security events (authentication, authorization)
- System events (services, drivers)
- Application events
- PowerShell (operational & classic)
- Windows Defender events
- Task Scheduler events
- Terminal Services (RDP) events

**Optional:**
- Sysmon events (requires Sysmon installed)

**Usage:**
```powershell
# Basic forwarding
.\forward-logs-splunk.ps1 -IndexerHost splunk.example.com

# With Sysmon
.\forward-logs-splunk.ps1 -IndexerHost splunk.example.com -EnableSysmon

# Custom Splunk installation path
.\forward-logs-splunk.ps1 -SplunkHome "D:\Splunk" -IndexerHost splunk.example.com
```

### Linux Syslog Forwarding

The `forward-logs-rsyslog.sh` script configures rsyslog to forward:

**All System Logs:**
- Authentication logs (/var/log/auth.log)
- System logs (/var/log/syslog)
- Kernel logs (/var/log/kern.log)
- Audit logs (/var/log/audit/audit.log)
- Application logs

**Protocol Options:**
- UDP (fast, less reliable)
- TCP (reliable)
- TCP with TLS (secure, recommended for production)

**Usage:**
```bash
# TCP forwarding
sudo ./forward-logs-rsyslog.sh -h siem.example.com -p 514 -t tcp

# UDP forwarding
sudo ./forward-logs-rsyslog.sh -h siem.example.com -p 514 -t udp

# Secure TLS forwarding
sudo ./forward-logs-rsyslog.sh -h siem.example.com -p 6514 -t tcp -s
```

## Security Dashboards

### Grafana Dashboards

**Security Operations Overview** (`dashboards/grafana/security-overview.json`)

Provides real-time visibility into:
- Security events rate (events/sec)
- Critical alerts (last 24h)
- Events timeline
- Events by severity distribution
- Top failed logon attempts
- PowerShell execution monitoring
- Network connection anomalies
- Detection rules status
- Systems monitored count
- SIEM health metrics

**Import Instructions:**
1. Copy JSON to Grafana dashboards directory
2. Or use Grafana UI: + > Import > Upload JSON
3. Configure data source (Prometheus recommended)
4. Customize time ranges and filters

### Kibana Dashboards

(Planned - templates coming soon)

## Health Monitoring

### Security Tool Health Check

The `check-security-tools.ps1` script monitors:

**Windows Components:**
- Windows Defender (antivirus status, signature updates)
- Windows Firewall (all profiles)
- Event Log service
- Security event log (recent events)
- Splunk Universal Forwarder (if installed)
- Sysmon (if installed)
- Disk space
- Windows Update status

**Output Formats:**
- Text (console, colored output)
- JSON (for automation/SIEM ingestion)
- HTML (for email reports)

**Usage:**
```powershell
# Console output
.\check-security-tools.ps1

# JSON output (for automation)
.\check-security-tools.ps1 -OutputFormat JSON

# HTML report
.\check-security-tools.ps1 -OutputFormat HTML > health-report.html
```

**Automation:**

Schedule via Task Scheduler:
```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\path\to\check-security-tools.ps1"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName "Security Health Check" -Action $action -Trigger $trigger
```

## Alerting

### Alert Configuration

Configure alerts in your SIEM based on deployed detection rules:

**Splunk:** Saved searches are created with alert actions configured
**Azure Sentinel:** Analytics rules create incidents automatically
**Custom:** Use health check JSON output for custom alerting

### Alert Best Practices

1. **Tune Detection Rules**: Start with monitoring mode before enabling alerts
2. **Reduce False Positives**: Add filters and whitelists
3. **Severity Mapping**:
   - Critical: Immediate response required
   - High: Response within 1 hour
   - Medium: Response within 4 hours
   - Low: Response within 24 hours
4. **Alert Fatigue**: Aggregate similar alerts
5. **Escalation**: Define escalation paths for each severity

## Integration Examples

### Integrate with SOAR

```python
# Example: Send health check results to SOAR platform
import requests
import json

health_data = subprocess.check_output([
    'powershell.exe',
    '-File', 'check-security-tools.ps1',
    '-OutputFormat', 'JSON'
])

requests.post(
    'https://soar.example.com/api/health',
    json=json.loads(health_data)
)
```

### Integrate with Slack

```bash
# Example: Send health check alerts to Slack
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

health_status=$(./check-security-tools.ps1 -OutputFormat JSON)
issues=$(echo $health_status | jq '.IssuesFound')

if [ $issues -gt 0 ]; then
    curl -X POST $SLACK_WEBHOOK -d "{\"text\":\"Security health check failed: $issues issues found\"}"
fi
```

## Troubleshooting

### SIEM Deployment Issues

**Problem:** Sigma rule conversion fails

**Solution:**
```bash
# Update sigma-cli
pip install --upgrade sigma-cli

# Test rule syntax
sigma check detection-rules/sigma/execution/suspicious_powershell_execution.yml

# Convert single rule for testing
sigma convert -t splunk detection-rules/sigma/execution/suspicious_powershell_execution.yml
```

**Problem:** Cannot connect to SIEM

**Solution:**
- Check network connectivity: `Test-NetConnection -ComputerName siem-host -Port 8089`
- Verify credentials
- Check firewall rules
- Review SIEM API documentation

### Log Forwarding Issues

**Problem:** Logs not appearing in SIEM

**Solution (Windows):**
```powershell
# Check Splunk Forwarder service
Get-Service SplunkForwarder

# Check logs
Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" -Tail 50

# Test connectivity
Test-NetConnection -ComputerName splunk-host -Port 9997
```

**Solution (Linux):**
```bash
# Check rsyslog service
systemctl status rsyslog

# Check rsyslog logs
tail -f /var/log/syslog | grep rsyslog

# Test connectivity
nc -zv siem-host 514

# Send test message
logger "Test message from rsyslog"
```

### Dashboard Issues

**Problem:** Dashboard shows no data

**Solution:**
- Verify data source configuration
- Check Prometheus/data source connectivity
- Ensure metrics are being collected
- Review time range selection
- Check dashboard variable configuration

## Best Practices

### SIEM Integration
1. **Test in Non-Production**: Always test rule deployment in dev/test environment first
2. **Version Control**: Keep SIEM configs in version control (Git)
3. **Documentation**: Document custom filters and modifications
4. **Change Management**: Follow change control processes for production deployments

### Log Collection
1. **Secure Transmission**: Use TLS/SSL for log forwarding
2. **Compression**: Enable compression to reduce bandwidth
3. **Queuing**: Configure disk queuing for reliability
4. **Filtering**: Filter noisy logs at source to reduce SIEM load
5. **Time Sync**: Ensure NTP is configured for accurate timestamps

### Monitoring
1. **Regular Reviews**: Review dashboards weekly
2. **Alert Tuning**: Continuously tune alerts to reduce false positives
3. **Health Checks**: Run health checks hourly
4. **Capacity Planning**: Monitor SIEM storage and performance
5. **Documentation**: Keep runbooks updated

## Support

### Documentation
- Sigma: https://sigmahq.io/docs/
- Splunk: https://docs.splunk.com/
- Azure Sentinel: https://docs.microsoft.com/en-us/azure/sentinel/
- Grafana: https://grafana.com/docs/

### Troubleshooting
- Check individual script comments for detailed usage
- Review log files for error messages
- Test connectivity with native tools first
- Validate configurations before deployment

---

**Monitor Continuously. Detect Early. Respond Quickly.**
