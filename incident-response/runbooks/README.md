# Incident Response Runbooks

Automated incident response orchestration with approval gates, evidence preservation, and graduated response automation.

## Overview

This module provides a YAML-based runbook execution engine for automating incident response workflows. Key features:

- **Approval Gates**: High-risk actions require analyst approval
- **Evidence Chain of Custody**: All collected evidence is hashed and timestamped
- **Dry-Run Mode**: Validate runbooks without executing actions
- **Rollback Tracking**: Actions that can be undone are tracked for rollback
- **Graduated Automation**: Auto-approve low-risk actions, prompt for high-risk

## Quick Start

```bash
# Validate a runbook (dry run)
python runbook_engine.py --runbook templates/ransomware.yaml --dry-run

# Execute with approval prompts
python runbook_engine.py --runbook templates/malware.yaml

# Auto-approve low severity actions
python runbook_engine.py --runbook templates/credential_compromise.yaml --auto-approve low

# Specify output directory
python runbook_engine.py --runbook templates/ransomware.yaml --output-dir /path/to/evidence
```

## Directory Structure

```
incident-response/runbooks/
    runbook_engine.py       # Main execution engine
    __init__.py
    actions/
        __init__.py
        containment.py      # Host isolation, IP blocking, account disable
        preservation.py     # Evidence collection, forensic packaging
        escalation.py       # Alerts, tickets, on-call notification
    templates/
        ransomware.yaml     # Ransomware response playbook
        malware.yaml        # General malware response
        credential_compromise.yaml  # Compromised credentials
```

## Runbook Template Format

```yaml
name: Incident Response Runbook
description: Description of the runbook
version: "1.0.0"

variables:
  alert_email: "security@company.com"

steps:
  - name: Step name
    action: action_name
    severity: low|medium|high|critical
    description: What this step does
    when: "optional_condition"
    parameters:
      param1: value1
      param2: "${variable}"
```

## Severity Levels

| Level | Auto-Approve | Description | Examples |
|-------|--------------|-------------|----------|
| `low` | Always | Logging, variable setting | Log messages, set variables |
| `medium` | Optional | Evidence collection, alerts | Collect logs, send notifications |
| `high` | Never | Containment actions | Block IP, kill process, quarantine |
| `critical` | Never | Destructive/irreversible | Disable account, isolate host |

Use `--auto-approve low` or `--auto-approve medium` to skip prompts for lower severity actions.

## Available Actions

### Containment Actions

| Action | Severity | Description |
|--------|----------|-------------|
| `isolate_host` | critical | Isolate host from network via firewall |
| `block_ip` | high | Block IP address inbound/outbound |
| `disable_account` | critical | Disable user account |
| `quarantine_file` | high | Move file to quarantine with metadata |
| `kill_process` | high | Terminate process by name or PID |

### Preservation Actions

| Action | Severity | Description |
|--------|----------|-------------|
| `collect_evidence` | medium | Collect evidence (logs, processes, network, etc.) |
| `run_triage` | medium | Execute triage script (windows/linux) |
| `create_forensic_package` | medium | Package evidence with chain of custody |
| `capture_memory` | medium | Capture memory dump (requires tools) |
| `snapshot_disk` | medium | Create disk snapshot (VSS on Windows) |

### Escalation Actions

| Action | Severity | Description |
|--------|----------|-------------|
| `send_alert` | medium | Send alert via email/Slack/Teams/PagerDuty |
| `create_ticket` | medium | Create ticket in Jira/ServiceNow |
| `update_severity` | low | Update incident severity level |
| `notify_oncall` | medium | Page on-call personnel |

### Control Flow Actions

| Action | Severity | Description |
|--------|----------|-------------|
| `log` | low | Log a message |
| `set_variable` | low | Set a runtime variable |
| `prompt_analyst` | medium | Prompt analyst for input |
| `conditional` | low | Conditional branching |

## Evidence Types

The `collect_evidence` action supports these evidence types:

- `logs` - System/security event logs
- `files` - Specific files or directories
- `registry` - Windows registry keys (forensic locations)
- `processes` - Running process information
- `network` - Network connections, ARP, DNS cache
- `users` - User accounts and sessions
- `services` - Running services/daemons
- `scheduled_tasks` - Scheduled tasks/cron jobs

## Configuration

### Environment Variables

Configure integrations via environment variables:

```bash
# Email (SMTP)
export SMTP_SERVER="smtp.company.com"
export SMTP_PORT="587"
export SMTP_USER="alerts@company.com"
export SMTP_PASSWORD="password"
export ALERT_FROM_ADDRESS="ir-automation@company.com"

# Slack
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."

# Microsoft Teams
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."

# PagerDuty
export PAGERDUTY_ROUTING_KEY="your-routing-key"

# Jira
export JIRA_URL="https://company.atlassian.net"
export JIRA_USER="user@company.com"
export JIRA_API_TOKEN="api-token"
export JIRA_PROJECT_KEY="SEC"

# ServiceNow
export SERVICENOW_URL="https://company.service-now.com"
export SERVICENOW_USER="api-user"
export SERVICENOW_PASSWORD="password"
```

### Variables File

Pass additional variables via JSON:

```json
{
  "alert_email": "security@company.com",
  "oncall_team": "security-oncall",
  "management_ips": ["10.0.0.1", "10.0.0.2"]
}
```

```bash
python runbook_engine.py --runbook templates/ransomware.yaml --variables vars.json
```

## Output Structure

Each execution creates an incident directory:

```
ir-output/
    IR-20251130-143022/
        execution_log.json      # Full execution log
        chain_of_custody.json   # Evidence chain of custody
        evidence/
            IR-..._processes.json
            IR-..._network.json
            IR-..._logs.zip
            ...
        IR-..._forensic_package.zip
```

## Writing Custom Runbooks

### Basic Structure

```yaml
name: Custom Incident Response
description: Custom response playbook
version: "1.0.0"

variables:
  custom_var: "default_value"

steps:
  - name: First Step
    action: log
    severity: low
    parameters:
      message: "Starting custom runbook"
```

### Using Conditions

```yaml
steps:
  - name: Block C2 if identified
    action: block_ip
    severity: high
    when: "c2_ip is defined and c2_ip != ''"
    parameters:
      ip_address: "${c2_ip}"
      direction: both
```

### Using Prompts

```yaml
steps:
  - name: Get analyst input
    action: prompt_analyst
    severity: medium
    parameters:
      prompt: "Enter the suspicious file path"
      variable: suspicious_file

  - name: Quarantine if provided
    action: quarantine_file
    severity: high
    when: "suspicious_file != 'skip'"
    parameters:
      file_path: "${suspicious_file}"
```

### Continue on Failure

```yaml
steps:
  - name: Optional step
    action: collect_evidence
    severity: medium
    continue_on_failure: true  # Don't stop if this fails
    parameters:
      evidence_type: logs
      source: "/var/log/custom"
```

## Integration with Detection Rules

Runbooks can be triggered automatically by detection systems:

```python
from incident_response.runbooks.runbook_engine import RunbookEngine

# When alert fires
engine = RunbookEngine(auto_approve="medium")
engine.variables["alert_id"] = alert.id
engine.variables["affected_host"] = alert.host

runbook = engine.load_runbook("templates/malware.yaml")
engine.execute(runbook)
```

## Best Practices

1. **Always dry-run first**: Use `--dry-run` before executing any runbook
2. **Review approval prompts**: Don't blindly approve - verify the action is appropriate
3. **Preserve evidence before containment**: Collect volatile data before isolation
4. **Document analyst decisions**: Use prompts to record analyst input
5. **Test integrations**: Verify email/Slack/ticketing integrations before incidents
6. **Customize templates**: Adapt templates to your environment
7. **Version control runbooks**: Track changes to runbooks in git

## Requirements

- Python 3.8+
- PyYAML (`pip install pyyaml`)
- Administrator/root privileges for containment actions
- Platform-specific:
  - Windows: PowerShell, netsh
  - Linux: iptables, systemd

## Related Resources

- [NIST SP 800-61](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) - Computer Security Incident Handling Guide
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics and techniques

## License

Part of Defensive Toolkit - MIT License
