# Security Automation & Orchestration (SOAR)

**100% Open Source** security automation framework for orchestrating incident response, threat detection, and vulnerability management workflows.

## Overview

This automation framework provides:
- **YAML Playbook Engine**: Define security workflows as code
- **Pre-built Actions**: Containment, enrichment, notification, analysis
- **Open Source Integrations**: TheHive, Shuffle, MISP, Wazuh, Elastic
- **Example Playbooks**: Phishing response, malware containment, vulnerability remediation, alert triage
- **Audit Logging**: Complete execution trails for compliance

## Open Source SOAR Platforms

### TheHive
Scalable incident response platform with case management.
- **Location**: `soar/thehive/`
- **Use Case**: Security incident management and collaboration
- **Documentation**: [TheHive README](soar/thehive/README.md)

### Shuffle
General-purpose security automation with visual workflow builder.
- **Location**: `soar/shuffle/`
- **Use Case**: Workflow automation and orchestration
- **Documentation**: [Shuffle README](soar/shuffle/README.md)

## Quick Start

### Run Example Playbook

```bash
# Phishing response (dry run)
python playbooks/playbook-engine.py \
    --playbook playbooks/examples/phishing-response.yaml \
    --dry-run

# Malware containment with variables
python playbooks/playbook-engine.py \
    --playbook playbooks/examples/malware-containment.yaml \
    --variables incident_vars.json \
    --log-output execution.json

# Vulnerability remediation
python playbooks/playbook-engine.py \
    --playbook playbooks/examples/vuln-remediation.yaml
```

### Create Custom Playbook

```yaml
---
name: "Custom Security Workflow"
description: "My automated security response"
version: "1.0"

variables:
  target_ip: ""
  alert_severity: "medium"

tasks:
  - name: "Enrich IP address"
    action: log
    parameters:
      message: "Analyzing IP: ${target_ip}"
      level: info

  - name: "Block if malicious"
    action: conditional
    parameters:
      condition: "alert_severity == 'high'"
      if_true:
        - name: "Block IP"
          action: log
          parameters:
            message: "Blocking malicious IP"
            level: error
```

## Directory Structure

```
automation/
├── playbooks/
│   ├── playbook-engine.py       # YAML playbook executor
│   └── examples/                # Example playbooks
│       ├── phishing-response.yaml
│       ├── malware-containment.yaml
│       ├── vuln-remediation.yaml
│       └── alert-enrichment.yaml
├── actions/                     # Automation actions
│   ├── containment.py          # Host isolation, IP blocking, quarantine
│   ├── enrichment.py           # Threat intel enrichment
│   ├── notification.py         # Email, Slack, webhook
│   └── analysis.py             # Automated analysis
├── integrations/                # External integrations
│   ├── email-connector.py      # Email (phishing analysis)
│   ├── siem-connector.py       # SIEM integration
│   ├── ticket-connector.py     # Jira/ServiceNow
│   └── toolkit-connector.py    # Our existing tools
└── workflows/                   # Orchestration
    ├── workflow-executor.py    # Complex workflow execution
    └── workflow-scheduler.py   # Scheduled automation
```

## Playbook Syntax

### Basic Structure

```yaml
name: "Playbook Name"
description: "What this playbook does"
version: "1.0"

variables:
  var_name: default_value

tasks:
  - name: "Task description"
    action: action_name
    parameters:
      param1: value1
      param2: ${var_name}
    continue_on_failure: false
```

### Built-in Actions

**Log Message**:
```yaml
- name: "Log info"
  action: log
  parameters:
    message: "Processing ${variable}"
    level: info  # info, warning, error
```

**Set Variable**:
```yaml
- name: "Set flag"
  action: set_variable
  parameters:
    name: is_malicious
    value: true
```

**Sleep**:
```yaml
- name: "Wait for scan"
  action: sleep
  parameters:
    seconds: 30
```

**Conditional Logic**:
```yaml
- name: "Check severity"
  action: conditional
  parameters:
    condition: "severity == 'critical'"
    if_true:
      - name: "Escalate"
        action: log
        parameters:
          message: "CRITICAL alert"
          level: error
    if_false:
      - name: "Queue"
        action: log
        parameters:
          message: "Standard alert"
          level: info
```

**Loop**:
```yaml
- name: "Process hosts"
  action: loop
  parameters:
    items: ["host1", "host2", "host3"]
    variable: current_host
    tasks:
      - name: "Scan host"
        action: log
        parameters:
          message: "Scanning ${current_host}"
```

### External Actions

External actions are defined in `actions/` and `integrations/`:

**Containment Actions** (`actions/containment.py`):
- `isolate_host(hostname, method, dry_run)`
- `block_ip(ip_address, direction, duration, dry_run)`
- `quarantine_file(file_path, quarantine_dir, dry_run)`
- `terminate_process(process_name, pid, dry_run)`
- `disable_user_account(username, dry_run)`

**Enrichment Actions** (`actions/enrichment.py`):
- `enrich_ioc(ioc, ioc_type, sources)`
- `lookup_domain(domain)`
- `geolocate_ip(ip)`

**Notification Actions** (`actions/notification.py`):
- `send_email(to, subject, body, smtp_server, dry_run)`
- `send_slack(webhook_url, message, dry_run)`
- `send_webhook(url, payload, dry_run)`

## Example Playbooks

### 1. Phishing Response

**File**: `playbooks/examples/phishing-response.yaml`

**Workflow**:
1. Extract email indicators (sender, subject, attachments)
2. Analyze sender reputation
3. Scan attachments for malware
4. Calculate risk score
5. If high risk: Quarantine email, block sender, create ticket, notify SOC
6. If low risk: Move to spam

**Usage**:
```bash
python playbooks/playbook-engine.py \
    --playbook playbooks/examples/phishing-response.yaml \
    --variables phishing_vars.json
```

**Variables** (`phishing_vars.json`):
```json
{
  "email_subject": "Urgent: Wire Transfer Required",
  "sender_email": "attacker@malicious.com",
  "attachments": ["invoice.doc", "payment.exe"]
}
```

### 2. Malware Containment

**File**: `playbooks/examples/malware-containment.yaml`

**Workflow**:
1. Isolate infected host from network
2. Block C2 IP addresses
3. Terminate malicious processes
4. Collect forensic artifacts
5. Run container vulnerability scan
6. Quarantine malware files
7. Enrich threat intelligence
8. Create high-priority incident ticket
9. Notify security team

**Usage**:
```bash
python playbooks/playbook-engine.py \
    --playbook playbooks/examples/malware-containment.yaml \
    --variables malware_incident.json
```

### 3. Vulnerability Remediation

**File**: `playbooks/examples/vuln-remediation.yaml`

**Workflow**:
1. Run OpenVAS vulnerability scan
2. Calculate risk-based priority scores
3. Check CISA KEV catalog
4. For critical vulnerabilities: Create urgent tickets, send alerts
5. Generate vulnerability report
6. Schedule follow-up verification scan

**Usage**:
```bash
python playbooks/playbook-engine.py \
    --playbook playbooks/examples/vuln-remediation.yaml
```

### 4. Alert Enrichment

**File**: `playbooks/examples/alert-enrichment.yaml`

**Workflow**:
1. Enrich source IP with threat intelligence
2. Geolocate IP address
3. Check reputation databases (VirusTotal, AbuseIPDB)
4. Correlate with recent alerts
5. Calculate risk score
6. Route based on severity: Escalate high/critical, queue low
7. Update SIEM with enrichment data

**Usage**:
```bash
python playbooks/playbook-engine.py \
    --playbook playbooks/examples/alert-enrichment.yaml \
    --variables alert_data.json
```

## Integration with Existing Toolkit

### Detection Rules Integration

```python
# In custom action
def check_sigma_rules(log_file):
    import subprocess
    result = subprocess.run(['sigma', 'convert', log_file], capture_output=True)
    return result.stdout
```

### Forensics Integration

```yaml
- name: "Collect memory dump"
  action: log
  parameters:
    message: "Running: python forensics/memory/volatility-auto-analyze.py"
```

### Vulnerability Management Integration

```yaml
- name: "Run vulnerability scan"
  action: log
  parameters:
    message: "Running: python vulnerability-mgmt/scanners/openvas-scan.py"
```

## Best Practices

### Playbook Design

1. **Start Simple**: Begin with basic workflows, add complexity gradually
2. **Use Variables**: Make playbooks reusable with variables
3. **Error Handling**: Set `continue_on_failure` appropriately
4. **Logging**: Log all actions for audit trails
5. **Dry Run First**: Always test with `--dry-run` before production

### Security Considerations

1. **Credentials**: Never hardcode credentials in playbooks
2. **Authorization**: Ensure actions are authorized before execution
3. **Validation**: Validate all input variables
4. **Audit Trails**: Always save execution logs
5. **Human-in-the-Loop**: Require approval for critical actions

### Production Deployment

1. **Version Control**: Store playbooks in Git
2. **Code Review**: Review all playbooks before deployment
3. **Testing**: Test in non-production environment first
4. **Monitoring**: Monitor playbook execution for failures
5. **Documentation**: Document all custom playbooks

## Workflow Patterns

### Sequential Execution

Tasks execute one after another:
```yaml
tasks:
  - name: "Step 1"
    action: log
  - name: "Step 2"
    action: log
  - name: "Step 3"
    action: log
```

### Conditional Branching

Execute different paths based on conditions:
```yaml
- name: "Route based on severity"
  action: conditional
  parameters:
    condition: "severity > 7"
    if_true: [high_severity_tasks]
    if_false: [low_severity_tasks]
```

### Iterative Processing

Process multiple items:
```yaml
- name: "Scan multiple hosts"
  action: loop
  parameters:
    items: ["host1", "host2", "host3"]
    tasks: [scan_task]
```

### Error Handling

Continue on failure:
```yaml
- name: "Optional step"
  action: some_action
  continue_on_failure: true
```

## Extending the Framework

### Create Custom Action

1. **Create Python module** in `actions/` or `integrations/`:

```python
# actions/custom_action.py
def my_custom_action(param1, param2, dry_run=False):
    logger.info(f"Executing custom action: {param1}, {param2}")
    if dry_run:
        return True
    # Your logic here
    return True
```

2. **Register in playbook engine** (add to action_modules dict):

```python
action_modules = {
    'my_custom_action': 'actions.custom_action'
}
```

3. **Use in playbook**:

```yaml
- name: "Run custom action"
  action: my_custom_action
  parameters:
    param1: value1
    param2: value2
```

## Performance Considerations

### Playbook Execution Time

- Simple playbooks: < 1 second
- Complex workflows: 1-30 seconds
- Long-running scans: Minutes to hours (use async execution)

### Resource Usage

- **CPU**: Low (Python interpreter)
- **Memory**: < 100MB per playbook
- **Network**: Depends on integrations

### Scaling

- Run multiple playbooks in parallel
- Use workflow scheduler for periodic execution
- Implement queue-based execution for high volume

## Troubleshooting

### Common Issues

**Playbook fails to load**:
```bash
# Check YAML syntax
python -m yaml playbook.yaml

# Validate structure
grep -E "^(name|description|tasks):" playbook.yaml
```

**Action not found**:
```bash
# Check action is registered
python playbooks/playbook-engine.py --help

# Verify module exists
ls -la actions/
```

**Variable substitution not working**:
```yaml
# Correct syntax: ${variable_name}
message: "Processing ${hostname}"

# Incorrect syntax:
message: "Processing $hostname"  # Wrong
message: "Processing {hostname}" # Wrong
```

## Compliance and Audit

### Audit Logging

All playbook executions are logged:
```json
{
  "timestamp": "2025-10-15T10:30:00",
  "playbook": "phishing-response.yaml",
  "user": "analyst@company.com",
  "variables": {"email_subject": "..."},
  "execution_log": [...]
}
```

### Compliance Frameworks

- **SOC2**: Automated controls with audit trails
- **ISO 27001**: Incident response automation
- **NIST**: Continuous monitoring and response
- **PCI-DSS**: Automated security monitoring

## Additional Resources

### SOAR Platforms
- SOAR: https://www.splunk.com/en_us/products/splunk-security-orchestration-and-automation.html
- Microsoft Sentinel: https://azure.microsoft.com/en-us/products/microsoft-sentinel/
- Palo Alto Cortex XSOAR: https://www.paloaltonetworks.com/cortex/cortex-xsoar

### Standards
- OASIS CACAO: https://docs.oasis-open.org/cacao/security-playbooks/
- NIST SP 800-61: Incident Response Guide

---

**Last Updated**: 2025-10-15
**Maintainer**: Defensive Toolkit
**License**: MIT
