# Compliance Automation

Automated compliance checking, multi-framework mapping, and continuous monitoring tools for security standards.

## Overview

This category provides tools for:
- **Framework Checkers**: CIS Controls v8, NIST 800-53 Rev 5
- **Multi-Framework Mapping**: Map controls between CIS, NIST, ISO 27001, PCI-DSS, SOC2
- **Policy Validation**: YAML-based security policy enforcement
- **Configuration Drift**: Detect changes from baseline configuration
- **Compliance Dashboards**: Real-time compliance status visualization
- **Evidence Collection**: Automated audit trail generation

## Directory Structure

```
compliance/
├── frameworks/                  # Compliance framework checkers
│   ├── cis-checker.py          # CIS Controls v8 compliance checker
│   ├── nist-checker.py         # NIST 800-53 Rev 5 checker
│   └── framework-mapper.py     # Multi-framework control mapping
├── policy/                      # Policy validation
│   ├── policy-checker.py       # Security policy validator
│   ├── config-drift.py         # Configuration drift detector
│   └── example-baseline-policy.yaml
├── reporting/                   # Compliance reporting
│   └── dashboard.py            # HTML compliance dashboard generator
└── evidence/                    # Audit evidence collection
```

## Quick Start

### CIS Controls v8 Check

```bash
# Run all CIS checks
python compliance/frameworks/cis-checker.py --output-format text

# Check specific controls
python compliance/frameworks/cis-checker.py --controls 1 2 3 5 6 10

# Generate JSON report
python compliance/frameworks/cis-checker.py --output-format json --output cis-report.json
```

### NIST 800-53 Compliance Check

```bash
# Moderate impact baseline (default)
python compliance/frameworks/nist-checker.py --impact-level moderate

# High impact baseline
python compliance/frameworks/nist-checker.py --impact-level high --output nist-high.json

# Check specific control families
python compliance/frameworks/nist-checker.py --families AC AU IA SC SI
```

### Multi-Framework Mapping

```bash
# Map a specific control to other frameworks
python compliance/frameworks/framework-mapper.py --map CIS-5

# Find overlaps between frameworks
python compliance/frameworks/framework-mapper.py --overlaps CIS NIST-800-53 PCI-DSS

# Generate coverage matrix for PCI-DSS
python compliance/frameworks/framework-mapper.py --coverage PCI-DSS

# Recommend implementation order for maximum coverage
python compliance/frameworks/framework-mapper.py --recommend NIST-800-53 ISO-27001 SOC2
```

### Policy Validation

```bash
# Validate security policy
python compliance/policy/policy-checker.py --policy example-baseline-policy.yaml

# Generate JSON output
python compliance/policy/policy-checker.py \\
    --policy baseline-security.yaml \\
    --output-format json \\
    --output policy-results.json
```

### Configuration Drift Detection

```bash
# Create baseline snapshot
python compliance/policy/config-drift.py \\
    --create-baseline \\
    --files /etc/ssh/sshd_config /etc/pam.d/* /etc/sudoers \\
    --output config-baseline.json

# Detect drift from baseline
python compliance/policy/config-drift.py \\
    --detect \\
    --baseline config-baseline.json \\
    --output-format text

# Generate drift report
python compliance/policy/config-drift.py \\
    --detect \\
    --baseline config-baseline.json \\
    --output-format json \\
    --output drift-report.json
```

### Compliance Dashboard

```bash
# Generate HTML dashboard from multiple results
python compliance/reporting/dashboard.py \\
    --results cis-report.json nist-report.json policy-report.json \\
    --output compliance-dashboard.html

# Open dashboard in browser
firefox compliance-dashboard.html
```

## CIS Controls v8 Checker

### Supported Controls

- **Control 1**: Inventory and Control of Enterprise Assets
- **Control 2**: Inventory and Control of Software Assets
- **Control 3**: Data Protection (encryption, ACLs)
- **Control 4**: Secure Configuration of Enterprise Assets
- **Control 5**: Account Management (passwords, accounts)
- **Control 6**: Access Control Management (MFA, least privilege)
- **Control 10**: Malware Defenses

### Example Usage

```python
from compliance.frameworks.cis_checker import CISChecker

checker = CISChecker(output_format='json')
results = checker.run_all_checks()
report = checker.generate_report()
```

### Output Format

```json
{
  "timestamp": "2025-10-15T10:30:00",
  "cis_version": "v8",
  "compliance_summary": {
    "total": 25,
    "passed": 18,
    "failed": 3,
    "not_applicable": 4,
    "compliance_percentage": 72.0
  },
  "controls_checked": [
    {
      "control": "1",
      "title": "Inventory and Control of Enterprise Assets",
      "checks": [...]
    }
  ]
}
```

## NIST 800-53 Rev 5 Checker

### Supported Control Families

- **AC**: Access Control
- **AU**: Audit and Accountability
- **CM**: Configuration Management
- **IA**: Identification and Authentication
- **SC**: System and Communications Protection
- **SI**: System and Information Integrity

### Impact Levels

- **Low**: Basic security controls
- **Moderate**: Enhanced security controls (default)
- **High**: Stringent security controls

### Example Usage

```bash
# Check moderate baseline
python compliance/frameworks/nist-checker.py --impact-level moderate

# Check high baseline for federal systems
python compliance/frameworks/nist-checker.py --impact-level high --output fedramp-high.json
```

## Multi-Framework Mapping

### Control Mapping Database

Maps controls between:
- CIS Controls v8
- NIST 800-53 Rev 5
- ISO 27001:2013
- PCI-DSS 4.0
- SOC2 Trust Service Criteria

### Use Cases

1. **Compliance Synergy**: Implement one control to satisfy multiple frameworks
2. **Gap Analysis**: Identify which controls are missing for target framework
3. **Implementation Planning**: Prioritize controls by multi-framework coverage
4. **Audit Preparation**: Show control overlap for multiple audits

### Example: Finding Overlaps

```bash
$ python framework-mapper.py --overlaps CIS NIST-800-53

Control Overlaps for CIS, NIST-800-53:

CIS-5: Account Management
  NIST-800-53: AC-2, IA-2, IA-4, IA-5

CIS-6: Access Control Management
  NIST-800-53: AC-3, AC-6, AC-17
```

## Policy Checker

### Policy Definition Format

Policies are defined in YAML with support for:
- File existence/permission checks
- Service status validation
- Port availability checks
- User account verification
- Registry value checks (Windows)
- Command execution validation
- File content pattern matching

### Example Policy

```yaml
name: "SSH Hardening Policy"
description: "Secure SSH configuration requirements"
version: "1.0"

checks:
  - id: "SSH-001"
    type: "file_content"
    description: "Verify SSH root login is disabled"
    severity: "critical"
    path: "/etc/ssh/sshd_config"
    content: "PermitRootLogin no"
    match_type: "regex"

  - id: "SSH-002"
    type: "service_status"
    description: "Verify SSH service is running"
    severity: "high"
    service: "sshd"
    expected_status: "running"
```

### Check Types

- **file_exists**: Verify file/directory existence
- **file_content**: Check file content for patterns
- **permission**: Validate file permissions
- **command**: Execute command and validate output
- **registry**: Check Windows registry values
- **service_status**: Verify service running/stopped
- **port_status**: Check port open/closed
- **user_exists**: Validate user account existence

## Configuration Drift Detection

### Workflow

1. **Create Baseline**: Snapshot current configuration files
2. **Monitor**: Periodically check for changes
3. **Alert**: Detect and report configuration drift
4. **Investigate**: Review changes and validate

### Baseline Creation

```bash
# Create baseline for critical config files
python config-drift.py --create-baseline \\
    --files /etc/ssh/sshd_config \\
            /etc/pam.d/common-auth \\
            /etc/sudoers \\
            /etc/security/limits.conf \\
    --output config-baseline.json
```

### Drift Detection

```bash
# Check for drift
python config-drift.py --detect --baseline config-baseline.json

# Output example:
# DRIFT: File modified - /etc/ssh/sshd_config
#   Baseline Hash: a1b2c3d4...
#   Current Hash:  e5f6g7h8...
```

### Automation

Schedule drift detection with cron:

```bash
# Check for drift daily at 2 AM
0 2 * * * /usr/bin/python3 /path/to/config-drift.py --detect --baseline /etc/compliance/baseline.json --output /var/log/drift-$(date +\%Y\%m\%d).txt
```

## Compliance Dashboard

### Features

- **Real-time Status**: Overall compliance percentage
- **Framework Breakdown**: Per-framework compliance scores
- **Visual Status Bars**: Pass/fail/skip distribution
- **Multi-framework View**: Aggregate multiple compliance checks

### Dashboard Generation

```bash
# Collect compliance data
python frameworks/cis-checker.py --output cis.json
python frameworks/nist-checker.py --output nist.json
python policy/policy-checker.py --policy baseline.yaml --output policy.json

# Generate dashboard
python reporting/dashboard.py --results cis.json nist.json policy.json --output dashboard.html
```

## Best Practices

### Continuous Compliance Monitoring

1. **Automated Checks**: Schedule regular compliance scans (daily/weekly)
2. **Baseline Management**: Update baselines after approved changes
3. **Alert Integration**: Send notifications for failed checks
4. **Evidence Collection**: Maintain audit trails for compliance reviews
5. **Remediation Tracking**: Track findings to resolution

### Multi-Framework Strategy

1. **Map Controls First**: Use framework mapper to understand overlaps
2. **Prioritize High-Coverage Controls**: Implement controls that satisfy multiple frameworks
3. **Customize for Context**: Adapt checks to your organization's environment
4. **Document Exceptions**: Track and justify non-applicable controls

### Policy Management

1. **Version Control**: Store policies in Git
2. **Peer Review**: Review policy changes before deployment
3. **Testing**: Test policies in non-production first
4. **Documentation**: Document policy intent and requirements

## Integration with Other Toolkit Components

### Detection Rules Integration

```bash
# Validate that detection rules are properly configured
python policy-checker.py --policy detection-rules-policy.yaml
```

### Hardening Script Validation

```bash
# Create baseline after hardening
python config-drift.py --create-baseline \\
    --files /etc/ssh/sshd_config /etc/pam.d/* \\
    --output post-hardening-baseline.json

# Verify hardening persistence
python config-drift.py --detect --baseline post-hardening-baseline.json
```

### Audit Trail for Incident Response

```bash
# Generate compliance evidence during IR
python reporting/audit-report.py \\
    --incident-date 2025-10-15 \\
    --frameworks CIS NIST \\
    --output incident-compliance-evidence.pdf
```

## Troubleshooting

### Common Issues

**Permission Denied Errors**:
```bash
# Run with appropriate privileges
sudo python cis-checker.py
```

**Baseline Not Found**:
```bash
# Verify baseline file exists
ls -l config-baseline.json

# Recreate if missing
python config-drift.py --create-baseline ...
```

**Policy Check Failures**:
```bash
# Run in verbose mode for details
python policy-checker.py --policy baseline.yaml --verbose

# Validate policy syntax
python -c "import yaml; yaml.safe_load(open('policy.yaml'))"
```

## Compliance Frameworks Supported

- **CIS Controls v8**: Critical Security Controls for Effective Cyber Defense
- **NIST 800-53 Rev 5**: Security and Privacy Controls for Information Systems
- **ISO 27001:2013**: Information Security Management Systems
- **PCI-DSS 4.0**: Payment Card Industry Data Security Standard
- **SOC2**: Service Organization Control 2 (Trust Service Criteria)

## Additional Resources

- CIS Controls: https://www.cisecurity.org/controls
- NIST 800-53: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- ISO 27001: https://www.iso.org/isoiec-27001-information-security.html
- PCI-DSS: https://www.pcisecuritystandards.org/
- SOC2: https://www.aicpa.org/soc2

---

**Last Updated**: 2025-10-15
**Maintainer**: Defensive Toolkit
**License**: MIT
