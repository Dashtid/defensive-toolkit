# Wazuh SIEM Integration

Deploy Sigma detection rules to Wazuh open-source SIEM platform.

## Overview

[Wazuh](https://wazuh.com/) is a free, open-source security monitoring platform that provides:
- SIEM and XDR capabilities
- Intrusion detection (host and network based)
- Log analysis and correlation
- File integrity monitoring
- Vulnerability detection
- Compliance management (PCI-DSS, HIPAA, NIST, etc.)
- Cloud security monitoring

## Prerequisites

- Wazuh Manager 4.x or later
- Python 3.10+
- `sigma-cli` for rule conversion
- Wazuh API credentials

## Installation

```bash
# Install dependencies
pip install pyyaml requests sigma-cli

# Or using the project dependencies
cd ../../..
pip install -e ".[all]"
```

## Configuration

1. Copy the configuration template:
```bash
cp wazuh_config.yml my_wazuh_config.yml
```

2. Edit `my_wazuh_config.yml`:
```yaml
wazuh:
  manager_host: wazuh-manager.example.com
  manager_port: 55000
  username: admin
  password: ${WAZUH_PASSWORD}  # Set via environment variable
```

3. Set environment variables:
```bash
export WAZUH_PASSWORD="your-secure-password"
```

## Usage

### Deploy All Sigma Rules

```bash
python deploy_rules.py --config my_wazuh_config.yml
```

### Dry Run (Preview Only)

```bash
python deploy_rules.py --config my_wazuh_config.yml --dry-run
```

### Deploy Specific Rule Directory

```bash
python deploy_rules.py --config my_wazuh_config.yml --rules-dir ../../detection-rules/sigma/execution
```

## How It Works

1. **Conversion**: Sigma rules are converted to Wazuh XML format
2. **Validation**: Rules are validated before deployment
3. **Backup**: Existing rules are backed up automatically
4. **Deployment**: Rules are deployed to Wazuh Manager
5. **Restart**: Optionally restart Wazuh Manager to apply rules

## Wazuh Rule Format

Wazuh uses XML-based rules. Example:

```xml
<rule id="100001" level="10">
  <description>Suspicious PowerShell Execution</description>
  <info type="text">Detects suspicious PowerShell command execution</info>
  <group>custom_detection,sigma_rules,execution</group>
</rule>
```

## Features

- [OK] Sigma to Wazuh conversion
- [OK] Batch rule deployment
- [OK] Automatic rule backup
- [OK] Dry-run mode
- [OK] API authentication
- [OK] Comprehensive logging

## Troubleshooting

### Authentication Failed

**Problem**: `Authentication failed: 401 Unauthorized`

**Solution**:
```bash
# Verify credentials
curl -u admin:password -k -X POST https://wazuh-manager:55000/security/user/authenticate

# Check environment variable
echo $WAZUH_PASSWORD
```

### Rules Not Loading

**Problem**: Rules deployed but not active

**Solution**:
```bash
# Restart Wazuh Manager
sudo systemctl restart wazuh-manager

# Check rule syntax
sudo /var/ossec/bin/wazuh-logtest
```

### Connection Timeout

**Problem**: `Connection timeout to Wazuh API`

**Solution**:
- Verify Wazuh Manager is running
- Check firewall rules (port 55000)
- Verify SSL certificate if `verify_ssl: true`

## Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh Rules Syntax](https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html)
- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Sigma to Wazuh Conversion](https://github.com/SigmaHQ/sigma)

## License

MIT License - See project root LICENSE file
