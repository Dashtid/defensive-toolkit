# Suricata IDS/IPS Rules

Deploy and manage Suricata rules for network intrusion detection and prevention.

## Overview

[Suricata](https://suricata.io/) is a high-performance open-source IDS, IPS, and network security monitoring engine.

**Key Features:**
- Multi-threaded architecture
- Protocol detection and parsing
- File extraction and logging
- Lua scripting support
- Integration with Elastic, Splunk, etc.

## Rule Sources

This toolkit integrates with:
- **Emerging Threats Open** - Community ruleset
- **Suricata Rules** - Official Suricata rules
- **Custom Rules** - Organization-specific detections

## Quick Start

### Deploy Rules

```bash
# Update Suricata rules
sudo suricata-update

# Deploy custom rules
sudo cp custom-rules/*.rules /etc/suricata/rules/
sudo suricatasc -c reload-rules
```

### Verify Rules

```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Check loaded rules
sudo suricatasc -c ruleset-stats
```

## Rule Format

Suricata uses its own rule syntax:

```
alert http any any -> any any (msg:"Suspicious User-Agent"; \
  http.user_agent; content:"malware"; sid:1000001; rev:1;)
```

## Integration with Defensive Toolkit

- Convert Sigma rules to Suricata format
- Deploy via API endpoints
- Monitor alerts in SIEM
- Trigger incident response playbooks

## Resources

- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Rule Format](https://suricata.readthedocs.io/en/latest/rules/)
- [Emerging Threats](https://rules.emergingthreats.net/)
