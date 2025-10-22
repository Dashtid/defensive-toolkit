# Zeek Network Analysis Scripts

Deploy and manage Zeek (formerly Bro) scripts for network security monitoring.

## Overview

[Zeek](https://zeek.org/) is a powerful open-source network security monitoring tool that provides a comprehensive platform for network traffic analysis.

**Key Features:**
- Deep packet inspection
- Protocol analysis (100+ protocols)
- Flexible scripting language
- Log generation and correlation
- Real-time and offline analysis

## Script Categories

- **Detection** - Identify suspicious network behavior
- **Protocols** - Parse and analyze network protocols
- **Files** - Extract and analyze files from traffic
- **Anomalies** - Detect statistical anomalies

## Quick Start

### Deploy Scripts

```bash
# Copy custom scripts
sudo cp custom-scripts/*.zeek /usr/local/zeek/share/zeek/site/

# Load scripts in local.zeek
echo '@load ./custom-detection' | sudo tee -a /usr/local/zeek/share/zeek/site/local.zeek

# Deploy configuration
sudo zeekctl deploy
```

### Verify Scripts

```bash
# Check configuration
sudo zeekctl check

# View loaded scripts
zeek -NN
```

## Example Script

```zeek
@load base/frameworks/notice

event http_request(c: connection, method: string, original_URI: string) {
    if ( /malware/ in original_URI ) {
        NOTICE([$note=Malware_Download_Attempt,
                $msg="Suspicious HTTP request detected",
                $conn=c]);
    }
}
```

## Integration Points

- Export logs to SIEM (Wazuh, Elastic, etc.)
- Trigger alerts on suspicious activity
- Correlate with threat intelligence (MISP)
- Generate detection rules from Zeek logs

## Resources

- [Zeek Documentation](https://docs.zeek.org/)
- [Zeek Scripting](https://docs.zeek.org/en/master/scripting/index.html)
- [Zeek Packages](https://packages.zeek.org/)
