# TheHive Integration

Integrate with TheHive open-source Security Incident Response Platform.

## Overview

[TheHive](https://thehive-project.org/) is a scalable, open-source Security Incident Response Platform designed for SOCs, CSIRTs, and CERTs to collaborate, elaborate, analyze and get their job done.

**Key Features:**
- Case management
- Task assignment and tracking
- Observable enrichment
- Integration with MISP, Cortex analyzers
- Collaboration tools

## Prerequisites

- TheHive 5.x or later
- Python 3.10+
- TheHive API credentials

## Installation

```bash
pip install thehive4py
```

## Quick Start

```bash
# Set credentials
export THEHIVE_URL="https://thehive.example.com"
export THEHIVE_API_KEY="your-api-key"

# Create a case
python case_manager.py create --title "Security Incident" --severity 2

# Execute playbook
python playbook_executor.py --playbook ransomware-response --case-id <case-id>
```

## Integration Points

This integration provides:
- **Case Management**: Create, update, close security cases
- **Playbook Execution**: Run IR playbooks within TheHive
- **Observable Management**: Add IOCs and enrichment data
- **Alert Integration**: Forward alerts from SIEM to TheHive

## Resources

- [TheHive Documentation](https://docs.thehive-project.org/)
- [TheHive4py](https://github.com/TheHive-Project/TheHive4py)
- [API Documentation](https://docs.thehive-project.org/thehive/api-documentation/)
