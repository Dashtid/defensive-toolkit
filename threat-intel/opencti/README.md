# OpenCTI Threat Intelligence Integration

Integrate with OpenCTI (Open Cyber Threat Intelligence Platform).

## Overview

[OpenCTI](https://www.opencti.io/) is an open-source cyber threat intelligence platform that allows organizations to manage their cyber threat intelligence knowledge and observables.

**Key Features:**
- Knowledge graph for threat relationships
- STIX 2.1 native support
- Integration with MISP, TheHive, VirusTotal, etc.
- Advanced threat actor tracking
- TTPs and campaign analysis

## Prerequisites

- OpenCTI 5.x or later
- Python 3.10+
- pycti library

## Installation

```bash
pip install pycti
```

## Quick Start

```bash
# Set credentials
export OPENCTI_URL="https://opencti.example.com"
export OPENCTI_TOKEN="your-api-token"

# Sync threat data
python threat_sync.py
```

## Resources

- [OpenCTI Documentation](https://docs.opencti.io/)
- [OpenCTI GitHub](https://github.com/OpenCTI-Platform/opencti)
- [pycti Library](https://github.com/OpenCTI-Platform/client-python)
