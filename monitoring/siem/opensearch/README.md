# OpenSearch Security Analytics Integration

Deploy detection rules to OpenSearch Security Analytics platform.

## Overview

[OpenSearch](https://opensearch.org/) is an open-source search and analytics suite derived from Elasticsearch. OpenSearch Security Analytics provides SIEM capabilities including threat detection, correlation, and alerting.

**Key Features:**
- Real-time threat detection
- Security event correlation
- Built-in detectors and rules
- Integration with OpenSearch Dashboards
- Scalable architecture

## Prerequisites

- OpenSearch 2.x or later with Security Analytics plugin
- Python 3.10+
- `opensearch-py` client library

## Installation

```bash
pip install opensearch-py pyyaml sigma-cli
```

## Configuration

1. Copy and edit configuration:
```bash
cp opensearch_config.yml my_opensearch_config.yml
nano my_opensearch_config.yml
```

2. Set environment variables:
```bash
export OPENSEARCH_PASSWORD="your-password"
```

## Usage

```bash
# Deploy rules
python deploy_rules.py --config my_opensearch_config.yml

# Dry run
python deploy_rules.py --dry-run
```

## Integration Status

⚠️ **Template Implementation**: This is a starter template. Full OpenSearch Security Analytics API integration requires:
- OpenSearch Security Analytics plugin installed
- API endpoint configuration
- Detector creation logic
- Rule format conversion

## Resources

- [OpenSearch Security Analytics](https://opensearch.org/docs/latest/security-analytics/)
- [OpenSearch Python Client](https://github.com/opensearch-project/opensearch-py)
- [Security Analytics API](https://opensearch.org/docs/latest/security-analytics/api-tools/)
