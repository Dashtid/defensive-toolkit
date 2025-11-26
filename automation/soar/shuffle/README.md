# Shuffle Automation Integration

Integrate with Shuffle open-source SOAR platform.

## Overview

[Shuffle](https://shuffler.io/) is a general-purpose security automation platform focused on accessibility and collaboration.

**Key Features:**
- Visual workflow builder
- 1000+ pre-built integrations
- Cloud and on-premise deployment
- Open-source and community-driven

## Prerequisites

- Shuffle instance (cloud or self-hosted)
- Python 3.10+
- Shuffle API key

## Quick Start

```bash
# Set credentials
export SHUFFLE_URL="https://shuffler.io"
export SHUFFLE_API_KEY="your-api-key"

# Execute workflow
python workflow_executor.py --workflow-id <id> --execution-argument '{"key": "value"}'
```

## Integration Points

- Execute Shuffle workflows from Defensive Toolkit
- Trigger workflows based on detection rules
- Orchestrate multi-tool security operations
- Automate incident response procedures

## Resources

- [Shuffle Documentation](https://shuffler.io/docs)
- [Shuffle GitHub](https://github.com/Shuffle/Shuffle)
- [Workflow Examples](https://shuffler.io/workflows)
