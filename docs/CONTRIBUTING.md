# Contributing to Defensive Toolkit

Thank you for your interest in contributing to the Defensive Toolkit! This project relies on community contributions to stay current with evolving threats and defensive techniques.

## Code of Conduct

### Our Mission

This project exists solely for **defensive security purposes**. All contributions must align with this mission.

### Acceptable Contributions

- [OK] Detection rules for identifying threats
- [OK] Security hardening scripts
- [OK] Incident response playbooks
- [OK] Threat hunting queries
- [OK] Forensics tools and scripts
- [OK] Defensive automation
- [OK] Documentation improvements

### Unacceptable Contributions

- [X] Offensive tools or exploits
- [X] Malware samples or payloads
- [X] Credential harvesting tools
- [X] Attack frameworks or penetration testing tools
- [X] Anything that violates security policies or laws

## How to Contribute

### Reporting Issues

If you find a bug, false positive, or have a suggestion:

1. Check existing issues to avoid duplicates
2. Open a new issue with a clear title and description
3. Include relevant details:
   - Tool/script version
   - Operating system
   - Expected vs actual behavior
   - Steps to reproduce

### Suggesting Enhancements

For new features or improvements:

1. Open an issue describing the enhancement
2. Explain the use case and benefits
3. Provide examples if applicable
4. Wait for discussion before implementing

### Contributing Code

#### Before You Start

1. Fork the repository
2. Create a feature branch from `main`
3. Review existing code style and structure
4. Ensure your contribution aligns with defensive security principles

#### Development Guidelines

**Detection Rules (Sigma/YARA):**
- Follow official Sigma/YARA syntax and best practices
- Include comprehensive metadata (description, author, date, references)
- Map to MITRE ATT&CK techniques
- Document false positives
- Test rules before submitting

**Scripts (PowerShell/Bash/Python):**
- Include clear comments and documentation
- Add usage examples in header
- Implement proper error handling
- Follow secure coding practices
- Never hardcode credentials
- Require explicit administrator/root privileges where needed

**Playbooks:**
- Use clear, actionable language
- Include decision trees and checklists
- Reference relevant regulations and standards
- Provide communication templates
- Add tool recommendations

**Threat Hunting Queries:**
- Include platform information (Splunk/Sentinel/Elastic)
- Add usage instructions and examples
- Document query parameters and tuning options
- Explain the threat being hunted
- Provide false positive guidance

#### Code Style

**PowerShell:**
```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Brief description

.DESCRIPTION
    Detailed description

.PARAMETER ParamName
    Parameter description

.EXAMPLE
    Example usage
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$RequiredParam
)

# Use approved verbs
# PascalCase for functions
# $PascalCase for variables
```

**Bash:**
```bash
#!/bin/bash

################################################################################
# Script Name
# Description: What it does
# Author: Your name
# Date: YYYY-MM-DD
# Usage: script.sh [options]
################################################################################

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Use set -e for error handling
set -e
```

**Python:**
```python
#!/usr/bin/env python3
"""
Module docstring describing purpose
"""

import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Main function docstring"""
    pass

if __name__ == "__main__":
    main()
```

**Sigma Rules:**
```yaml
title: Clear, Descriptive Title
id: unique-uuid-here
status: stable|testing|experimental
description: Detailed description of what is detected
references:
    - https://attack.mitre.org/techniques/TXXXX/
author: Your Name
date: YYYY-MM-DD
modified: YYYY-MM-DD
tags:
    - attack.tactic
    - attack.technique_id
logsource:
    category: category_name
    product: windows|linux|macos
detection:
    selection:
        FieldName: value
    condition: selection
falsepositives:
    - Known legitimate scenario
level: low|medium|high|critical
```

**YARA Rules:**
```yara
rule RuleName
{
    meta:
        description = "What this detects"
        author = "Your Name"
        date = "YYYY-MM-DD"
        severity = "low|medium|high|critical"
        reference = "URL to more info"

    strings:
        $string1 = "pattern"
        $regex1 = /regex pattern/

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        any of them
}
```

#### Testing Requirements

Before submitting, ensure:

**Detection Rules:**
- [v] Syntax is valid (use sigma CLI or yara compiler)
- [v] Rule triggers on known-bad samples
- [v] Rule doesn't trigger on known-good samples
- [v] Tested in lab environment
- [v] False positives documented

**Scripts:**
- [v] Runs without errors on target platform
- [v] Handles edge cases gracefully
- [v] Doesn't damage systems or data
- [v] Tested in isolated environment
- [v] Requires appropriate permissions

**Playbooks:**
- [v] Steps are clear and actionable
- [v] Reviewed by another person
- [v] References are valid
- [v] Aligns with industry standards

#### Security Considerations

- **Never** include real credentials, API keys, or tokens
- **Never** include actual malware samples
- **Always** sanitize example data (IPs, hostnames, usernames)
- **Always** test in isolated environments
- **Always** consider impact on production systems
- **Always** follow responsible disclosure for vulnerabilities

### Pull Request Process

1. **Create Your Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Write clear, focused commits
   - Follow conventional commit messages:
     - `feat: Add new feature`
     - `fix: Fix bug in script`
     - `docs: Update documentation`
     - `refactor: Improve code structure`
     - `test: Add or update tests`

3. **Test Thoroughly**
   - Verify all functionality works
   - Check for unintended side effects
   - Test on multiple platforms if applicable

4. **Update Documentation**
   - Update README.md if needed
   - Add usage examples
   - Update CHANGELOG.md
   - Add inline code comments

5. **Submit Pull Request**
   - Provide clear PR title and description
   - Reference related issues
   - Explain what changed and why
   - Include testing performed
   - Add screenshots/logs if relevant

6. **Address Review Feedback**
   - Respond to reviewer comments
   - Make requested changes
   - Update PR with new commits

### PR Review Criteria

Pull requests will be evaluated on:

- [v] **Functionality**: Does it work as intended?
- [v] **Security**: Does it follow secure coding practices?
- [v] **Defensive Focus**: Is it purely defensive in nature?
- [v] **Quality**: Is the code clean and well-documented?
- [v] **Testing**: Has it been adequately tested?
- [v] **Documentation**: Is usage clear and complete?
- [v] **Compatibility**: Does it work on target platforms?

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes for significant contributions
- Project README (for major contributors)

## Questions?

- Open an issue for project-related questions
- Check existing documentation first
- Be respectful and professional

## Legal

By contributing, you agree that:
- Your contributions will be licensed under the MIT License
- You have the right to submit your contributions
- You understand this is a defensive security project
- Your contributions comply with all applicable laws

---

**Thank you for helping make the internet more secure!**
