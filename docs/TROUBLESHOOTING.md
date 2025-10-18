# Defensive Toolkit - Troubleshooting Guide

**Version**: 1.0.0
**Last Updated**: 2025-10-18

---

## Table of Contents

- [Installation Issues](#installation-issues)
- [Dependency Problems](#dependency-problems)
- [Import Errors](#import-errors)
- [Permission Issues](#permission-issues)
- [SIEM Integration](#siem-integration)
- [Scanner Problems](#scanner-problems)
- [Playbook Execution](#playbook-execution)
- [Test Failures](#test-failures)
- [Performance Issues](#performance-issues)
- [Platform-Specific Issues](#platform-specific-issues)

---

## Installation Issues

### uv Installation Fails

**Problem**: `curl: command not found` or uv install script fails

**Solution**:
```bash
# Alternative installation methods

# macOS with Homebrew
brew install uv

# Windows with winget
winget install --id=astral-sh.uv -e

# Or install via pip
pip install uv
```

### Git Clone Fails

**Problem**: `Permission denied (publickey)` or `Repository not found`

**Solution**:
```bash
# Use HTTPS instead of SSH
git clone https://github.com/yourusername/defensive-toolkit.git

# If private repo, authenticate with token
git clone https://oauth2:YOUR_TOKEN@github.com/yourusername/defensive-toolkit.git
```

---

## Dependency Problems

### ModuleNotFoundError

**Problem**: `ModuleNotFoundError: No module named 'yaml'`

**Solutions**:
```bash
# 1. Ensure virtual environment is activated
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate  # Windows

# 2. Reinstall all dependencies
uv sync --all-extras --dev

# 3. If using pip, reinstall
pip install -r requirements.txt

# 4. Check Python version (must be 3.10+)
python --version
```

### Version Conflicts

**Problem**: `ERROR: pip's dependency resolver does not currently take into account all the packages that are installed`

**Solution**:
```bash
# Use uv (better dependency resolution)
uv sync

# Or create clean virtual environment
rm -rf venv/
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Missing System Libraries

**Problem**: `fatal error: Python.h: No such file or directory`

**Solution**:
```bash
# Ubuntu/Debian
sudo apt install python3-dev

# RHEL/CentOS
sudo yum install python3-devel

# macOS
xcode-select --install
```

---

## Import Errors

### Cannot Import Local Modules

**Problem**: `ModuleNotFoundError: No module named 'automation'`

**Solutions**:
```bash
# 1. Install in editable mode
pip install -e .

# 2. Check __init__.py files exist
ls automation/__init__.py
ls compliance/__init__.py

# 3. Run from project root
cd /path/to/defensive-toolkit
python automation/playbooks/playbook_engine.py

# 4. Add to PYTHONPATH (temporary fix)
export PYTHONPATH="${PYTHONPATH}:/path/to/defensive-toolkit"
```

### Circular Import Errors

**Problem**: `ImportError: cannot import name 'X' from partially initialized module`

**Solution**:
```bash
# This is a code issue, not configuration
# Check for circular dependencies in imports

# Workaround: Import inside functions instead of module level
# BAD:
# import module_a
# def func():
#     module_a.something()

# GOOD:
# def func():
#     import module_a
#     module_a.something()
```

---

## Permission Issues

### Permission Denied on Linux

**Problem**: `PermissionError: [Errno 13] Permission denied`

**Solutions**:
```bash
# 1. Run with sudo (if truly needed)
sudo uv run python forensics/memory/volatility_automation.py

# 2. Fix file permissions
chmod +x script.py

# 3. Fix directory permissions
sudo chown -R $USER:$USER /opt/defensive-toolkit

# 4. Check SELinux (if enabled)
sudo setenforce 0  # Temporary, for testing
getenforce

# 5. Check AppArmor
sudo aa-status
```

### Windows Execution Policy

**Problem**: `cannot be loaded because running scripts is disabled on this system`

**Solution**:
```powershell
# Temporary (current session only)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Permanent (requires Admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Admin Rights Required

**Problem**: `You do not have sufficient privileges`

**Solution**:
```bash
# Windows: Run PowerShell/CMD as Administrator
# Right-click > Run as Administrator

# Linux: Use sudo
sudo -i
cd /opt/defensive-toolkit
```

---

## SIEM Integration

### Sigma Conversion Fails

**Problem**: `ERROR: Backend not found: splunk`

**Solution**:
```bash
# Install/upgrade sigma-cli
pip install --upgrade sigma-cli

# List available backends
sigma list targets

# Use correct backend name
sigma convert -t splunk detection-rules/sigma/execution/*.yml
```

### SIEM Connection Timeout

**Problem**: `Connection to SIEM timed out`

**Solutions**:
```bash
# 1. Test network connectivity
ping siem.example.com
curl -v https://siem.example.com:8089

# 2. Check firewall rules
telnet siem.example.com 8089

# 3. Verify API credentials
curl -u admin:password https://siem.example.com:8089/services/auth/login

# 4. Check proxy settings
export HTTPS_PROXY=http://proxy.example.com:3128
```

### Invalid API Key

**Problem**: `401 Unauthorized` or `403 Forbidden`

**Solution**:
```bash
# 1. Verify API key is correct
echo $SIEM_API_KEY

# 2. Check .env file
cat .env | grep SIEM_API_KEY

# 3. Regenerate API key in SIEM platform

# 4. Test with curl
curl -H "Authorization: Bearer $SIEM_API_KEY" https://siem.example.com/api/test
```

---

## Scanner Problems

### OpenVAS Connection Failed

**Problem**: `Could not connect to OpenVAS`

**Solutions**:
```bash
# 1. Check OpenVAS is running
sudo systemctl status ospd-openvas
sudo systemctl status gvmd

# 2. Start OpenVAS services
sudo gvm-start

# 3. Test connection
gvm-cli --gmp-username admin --gmp-password password socket --socketpath /var/run/gvmd.sock --xml "<get_version/>"

# 4. Check socket permissions
ls -la /var/run/gvmd.sock
sudo chmod 666 /var/run/gvmd.sock  # Temporary fix
```

### Nmap Not Found

**Problem**: `nmap: command not found`

**Solution**:
```bash
# Ubuntu/Debian
sudo apt install nmap

# RHEL/CentOS
sudo yum install nmap

# macOS
brew install nmap

# Windows
choco install nmap
# or download from https://nmap.org/download.html
```

### Trivy Scan Fails

**Problem**: `trivy: command not found`

**Solution**:
```bash
# Install Trivy
# Ubuntu/Debian
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update
sudo apt install trivy

# Or use Docker
docker run aquasec/trivy image myimage:tag
```

---

## Playbook Execution

### Playbook Validation Fails

**Problem**: `Invalid YAML syntax` or `Schema validation failed`

**Solution**:
```bash
# 1. Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('playbook.yml'))"

# 2. Check for common YAML errors
# - Tabs instead of spaces (use spaces only)
# - Incorrect indentation
# - Missing colons
# - Unquoted special characters

# 3. Use YAML linter
yamllint playbook.yml
```

### Task Execution Fails

**Problem**: `Task failed: <action_name>`

**Solutions**:
```bash
# 1. Enable dry-run mode
export DRY_RUN=true
uv run python automation/playbooks/playbook_engine.py playbook.yml

# 2. Enable debug logging
export LOG_LEVEL=DEBUG
uv run python automation/playbooks/playbook_engine.py playbook.yml

# 3. Check task dependencies
# Ensure required tools/credentials available

# 4. Test individual actions
python -c "from automation.actions.containment_actions import isolate_host; isolate_host('test', dry_run=True)"
```

### Variable Substitution Not Working

**Problem**: `${variable}` not replaced in playbook

**Solution**:
```yaml
# Ensure variables defined in playbook:
variables:
  username: "admin"
  server: "web01"

tasks:
  - name: "Connect to ${server} as ${username}"  # Will be substituted
```

---

## Test Failures

### Pytest Not Found

**Problem**: `pytest: command not found`

**Solution**:
```bash
# Install test dependencies
uv sync --dev

# Or with pip
pip install pytest pytest-cov pytest-mock
```

### Fixture Not Found

**Problem**: `fixture 'sample_syslog_line' not found`

**Solution**:
```bash
# 1. Ensure conftest.py exists
ls tests/conftest.py

# 2. Run from project root (not tests/ dir)
cd /path/to/defensive-toolkit
pytest tests/ -v

# 3. Check fixture is defined
grep "sample_syslog_line" tests/conftest.py
```

### Import Errors in Tests

**Problem**: Tests fail with `ModuleNotFoundError`

**Solution**:
```bash
# 1. Install in editable mode
pip install -e .

# 2. Check PYTHONPATH
export PYTHONPATH=$PYTHONPATH:$(pwd)

# 3. Verify __init__.py files
find . -name "__init__.py"
```

### Coverage Report Not Generated

**Problem**: No `htmlcov/` directory

**Solution**:
```bash
# 1. Install pytest-cov
pip install pytest-cov

# 2. Run with explicit coverage options
pytest --cov=. --cov-report=html tests/

# 3. Check .coveragerc exists
ls .coveragerc
```

---

## Performance Issues

### Tests Running Slowly

**Problem**: Test suite takes too long

**Solutions**:
```bash
# 1. Skip slow tests
pytest -m "not slow" tests/

# 2. Run in parallel
pytest -n auto tests/

# 3. Run only unit tests (skip integration)
pytest tests/unit/ -v

# 4. Run specific test file
pytest tests/unit/test_automation/test_playbook_engine.py -v
```

### High Memory Usage

**Problem**: Tools consuming excessive RAM

**Solutions**:
```bash
# 1. Process large files in chunks
# Check code for file.read() on large files
# Use file.readline() or generators instead

# 2. Limit concurrent operations
# Reduce pytest workers: pytest -n 2 (instead of -n auto)

# 3. Monitor memory
top -p $(pgrep python)
```

### Slow Scanner Performance

**Problem**: Vulnerability scans taking too long

**Solutions**:
```bash
# 1. Reduce scan scope
# Limit target IPs, use quick scan profiles

# 2. Increase scanner resources
# Allocate more RAM/CPU to OpenVAS

# 3. Use parallel scanning
# Scan multiple targets concurrently

# 4. Use network proximity
# Deploy scanner close to target network
```

---

## Platform-Specific Issues

### Windows Issues

**Git Bash Fork Errors**:
```
child_copy: cygheap read copy failed
fork: retry: Resource temporarily unavailable
```

**Solution**: These are Git Bash resource warnings on Windows, usually harmless. Workaround:
```bash
# Use PowerShell instead
powershell

# Or use WSL2
wsl
cd /mnt/c/Code/defensive-toolkit
```

**Path Issues**:
```bash
# Windows uses backslashes, Python/Git Bash use forward slashes
# Always use forward slashes in code
path = "C:/Code/defensive-toolkit"  # Good
path = "C:\\Code\\defensive-toolkit"  # Avoid
```

**Long Path Errors**:
```powershell
# Enable long paths in Windows
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# Or use \\?\ prefix
\\?\C:\Very\Long\Path\To\File
```

### Linux Issues

**SELinux Blocking Execution**:
```bash
# Check SELinux status
getenforce

# Temporarily disable (testing only)
sudo setenforce 0

# Permanent fix: Create SELinux policy or use audit2allow
sudo audit2allow -a -M defensive-toolkit
sudo semodule -i defensive-toolkit.pp
```

**AppArmor Restrictions**:
```bash
# Check AppArmor status
sudo aa-status

# Disable profile (testing only)
sudo aa-complain /path/to/profile
```

---

## Diagnostic Commands

### Collect System Information

```bash
#!/bin/bash
# diagnostic.sh - Collect diagnostic information

echo "=== System Information ==="
uname -a
python --version
pip --version

echo -e "\n=== Installed Packages ==="
pip list | grep -E "pytest|sigma|yara|gvm"

echo -e "\n=== Environment Variables ==="
env | grep -E "SIEM|OPENVAS|API"

echo -e "\n=== Network Connectivity ==="
ping -c 3 8.8.8.8
curl -I https://github.com

echo -e "\n=== Disk Space ==="
df -h /

echo -e "\n=== Memory ==="
free -h

echo -e "\n=== Running Processes ==="
ps aux | grep -E "python|pytest"
```

### Enable Debug Logging

```python
# Add to top of any Python script
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

---

## Getting Help

### Before Opening an Issue

1. **Search existing issues**: Check if problem already reported
2. **Check documentation**: Review [README.md](../README.md), [GETTING_STARTED.md](GETTING_STARTED.md)
3. **Enable debug logging**: Capture full error messages
4. **Collect diagnostics**: Run `diagnostic.sh` above
5. **Minimal reproduction**: Create simplest example that reproduces issue

### Opening a GitHub Issue

Include:
- **Environment**: OS, Python version, installation method
- **Error messages**: Full stack trace
- **Steps to reproduce**: Exact commands run
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happened
- **Configuration**: Relevant .env settings (redacted)

### Community Support

- **GitHub Discussions**: Ask questions, share use cases
- **Issue Tracker**: Report bugs, request features
- **Documentation**: Comprehensive guides in `/docs`

---

**For more information**:
- [Getting Started Guide](GETTING_STARTED.md)
- [Architecture Documentation](ARCHITECTURE.md)
- [Testing Documentation](TESTING.md)
- [Deployment Guide](DEPLOYMENT.md)
