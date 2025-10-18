#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures for defensive-toolkit tests
"""

import json
import logging
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml


# [+] Logging Configuration
@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    """Configure logging for tests"""
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(levelname)s] %(name)s - %(message)s'
    )


# [+] Temporary Directory Fixtures
@pytest.fixture
def temp_dir(tmp_path):
    """Provide a temporary directory for test files"""
    return tmp_path


@pytest.fixture
def temp_file(tmp_path):
    """Provide a temporary file path"""
    temp_file = tmp_path / "test_file.txt"
    return temp_file


# [+] Sample Log Data Fixtures
@pytest.fixture
def sample_syslog_line():
    """Sample syslog line"""
    return "Oct 15 14:30:22 webserver01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"


@pytest.fixture
def sample_apache_log_line():
    """Sample Apache access log line"""
    return '192.168.1.50 - - [15/Oct/2025:14:30:22 +0000] "GET /admin/login HTTP/1.1" 200 4523 "-" "Mozilla/5.0"'


@pytest.fixture
def sample_json_log_line():
    """Sample JSON log line"""
    return json.dumps({
        "timestamp": "2025-10-15T14:30:22Z",
        "severity": "ERROR",
        "message": "Authentication failed",
        "user": "admin",
        "source_ip": "192.168.1.100"
    })


@pytest.fixture
def sample_windows_event_log():
    """Sample Windows Event Log entry"""
    return {
        "EventID": 4625,
        "TimeCreated": "2025-10-15T14:30:22.000Z",
        "Computer": "DC01.corp.local",
        "Level": "Information",
        "Message": "An account failed to log on",
        "EventData": {
            "TargetUserName": "admin",
            "IpAddress": "192.168.1.100"
        }
    }


# [+] Sample Configuration Fixtures
@pytest.fixture
def sample_security_policy():
    """Sample security policy configuration"""
    return {
        "name": "Test Security Policy",
        "version": "1.0",
        "policies": {
            "password_policy": {
                "min_length": 12,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numbers": True,
                "require_special": True
            },
            "account_lockout": {
                "enabled": True,
                "threshold": 5,
                "duration_minutes": 30
            },
            "audit_policy": {
                "log_failed_logins": True,
                "log_privilege_use": True
            }
        }
    }


@pytest.fixture
def sample_compliance_config():
    """Sample compliance configuration"""
    return {
        "framework": "CIS",
        "version": "8.0",
        "controls": [
            {"id": "1.1", "name": "Inventory of Authorized Devices", "implemented": True},
            {"id": "2.1", "name": "Inventory of Authorized Software", "implemented": True},
            {"id": "4.1", "name": "Secure Configuration", "implemented": False}
        ]
    }


# [+] Sample YAML Playbook Fixtures
@pytest.fixture
def sample_playbook_dict():
    """Sample playbook as dictionary"""
    return {
        "name": "Test Playbook",
        "description": "Test playbook for unit testing",
        "version": "1.0",
        "tasks": [
            {
                "name": "Log test message",
                "action": "log",
                "parameters": {
                    "message": "Test message",
                    "level": "info"
                }
            },
            {
                "name": "Set variable",
                "action": "set_variable",
                "parameters": {
                    "name": "test_var",
                    "value": "test_value"
                }
            }
        ]
    }


@pytest.fixture
def sample_playbook_file(tmp_path, sample_playbook_dict):
    """Sample playbook YAML file"""
    playbook_file = tmp_path / "test_playbook.yaml"
    with open(playbook_file, 'w') as f:
        yaml.dump(sample_playbook_dict, f)
    return playbook_file


# [+] Sample Vulnerability Data Fixtures
@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability finding"""
    return {
        "id": "CVE-2025-12345",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "title": "Remote Code Execution in Test Package",
        "description": "Test vulnerability description",
        "affected_package": "test-package",
        "affected_version": "1.0.0",
        "fixed_version": "1.0.1",
        "published_date": "2025-10-15T00:00:00Z"
    }


@pytest.fixture
def sample_vulnerability_scan_result():
    """Sample vulnerability scan result"""
    return {
        "scan_id": "scan-2025-10-15-001",
        "timestamp": "2025-10-15T14:30:22Z",
        "target": "192.168.1.10",
        "scanner": "openvas",
        "vulnerabilities": [
            {
                "id": "CVE-2025-12345",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "port": 443,
                "service": "https"
            },
            {
                "id": "CVE-2025-67890",
                "severity": "MEDIUM",
                "cvss_score": 5.0,
                "port": 22,
                "service": "ssh"
            }
        ],
        "summary": {
            "total": 2,
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 0
        }
    }


# [+] Sample SBOM Fixtures
@pytest.fixture
def sample_sbom():
    """Sample Software Bill of Materials"""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": "2025-10-15T14:30:22Z",
            "component": {
                "type": "application",
                "name": "test-app",
                "version": "1.0.0"
            }
        },
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0"
            },
            {
                "type": "library",
                "name": "PyYAML",
                "version": "6.0.1",
                "purl": "pkg:pypi/pyyaml@6.0.1"
            }
        ]
    }


# [+] Sample Forensics Data Fixtures
@pytest.fixture
def sample_memory_dump_metadata():
    """Sample memory dump metadata"""
    return {
        "filename": "memory.raw",
        "size_bytes": 8589934592,  # 8GB
        "acquired_date": "2025-10-15T14:30:22Z",
        "profile": "Win10x64_19041",
        "hostname": "WORKSTATION01",
        "case_id": "CASE-2025-001"
    }


@pytest.fixture
def sample_forensic_timeline_entry():
    """Sample forensic timeline entry"""
    return {
        "timestamp": "2025-10-15T14:30:22Z",
        "source": "MFT",
        "type": "FILE_CREATED",
        "path": "C:\\Windows\\Temp\\suspicious.exe",
        "size": 102400,
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "suspicious": True,
        "reason": "Created in suspicious location"
    }


# [+] Sample Detection Rule Fixtures
@pytest.fixture
def sample_sigma_rule():
    """Sample Sigma detection rule"""
    return {
        "title": "Suspicious PowerShell Execution",
        "id": "test-sigma-001",
        "status": "test",
        "description": "Detects suspicious PowerShell command execution",
        "author": "Test Author",
        "date": "2025-10-15",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {
            "category": "process_creation",
            "product": "windows"
        },
        "detection": {
            "selection": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": ["-enc", "-encodedcommand", "-nop"]
            },
            "condition": "selection"
        },
        "falsepositives": ["Administrative scripts"],
        "level": "high"
    }


@pytest.fixture
def sample_yara_rule():
    """Sample YARA rule content"""
    return '''rule test_webshell {
    meta:
        description = "Test webshell detection"
        author = "Test Author"
        date = "2025-10-15"

    strings:
        $php_tag = "<?php"
        $eval = "eval("
        $base64 = "base64_decode"

    condition:
        $php_tag and ($eval or $base64)
}'''


# [+] Mock Network Data Fixtures
@pytest.fixture
def sample_network_flow():
    """Sample network flow data"""
    return {
        "timestamp": "2025-10-15T14:30:22Z",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dst_ip": "10.0.0.5",
        "dst_port": 443,
        "protocol": "TCP",
        "bytes": 1024,
        "packets": 10,
        "duration_seconds": 5.2
    }


# [+] Mock SIEM Query Fixtures
@pytest.fixture
def sample_kql_query():
    """Sample KQL (Kusto Query Language) query"""
    return '''
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts=count() by Account, Computer
| where FailedAttempts > 5
'''


@pytest.fixture
def sample_spl_query():
    """Sample SPL (Splunk Processing Language) query"""
    return '''
index=windows EventCode=4625
| stats count by Account_Name, Computer_Name
| where count > 5
'''


# [+] Parametrized Test Data
@pytest.fixture(params=["syslog", "apache", "nginx", "json"])
def log_format(request):
    """Parametrized log format"""
    return request.param


@pytest.fixture(params=["HIGH", "MEDIUM", "LOW"])
def severity_level(request):
    """Parametrized severity levels"""
    return request.param


@pytest.fixture(params=["CIS", "NIST", "ISO27001", "PCI-DSS"])
def compliance_framework(request):
    """Parametrized compliance frameworks"""
    return request.param


# [+] Utility Functions
@pytest.fixture
def write_json_file(tmp_path):
    """Utility to write JSON files"""
    def _write(filename: str, data: Dict) -> Path:
        file_path = tmp_path / filename
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        return file_path
    return _write


@pytest.fixture
def write_yaml_file(tmp_path):
    """Utility to write YAML files"""
    def _write(filename: str, data: Dict) -> Path:
        file_path = tmp_path / filename
        with open(file_path, 'w') as f:
            yaml.dump(data, f)
        return file_path
    return _write


@pytest.fixture
def create_sample_log_file(tmp_path):
    """Utility to create sample log files"""
    def _create(filename: str, lines: List[str]) -> Path:
        file_path = tmp_path / filename
        with open(file_path, 'w') as f:
            for line in lines:
                f.write(line + '\n')
        return file_path
    return _create


# [+] Mock Environment Variables
@pytest.fixture
def mock_env_vars(monkeypatch):
    """Mock environment variables"""
    test_vars = {
        "DEFENSIVE_TOOLKIT_HOME": "/tmp/defensive-toolkit",
        "LOG_LEVEL": "DEBUG",
        "SIEM_HOST": "localhost",
        "SIEM_PORT": "514"
    }
    for key, value in test_vars.items():
        monkeypatch.setenv(key, value)
    return test_vars


# [+] Skip Markers Based on Platform
def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line(
        "markers", "windows: mark test to run only on Windows"
    )
    config.addinivalue_line(
        "markers", "linux: mark test to run only on Linux"
    )
    config.addinivalue_line(
        "markers", "requires_root: mark test as requiring root/admin privileges"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )


# [+] Test Summary
def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Add custom test summary"""
    terminalreporter.write_sep("=", "Defensive Toolkit Test Summary")
    terminalreporter.write_line(f"Test run completed with exit status: {exitstatus}")
