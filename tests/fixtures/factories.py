"""
Test Data Factories

Factory functions for generating realistic test data using Faker.
Follows the Factory pattern for consistent, maintainable test data generation.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import uuid4
import random


class DetectionRuleFactory:
    """Factory for creating detection rule test data"""

    @staticmethod
    def create(
        name: Optional[str] = None,
        rule_type: str = "sigma",
        severity: str = "medium",
        **kwargs
    ) -> Dict:
        """Create a detection rule"""
        return {
            "id": kwargs.get("id", str(uuid4())),
            "name": name or f"Test Rule {uuid4().hex[:8]}",
            "description": kwargs.get("description", "Test detection rule"),
            "rule_type": rule_type,
            "content": kwargs.get("content", "detection:\n  selection:\n    test: value"),
            "severity": severity,
            "mitre_attack": kwargs.get("mitre_attack", ["T1059.001"]),
            "tags": kwargs.get("tags", ["test", rule_type]),
            "created_at": kwargs.get("created_at", datetime.utcnow().isoformat()),
            "updated_at": kwargs.get("updated_at", datetime.utcnow().isoformat()),
            "enabled": kwargs.get("enabled", True)
        }

    @staticmethod
    def create_batch(count: int = 5, **kwargs) -> List[Dict]:
        """Create multiple detection rules"""
        return [DetectionRuleFactory.create(**kwargs) for _ in range(count)]


class IncidentFactory:
    """Factory for creating incident test data"""

    @staticmethod
    def create(
        title: Optional[str] = None,
        severity: str = "high",
        status: str = "open",
        **kwargs
    ) -> Dict:
        """Create an incident"""
        return {
            "id": kwargs.get("id", str(uuid4())),
            "title": title or f"Test Incident {uuid4().hex[:8]}",
            "description": kwargs.get("description", "Test incident description"),
            "severity": severity,
            "status": status,
            "mitre_tactics": kwargs.get("mitre_tactics", ["TA0001"]),
            "mitre_techniques": kwargs.get("mitre_techniques", ["T1059.001"]),
            "affected_hosts": kwargs.get("affected_hosts", ["host-001"]),
            "iocs": kwargs.get("iocs", ["192.168.1.100", "sha256:abc123..."]),
            "created_at": kwargs.get("created_at", datetime.utcnow().isoformat()),
            "updated_at": kwargs.get("updated_at", datetime.utcnow().isoformat()),
            "assigned_to": kwargs.get("assigned_to", "analyst-001")
        }

    @staticmethod
    def create_batch(count: int = 5, **kwargs) -> List[Dict]:
        """Create multiple incidents"""
        return [IncidentFactory.create(**kwargs) for _ in range(count)]


class VulnerabilityFactory:
    """Factory for creating vulnerability test data"""

    @staticmethod
    def create(
        cve_id: Optional[str] = None,
        severity: str = "HIGH",
        **kwargs
    ) -> Dict:
        """Create a vulnerability"""
        if not cve_id:
            cve_id = f"CVE-2025-{random.randint(10000, 99999)}"

        return {
            "id": kwargs.get("id", str(uuid4())),
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": kwargs.get("cvss_score", 7.5),
            "title": kwargs.get("title", f"Test Vulnerability {cve_id}"),
            "description": kwargs.get("description", "Test vulnerability description"),
            "affected_package": kwargs.get("affected_package", "test-package"),
            "affected_version": kwargs.get("affected_version", "1.0.0"),
            "fixed_version": kwargs.get("fixed_version", "1.0.1"),
            "published_date": kwargs.get("published_date", datetime.utcnow().isoformat()),
            "status": kwargs.get("status", "open")
        }

    @staticmethod
    def create_scan_result(target: str = "192.168.1.100", **kwargs) -> Dict:
        """Create a vulnerability scan result"""
        vulns = kwargs.get("vulnerabilities", [
            VulnerabilityFactory.create(severity="HIGH"),
            VulnerabilityFactory.create(severity="MEDIUM"),
            VulnerabilityFactory.create(severity="LOW")
        ])

        return {
            "scan_id": kwargs.get("scan_id", str(uuid4())),
            "timestamp": kwargs.get("timestamp", datetime.utcnow().isoformat()),
            "target": target,
            "scanner": kwargs.get("scanner", "openvas"),
            "vulnerabilities": vulns,
            "summary": {
                "total": len(vulns),
                "critical": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
                "high": sum(1 for v in vulns if v["severity"] == "HIGH"),
                "medium": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
                "low": sum(1 for v in vulns if v["severity"] == "LOW")
            }
        }


class PlaybookFactory:
    """Factory for creating playbook test data"""

    @staticmethod
    def create(name: Optional[str] = None, **kwargs) -> Dict:
        """Create a playbook"""
        return {
            "id": kwargs.get("id", str(uuid4())),
            "name": name or f"Test Playbook {uuid4().hex[:8]}",
            "description": kwargs.get("description", "Test playbook"),
            "version": kwargs.get("version", "1.0"),
            "tasks": kwargs.get("tasks", [
                {
                    "name": "Log message",
                    "action": "log",
                    "parameters": {"message": "Test", "level": "info"}
                }
            ]),
            "created_at": kwargs.get("created_at", datetime.utcnow().isoformat())
        }


class ComplianceCheckFactory:
    """Factory for creating compliance check test data"""

    @staticmethod
    def create(framework: str = "cis", **kwargs) -> Dict:
        """Create a compliance check result"""
        total_controls = kwargs.get("total_controls", 10)
        passed = kwargs.get("passed", 7)

        return {
            "check_id": kwargs.get("check_id", str(uuid4())),
            "framework": framework,
            "version": kwargs.get("version", "8.0"),
            "timestamp": kwargs.get("timestamp", datetime.utcnow().isoformat()),
            "target": kwargs.get("target", "localhost"),
            "results": {
                "total": total_controls,
                "passed": passed,
                "failed": total_controls - passed,
                "score_percent": round((passed / total_controls) * 100, 2)
            },
            "controls": kwargs.get("controls", [
                {"id": "1.1", "name": "Test Control 1", "passed": True},
                {"id": "1.2", "name": "Test Control 2", "passed": False}
            ])
        }


class ForensicArtifactFactory:
    """Factory for creating forensic artifact test data"""

    @staticmethod
    def create(artifact_type: str = "memory", **kwargs) -> Dict:
        """Create a forensic artifact"""
        return {
            "id": kwargs.get("id", str(uuid4())),
            "artifact_type": artifact_type,
            "filename": kwargs.get("filename", f"{artifact_type}-dump.raw"),
            "size_bytes": kwargs.get("size_bytes", 8589934592),  # 8GB
            "acquired_date": kwargs.get("acquired_date", datetime.utcnow().isoformat()),
            "case_id": kwargs.get("case_id", f"CASE-2025-{random.randint(100, 999)}"),
            "hostname": kwargs.get("hostname", "WORKSTATION01"),
            "hash_md5": kwargs.get("hash_md5", "d41d8cd98f00b204e9800998ecf8427e"),
            "hash_sha256": kwargs.get("hash_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            "metadata": kwargs.get("metadata", {})
        }

    @staticmethod
    def create_timeline_entry(**kwargs) -> Dict:
        """Create a forensic timeline entry"""
        return {
            "timestamp": kwargs.get("timestamp", datetime.utcnow().isoformat()),
            "source": kwargs.get("source", "MFT"),
            "type": kwargs.get("type", "FILE_CREATED"),
            "path": kwargs.get("path", "C:\\Windows\\Temp\\file.exe"),
            "size": kwargs.get("size", 102400),
            "md5": kwargs.get("md5", "d41d8cd98f00b204e9800998ecf8427e"),
            "suspicious": kwargs.get("suspicious", False),
            "reason": kwargs.get("reason", None)
        }


class LogEntryFactory:
    """Factory for creating log entry test data"""

    @staticmethod
    def create(log_type: str = "syslog", **kwargs) -> Dict:
        """Create a log entry"""
        return {
            "id": kwargs.get("id", str(uuid4())),
            "timestamp": kwargs.get("timestamp", datetime.utcnow().isoformat()),
            "log_type": log_type,
            "severity": kwargs.get("severity", "INFO"),
            "source": kwargs.get("source", "test-host"),
            "message": kwargs.get("message", "Test log message"),
            "raw": kwargs.get("raw", "Oct 22 14:30:22 test-host test: message"),
            "parsed_fields": kwargs.get("parsed_fields", {})
        }

    @staticmethod
    def create_syslog(**kwargs) -> str:
        """Create a syslog line"""
        timestamp = kwargs.get("timestamp", datetime.now().strftime("%b %d %H:%M:%S"))
        host = kwargs.get("host", "test-host")
        process = kwargs.get("process", "test")
        message = kwargs.get("message", "Test message")
        return f"{timestamp} {host} {process}[12345]: {message}"

    @staticmethod
    def create_apache_log(**kwargs) -> str:
        """Create an Apache log line"""
        ip = kwargs.get("ip", "192.168.1.100")
        timestamp = kwargs.get("timestamp", datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000"))
        method = kwargs.get("method", "GET")
        path = kwargs.get("path", "/")
        status = kwargs.get("status", 200)
        size = kwargs.get("size", 1234)
        return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"'


class ThreatHuntQueryFactory:
    """Factory for creating threat hunt query test data"""

    @staticmethod
    def create(name: Optional[str] = None, platform: str = "wazuh", **kwargs) -> Dict:
        """Create a threat hunt query"""
        return {
            "id": kwargs.get("id", str(uuid4())),
            "name": name or f"Test Hunt {uuid4().hex[:8]}",
            "description": kwargs.get("description", "Test threat hunt query"),
            "platform": platform,
            "query": kwargs.get("query", "rule.id:60122"),
            "time_range": kwargs.get("time_range", "24h"),
            "mitre_tactics": kwargs.get("mitre_tactics", ["TA0008"]),
            "created_at": kwargs.get("created_at", datetime.utcnow().isoformat())
        }


class AlertFactory:
    """Factory for creating alert test data"""

    @staticmethod
    def create(severity: str = "high", **kwargs) -> Dict:
        """Create an alert"""
        return {
            "id": kwargs.get("id", str(uuid4())),
            "name": kwargs.get("name", f"Test Alert {uuid4().hex[:8]}"),
            "description": kwargs.get("description", "Test alert"),
            "severity": severity,
            "status": kwargs.get("status", "active"),
            "metric": kwargs.get("metric", "cpu_usage"),
            "condition": kwargs.get("condition", "gt"),
            "threshold": kwargs.get("threshold", 90),
            "current_value": kwargs.get("current_value", 95),
            "triggered_at": kwargs.get("triggered_at", datetime.utcnow().isoformat())
        }


class SBOMFactory:
    """Factory for creating SBOM test data"""

    @staticmethod
    def create(app_name: str = "test-app", **kwargs) -> Dict:
        """Create an SBOM"""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "component": {
                    "type": "application",
                    "name": app_name,
                    "version": kwargs.get("version", "1.0.0")
                }
            },
            "components": kwargs.get("components", [
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
            ])
        }
