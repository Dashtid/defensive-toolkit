"""
Mock External Services

Mock implementations of external services for testing without dependencies.
Includes mocks for SIEM platforms, vulnerability scanners, ticketing systems, etc.
"""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4


class MockWazuhClient:
    """Mock Wazuh API client"""

    def __init__(self, host: str = "localhost", port: int = 55000, **kwargs):
        self.host = host
        self.port = port
        self.authenticated = False
        self.token = None

    def authenticate(self, username: str, password: str) -> bool:
        """Mock authentication"""
        self.authenticated = True
        self.token = f"mock-token-{uuid4().hex[:16]}"
        return True

    def deploy_rule(self, rule_content: str, rule_id: str) -> Dict:
        """Mock rule deployment"""
        return {
            "status": "success",
            "rule_id": rule_id,
            "message": "Rule deployed successfully"
        }

    def query_logs(self, query: str, time_range: str = "24h") -> Dict:
        """Mock log query"""
        return {
            "hits": {
                "total": 42,
                "results": [
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "rule_id": "60122",
                        "level": 5,
                        "description": "Test log entry"
                    }
                ]
            }
        }

    def get_agents(self) -> List[Dict]:
        """Mock get agents"""
        return [
            {"id": "001", "name": "agent-001", "status": "active"},
            {"id": "002", "name": "agent-002", "status": "active"}
        ]


class MockElasticClient:
    """Mock Elasticsearch/Elastic Stack client"""

    def __init__(self, hosts: List[str] = None, **kwargs):
        self.hosts = hosts or ["localhost:9200"]
        self.connected = True

    def search(self, index: str, body: Dict) -> Dict:
        """Mock search query"""
        return {
            "hits": {
                "total": {"value": 10, "relation": "eq"},
                "hits": [
                    {
                        "_index": index,
                        "_id": str(uuid4()),
                        "_source": {
                            "@timestamp": datetime.utcnow().isoformat(),
                            "message": "Test log message",
                            "severity": "high"
                        }
                    }
                ]
            }
        }

    def index(self, index: str, body: Dict, id: Optional[str] = None) -> Dict:
        """Mock document indexing"""
        return {
            "_index": index,
            "_id": id or str(uuid4()),
            "result": "created",
            "_version": 1
        }

    def indices_create(self, index: str, body: Optional[Dict] = None) -> Dict:
        """Mock index creation"""
        return {"acknowledged": True, "index": index}


class MockGraylogClient:
    """Mock Graylog API client"""

    def __init__(self, host: str = "localhost", port: int = 9000, **kwargs):
        self.host = host
        self.port = port
        self.api_token = kwargs.get("api_token")

    def search(self, query: str, time_range: str = "relative:3600") -> Dict:
        """Mock search"""
        return {
            "messages": [
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "message": "Test message",
                    "source": "test-host",
                    "level": 6
                }
            ],
            "total_results": 1
        }

    def create_stream(self, title: str, description: str) -> Dict:
        """Mock stream creation"""
        return {
            "stream_id": str(uuid4()),
            "title": title,
            "description": description
        }


class MockOpenVASScanner:
    """Mock OpenVAS vulnerability scanner"""

    def __init__(self, host: str = "localhost", port: int = 9390, **kwargs):
        self.host = host
        self.port = port
        self.authenticated = False

    def authenticate(self, username: str, password: str) -> bool:
        """Mock authentication"""
        self.authenticated = True
        return True

    def create_target(self, name: str, hosts: List[str]) -> str:
        """Mock target creation"""
        return f"target-{uuid4().hex[:8]}"

    def create_task(self, name: str, target_id: str, scan_config_id: str) -> str:
        """Mock task creation"""
        return f"task-{uuid4().hex[:8]}"

    def start_task(self, task_id: str) -> Dict:
        """Mock task start"""
        return {
            "status": "running",
            "report_id": f"report-{uuid4().hex[:8]}"
        }

    def get_results(self, task_id: str) -> Dict:
        """Mock get scan results"""
        return {
            "task_id": task_id,
            "status": "Done",
            "vulnerabilities": [
                {
                    "nvt_oid": "1.3.6.1.4.1.25623.1.0.12345",
                    "cve": "CVE-2025-12345",
                    "severity": 7.5,
                    "threat": "High",
                    "port": "443/tcp",
                    "description": "Test vulnerability"
                }
            ]
        }


class MockTrivyScanner:
    """Mock Trivy container scanner"""

    def __init__(self):
        self.cache_dir = "/tmp/trivy-cache"

    def scan_image(self, image: str) -> Dict:
        """Mock image scan"""
        return {
            "ArtifactName": image,
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": f"{image} (alpine 3.18.4)",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2025-12345",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.1.0-r0",
                            "FixedVersion": "3.1.1-r0",
                            "Severity": "HIGH",
                            "Title": "Test vulnerability in OpenSSL"
                        }
                    ]
                }
            ]
        }

    def scan_filesystem(self, path: str) -> Dict:
        """Mock filesystem scan"""
        return {
            "ArtifactName": path,
            "ArtifactType": "filesystem",
            "Results": []
        }


class MockTheHiveClient:
    """Mock TheHive case management client"""

    def __init__(self, url: str, api_key: str, **kwargs):
        self.url = url
        self.api_key = api_key

    def create_case(self, title: str, description: str, severity: int = 2) -> Dict:
        """Mock case creation"""
        return {
            "_id": str(uuid4()),
            "title": title,
            "description": description,
            "severity": severity,
            "status": "Open",
            "createdAt": int(datetime.utcnow().timestamp() * 1000)
        }

    def create_alert(self, title: str, description: str, source: str) -> Dict:
        """Mock alert creation"""
        return {
            "_id": str(uuid4()),
            "title": title,
            "description": description,
            "source": source,
            "status": "New",
            "createdAt": int(datetime.utcnow().timestamp() * 1000)
        }

    def add_observable(self, case_id: str, dataType: str, data: str) -> Dict:
        """Mock observable addition"""
        return {
            "_id": str(uuid4()),
            "dataType": dataType,
            "data": data,
            "case_id": case_id
        }


class MockJiraClient:
    """Mock Jira API client"""

    def __init__(self, url: str, username: str, api_token: str, **kwargs):
        self.url = url
        self.username = username
        self.api_token = api_token

    def create_issue(self, project: str, summary: str, description: str, issue_type: str = "Task") -> Dict:
        """Mock issue creation"""
        return {
            "id": str(random.randint(10000, 99999)),
            "key": f"{project}-{random.randint(100, 999)}",
            "self": f"{self.url}/rest/api/2/issue/12345",
            "fields": {
                "project": {"key": project},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
                "status": {"name": "Open"}
            }
        }

    def get_issue(self, issue_key: str) -> Dict:
        """Mock get issue"""
        return {
            "key": issue_key,
            "fields": {
                "summary": "Test Issue",
                "description": "Test description",
                "status": {"name": "Open"}
            }
        }


class MockVirusTotalClient:
    """Mock VirusTotal API client"""

    def __init__(self, api_key: str):
        self.api_key = api_key

    def get_file_report(self, file_hash: str) -> Dict:
        """Mock file report"""
        return {
            "sha256": file_hash,
            "positives": 5,
            "total": 70,
            "scan_date": datetime.utcnow().isoformat(),
            "permalink": f"https://virustotal.com/file/{file_hash}",
            "scans": {
                "Microsoft": {"detected": True, "result": "Trojan:Win32/Test"},
                "Kaspersky": {"detected": False, "result": None}
            }
        }

    def scan_url(self, url: str) -> Dict:
        """Mock URL scan"""
        return {
            "scan_id": str(uuid4()),
            "url": url,
            "permalink": f"https://virustotal.com/url/{uuid4()}",
            "scan_date": datetime.utcnow().isoformat()
        }


class MockAbuseIPDBClient:
    """Mock AbuseIPDB API client"""

    def __init__(self, api_key: str):
        self.api_key = api_key

    def check_ip(self, ip_address: str) -> Dict:
        """Mock IP check"""
        return {
            "ipAddress": ip_address,
            "isPublic": True,
            "ipVersion": 4,
            "abuseConfidenceScore": 75,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "totalReports": 42,
            "numDistinctUsers": 12,
            "lastReportedAt": datetime.utcnow().isoformat()
        }


# Import random for Jira mock
import random


def create_mock_siem_client(siem_type: str, **kwargs):
    """Factory function to create mock SIEM clients"""
    siem_clients = {
        "wazuh": MockWazuhClient,
        "elastic": MockElasticClient,
        "elasticsearch": MockElasticClient,
        "opensearch": MockElasticClient,
        "graylog": MockGraylogClient
    }

    client_class = siem_clients.get(siem_type.lower())
    if not client_class:
        raise ValueError(f"Unknown SIEM type: {siem_type}")

    return client_class(**kwargs)


def create_mock_scanner(scanner_type: str, **kwargs):
    """Factory function to create mock scanner clients"""
    scanner_clients = {
        "openvas": MockOpenVASScanner,
        "trivy": MockTrivyScanner
    }

    scanner_class = scanner_clients.get(scanner_type.lower())
    if not scanner_class:
        raise ValueError(f"Unknown scanner type: {scanner_type}")

    return scanner_class(**kwargs)


def create_mock_ticketing_client(system_type: str, **kwargs):
    """Factory function to create mock ticketing system clients"""
    ticketing_clients = {
        "thehive": MockTheHiveClient,
        "jira": MockJiraClient
    }

    client_class = ticketing_clients.get(system_type.lower())
    if not client_class:
        raise ValueError(f"Unknown ticketing system: {system_type}")

    return client_class(**kwargs)
