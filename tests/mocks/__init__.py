"""Mock external services for testing"""

from .external_services import (
    MockWazuhClient,
    MockElasticClient,
    MockGraylogClient,
    MockOpenVASScanner,
    MockTrivyScanner,
    MockTheHiveClient,
    MockJiraClient,
    MockVirusTotalClient,
    MockAbuseIPDBClient,
    create_mock_siem_client,
    create_mock_scanner,
    create_mock_ticketing_client
)

__all__ = [
    "MockWazuhClient",
    "MockElasticClient",
    "MockGraylogClient",
    "MockOpenVASScanner",
    "MockTrivyScanner",
    "MockTheHiveClient",
    "MockJiraClient",
    "MockVirusTotalClient",
    "MockAbuseIPDBClient",
    "create_mock_siem_client",
    "create_mock_scanner",
    "create_mock_ticketing_client"
]
