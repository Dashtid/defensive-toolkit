"""Log Analysis API Router Tests.

Comprehensive tests for log analysis endpoints including:
- Log parsing (lines and files)
- Parser info
- Anomaly detection
- Baseline management
- Log statistics and filtering
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from defensive_toolkit.api.main import app


@pytest.fixture(scope="module")
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_token(client):
    """Get authentication token."""
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "changeme123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Create auth headers."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture(scope="module")
def write_auth_token(client):
    """Get authentication token with write scope."""
    response = client.post(
        "/api/v1/auth/token",
        data={
            "username": "admin",
            "password": "changeme123",
            "scope": "read write",
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def write_auth_headers(write_auth_token):
    """Create auth headers with write scope."""
    return {"Authorization": f"Bearer {write_auth_token}"}


@pytest.fixture
def sample_log_lines():
    """Sample syslog lines."""
    return [
        "Dec 28 10:15:30 webserver sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2",
        "Dec 28 10:15:31 webserver sshd[1235]: Failed password for root from 10.0.0.5 port 22 ssh2",
        "Dec 28 10:15:32 webserver nginx[5678]: 192.168.1.50 - - [28/Dec/2024:10:15:32 +0000] \"GET /api/users HTTP/1.1\" 200 1234",
    ]


@pytest.fixture
def sample_parsed_entries():
    """Sample parsed log entries."""
    return [
        {
            "timestamp": "2024-12-28T10:15:30",
            "hostname": "webserver",
            "process": "sshd",
            "pid": 1234,
            "severity": "info",
            "message": "Accepted password for admin",
            "source_ip": "192.168.1.100",
        },
        {
            "timestamp": "2024-12-28T10:15:31",
            "hostname": "webserver",
            "process": "sshd",
            "pid": 1235,
            "severity": "warning",
            "message": "Failed password for root",
            "source_ip": "10.0.0.5",
        },
        {
            "timestamp": "2024-12-28T10:15:32",
            "hostname": "appserver",
            "process": "nginx",
            "pid": 5678,
            "severity": "info",
            "message": "GET /api/users HTTP/1.1 200",
            "source_ip": "192.168.1.50",
        },
    ]


@pytest.fixture
def mock_log_parser():
    """Mock log parser."""
    mock = MagicMock()
    parsed_entry = MagicMock()
    parsed_entry.timestamp = "2024-12-28T10:15:30"
    parsed_entry.hostname = "webserver"
    parsed_entry.process = "sshd"
    parsed_entry.pid = 1234
    parsed_entry.severity = "info"
    parsed_entry.message = "Test message"
    parsed_entry.source_ip = "192.168.1.100"
    parsed_entry.dest_ip = None
    parsed_entry.user = "admin"
    parsed_entry.event_id = None
    parsed_entry.raw = "Dec 28 10:15:30 webserver sshd[1234]: Test message"
    mock.parse_line.return_value = parsed_entry
    mock.parse_file.return_value = [parsed_entry, parsed_entry]
    return mock


@pytest.fixture
def mock_anomaly_detector():
    """Mock anomaly detector."""
    mock = MagicMock()
    mock.detect_anomalies.return_value = [
        {
            "type": "frequency",
            "severity": "high",
            "description": "High frequency of failed login attempts",
            "details": {"count": 50, "threshold": 10},
        }
    ]
    mock.current_stats = {
        "total_entries": 100,
        "processes": {"sshd": 50, "nginx": 30},
        "hostnames": {"webserver": 100},
        "severities": {"info": 80, "warning": 20},
    }
    mock._compute_statistics.return_value = {
        "total_entries": 50,
        "processes": {"sshd": 30},
        "hostnames": {"webserver": 50},
    }
    return mock


class TestLogParsing:
    """Test log parsing endpoints."""

    def test_parse_logs(self, client, auth_headers, sample_log_lines, mock_log_parser):
        """Test parsing log lines."""
        with patch(
            "defensive_toolkit.api.routers.log_analysis.get_log_parser",
            return_value=(mock_log_parser, "python"),
        ):
            response = client.post(
                "/api/v1/log-analysis/parse",
                json={
                    "log_lines": sample_log_lines,
                    "log_format": "syslog",
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["entries_parsed"] == len(sample_log_lines)
            assert data["log_format"] == "syslog"
            assert data["backend"] == "python"
            assert len(data["entries"]) == len(sample_log_lines)

    def test_parse_logs_auto_format(
        self, client, auth_headers, sample_log_lines, mock_log_parser
    ):
        """Test parsing logs with auto format detection."""
        with patch(
            "defensive_toolkit.api.routers.log_analysis.get_log_parser",
            return_value=(mock_log_parser, "python"),
        ):
            response = client.post(
                "/api/v1/log-analysis/parse",
                json={
                    "log_lines": sample_log_lines,
                    "log_format": "auto",
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            assert response.json()["log_format"] == "auto"

    def test_parse_logs_with_failures(self, client, auth_headers, mock_log_parser):
        """Test parsing logs with some failures."""
        mock_log_parser.parse_line.side_effect = [
            mock_log_parser.parse_line.return_value,
            None,  # Failed to parse
            mock_log_parser.parse_line.return_value,
        ]
        with patch(
            "defensive_toolkit.api.routers.log_analysis.get_log_parser",
            return_value=(mock_log_parser, "python"),
        ):
            response = client.post(
                "/api/v1/log-analysis/parse",
                json={
                    "log_lines": ["line1", "line2", "line3"],
                    "log_format": "auto",
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["entries_parsed"] == 2
            assert data["entries_failed"] == 1


class TestParserInfo:
    """Test parser info endpoint."""

    def test_get_parser_info(self, client, auth_headers):
        """Test getting parser info."""
        response = client.get(
            "/api/v1/log-analysis/parser-info",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "rust_available" in data
        assert "active_backend" in data
        assert "supported_formats" in data
        # Verify some supported formats exist
        assert len(data["supported_formats"]) > 0


class TestAnomalyDetection:
    """Test anomaly detection endpoints."""

    def test_detect_anomalies(
        self, client, auth_headers, sample_parsed_entries, mock_anomaly_detector
    ):
        """Test detecting anomalies in logs."""
        with patch(
            "defensive_toolkit.api.routers.log_analysis.get_anomaly_detector",
            return_value=mock_anomaly_detector,
        ):
            response = client.post(
                "/api/v1/log-analysis/anomalies/detect",
                json={
                    "log_entries": sample_parsed_entries,
                    "threshold_stddev": 2.0,
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert "analysis_id" in data
            assert data["entries_analyzed"] == len(sample_parsed_entries)
            assert "anomalies_detected" in data
            assert "anomalies" in data
            assert "statistics" in data

    def test_detect_anomalies_with_baseline(
        self, client, auth_headers, sample_parsed_entries, mock_anomaly_detector
    ):
        """Test detecting anomalies with a baseline."""
        with patch(
            "defensive_toolkit.api.routers.log_analysis.get_anomaly_detector",
            return_value=mock_anomaly_detector,
        ):
            response = client.post(
                "/api/v1/log-analysis/anomalies/detect",
                json={
                    "log_entries": sample_parsed_entries,
                    "baseline_id": "test-baseline-id",
                    "threshold_stddev": 3.0,
                },
                headers=auth_headers,
            )
            assert response.status_code == 200

    def test_detect_anomalies_with_severity_filter(
        self, client, auth_headers, sample_parsed_entries, mock_anomaly_detector
    ):
        """Test anomalies include severity information."""
        with patch(
            "defensive_toolkit.api.routers.log_analysis.get_anomaly_detector",
            return_value=mock_anomaly_detector,
        ):
            response = client.post(
                "/api/v1/log-analysis/anomalies/detect",
                json={"log_entries": sample_parsed_entries},
                headers=auth_headers,
            )
            data = response.json()
            if data["anomalies"]:
                assert "severity" in data["anomalies"][0]
                assert "type" in data["anomalies"][0]
                assert "description" in data["anomalies"][0]


class TestBaselineManagement:
    """Test baseline CRUD operations."""

    def test_create_baseline(
        self, client, write_auth_headers, sample_parsed_entries, mock_anomaly_detector
    ):
        """Test creating a baseline."""
        with patch(
            "defensive_toolkit.api.routers.log_analysis.get_anomaly_detector",
            return_value=mock_anomaly_detector,
        ):
            response = client.post(
                "/api/v1/log-analysis/anomalies/create-baseline",
                json={
                    "log_entries": sample_parsed_entries,
                    "name": "Test Baseline",
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert "baseline_id" in data
            assert data["name"] == "Test Baseline"
            assert data["entry_count"] == len(sample_parsed_entries)
            assert "created_at" in data
            assert "statistics_summary" in data

    def test_create_baseline_without_auth(self, client, sample_parsed_entries):
        """Test creating a baseline requires authentication."""
        response = client.post(
            "/api/v1/log-analysis/anomalies/create-baseline",
            json={
                "log_entries": sample_parsed_entries,
                "name": "Test",
            },
        )
        assert response.status_code == 401

    def test_list_baselines(self, client, auth_headers):
        """Test listing baselines."""
        response = client.get(
            "/api/v1/log-analysis/anomalies/baselines",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "baselines" in data
        assert isinstance(data["baselines"], list)

    def test_get_baseline_not_found(self, client, auth_headers):
        """Test getting a non-existent baseline."""
        response = client.get(
            "/api/v1/log-analysis/anomalies/baseline/nonexistent-id",
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_delete_baseline_not_found(self, client, write_auth_headers):
        """Test deleting a non-existent baseline."""
        response = client.delete(
            "/api/v1/log-analysis/anomalies/baseline/nonexistent-id",
            headers=write_auth_headers,
        )
        assert response.status_code == 404

    def test_delete_baseline_without_auth(self, client):
        """Test deleting a baseline requires authentication."""
        response = client.delete(
            "/api/v1/log-analysis/anomalies/baseline/some-id",
        )
        assert response.status_code == 401


class TestLogStatistics:
    """Test log statistics endpoint."""

    def test_get_log_stats(self, client, auth_headers, sample_parsed_entries):
        """Test getting log statistics."""
        response = client.post(
            "/api/v1/log-analysis/stats",
            json={"log_entries": sample_parsed_entries},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_entries"] == len(sample_parsed_entries)
        assert "with_timestamp" in data
        assert "with_hostname" in data
        assert "with_source_ip" in data
        assert "unique_hostnames" in data
        assert "unique_source_ips" in data
        assert "unique_processes" in data
        assert "top_processes" in data
        assert "top_source_ips" in data
        assert "severity_distribution" in data

    def test_stats_counts_fields_correctly(self, client, auth_headers):
        """Test statistics correctly count fields."""
        entries = [
            {"timestamp": "2024-01-01", "hostname": "host1", "severity": "info"},
            {"timestamp": "2024-01-01", "hostname": "host1", "severity": "warning"},
            {"hostname": "host2"},  # No timestamp
        ]
        response = client.post(
            "/api/v1/log-analysis/stats",
            json={"log_entries": entries},
            headers=auth_headers,
        )
        data = response.json()
        assert data["total_entries"] == 3
        assert data["with_timestamp"] == 2
        assert data["with_hostname"] == 3
        assert data["unique_hostnames"] == 2

    def test_stats_top_processes(self, client, auth_headers):
        """Test top processes are returned."""
        entries = [
            {"process": "nginx"},
            {"process": "nginx"},
            {"process": "sshd"},
        ]
        response = client.post(
            "/api/v1/log-analysis/stats",
            json={"log_entries": entries},
            headers=auth_headers,
        )
        data = response.json()
        assert "nginx" in data["top_processes"]
        assert data["top_processes"]["nginx"] == 2


class TestLogFiltering:
    """Test log filtering endpoint."""

    def test_filter_logs_by_hostname(self, client, auth_headers, sample_parsed_entries):
        """Test filtering logs by hostname."""
        response = client.post(
            "/api/v1/log-analysis/filter",
            json={
                "log_entries": sample_parsed_entries,
                "hostname": "webserver",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_input"] == len(sample_parsed_entries)
        assert data["filters_applied"]["hostname"] == "webserver"
        for entry in data["entries"]:
            assert entry.get("hostname") == "webserver"

    def test_filter_logs_by_source_ip(self, client, auth_headers, sample_parsed_entries):
        """Test filtering logs by source IP."""
        response = client.post(
            "/api/v1/log-analysis/filter",
            json={
                "log_entries": sample_parsed_entries,
                "source_ip": "192.168.1.100",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "source_ip" in data["filters_applied"]

    def test_filter_logs_by_process(self, client, auth_headers, sample_parsed_entries):
        """Test filtering logs by process name."""
        response = client.post(
            "/api/v1/log-analysis/filter",
            json={
                "log_entries": sample_parsed_entries,
                "process": "ssh",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "process" in data["filters_applied"]

    def test_filter_logs_by_severity(self, client, auth_headers, sample_parsed_entries):
        """Test filtering logs by severity."""
        response = client.post(
            "/api/v1/log-analysis/filter",
            json={
                "log_entries": sample_parsed_entries,
                "severity": "warning",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["filters_applied"]["severity"] == "warning"

    def test_filter_logs_by_message(self, client, auth_headers, sample_parsed_entries):
        """Test filtering logs by message content."""
        response = client.post(
            "/api/v1/log-analysis/filter",
            json={
                "log_entries": sample_parsed_entries,
                "message_contains": "Failed",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "message_contains" in data["filters_applied"]

    def test_filter_logs_with_limit(self, client, auth_headers, sample_parsed_entries):
        """Test filtering logs with limit."""
        response = client.post(
            "/api/v1/log-analysis/filter",
            json={
                "log_entries": sample_parsed_entries,
                "limit": 1,
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["entries"]) <= 1

    def test_filter_logs_multiple_filters(
        self, client, auth_headers, sample_parsed_entries
    ):
        """Test filtering logs with multiple filters."""
        response = client.post(
            "/api/v1/log-analysis/filter",
            json={
                "log_entries": sample_parsed_entries,
                "hostname": "webserver",
                "process": "sshd",
                "severity": "info",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["filters_applied"]) == 3


class TestLogSources:
    """Test log sources listing."""

    def test_list_log_sources(self, client, auth_headers):
        """Test listing supported log sources."""
        response = client.get(
            "/api/v1/log-analysis/sources",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "formats" in data
        assert data["total"] == 5
        format_names = [f["name"] for f in data["formats"]]
        assert "auto" in format_names
        assert "syslog" in format_names
        assert "json" in format_names
        assert "apache" in format_names
        assert "nginx" in format_names


class TestServiceUnavailable:
    """Test handling of unavailable services."""

    def test_log_parser_unavailable(self, client, auth_headers):
        """Test handling when log parser is unavailable."""
        from fastapi import HTTPException

        with patch(
            "defensive_toolkit.api.routers.log_analysis.get_log_parser",
            side_effect=HTTPException(
                status_code=503,
                detail="Log parser module not available",
            ),
        ):
            response = client.post(
                "/api/v1/log-analysis/parse",
                json={"log_lines": ["test"], "log_format": "auto"},
                headers=auth_headers,
            )
            assert response.status_code == 503

    def test_anomaly_detector_unavailable(self, client, auth_headers):
        """Test handling when anomaly detector is unavailable."""
        from fastapi import HTTPException

        with patch(
            "defensive_toolkit.api.routers.log_analysis.get_anomaly_detector",
            side_effect=HTTPException(
                status_code=503,
                detail="Anomaly detector module not available",
            ),
        ):
            response = client.post(
                "/api/v1/log-analysis/anomalies/detect",
                json={"log_entries": [{"message": "test"}]},
                headers=auth_headers,
            )
            assert response.status_code == 503


class TestAuthentication:
    """Test authentication requirements."""

    def test_parse_requires_auth(self, client):
        """Test parse endpoint requires authentication."""
        response = client.post(
            "/api/v1/log-analysis/parse",
            json={"log_lines": ["test"], "log_format": "auto"},
        )
        assert response.status_code == 401

    def test_parser_info_requires_auth(self, client):
        """Test parser-info endpoint requires authentication."""
        response = client.get("/api/v1/log-analysis/parser-info")
        assert response.status_code == 401

    def test_anomalies_require_auth(self, client):
        """Test anomalies endpoint requires authentication."""
        response = client.post(
            "/api/v1/log-analysis/anomalies/detect",
            json={"log_entries": []},
        )
        assert response.status_code == 401

    def test_stats_require_auth(self, client):
        """Test stats endpoint requires authentication."""
        response = client.post(
            "/api/v1/log-analysis/stats",
            json={"log_entries": []},
        )
        assert response.status_code == 401

    def test_sources_require_auth(self, client):
        """Test sources endpoint requires authentication."""
        response = client.get("/api/v1/log-analysis/sources")
        assert response.status_code == 401
