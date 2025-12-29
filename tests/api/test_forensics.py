"""Forensics API Router Tests.

Comprehensive tests for forensics endpoints including:
- Memory analysis (Volatility)
- Malware hunting
- Disk forensics (MFT, file carving)
- Browser artifacts
- Timeline generation and analysis
"""

import tempfile
from pathlib import Path
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
def temp_file():
    """Create a temporary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as f:
        f.write(b"test data for forensics analysis")
        temp_path = f.name
    yield temp_path
    # Cleanup
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def mock_volatility_analyzer():
    """Mock Volatility analyzer."""
    mock = MagicMock()
    mock.results = {
        "plugins_run": [
            {"name": "windows.pslist", "entries": 50},
            {"name": "windows.netscan", "entries": 20},
        ],
        "suspicious_findings": [
            {"type": "hidden_process", "severity": "high", "description": "Hidden process detected"}
        ],
        "statistics": {"total_processes": 50, "suspicious_count": 1},
    }
    return mock


@pytest.fixture
def mock_malware_hunter():
    """Mock malware hunter."""
    mock = MagicMock()
    mock.findings = [
        {
            "type": "code_injection",
            "severity": "critical",
            "process": "suspicious.exe",
            "description": "Code injection detected in process memory",
        },
        {
            "type": "suspicious_network",
            "severity": "high",
            "ip": "10.0.0.100",
            "description": "Connection to known C2 server",
        },
    ]
    return mock


@pytest.fixture
def mock_mft_analyzer():
    """Mock MFT analyzer."""
    mock = MagicMock()
    mock.suspicious_findings = [
        {
            "filename": "malware.exe",
            "path": "C:\\Users\\admin\\AppData\\Local\\Temp\\",
            "severity": "high",
            "reason": "Executable in temp directory",
        }
    ]
    return mock


@pytest.fixture
def mock_file_carver():
    """Mock file carver."""
    mock = MagicMock()
    mock.results = {
        "tools_run": [{"tool": "bulk_extractor", "success": True}],
        "files_carved": {"pdf": 10, "jpg": 25, "doc": 5},
        "statistics": {"total_files": 40, "total_size_mb": 125.5},
    }
    return mock


@pytest.fixture
def mock_browser_forensics():
    """Mock browser forensics."""
    mock = MagicMock()
    mock.results = {
        "browsers_analyzed": ["chrome", "edge"],
        "artifacts_extracted": {
            "history": 1000,
            "downloads": 50,
            "cookies": 500,
        },
    }
    return mock


@pytest.fixture
def mock_timeline_generator():
    """Mock timeline generator."""
    mock = MagicMock()
    mock.timeline_entries = [
        {
            "timestamp": "2024-01-01T10:00:00",
            "event_type": "process_create",
            "source": "memory",
            "description": "Process created: cmd.exe",
        },
        {
            "timestamp": "2024-01-01T10:05:00",
            "event_type": "file_access",
            "source": "mft",
            "description": "File accessed: passwords.txt",
        },
    ]
    return mock


class TestMemoryAnalysis:
    """Test memory analysis endpoints."""

    def test_analyze_memory_quick(
        self, client, auth_headers, temp_file, mock_volatility_analyzer
    ):
        """Test quick memory analysis."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_volatility_analyzer",
            return_value=mock_volatility_analyzer,
        ):
            response = client.post(
                "/api/v1/forensics/memory/analyze",
                json={
                    "memory_dump_path": temp_file,
                    "analysis_type": "quick",
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert "analysis_id" in data
            assert data["analysis_type"] == "quick"
            assert data["status"] in ["completed", "failed"]
            assert "plugins_run" in data

    def test_analyze_memory_full(
        self, client, auth_headers, temp_file, mock_volatility_analyzer
    ):
        """Test full memory analysis."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_volatility_analyzer",
            return_value=mock_volatility_analyzer,
        ):
            response = client.post(
                "/api/v1/forensics/memory/analyze",
                json={
                    "memory_dump_path": temp_file,
                    "analysis_type": "full",
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            assert response.json()["analysis_type"] == "full"

    def test_analyze_memory_malware_hunt(
        self, client, auth_headers, temp_file, mock_volatility_analyzer
    ):
        """Test malware hunt analysis."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_volatility_analyzer",
            return_value=mock_volatility_analyzer,
        ):
            response = client.post(
                "/api/v1/forensics/memory/analyze",
                json={
                    "memory_dump_path": temp_file,
                    "analysis_type": "malware_hunt",
                },
                headers=auth_headers,
            )
            assert response.status_code == 200

    def test_analyze_memory_with_plugins(
        self, client, auth_headers, temp_file, mock_volatility_analyzer
    ):
        """Test memory analysis with specific plugins."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_volatility_analyzer",
            return_value=mock_volatility_analyzer,
        ):
            response = client.post(
                "/api/v1/forensics/memory/analyze",
                json={
                    "memory_dump_path": temp_file,
                    "analysis_type": "quick",
                    "plugins": ["windows.pslist.PsList"],
                },
                headers=auth_headers,
            )
            assert response.status_code == 200

    def test_analyze_memory_file_not_found(self, client, auth_headers):
        """Test memory analysis with non-existent file."""
        response = client.post(
            "/api/v1/forensics/memory/analyze",
            json={
                "memory_dump_path": "/nonexistent/memory.dmp",
                "analysis_type": "quick",
            },
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_hunt_malware(
        self, client, auth_headers, temp_file, mock_malware_hunter
    ):
        """Test malware hunting in memory."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_malware_hunter",
            return_value=mock_malware_hunter,
        ):
            response = client.post(
                "/api/v1/forensics/memory/hunt",
                json={"memory_dump_path": temp_file},
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert "hunt_id" in data
            assert data["total_findings"] == 2
            assert "severity_counts" in data
            assert data["severity_counts"]["critical"] == 1
            assert data["severity_counts"]["high"] == 1

    def test_hunt_malware_with_ioc(
        self, client, auth_headers, temp_file, mock_malware_hunter
    ):
        """Test malware hunting with IOC file."""
        # Create a temp IOC file
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".txt", mode="w"
        ) as ioc_file:
            ioc_file.write("malicious.exe\n10.0.0.100\n")
            ioc_path = ioc_file.name

        try:
            with patch(
                "defensive_toolkit.api.routers.forensics.get_malware_hunter",
                return_value=mock_malware_hunter,
            ):
                response = client.post(
                    "/api/v1/forensics/memory/hunt",
                    json={
                        "memory_dump_path": temp_file,
                        "ioc_file_path": ioc_path,
                    },
                    headers=auth_headers,
                )
                assert response.status_code == 200
        finally:
            Path(ioc_path).unlink(missing_ok=True)

    def test_hunt_malware_ioc_not_found(self, client, auth_headers, temp_file):
        """Test malware hunting with non-existent IOC file."""
        response = client.post(
            "/api/v1/forensics/memory/hunt",
            json={
                "memory_dump_path": temp_file,
                "ioc_file_path": "/nonexistent/ioc.txt",
            },
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_list_volatility_plugins(self, client, auth_headers):
        """Test listing Volatility plugins."""
        response = client.get(
            "/api/v1/forensics/memory/plugins",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "plugins" in data
        assert "total" in data
        assert "categories" in data
        assert data["total"] > 0

        # Check for essential plugins
        plugin_names = [p["name"] for p in data["plugins"]]
        assert "windows.pslist.PsList" in plugin_names
        assert "windows.netscan.NetScan" in plugin_names
        assert "windows.malfind.Malfind" in plugin_names


class TestDiskForensics:
    """Test disk forensics endpoints."""

    def test_parse_mft(self, client, auth_headers, temp_file, mock_mft_analyzer):
        """Test MFT parsing."""
        # Create a mock parsed CSV path
        mock_mft_analyzer.parse_mft.return_value = Path(temp_file)
        mock_mft_analyzer.analyze_suspicious_files.return_value = None

        with patch(
            "defensive_toolkit.api.routers.forensics.get_mft_analyzer",
            return_value=mock_mft_analyzer,
        ):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__ = lambda s: s
                mock_open.return_value.__exit__ = MagicMock(return_value=False)
                mock_open.return_value.__iter__ = lambda s: iter(
                    ["header\n", "row1\n", "row2\n"]
                )

                response = client.post(
                    "/api/v1/forensics/disk/parse-mft",
                    json={
                        "mft_file_path": temp_file,
                        "analyze_suspicious": True,
                    },
                    headers=auth_headers,
                )
                assert response.status_code == 200
                data = response.json()
                assert "parse_id" in data
                assert "entries_parsed" in data
                assert "suspicious_files" in data
                assert "severity_counts" in data

    def test_parse_mft_file_not_found(self, client, auth_headers):
        """Test MFT parsing with non-existent file."""
        response = client.post(
            "/api/v1/forensics/disk/parse-mft",
            json={
                "mft_file_path": "/nonexistent/$MFT",
                "analyze_suspicious": False,
            },
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_carve_files(
        self, client, write_auth_headers, temp_file, mock_file_carver
    ):
        """Test file carving."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_file_carver",
            return_value=mock_file_carver,
        ):
            response = client.post(
                "/api/v1/forensics/disk/carve",
                json={
                    "image_path": temp_file,
                    "tool": "both",
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert "carve_id" in data
            assert "tools_run" in data
            assert "files_carved" in data
            assert "statistics" in data

    def test_carve_files_bulk_extractor_only(
        self, client, write_auth_headers, temp_file, mock_file_carver
    ):
        """Test file carving with bulk_extractor only."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_file_carver",
            return_value=mock_file_carver,
        ):
            response = client.post(
                "/api/v1/forensics/disk/carve",
                json={
                    "image_path": temp_file,
                    "tool": "bulk_extractor",
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200

    def test_carve_files_foremost_only(
        self, client, write_auth_headers, temp_file, mock_file_carver
    ):
        """Test file carving with foremost only."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_file_carver",
            return_value=mock_file_carver,
        ):
            response = client.post(
                "/api/v1/forensics/disk/carve",
                json={
                    "image_path": temp_file,
                    "tool": "foremost",
                    "file_types": ["jpg", "pdf"],
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200

    def test_carve_files_without_auth(self, client, temp_file):
        """Test file carving requires authentication."""
        response = client.post(
            "/api/v1/forensics/disk/carve",
            json={
                "image_path": temp_file,
                "tool": "both",
            },
        )
        assert response.status_code == 401

    def test_carve_files_not_found(self, client, write_auth_headers):
        """Test file carving with non-existent image."""
        response = client.post(
            "/api/v1/forensics/disk/carve",
            json={
                "image_path": "/nonexistent/disk.img",
                "tool": "both",
            },
            headers=write_auth_headers,
        )
        assert response.status_code == 404


class TestBrowserForensics:
    """Test browser artifact extraction."""

    def test_extract_browser_artifacts(
        self, client, auth_headers, temp_file, mock_browser_forensics
    ):
        """Test browser artifact extraction."""
        # Create a temp directory as user profile
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "defensive_toolkit.api.routers.forensics.get_browser_forensics",
                return_value=mock_browser_forensics,
            ):
                response = client.post(
                    "/api/v1/forensics/artifacts/browser",
                    json={
                        "user_profile_path": temp_dir,
                        "browsers": ["chrome", "edge"],
                    },
                    headers=auth_headers,
                )
                assert response.status_code == 200
                data = response.json()
                assert "extract_id" in data
                assert "browsers_analyzed" in data
                assert "artifacts_extracted" in data

    def test_extract_browser_artifacts_all_browsers(
        self, client, auth_headers, mock_browser_forensics
    ):
        """Test extracting from all browsers."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "defensive_toolkit.api.routers.forensics.get_browser_forensics",
                return_value=mock_browser_forensics,
            ):
                response = client.post(
                    "/api/v1/forensics/artifacts/browser",
                    json={
                        "user_profile_path": temp_dir,
                        "browsers": ["chrome", "edge", "firefox"],
                    },
                    headers=auth_headers,
                )
                assert response.status_code == 200

    def test_extract_browser_profile_not_found(self, client, auth_headers):
        """Test extraction with non-existent profile."""
        response = client.post(
            "/api/v1/forensics/artifacts/browser",
            json={
                "user_profile_path": "/nonexistent/Users/victim",
                "browsers": ["chrome"],
            },
            headers=auth_headers,
        )
        assert response.status_code == 404


class TestTimeline:
    """Test timeline endpoints."""

    def test_generate_timeline(
        self, client, auth_headers, temp_file, mock_timeline_generator
    ):
        """Test timeline generation."""
        # Set up the mock properly
        mock_timeline_generator.analyze_timeline.return_value = {
            "patterns": [],
            "anomalies": [],
        }
        with patch(
            "defensive_toolkit.api.routers.forensics.get_timeline_generator",
            return_value=mock_timeline_generator,
        ):
            response = client.post(
                "/api/v1/forensics/timeline/generate",
                json={
                    "source_files": [temp_file],
                    "analyze": True,
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert "timeline_id" in data
            assert "total_entries" in data

    def test_generate_timeline_without_analysis(
        self, client, auth_headers, temp_file, mock_timeline_generator
    ):
        """Test timeline generation without analysis."""
        mock_timeline_generator.timeline_entries = []
        with patch(
            "defensive_toolkit.api.routers.forensics.get_timeline_generator",
            return_value=mock_timeline_generator,
        ):
            response = client.post(
                "/api/v1/forensics/timeline/generate",
                json={
                    "source_files": [temp_file],
                    "analyze": False,
                },
                headers=auth_headers,
            )
            assert response.status_code == 200

    def test_generate_timeline_file_not_found(self, client, auth_headers):
        """Test timeline generation with non-existent file."""
        response = client.post(
            "/api/v1/forensics/timeline/generate",
            json={
                "source_files": ["/nonexistent/timeline.json"],
                "analyze": False,
            },
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_analyze_timeline(self, client, auth_headers):
        """Test timeline analysis."""
        entries = [
            {
                "timestamp": "2024-01-01T10:00:00",
                "event_type": "process_create",
                "source": "memory",
            },
            {
                "timestamp": "2024-01-01T11:00:00",
                "event_type": "file_access",
                "source": "mft",
            },
            {
                "timestamp": "2024-01-02T10:00:00",
                "event_type": "process_create",
                "source": "memory",
            },
        ]
        response = client.post(
            "/api/v1/forensics/timeline/analyze",
            json=entries,
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "timeline_id" in data
        assert data["total_entries"] == 3
        assert "event_types" in data
        assert data["event_types"]["process_create"] == 2
        assert "sources" in data
        assert data["sources"]["memory"] == 2
        assert "daily_distribution" in data
        assert "busiest_days" in data

    def test_merge_timelines(
        self, client, auth_headers, temp_file, mock_timeline_generator
    ):
        """Test merging multiple timelines."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_timeline_generator",
            return_value=mock_timeline_generator,
        ):
            response = client.post(
                "/api/v1/forensics/timeline/merge",
                json=[temp_file],
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "merged"
            assert "total_entries" in data
            assert "sources" in data

    def test_merge_timelines_file_not_found(self, client, auth_headers):
        """Test merging with non-existent file."""
        response = client.post(
            "/api/v1/forensics/timeline/merge",
            json=["/nonexistent/timeline1.csv", "/nonexistent/timeline2.csv"],
            headers=auth_headers,
        )
        assert response.status_code == 404


class TestAsyncResults:
    """Test async results endpoint."""

    def test_get_analysis_results_not_found(self, client, auth_headers):
        """Test getting non-existent analysis results."""
        response = client.get(
            "/api/v1/forensics/results/nonexistent-task-id",
            headers=auth_headers,
        )
        assert response.status_code == 404


class TestArtifactTypes:
    """Test artifact types listing."""

    def test_list_artifact_types(self, client, auth_headers):
        """Test listing supported artifact types."""
        response = client.get(
            "/api/v1/forensics/artifacts/types",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "artifact_types" in data
        assert data["total"] == 6

        types = [t["type"] for t in data["artifact_types"]]
        assert "memory" in types
        assert "disk" in types
        assert "mft" in types
        assert "browser" in types
        assert "timeline" in types
        assert "file_carving" in types


class TestLegacyEndpoints:
    """Test legacy/compatibility endpoints."""

    def test_analyze_artifact_memory(
        self, client, auth_headers, temp_file, mock_volatility_analyzer
    ):
        """Test legacy analyze endpoint for memory."""
        with patch(
            "defensive_toolkit.api.routers.forensics.get_volatility_analyzer",
            return_value=mock_volatility_analyzer,
        ):
            response = client.post(
                "/api/v1/forensics/analyze",
                params={
                    "artifact_type": "memory",
                    "artifact_path": temp_file,
                },
                headers=auth_headers,
            )
            assert response.status_code == 200

    def test_analyze_artifact_unsupported_type(self, client, auth_headers, temp_file):
        """Test legacy analyze endpoint with unsupported type."""
        response = client.post(
            "/api/v1/forensics/analyze",
            params={
                "artifact_type": "unsupported",
                "artifact_path": temp_file,
            },
            headers=auth_headers,
        )
        assert response.status_code == 400
        assert "Use specific endpoint" in response.json()["detail"]


class TestServiceUnavailable:
    """Test handling of unavailable services."""

    def test_volatility_unavailable(self, client, auth_headers, temp_file):
        """Test handling when Volatility is unavailable."""
        from fastapi import HTTPException

        with patch(
            "defensive_toolkit.api.routers.forensics.get_volatility_analyzer",
            side_effect=HTTPException(
                status_code=503,
                detail="Volatility analyzer module not available",
            ),
        ):
            response = client.post(
                "/api/v1/forensics/memory/analyze",
                json={"memory_dump_path": temp_file, "analysis_type": "quick"},
                headers=auth_headers,
            )
            assert response.status_code == 503

    def test_mft_analyzer_unavailable(self, client, auth_headers, temp_file):
        """Test handling when MFT analyzer is unavailable."""
        from fastapi import HTTPException

        with patch(
            "defensive_toolkit.api.routers.forensics.get_mft_analyzer",
            side_effect=HTTPException(
                status_code=503,
                detail="MFT analyzer module not available",
            ),
        ):
            response = client.post(
                "/api/v1/forensics/disk/parse-mft",
                json={"mft_file_path": temp_file, "analyze_suspicious": False},
                headers=auth_headers,
            )
            assert response.status_code == 503


class TestAuthentication:
    """Test authentication requirements."""

    def test_memory_analyze_requires_auth(self, client):
        """Test memory analyze requires authentication."""
        response = client.post(
            "/api/v1/forensics/memory/analyze",
            json={"memory_dump_path": "/tmp/test", "analysis_type": "quick"},
        )
        assert response.status_code == 401

    def test_plugins_require_auth(self, client):
        """Test plugins endpoint requires authentication."""
        response = client.get("/api/v1/forensics/memory/plugins")
        assert response.status_code == 401

    def test_mft_parse_requires_auth(self, client):
        """Test MFT parse requires authentication."""
        response = client.post(
            "/api/v1/forensics/disk/parse-mft",
            json={"mft_file_path": "/tmp/test"},
        )
        assert response.status_code == 401

    def test_timeline_requires_auth(self, client):
        """Test timeline endpoint requires authentication."""
        response = client.post(
            "/api/v1/forensics/timeline/analyze",
            json=[],
        )
        assert response.status_code == 401

    def test_artifact_types_require_auth(self, client):
        """Test artifact types requires authentication."""
        response = client.get("/api/v1/forensics/artifacts/types")
        assert response.status_code == 401
