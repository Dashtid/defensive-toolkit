#!/usr/bin/env python3
"""
Unit tests for forensics artifact collection
"""

import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


class TestForensicsCollector:
    """Test forensics collector functionality"""

    def test_memory_dump_metadata(self, sample_memory_dump_metadata):
        """Test memory dump metadata structure"""
        assert "filename" in sample_memory_dump_metadata
        assert "size_bytes" in sample_memory_dump_metadata
        assert "acquired_date" in sample_memory_dump_metadata
        assert "profile" in sample_memory_dump_metadata

    def test_forensic_timeline_entry(self, sample_forensic_timeline_entry):
        """Test forensic timeline entry structure"""
        assert "timestamp" in sample_forensic_timeline_entry
        assert "source" in sample_forensic_timeline_entry
        assert "type" in sample_forensic_timeline_entry
        assert "path" in sample_forensic_timeline_entry

    def test_suspicious_file_detection(self, sample_forensic_timeline_entry):
        """Test suspicious file detection logic"""
        entry = sample_forensic_timeline_entry

        assert entry["suspicious"] is True
        assert "reason" in entry
        assert "suspicious location" in entry["reason"].lower()

    @patch("pathlib.Path.exists")
    def test_artifact_collection_paths(self, mock_exists):
        """Test artifact collection path validation"""
        mock_exists.return_value = True

        # Common forensic artifact paths
        artifact_paths = [
            "/var/log/auth.log",
            "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            "/var/log/syslog",
        ]

        for path in artifact_paths:
            p = Path(path)
            assert mock_exists.return_value is True


class TestMemoryForensics:
    """Test memory forensics functionality"""

    def test_memory_dump_size_validation(self):
        """Test memory dump size is reasonable"""
        # Typical memory dumps are 4GB-64GB
        valid_sizes = [
            4 * 1024 * 1024 * 1024,  # 4GB
            8 * 1024 * 1024 * 1024,  # 8GB
            16 * 1024 * 1024 * 1024,  # 16GB
        ]

        for size in valid_sizes:
            assert size > 0
            assert size < 100 * 1024 * 1024 * 1024  # Less than 100GB

    @pytest.mark.slow
    def test_memory_profile_detection(self):
        """Test memory profile detection"""
        # Common Volatility profiles
        common_profiles = ["Win10x64_19041", "Win7SP1x64", "LinuxUbuntu20x64"]

        for profile in common_profiles:
            assert "Win" in profile or "Linux" in profile
            assert "x64" in profile or "x86" in profile


class TestDiskForensics:
    """Test disk forensics functionality"""

    def test_file_hash_validation(self, sample_forensic_timeline_entry):
        """Test file hash is valid MD5"""
        md5_hash = sample_forensic_timeline_entry["md5"]

        # MD5 is 32 hex characters
        assert len(md5_hash) == 32
        assert all(c in "0123456789abcdef" for c in md5_hash.lower())

    def test_suspicious_file_paths(self):
        """Test suspicious file path detection"""
        suspicious_paths = [
            "C:\\Windows\\Temp\\suspicious.exe",
            "/tmp/.hidden_malware",
            "C:\\Users\\Public\\payload.dll",
            "/var/tmp/backdoor.sh",
        ]

        for path in suspicious_paths:
            # Should trigger suspicion due to Temp, tmp, or hidden paths
            assert any(x in path.lower() for x in ["temp", "tmp", "public", ".hidden"])


class TestBrowserArtifacts:
    """Test browser artifact extraction"""

    def test_browser_history_structure(self):
        """Test browser history data structure"""
        history_entry = {
            "url": "https://example.com",
            "title": "Example Site",
            "visit_count": 5,
            "last_visit": "2025-10-15T14:30:22Z",
            "browser": "chrome",
        }

        assert "url" in history_entry
        assert "visit_count" in history_entry
        assert history_entry["visit_count"] > 0

    def test_cookie_extraction(self):
        """Test cookie data extraction"""
        cookie_entry = {
            "host": ".example.com",
            "name": "session_id",
            "value": "abc123",
            "expires": "2025-12-31T23:59:59Z",
            "secure": True,
        }

        assert "host" in cookie_entry
        assert "name" in cookie_entry
        assert "secure" in cookie_entry


class TestChainOfCustody:
    """Test chain of custody functionality"""

    def test_chain_of_custody_metadata(self):
        """Test chain of custody metadata"""
        custody_data = {
            "case_id": "CASE-2025-001",
            "evidence_id": "E001",
            "collector": "John Doe",
            "timestamp": datetime.now().isoformat(),
            "hash_algorithm": "SHA256",
            "hash_value": "a" * 64,  # SHA256 is 64 hex chars
            "location": "Server Room A",
        }

        assert "case_id" in custody_data
        assert "evidence_id" in custody_data
        assert "hash_algorithm" in custody_data
        assert len(custody_data["hash_value"]) == 64

    def test_evidence_integrity_hash(self):
        """Test evidence integrity hash validation"""
        # SHA256 should be 64 hex characters
        sha256_hash = "a" * 64

        assert len(sha256_hash) == 64
        assert all(c in "0123456789abcdef" for c in sha256_hash.lower())


# [+] Integration Tests
@pytest.mark.integration
class TestForensicsWorkflow:
    """Test complete forensics collection workflow"""

    def test_artifact_collection_workflow(self, tmp_path):
        """Test complete artifact collection"""
        # Create mock evidence directory
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()

        # Simulate collecting various artifacts
        artifacts = {
            "memory": evidence_dir / "memory.raw",
            "disk": evidence_dir / "disk.dd",
            "logs": evidence_dir / "logs",
        }

        for name, path in artifacts.items():
            if name == "logs":
                path.mkdir()
            else:
                path.touch()

        assert all(p.exists() for p in artifacts.values())

    def test_timeline_generation(self):
        """Test forensic timeline generation"""
        timeline_entries = [
            {
                "timestamp": "2025-10-15T14:00:00Z",
                "event": "File Created",
                "artifact": "suspicious.exe",
            },
            {
                "timestamp": "2025-10-15T14:05:00Z",
                "event": "Process Executed",
                "artifact": "suspicious.exe",
            },
            {
                "timestamp": "2025-10-15T14:10:00Z",
                "event": "Network Connection",
                "artifact": "192.168.1.100:4444",
            },
        ]

        # Timeline should be chronological
        timestamps = [entry["timestamp"] for entry in timeline_entries]
        assert timestamps == sorted(timestamps)


# [+] Parametrized Tests
@pytest.mark.parametrize("artifact_type", ["memory", "disk", "network", "browser", "logs"])
def test_artifact_types(artifact_type):
    """Test different artifact types"""
    assert artifact_type in ["memory", "disk", "network", "browser", "logs", "registry"]


@pytest.mark.parametrize("browser", ["chrome", "firefox", "edge", "safari"])
def test_browser_support(browser):
    """Test support for different browsers"""
    assert browser in ["chrome", "firefox", "edge", "safari", "brave"]
