"""
Unit tests for Kubernetes Threat Hunting Queries.

Tests validate query file syntax, structure, and content for
KQL, SPL, and EQL Kubernetes threat hunting queries.

Author: Defensive Toolkit
Date: 2025-12-28
"""

import re
from pathlib import Path

import pytest


def get_threat_hunting_path() -> Path:
    """Get path to threat hunting queries directory."""
    # Try relative to test file
    test_dir = Path(__file__).parent
    hunting_path = (
        test_dir.parent.parent.parent
        / "src"
        / "defensive_toolkit"
        / "threat_hunting"
        / "queries"
    )
    if hunting_path.exists():
        return hunting_path

    # Try from current working directory
    hunting_path = Path("src/defensive_toolkit/threat_hunting/queries")
    if hunting_path.exists():
        return hunting_path

    pytest.skip("Threat hunting queries directory not found")


class TestKubernetesQueryFilesExist:
    """Test that Kubernetes query files exist."""

    def test_kql_file_exists(self):
        """Test KQL Kubernetes query file exists."""
        queries_path = get_threat_hunting_path()
        kql_file = queries_path / "kql" / "kubernetes_threat_hunting.kql"
        assert kql_file.exists(), f"KQL file not found: {kql_file}"

    def test_spl_file_exists(self):
        """Test SPL Kubernetes query file exists."""
        queries_path = get_threat_hunting_path()
        spl_file = queries_path / "spl" / "kubernetes_threat_hunting.spl"
        assert spl_file.exists(), f"SPL file not found: {spl_file}"

    def test_eql_file_exists(self):
        """Test EQL Kubernetes query file exists."""
        queries_path = get_threat_hunting_path()
        eql_file = queries_path / "eql" / "kubernetes_threat_hunting.eql"
        assert eql_file.exists(), f"EQL file not found: {eql_file}"


class TestKQLQueryContent:
    """Test KQL Kubernetes query content."""

    @pytest.fixture
    def kql_content(self) -> str:
        """Load KQL file content."""
        queries_path = get_threat_hunting_path()
        kql_file = queries_path / "kql" / "kubernetes_threat_hunting.kql"
        if not kql_file.exists():
            pytest.skip("KQL file not found")
        return kql_file.read_text(encoding="utf-8")

    def test_has_header_comments(self, kql_content: str):
        """Test that KQL file has header documentation."""
        assert "Kubernetes Threat Hunting" in kql_content
        assert "MITRE ATT&CK" in kql_content

    def test_has_multiple_queries(self, kql_content: str):
        """Test that KQL file has multiple queries."""
        # Count query headers (// Query N:)
        query_pattern = r"// Query \d+:"
        matches = re.findall(query_pattern, kql_content)
        assert len(matches) >= 5, f"Expected at least 5 queries, found {len(matches)}"

    def test_uses_azure_diagnostics(self, kql_content: str):
        """Test that KQL queries use AzureDiagnostics table."""
        assert "AzureDiagnostics" in kql_content

    def test_filters_kube_audit(self, kql_content: str):
        """Test that queries filter for kube-audit logs."""
        assert "kube-audit" in kql_content

    def test_covers_secrets_access(self, kql_content: str):
        """Test that queries cover secrets access detection."""
        assert "secrets" in kql_content.lower()

    def test_covers_privileged_pods(self, kql_content: str):
        """Test that queries cover privileged pod detection."""
        assert "privileged" in kql_content.lower()

    def test_covers_rbac(self, kql_content: str):
        """Test that queries cover RBAC modifications."""
        assert any(
            term in kql_content.lower()
            for term in ["clusterrole", "rolebinding", "rbac"]
        )


class TestSPLQueryContent:
    """Test SPL Kubernetes query content."""

    @pytest.fixture
    def spl_content(self) -> str:
        """Load SPL file content."""
        queries_path = get_threat_hunting_path()
        spl_file = queries_path / "spl" / "kubernetes_threat_hunting.spl"
        if not spl_file.exists():
            pytest.skip("SPL file not found")
        return spl_file.read_text(encoding="utf-8")

    def test_has_header_comments(self, spl_content: str):
        """Test that SPL file has header documentation."""
        assert "Kubernetes Threat Hunting" in spl_content
        assert "MITRE ATT&CK" in spl_content

    def test_has_multiple_queries(self, spl_content: str):
        """Test that SPL file has multiple queries."""
        # Count query headers (# Query N:)
        query_pattern = r"# Query \d+:"
        matches = re.findall(query_pattern, spl_content)
        assert len(matches) >= 5, f"Expected at least 5 queries, found {len(matches)}"

    def test_uses_index(self, spl_content: str):
        """Test that SPL queries specify an index."""
        assert "index=" in spl_content

    def test_uses_sourcetype(self, spl_content: str):
        """Test that SPL queries use appropriate sourcetype."""
        assert "sourcetype=" in spl_content or "kube" in spl_content.lower()

    def test_covers_secrets_access(self, spl_content: str):
        """Test that queries cover secrets access detection."""
        assert "secrets" in spl_content.lower()

    def test_covers_pod_exec(self, spl_content: str):
        """Test that queries cover pod exec detection."""
        assert "exec" in spl_content.lower()

    def test_uses_spath(self, spl_content: str):
        """Test that SPL queries use spath for JSON parsing."""
        assert "spath" in spl_content.lower()


class TestEQLQueryContent:
    """Test EQL Kubernetes query content."""

    @pytest.fixture
    def eql_content(self) -> str:
        """Load EQL file content."""
        queries_path = get_threat_hunting_path()
        eql_file = queries_path / "eql" / "kubernetes_threat_hunting.eql"
        if not eql_file.exists():
            pytest.skip("EQL file not found")
        return eql_file.read_text(encoding="utf-8")

    def test_has_header_comments(self, eql_content: str):
        """Test that EQL file has header documentation."""
        assert "Kubernetes Threat Hunting" in eql_content
        assert "MITRE ATT&CK" in eql_content

    def test_has_multiple_queries(self, eql_content: str):
        """Test that EQL file has multiple queries."""
        # Count query headers (// Query N:)
        query_pattern = r"// Query \d+:"
        matches = re.findall(query_pattern, eql_content)
        assert len(matches) >= 10, f"Expected at least 10 queries, found {len(matches)}"

    def test_uses_kubernetes_audit_fields(self, eql_content: str):
        """Test that EQL queries use kubernetes.audit fields."""
        assert "kubernetes.audit" in eql_content

    def test_has_sequence_queries(self, eql_content: str):
        """Test that EQL file includes sequence queries."""
        assert "sequence by" in eql_content.lower()

    def test_covers_secrets_access(self, eql_content: str):
        """Test that queries cover secrets access detection."""
        assert "secrets" in eql_content.lower()

    def test_covers_privileged_pods(self, eql_content: str):
        """Test that queries cover privileged pod detection."""
        assert "privileged" in eql_content.lower()

    def test_covers_exec_attach(self, eql_content: str):
        """Test that queries cover exec/attach detection."""
        assert "exec" in eql_content.lower()
        assert "attach" in eql_content.lower()


class TestMITREATTACKCoverage:
    """Test that queries cover key MITRE ATT&CK techniques."""

    EXPECTED_TECHNIQUES = [
        "T1552",  # Credentials
        "T1611",  # Escape to Host
        "T1609",  # Container Admin Command
        "T1078",  # Valid Accounts
        "T1098",  # Account Manipulation
    ]

    def test_kql_mitre_coverage(self):
        """Test KQL file references MITRE techniques."""
        queries_path = get_threat_hunting_path()
        kql_file = queries_path / "kql" / "kubernetes_threat_hunting.kql"
        if not kql_file.exists():
            pytest.skip("KQL file not found")

        content = kql_file.read_text(encoding="utf-8")
        found_techniques = [t for t in self.EXPECTED_TECHNIQUES if t in content]
        assert len(found_techniques) >= 3, (
            f"Expected at least 3 MITRE techniques, found: {found_techniques}"
        )

    def test_spl_mitre_coverage(self):
        """Test SPL file references MITRE techniques."""
        queries_path = get_threat_hunting_path()
        spl_file = queries_path / "spl" / "kubernetes_threat_hunting.spl"
        if not spl_file.exists():
            pytest.skip("SPL file not found")

        content = spl_file.read_text(encoding="utf-8")
        found_techniques = [t for t in self.EXPECTED_TECHNIQUES if t in content]
        assert len(found_techniques) >= 3, (
            f"Expected at least 3 MITRE techniques, found: {found_techniques}"
        )

    def test_eql_mitre_coverage(self):
        """Test EQL file references MITRE techniques."""
        queries_path = get_threat_hunting_path()
        eql_file = queries_path / "eql" / "kubernetes_threat_hunting.eql"
        if not eql_file.exists():
            pytest.skip("EQL file not found")

        content = eql_file.read_text(encoding="utf-8")
        found_techniques = [t for t in self.EXPECTED_TECHNIQUES if t in content]
        assert len(found_techniques) >= 3, (
            f"Expected at least 3 MITRE techniques, found: {found_techniques}"
        )


class TestQueryFileEncoding:
    """Test that query files are properly encoded."""

    def test_kql_utf8_encoding(self):
        """Test KQL file is valid UTF-8."""
        queries_path = get_threat_hunting_path()
        kql_file = queries_path / "kql" / "kubernetes_threat_hunting.kql"
        if not kql_file.exists():
            pytest.skip("KQL file not found")

        try:
            kql_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            pytest.fail("KQL file is not valid UTF-8")

    def test_spl_utf8_encoding(self):
        """Test SPL file is valid UTF-8."""
        queries_path = get_threat_hunting_path()
        spl_file = queries_path / "spl" / "kubernetes_threat_hunting.spl"
        if not spl_file.exists():
            pytest.skip("SPL file not found")

        try:
            spl_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            pytest.fail("SPL file is not valid UTF-8")

    def test_eql_utf8_encoding(self):
        """Test EQL file is valid UTF-8."""
        queries_path = get_threat_hunting_path()
        eql_file = queries_path / "eql" / "kubernetes_threat_hunting.eql"
        if not eql_file.exists():
            pytest.skip("EQL file not found")

        try:
            eql_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            pytest.fail("EQL file is not valid UTF-8")


class TestQueryCount:
    """Test minimum query counts per file."""

    def test_minimum_kql_queries(self):
        """Test KQL file has minimum number of queries."""
        queries_path = get_threat_hunting_path()
        kql_file = queries_path / "kql" / "kubernetes_threat_hunting.kql"
        if not kql_file.exists():
            pytest.skip("KQL file not found")

        content = kql_file.read_text(encoding="utf-8")
        query_pattern = r"// Query \d+:"
        matches = re.findall(query_pattern, content)
        assert len(matches) >= 10, (
            f"Expected at least 10 KQL queries, found {len(matches)}"
        )

    def test_minimum_spl_queries(self):
        """Test SPL file has minimum number of queries."""
        queries_path = get_threat_hunting_path()
        spl_file = queries_path / "spl" / "kubernetes_threat_hunting.spl"
        if not spl_file.exists():
            pytest.skip("SPL file not found")

        content = spl_file.read_text(encoding="utf-8")
        query_pattern = r"# Query \d+:"
        matches = re.findall(query_pattern, content)
        assert len(matches) >= 10, (
            f"Expected at least 10 SPL queries, found {len(matches)}"
        )

    def test_minimum_eql_queries(self):
        """Test EQL file has minimum number of queries."""
        queries_path = get_threat_hunting_path()
        eql_file = queries_path / "eql" / "kubernetes_threat_hunting.eql"
        if not eql_file.exists():
            pytest.skip("EQL file not found")

        content = eql_file.read_text(encoding="utf-8")
        query_pattern = r"// Query \d+:"
        matches = re.findall(query_pattern, content)
        assert len(matches) >= 20, (
            f"Expected at least 20 EQL queries, found {len(matches)}"
        )
