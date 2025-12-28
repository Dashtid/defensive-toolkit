"""
Unit tests for Threat Hunting Service.

Tests query loading, parsing, and management functionality.

Author: Defensive Toolkit
Date: 2025-12-28
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from defensive_toolkit.api.services.threat_hunting import (
    QueryLanguage,
    ThreatHuntingQuery,
    ThreatHuntingService,
    get_threat_hunting_service,
)


class TestThreatHuntingServiceInit:
    """Test service initialization."""

    def test_service_creates_with_default_path(self):
        """Test service initializes with default query path."""
        service = ThreatHuntingService()
        assert service.queries_base_path is not None
        assert "threat_hunting" in str(service.queries_base_path)

    def test_service_creates_with_custom_path(self, tmp_path):
        """Test service initializes with custom query path."""
        service = ThreatHuntingService(queries_base_path=tmp_path)
        assert service.queries_base_path == tmp_path

    def test_singleton_returns_same_instance(self):
        """Test singleton pattern returns same instance."""
        service1 = get_threat_hunting_service()
        service2 = get_threat_hunting_service()
        assert service1 is service2


class TestQueryParsing:
    """Test query file parsing."""

    @pytest.fixture
    def service(self, tmp_path):
        """Create service with temporary path."""
        return ThreatHuntingService(queries_base_path=tmp_path)

    def test_parse_kql_file(self, service, tmp_path):
        """Test parsing KQL query file."""
        kql_dir = tmp_path / "kql"
        kql_dir.mkdir()
        kql_file = kql_dir / "test_queries.kql"
        kql_file.write_text("""// Query 1: Test Query One
// MITRE: T1078
// Description: A test query
AzureDiagnostics
| where Category == "test"

// Query 2: Test Query Two
// MITRE: T1552
// Description: Another test query
SecurityEvent
| where EventID == 4688
""")

        queries = service._parse_query_file(kql_file)
        assert len(queries) == 2
        assert queries[0].name == "Test Query One"
        assert queries[0].language == QueryLanguage.KQL
        assert "T1078" in queries[0].mitre_techniques
        assert "AzureDiagnostics" in queries[0].query_text

    def test_parse_spl_file(self, service, tmp_path):
        """Test parsing SPL query file."""
        spl_dir = tmp_path / "spl"
        spl_dir.mkdir()
        spl_file = spl_dir / "test_queries.spl"
        spl_file.write_text("""# Query 1: Splunk Test Query
# MITRE: T1059
# Description: Test SPL query
index=security sourcetype=WinEventLog
| stats count by EventCode

# Query 2: Another SPL Query
# MITRE: T1003
# Description: Second test query
index=main EventCode=4624
| table _time user
""")

        queries = service._parse_query_file(spl_file)
        assert len(queries) == 2
        assert queries[0].name == "Splunk Test Query"
        assert queries[0].language == QueryLanguage.SPL
        assert "index=security" in queries[0].query_text

    def test_parse_eql_file(self, service, tmp_path):
        """Test parsing EQL query file."""
        eql_dir = tmp_path / "eql"
        eql_dir.mkdir()
        eql_file = eql_dir / "test_queries.eql"
        eql_file.write_text("""// Query 1: EQL Test Query
// MITRE: T1611
// Description: Test EQL query
any where kubernetes.audit.verb == "create"

// Query 2: Sequence Query
// MITRE: T1552
// Description: Test sequence
sequence by user with maxspan=5m
  [process where process.name == "cmd.exe"]
  [file where file.path : "*"]
""")

        queries = service._parse_query_file(eql_file)
        assert len(queries) == 2
        assert queries[0].name == "EQL Test Query"
        assert queries[0].language == QueryLanguage.EQL
        assert "kubernetes.audit" in queries[0].query_text


class TestQueryLoading:
    """Test query loading from directories."""

    @pytest.fixture
    def populated_service(self, tmp_path):
        """Create service with sample queries."""
        # Create query directories
        kql_dir = tmp_path / "kql"
        kql_dir.mkdir()
        spl_dir = tmp_path / "spl"
        spl_dir.mkdir()

        # Add sample files (unique names to avoid ID collision)
        (kql_dir / "kql_sample.kql").write_text("""// Query 1: Sample KQL
// MITRE: T1078
// Description: Sample query
SecurityEvent | take 10
""")
        (spl_dir / "spl_sample.spl").write_text("""# Query 1: Sample SPL
# MITRE: T1059
# Description: Sample SPL query
index=main | head 10
""")

        return ThreatHuntingService(queries_base_path=tmp_path)

    def test_load_queries_returns_count(self, populated_service):
        """Test load_queries returns correct count."""
        count = populated_service.load_queries()
        assert count >= 2

    def test_load_queries_populates_cache(self, populated_service):
        """Test load_queries populates the cache."""
        populated_service.load_queries()
        assert len(populated_service._query_cache) >= 2

    def test_force_reload(self, populated_service):
        """Test force reload clears and reloads cache."""
        populated_service.load_queries()
        initial_count = len(populated_service._query_cache)

        populated_service.load_queries(force_reload=True)
        assert len(populated_service._query_cache) == initial_count


class TestQueryManagement:
    """Test query retrieval and filtering."""

    @pytest.fixture
    def service_with_queries(self, tmp_path):
        """Create service with loaded queries."""
        kql_dir = tmp_path / "kql"
        kql_dir.mkdir()
        eql_dir = tmp_path / "eql"
        eql_dir.mkdir()

        (kql_dir / "k8s_secrets.kql").write_text("""// Query 1: K8s Secrets Access
// MITRE: T1552
// Description: Detect secrets access
AzureDiagnostics | where Resource == "secrets"
""")
        (eql_dir / "k8s_exec.eql").write_text("""// Query 1: K8s Pod Exec
// MITRE: T1609
// Description: Detect pod exec
any where kubernetes.audit.subresource == "exec"
""")

        service = ThreatHuntingService(queries_base_path=tmp_path)
        service.load_queries()
        return service

    def test_get_query_by_id(self, service_with_queries):
        """Test retrieving query by ID."""
        queries = service_with_queries.list_queries()
        if queries:
            query = service_with_queries.get_query(queries[0].query_id)
            assert query is not None
            assert query.query_id == queries[0].query_id

    def test_get_nonexistent_query(self, service_with_queries):
        """Test retrieving non-existent query returns None."""
        query = service_with_queries.get_query("nonexistent_query_id")
        assert query is None

    def test_list_queries_all(self, service_with_queries):
        """Test listing all queries."""
        queries = service_with_queries.list_queries()
        assert len(queries) >= 2

    def test_list_queries_by_language(self, service_with_queries):
        """Test filtering queries by language."""
        kql_queries = service_with_queries.list_queries(language=QueryLanguage.KQL)
        for q in kql_queries:
            assert q.language == QueryLanguage.KQL

    def test_list_queries_by_search(self, service_with_queries):
        """Test searching queries by text."""
        queries = service_with_queries.list_queries(search="secrets")
        assert any("secret" in q.name.lower() or "secret" in q.description.lower() for q in queries)


class TestQuerySummary:
    """Test query summary functionality."""

    @pytest.fixture
    def service_with_queries(self, tmp_path):
        """Create service with loaded queries."""
        kql_dir = tmp_path / "kql"
        kql_dir.mkdir()

        (kql_dir / "test.kql").write_text("""// Query 1: Test Query
// MITRE: T1078, T1552
// Description: Test
SecurityEvent | take 10
""")

        service = ThreatHuntingService(queries_base_path=tmp_path)
        service.load_queries()
        return service

    def test_get_summary(self, service_with_queries):
        """Test getting query summary."""
        summary = service_with_queries.get_query_summary()
        assert "total_queries" in summary
        assert "by_language" in summary
        assert "mitre_techniques_count" in summary
        assert summary["total_queries"] >= 1

    def test_summary_counts_languages(self, service_with_queries):
        """Test summary counts queries by language."""
        summary = service_with_queries.get_query_summary()
        assert isinstance(summary["by_language"], dict)


class TestQueryExecution:
    """Test query execution functionality."""

    @pytest.fixture
    def service_with_query(self, tmp_path):
        """Create service with a test query."""
        kql_dir = tmp_path / "kql"
        kql_dir.mkdir()

        (kql_dir / "test.kql").write_text("""// Query 1: Test Query
// MITRE: T1078
// Description: Test query for execution
SecurityEvent | take 10
""")

        service = ThreatHuntingService(queries_base_path=tmp_path)
        service.load_queries()
        return service

    @pytest.mark.asyncio
    async def test_execute_nonexistent_query(self, service_with_query):
        """Test executing non-existent query returns error."""
        result = await service_with_query.execute_query(
            query_id="nonexistent",
            siem_client=MagicMock(),
        )
        assert not result.success
        assert "not found" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_execute_query_without_siem_support(self, service_with_query):
        """Test executing query without SIEM support returns error."""
        queries = service_with_query.list_queries()
        if queries:
            mock_client = MagicMock()
            mock_client.execute_kql = None  # No KQL support

            result = await service_with_query.execute_query(
                query_id=queries[0].query_id,
                siem_client=mock_client,
            )
            # Should fail gracefully
            assert result.query_name == queries[0].name
