"""
Threat Intelligence Router Tests

Tests for the threat intelligence API endpoints including:
- IOC enrichment
- Source status
- Caching
- Feed management
- IOC type detection
"""

import pytest
from datetime import datetime, timedelta
from fastapi import status
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock

from defensive_toolkit.api.main import app
from defensive_toolkit.api.routers import threat_intel
from defensive_toolkit.api.models import (
    IOCTypeEnum,
    ReputationScoreEnum,
    ThreatIntelSourceEnum,
    ThreatCategoryEnum,
    SourceResult,
)


@pytest.fixture(autouse=True)
def clear_caches():
    """Clear caches before each test."""
    threat_intel.ioc_cache.clear()
    threat_intel.feeds_db.clear()
    threat_intel.query_stats["total_queries"] = 0
    threat_intel.query_stats["cache_hits"] = 0
    threat_intel.query_stats["query_times"] = []
    yield
    threat_intel.ioc_cache.clear()
    threat_intel.feeds_db.clear()


# ============================================================================
# IOC Type Detection Tests
# ============================================================================


class TestIOCTypeDetection:
    """Tests for IOC type detection."""

    def test_detect_ipv4(self):
        """Test IPv4 address detection."""
        assert threat_intel._detect_ioc_type("192.168.1.1") == IOCTypeEnum.IP
        assert threat_intel._detect_ioc_type("10.0.0.1") == IOCTypeEnum.IP
        assert threat_intel._detect_ioc_type("8.8.8.8") == IOCTypeEnum.IP

    def test_detect_domain(self):
        """Test domain detection."""
        assert threat_intel._detect_ioc_type("example.com") == IOCTypeEnum.DOMAIN
        assert threat_intel._detect_ioc_type("sub.example.com") == IOCTypeEnum.DOMAIN
        assert threat_intel._detect_ioc_type("malware.evil.org") == IOCTypeEnum.DOMAIN

    def test_detect_url(self):
        """Test URL detection."""
        assert threat_intel._detect_ioc_type("http://example.com") == IOCTypeEnum.URL
        assert threat_intel._detect_ioc_type("https://evil.com/malware") == IOCTypeEnum.URL
        assert threat_intel._detect_ioc_type("ftp://files.example.com") == IOCTypeEnum.URL

    def test_detect_md5_hash(self):
        """Test MD5 hash detection."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        assert threat_intel._detect_ioc_type(md5) == IOCTypeEnum.FILE_HASH_MD5

    def test_detect_sha1_hash(self):
        """Test SHA1 hash detection."""
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert threat_intel._detect_ioc_type(sha1) == IOCTypeEnum.FILE_HASH_SHA1

    def test_detect_sha256_hash(self):
        """Test SHA256 hash detection."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert threat_intel._detect_ioc_type(sha256) == IOCTypeEnum.FILE_HASH_SHA256

    def test_detect_email(self):
        """Test email detection."""
        assert threat_intel._detect_ioc_type("user@example.com") == IOCTypeEnum.EMAIL
        assert threat_intel._detect_ioc_type("test.user@sub.domain.org") == IOCTypeEnum.EMAIL

    def test_detect_cve(self):
        """Test CVE detection."""
        assert threat_intel._detect_ioc_type("CVE-2021-44228") == IOCTypeEnum.CVE
        assert threat_intel._detect_ioc_type("cve-2023-1234") == IOCTypeEnum.CVE

    def test_detect_type_endpoint(self, test_client, auth_headers):
        """Test IOC type detection endpoint."""
        response = test_client.get("/api/v1/threat-intel/detect-type/8.8.8.8", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["detected_type"] == "ip"
        assert "virustotal" in data["supported_sources"]


# ============================================================================
# Cache Tests
# ============================================================================


class TestCaching:
    """Tests for IOC caching functionality."""

    def test_cache_key_generation(self):
        """Test cache key generation."""
        key = threat_intel._get_cache_key(
            "8.8.8.8",
            IOCTypeEnum.IP,
            [ThreatIntelSourceEnum.VIRUSTOTAL, ThreatIntelSourceEnum.ABUSEIPDB],
        )
        assert "ip" in key
        assert "8.8.8.8" in key
        assert "virustotal" in key

    def test_cache_miss(self):
        """Test cache miss."""
        result = threat_intel._check_cache("nonexistent-key")
        assert result is None

    def test_cache_hit(self):
        """Test cache hit."""
        from defensive_toolkit.api.models import IOCEnrichmentResult

        # Create mock result
        result = IOCEnrichmentResult(
            ioc="8.8.8.8",
            ioc_type=IOCTypeEnum.IP,
            enriched_at=datetime.utcnow(),
            overall_reputation=ReputationScoreEnum.CLEAN,
            overall_risk_score=10,
            confidence=80,
            source_results=[],
        )

        # Store in cache
        threat_intel._store_cache("test-key", result)

        # Should get cache hit
        cached = threat_intel._check_cache("test-key")
        assert cached is not None
        assert cached.ioc == "8.8.8.8"

    def test_cache_expiry(self):
        """Test cache expiry."""
        from defensive_toolkit.api.models import IOCEnrichmentResult

        result = IOCEnrichmentResult(
            ioc="1.2.3.4",
            ioc_type=IOCTypeEnum.IP,
            enriched_at=datetime.utcnow(),
            overall_reputation=ReputationScoreEnum.UNKNOWN,
            overall_risk_score=50,
            confidence=50,
            source_results=[],
        )

        # Store with very short TTL
        threat_intel._store_cache("expiry-test", result, ttl_seconds=0)

        # Should be expired
        cached = threat_intel._check_cache("expiry-test")
        assert cached is None

    def test_clear_cache_endpoint(self, test_client, auth_headers):
        """Test cache clearing endpoint."""
        # Add something to cache
        from defensive_toolkit.api.models import IOCEnrichmentResult

        result = IOCEnrichmentResult(
            ioc="test",
            ioc_type=IOCTypeEnum.DOMAIN,
            enriched_at=datetime.utcnow(),
            overall_reputation=ReputationScoreEnum.UNKNOWN,
            overall_risk_score=50,
            confidence=50,
            source_results=[],
        )
        threat_intel._store_cache("clear-test", result)

        assert len(threat_intel.ioc_cache) > 0

        # Clear cache
        response = test_client.delete("/api/v1/threat-intel/cache", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        assert len(threat_intel.ioc_cache) == 0


# ============================================================================
# Rate Limiting Tests
# ============================================================================


class TestRateLimiting:
    """Tests for rate limiting functionality."""

    def test_check_rate_limit_within_limits(self):
        """Test rate limit check when within limits."""
        result = threat_intel._check_rate_limit(ThreatIntelSourceEnum.VIRUSTOTAL)
        assert result is True

    def test_check_rate_limit_unknown_source(self):
        """Test rate limit check for unknown source."""
        # Create a mock source that's not in configs
        with patch.dict(threat_intel.source_configs, {}, clear=True):
            result = threat_intel._check_rate_limit(ThreatIntelSourceEnum.VIRUSTOTAL)
            assert result is False

    def test_record_query(self):
        """Test query recording."""
        initial_count = threat_intel.rate_limit_tracker[
            ThreatIntelSourceEnum.VIRUSTOTAL.value
        ]["day_count"]

        threat_intel._record_query(ThreatIntelSourceEnum.VIRUSTOTAL)

        new_count = threat_intel.rate_limit_tracker[
            ThreatIntelSourceEnum.VIRUSTOTAL.value
        ]["day_count"]
        assert new_count == initial_count + 1


# ============================================================================
# Result Aggregation Tests
# ============================================================================


class TestResultAggregation:
    """Tests for result aggregation logic."""

    def test_aggregate_empty_results(self):
        """Test aggregation with no results."""
        reputation, risk, confidence = threat_intel._aggregate_results([])
        assert reputation == ReputationScoreEnum.UNKNOWN
        assert risk == 0
        assert confidence == 0

    def test_aggregate_malicious_results(self):
        """Test aggregation with malicious results."""
        results = [
            SourceResult(
                source=ThreatIntelSourceEnum.VIRUSTOTAL,
                queried_at=datetime.utcnow(),
                success=True,
                reputation=ReputationScoreEnum.MALICIOUS,
                risk_score=90,
                confidence=80,
            ),
            SourceResult(
                source=ThreatIntelSourceEnum.ABUSEIPDB,
                queried_at=datetime.utcnow(),
                success=True,
                reputation=ReputationScoreEnum.MALICIOUS,
                risk_score=85,
                confidence=75,
            ),
        ]

        reputation, risk, confidence = threat_intel._aggregate_results(results)
        assert reputation == ReputationScoreEnum.MALICIOUS

    def test_aggregate_clean_results(self):
        """Test aggregation with clean results."""
        results = [
            SourceResult(
                source=ThreatIntelSourceEnum.VIRUSTOTAL,
                queried_at=datetime.utcnow(),
                success=True,
                reputation=ReputationScoreEnum.CLEAN,
                risk_score=5,
                confidence=90,
            ),
            SourceResult(
                source=ThreatIntelSourceEnum.GREYNOISE,
                queried_at=datetime.utcnow(),
                success=True,
                reputation=ReputationScoreEnum.CLEAN,
                risk_score=0,
                confidence=95,
            ),
        ]

        reputation, risk, confidence = threat_intel._aggregate_results(results)
        assert reputation == ReputationScoreEnum.CLEAN

    def test_aggregate_mixed_results(self):
        """Test aggregation with mixed results."""
        results = [
            SourceResult(
                source=ThreatIntelSourceEnum.VIRUSTOTAL,
                queried_at=datetime.utcnow(),
                success=True,
                reputation=ReputationScoreEnum.MALICIOUS,
                risk_score=80,
                confidence=70,
            ),
            SourceResult(
                source=ThreatIntelSourceEnum.GREYNOISE,
                queried_at=datetime.utcnow(),
                success=True,
                reputation=ReputationScoreEnum.SUSPICIOUS,
                risk_score=60,
                confidence=60,
            ),
        ]

        reputation, risk, confidence = threat_intel._aggregate_results(results)
        assert reputation == ReputationScoreEnum.MALICIOUS


# ============================================================================
# Recommendation Generation Tests
# ============================================================================


class TestRecommendations:
    """Tests for recommendation generation."""

    def test_malicious_ip_recommendations(self):
        """Test recommendations for malicious IP."""
        recommendations, block = threat_intel._generate_recommendations(
            IOCTypeEnum.IP,
            ReputationScoreEnum.MALICIOUS,
            90,
            [ThreatCategoryEnum.C2],
        )

        assert block is True
        assert len(recommendations) > 0
        assert any("block" in r.lower() for r in recommendations)

    def test_malicious_hash_recommendations(self):
        """Test recommendations for malicious file hash."""
        recommendations, block = threat_intel._generate_recommendations(
            IOCTypeEnum.FILE_HASH_SHA256,
            ReputationScoreEnum.MALICIOUS,
            95,
            [ThreatCategoryEnum.RANSOMWARE],
        )

        assert block is True
        assert any("ransomware" in r.lower() for r in recommendations)

    def test_clean_recommendations(self):
        """Test recommendations for clean IOC."""
        recommendations, block = threat_intel._generate_recommendations(
            IOCTypeEnum.DOMAIN,
            ReputationScoreEnum.CLEAN,
            5,
            [],
        )

        assert block is False
        assert any("no immediate action" in r.lower() for r in recommendations)

    def test_unknown_recommendations(self):
        """Test recommendations for unknown IOC."""
        recommendations, block = threat_intel._generate_recommendations(
            IOCTypeEnum.FILE_HASH_MD5,
            ReputationScoreEnum.UNKNOWN,
            50,
            [],
        )

        assert block is False
        assert any("manual analysis" in r.lower() for r in recommendations)


# ============================================================================
# Source Status Tests
# ============================================================================


class TestSourceStatus:
    """Tests for source status endpoint."""

    def test_get_source_status(self, test_client, auth_headers):
        """Test getting source status."""
        response = test_client.get("/api/v1/threat-intel/sources", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

        # Check structure
        for source in data:
            assert "source" in source
            assert "enabled" in source
            assert "api_key_configured" in source


# ============================================================================
# Statistics Tests
# ============================================================================


class TestStatistics:
    """Tests for statistics endpoint."""

    def test_get_stats(self, test_client, auth_headers):
        """Test getting statistics."""
        response = test_client.get("/api/v1/threat-intel/stats", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "total_iocs_cached" in data
        assert "cache_hit_rate" in data
        assert "sources_status" in data

    def test_stats_cache_hit_rate(self, test_client, auth_headers):
        """Test cache hit rate calculation."""
        # Simulate some queries
        threat_intel.query_stats["total_queries"] = 100
        threat_intel.query_stats["cache_hits"] = 25

        response = test_client.get("/api/v1/threat-intel/stats", headers=auth_headers)
        data = response.json()
        assert data["cache_hit_rate"] == 0.25


# ============================================================================
# Feed Management Tests
# ============================================================================


class TestFeedManagement:
    """Tests for threat intel feed management."""

    def test_list_feeds_empty(self, test_client, auth_headers):
        """Test listing feeds when none exist."""
        response = test_client.get("/api/v1/threat-intel/feeds", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 0
        assert data["feeds"] == []

    def test_create_feed(self, test_client, auth_headers):
        """Test creating a feed."""
        feed_data = {
            "name": "Test Feed",
            "source": "virustotal",
            "feed_type": "iocs",
            "feed_url": "https://example.com/feed.txt",
            "enabled": True,
            "sync_interval_minutes": 60,
        }

        response = test_client.post("/api/v1/threat-intel/feeds", json=feed_data, headers=auth_headers)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["status"] == "success"
        assert "feed_id" in data["data"]

    def test_delete_feed_not_found(self, test_client, auth_headers):
        """Test deleting non-existent feed."""
        response = test_client.delete("/api/v1/threat-intel/feeds/FEED-NONEXISTENT", headers=auth_headers)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_feed(self, test_client, auth_headers):
        """Test deleting a feed."""
        # Create feed first
        feed_data = {
            "name": "Delete Test Feed",
            "source": "alienvault_otx",
            "feed_type": "stix",
            "feed_url": "https://example.com/domains.txt",
            "enabled": True,
        }
        create_response = test_client.post("/api/v1/threat-intel/feeds", json=feed_data, headers=auth_headers)
        feed_id = create_response.json()["data"]["feed_id"]

        # Delete it
        response = test_client.delete(f"/api/v1/threat-intel/feeds/{feed_id}", headers=auth_headers)
        assert response.status_code == status.HTTP_200_OK


# ============================================================================
# IOC Enrichment Tests
# ============================================================================


class TestIOCEnrichment:
    """Tests for IOC enrichment functionality."""

    def test_enrich_single_ioc_endpoint(self, test_client, auth_headers):
        """Test single IOC enrichment endpoint."""
        # Mock the actual API calls
        with patch.object(
            threat_intel, "_enrich_single_ioc", new_callable=AsyncMock
        ) as mock_enrich:
            from defensive_toolkit.api.models import IOCEnrichmentResult

            mock_enrich.return_value = IOCEnrichmentResult(
                ioc="8.8.8.8",
                ioc_type=IOCTypeEnum.IP,
                enriched_at=datetime.utcnow(),
                overall_reputation=ReputationScoreEnum.CLEAN,
                overall_risk_score=5,
                confidence=90,
                source_results=[],
            )

            response = test_client.get("/api/v1/threat-intel/enrich/8.8.8.8", headers=auth_headers)
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["ioc"] == "8.8.8.8"

    def test_bulk_enrich_endpoint(self, test_client, auth_headers):
        """Test bulk IOC enrichment endpoint."""
        with patch.object(
            threat_intel, "_enrich_single_ioc", new_callable=AsyncMock
        ) as mock_enrich:
            from defensive_toolkit.api.models import IOCEnrichmentResult

            mock_enrich.return_value = IOCEnrichmentResult(
                ioc="test",
                ioc_type=IOCTypeEnum.DOMAIN,
                enriched_at=datetime.utcnow(),
                overall_reputation=ReputationScoreEnum.UNKNOWN,
                overall_risk_score=50,
                confidence=50,
                source_results=[],
            )

            response = test_client.post(
                "/api/v1/threat-intel/enrich",
                json={
                    "iocs": ["example.com", "evil.com"],
                    "sources": ["virustotal"],
                },
                headers=auth_headers,
            )
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "request_id" in data
            assert data["total_iocs"] == 2


# ============================================================================
# Supported Sources Tests
# ============================================================================


class TestSupportedSources:
    """Tests for supported sources lookup."""

    def test_get_supported_sources_ip(self):
        """Test supported sources for IP."""
        sources = threat_intel._get_supported_sources(IOCTypeEnum.IP)
        assert "virustotal" in sources
        assert "abuseipdb" in sources
        assert "greynoise" in sources

    def test_get_supported_sources_domain(self):
        """Test supported sources for domain."""
        sources = threat_intel._get_supported_sources(IOCTypeEnum.DOMAIN)
        assert "virustotal" in sources
        assert "alienvault_otx" in sources

    def test_get_supported_sources_hash(self):
        """Test supported sources for file hash."""
        sources = threat_intel._get_supported_sources(IOCTypeEnum.FILE_HASH_SHA256)
        assert "virustotal" in sources
        assert "hybrid_analysis" in sources
