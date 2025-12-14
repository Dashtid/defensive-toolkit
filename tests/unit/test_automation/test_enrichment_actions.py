#!/usr/bin/env python3
"""
Unit tests for automation/actions/enrichment.py
"""

import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from defensive_toolkit.automation.actions.enrichment import (
    _check_abuseipdb,
    _check_virustotal,
    enrich_ioc,
    geolocate_ip,
    lookup_domain,
)


class TestEnrichIOC:
    """Test IOC enrichment functionality"""

    def test_enrich_ioc_basic(self):
        """Test basic IOC enrichment"""
        result = enrich_ioc("192.168.1.100", "ip")

        assert isinstance(result, dict)
        assert result["ioc"] == "192.168.1.100"
        assert result["type"] == "ip"
        assert "reputation" in result
        assert "sources" in result

    def test_enrich_ip_address(self):
        """Test enriching IP address"""
        result = enrich_ioc("8.8.8.8", "ip")

        assert result["ioc"] == "8.8.8.8"
        assert result["type"] == "ip"

    def test_enrich_domain(self):
        """Test enriching domain"""
        result = enrich_ioc("evil.com", "domain")

        assert result["ioc"] == "evil.com"
        assert result["type"] == "domain"

    def test_enrich_file_hash(self):
        """Test enriching file hash"""
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = enrich_ioc(test_hash, "hash")

        assert result["ioc"] == test_hash
        assert result["type"] == "hash"

    def test_enrich_url(self):
        """Test enriching URL"""
        test_url = "http://malicious-site.com/payload.exe"
        result = enrich_ioc(test_url, "url")

        assert result["ioc"] == test_url
        assert result["type"] == "url"

    def test_enrich_with_custom_sources(self):
        """Test enrichment with custom sources"""
        result = enrich_ioc("192.168.1.100", "ip", sources=["virustotal", "abuseipdb"])

        assert "virustotal" in result["sources"]
        assert "abuseipdb" in result["sources"]

    def test_enrich_with_single_source(self):
        """Test enrichment with single source"""
        result = enrich_ioc("evil.com", "domain", sources=["virustotal"])

        assert "virustotal" in result["sources"]

    @pytest.mark.parametrize("ioc_type", ["ip", "domain", "hash", "url"])
    def test_enrich_all_ioc_types(self, ioc_type):
        """Test enrichment for all IOC types"""
        test_iocs = {
            "ip": "192.168.1.100",
            "domain": "test.com",
            "hash": "d41d8cd98f00b204e9800998ecf8427e",
            "url": "http://test.com",
        }

        result = enrich_ioc(test_iocs[ioc_type], ioc_type)

        assert result["type"] == ioc_type
        assert isinstance(result, dict)


class TestThreatIntelligenceSources:
    """Test threat intelligence source integrations"""

    def test_check_virustotal_basic(self):
        """Test VirusTotal check"""
        result = _check_virustotal("evil.com", "domain")

        assert isinstance(result, dict)
        assert "malicious" in result or "score" in result

    def test_check_virustotal_ip(self):
        """Test VirusTotal IP check"""
        result = _check_virustotal("8.8.8.8", "ip")

        assert isinstance(result, dict)

    def test_check_virustotal_hash(self):
        """Test VirusTotal hash check"""
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = _check_virustotal(test_hash, "hash")

        assert isinstance(result, dict)

    def test_check_abuseipdb_basic(self):
        """Test AbuseIPDB check"""
        result = _check_abuseipdb("8.8.8.8")

        assert isinstance(result, dict)
        assert "abuse_score" in result or "reports" in result

    def test_check_abuseipdb_suspicious_ip(self):
        """Test AbuseIPDB with known bad IP"""
        result = _check_abuseipdb("192.168.1.100")

        assert isinstance(result, dict)

    @patch("automation.actions.enrichment.requests.get")
    def test_virustotal_api_call(self, mock_get):
        """Test actual API call structure"""
        mock_get.return_value = Mock(
            status_code=200, json=lambda: {"data": {"attributes": {"malicious": 0}}}
        )

        # If API integration exists
        result = _check_virustotal("test.com", "domain")
        assert isinstance(result, dict)


class TestDomainLookup:
    """Test domain lookup functionality"""

    def test_lookup_domain_basic(self):
        """Test basic domain lookup"""
        result = lookup_domain("google.com")

        assert isinstance(result, dict)
        assert result["domain"] == "google.com"
        assert "resolved_ips" in result
        assert "whois" in result

    def test_lookup_domain_subdomain(self):
        """Test subdomain lookup"""
        result = lookup_domain("mail.google.com")

        assert result["domain"] == "mail.google.com"

    def test_lookup_domain_invalid(self):
        """Test invalid domain lookup"""
        result = lookup_domain("invalid-domain-that-does-not-exist-123456")

        assert isinstance(result, dict)
        assert result["domain"] == "invalid-domain-that-does-not-exist-123456"

    @pytest.mark.parametrize(
        "domain", ["google.com", "github.com", "microsoft.com", "cloudflare.com"]
    )
    def test_lookup_known_domains(self, domain):
        """Test lookup of known domains"""
        result = lookup_domain(domain)

        assert result["domain"] == domain
        assert isinstance(result, dict)


class TestIPGeolocation:
    """Test IP geolocation functionality"""

    def test_geolocate_ip_basic(self):
        """Test basic IP geolocation"""
        result = geolocate_ip("8.8.8.8")

        assert isinstance(result, dict)
        assert result["ip"] == "8.8.8.8"
        assert "country" in result
        assert "city" in result

    def test_geolocate_private_ip(self):
        """Test geolocation of private IP"""
        result = geolocate_ip("192.168.1.1")

        assert result["ip"] == "192.168.1.1"
        # Private IPs may have limited geolocation

    def test_geolocate_public_ip(self):
        """Test geolocation of public IP"""
        result = geolocate_ip("1.1.1.1")  # Cloudflare DNS

        assert result["ip"] == "1.1.1.1"
        assert isinstance(result, dict)

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "4.4.4.4", "192.168.1.1"])
    def test_geolocate_multiple_ips(self, ip):
        """Test geolocation of multiple IPs"""
        result = geolocate_ip(ip)

        assert result["ip"] == ip
        assert "country" in result


class TestEnrichmentIntegration:
    """Test integrated enrichment workflows"""

    def test_full_threat_intel_workflow(self):
        """Test complete threat intelligence workflow"""
        suspicious_ip = "192.168.1.100"

        # 1. Enrich IOC
        enrichment = enrich_ioc(suspicious_ip, "ip")

        # 2. Geolocate
        geolocation = geolocate_ip(suspicious_ip)

        # 3. Combine results
        full_intel = {**enrichment, "geolocation": geolocation}

        assert full_intel["ioc"] == suspicious_ip
        assert "geolocation" in full_intel
        assert "sources" in full_intel

    def test_multi_ioc_enrichment(self):
        """Test enriching multiple IOCs"""
        iocs = [
            {"value": "192.168.1.100", "type": "ip"},
            {"value": "evil.com", "type": "domain"},
            {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "hash"},
        ]

        results = []
        for ioc in iocs:
            result = enrich_ioc(ioc["value"], ioc["type"])
            results.append(result)

        assert len(results) == 3
        assert all(isinstance(r, dict) for r in results)

    def test_phishing_investigation_enrichment(self):
        """Test enrichment for phishing investigation"""
        # Phishing email analysis
        sender_ip = "192.168.1.100"
        sender_domain = "phishing-site.com"
        attachment_hash = "abc123def456"

        # Enrich all IOCs
        ip_intel = enrich_ioc(sender_ip, "ip")
        domain_intel = enrich_ioc(sender_domain, "domain")
        hash_intel = enrich_ioc(attachment_hash, "hash")

        # All enrichment should succeed
        assert ip_intel["ioc"] == sender_ip
        assert domain_intel["ioc"] == sender_domain
        assert hash_intel["ioc"] == attachment_hash


class TestEnrichmentErrorHandling:
    """Test error handling in enrichment"""

    def test_enrich_empty_ioc(self):
        """Test enriching empty IOC"""
        result = enrich_ioc("", "ip")

        assert isinstance(result, dict)
        assert result["ioc"] == ""

    def test_enrich_invalid_type(self):
        """Test enriching with invalid type"""
        result = enrich_ioc("test", "invalid_type")

        assert isinstance(result, dict)
        assert result["type"] == "invalid_type"

    def test_lookup_domain_empty(self):
        """Test domain lookup with empty string"""
        result = lookup_domain("")

        assert isinstance(result, dict)

    def test_geolocate_invalid_ip(self):
        """Test geolocating invalid IP"""
        result = geolocate_ip("not-an-ip")

        assert isinstance(result, dict)


class TestEnrichmentPerformance:
    """Test enrichment performance"""

    @pytest.mark.slow
    def test_bulk_ioc_enrichment(self):
        """Test enriching many IOCs"""
        import time

        iocs = [f"192.168.1.{i}" for i in range(100)]

        start = time.time()
        results = [enrich_ioc(ioc, "ip") for ioc in iocs]
        duration = time.time() - start

        assert len(results) == 100
        assert all(isinstance(r, dict) for r in results)
        # Should complete quickly (< 10 seconds for 100 IOCs)
        assert duration < 10.0

    @pytest.mark.slow
    def test_enrichment_caching(self):
        """Test enrichment with caching"""
        # Enrich same IOC multiple times
        ioc = "8.8.8.8"

        results = []
        for _ in range(10):
            result = enrich_ioc(ioc, "ip")
            results.append(result)

        # All results should be consistent
        assert all(r["ioc"] == ioc for r in results)


# [+] Parametrized tests
@pytest.mark.parametrize("source", ["virustotal", "abuseipdb"])
def test_enrichment_sources(source):
    """Test different enrichment sources"""
    result = enrich_ioc("test.com", "domain", sources=[source])

    assert source in result["sources"]


@pytest.mark.parametrize(
    "ioc,ioc_type",
    [
        ("192.168.1.100", "ip"),
        ("evil.com", "domain"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
        ("http://evil.com/payload", "url"),
    ],
)
def test_ioc_enrichment_variants(ioc, ioc_type):
    """Test enrichment with various IOC types"""
    result = enrich_ioc(ioc, ioc_type)

    assert result["ioc"] == ioc
    assert result["type"] == ioc_type
