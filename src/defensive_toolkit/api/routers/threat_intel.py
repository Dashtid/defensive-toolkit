"""
Threat Intelligence API Router

IOC enrichment and threat intelligence feed management.
Supports VirusTotal, AbuseIPDB, AlienVault OTX, MISP, GreyNoise, and more.

Version: 1.7.3
Author: Defensive Toolkit
"""

import asyncio
import base64
import ipaddress
import logging
import os
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx
from api.dependencies import get_current_active_user, require_write_scope
from api.models import (
    APIResponse,
    BulkEnrichmentResponse,
    GeoIPData,
    IOCEnrichmentRequest,
    IOCEnrichmentResult,
    IOCTypeEnum,
    ReputationScoreEnum,
    SourceResult,
    StatusEnum,
    ThreatCategoryEnum,
    ThreatIntelFeed,
    ThreatIntelFeedList,
    ThreatIntelSourceConfig,
    ThreatIntelSourceEnum,
    ThreatIntelSourceStatus,
    ThreatIntelStats,
)
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

# ============================================================================
# Configuration and Storage
# ============================================================================

# In-memory cache for IOC enrichment results (production: use Redis)
ioc_cache: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour default

# Rate limiting tracking per source
rate_limit_tracker: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    "minute_count": 0,
    "minute_reset": datetime.utcnow(),
    "day_count": 0,
    "day_reset": datetime.utcnow(),
})

# Query statistics
query_stats: Dict[str, Any] = {
    "total_queries": 0,
    "cache_hits": 0,
    "source_queries": defaultdict(int),
    "query_times": [],
}

# Threat intel feeds storage
feeds_db: Dict[str, ThreatIntelFeed] = {}

# Source configurations
source_configs: Dict[ThreatIntelSourceEnum, ThreatIntelSourceConfig] = {
    ThreatIntelSourceEnum.VIRUSTOTAL: ThreatIntelSourceConfig(
        source=ThreatIntelSourceEnum.VIRUSTOTAL,
        enabled=True,
        api_key_configured=bool(os.getenv("VIRUSTOTAL_API_KEY")),
        base_url="https://www.virustotal.com/api/v3",
        rate_limit_per_minute=4,
        rate_limit_per_day=500,
        priority=1,
    ),
    ThreatIntelSourceEnum.ABUSEIPDB: ThreatIntelSourceConfig(
        source=ThreatIntelSourceEnum.ABUSEIPDB,
        enabled=True,
        api_key_configured=bool(os.getenv("ABUSEIPDB_API_KEY")),
        base_url="https://api.abuseipdb.com/api/v2",
        rate_limit_per_minute=60,
        rate_limit_per_day=1000,
        priority=2,
    ),
    ThreatIntelSourceEnum.ALIENVAULT_OTX: ThreatIntelSourceConfig(
        source=ThreatIntelSourceEnum.ALIENVAULT_OTX,
        enabled=True,
        api_key_configured=bool(os.getenv("OTX_API_KEY")),
        base_url="https://otx.alienvault.com/api/v1",
        rate_limit_per_minute=100,
        rate_limit_per_day=10000,
        priority=3,
    ),
    ThreatIntelSourceEnum.GREYNOISE: ThreatIntelSourceConfig(
        source=ThreatIntelSourceEnum.GREYNOISE,
        enabled=True,
        api_key_configured=bool(os.getenv("GREYNOISE_API_KEY")),
        base_url="https://api.greynoise.io/v3",
        rate_limit_per_minute=100,
        rate_limit_per_day=5000,
        priority=4,
    ),
    ThreatIntelSourceEnum.URLSCAN: ThreatIntelSourceConfig(
        source=ThreatIntelSourceEnum.URLSCAN,
        enabled=True,
        api_key_configured=bool(os.getenv("URLSCAN_API_KEY")),
        base_url="https://urlscan.io/api/v1",
        rate_limit_per_minute=60,
        rate_limit_per_day=5000,
        priority=5,
    ),
    ThreatIntelSourceEnum.SHODAN: ThreatIntelSourceConfig(
        source=ThreatIntelSourceEnum.SHODAN,
        enabled=True,
        api_key_configured=bool(os.getenv("SHODAN_API_KEY")),
        base_url="https://api.shodan.io",
        rate_limit_per_minute=60,
        rate_limit_per_day=10000,
        priority=6,
    ),
    ThreatIntelSourceEnum.MISP: ThreatIntelSourceConfig(
        source=ThreatIntelSourceEnum.MISP,
        enabled=True,
        api_key_configured=bool(os.getenv("MISP_API_KEY")),
        base_url=os.getenv("MISP_URL", ""),
        rate_limit_per_minute=100,
        rate_limit_per_day=50000,
        priority=7,
    ),
    ThreatIntelSourceEnum.HYBRID_ANALYSIS: ThreatIntelSourceConfig(
        source=ThreatIntelSourceEnum.HYBRID_ANALYSIS,
        enabled=True,
        api_key_configured=bool(os.getenv("HYBRID_ANALYSIS_API_KEY")),
        base_url="https://www.hybrid-analysis.com/api/v2",
        rate_limit_per_minute=10,
        rate_limit_per_day=200,
        priority=8,
    ),
}


# ============================================================================
# Helper Functions
# ============================================================================

def _detect_ioc_type(ioc: str) -> IOCTypeEnum:
    """Auto-detect the type of an IOC."""
    ioc = ioc.strip().lower()

    # Check for file hashes first
    if re.match(r"^[a-f0-9]{32}$", ioc):
        return IOCTypeEnum.FILE_HASH_MD5
    if re.match(r"^[a-f0-9]{40}$", ioc):
        return IOCTypeEnum.FILE_HASH_SHA1
    if re.match(r"^[a-f0-9]{64}$", ioc):
        return IOCTypeEnum.FILE_HASH_SHA256

    # Check for CVE
    if re.match(r"^cve-\d{4}-\d+$", ioc, re.IGNORECASE):
        return IOCTypeEnum.CVE

    # Check for email
    if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", ioc):
        return IOCTypeEnum.EMAIL

    # Check for URL
    if ioc.startswith(("http://", "https://", "ftp://")):
        return IOCTypeEnum.URL

    # Check for IP address
    try:
        ipaddress.ip_address(ioc)
        return IOCTypeEnum.IP
    except ValueError:
        pass

    # Default to domain
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", ioc):
        return IOCTypeEnum.DOMAIN

    # Fallback - assume domain
    return IOCTypeEnum.DOMAIN


def _get_cache_key(ioc: str, ioc_type: IOCTypeEnum, sources: List[ThreatIntelSourceEnum]) -> str:
    """Generate cache key for IOC enrichment."""
    sources_str = ",".join(sorted(s.value for s in sources))
    return f"{ioc_type.value}:{ioc.lower()}:{sources_str}"


def _check_cache(cache_key: str) -> Optional[IOCEnrichmentResult]:
    """Check if IOC is in cache and not expired."""
    if cache_key in ioc_cache:
        entry = ioc_cache[cache_key]
        if datetime.utcnow() < entry["expires_at"]:
            query_stats["cache_hits"] += 1
            return entry["result"]
        else:
            del ioc_cache[cache_key]
    return None


def _store_cache(cache_key: str, result: IOCEnrichmentResult, ttl_seconds: int = CACHE_TTL_SECONDS):
    """Store IOC enrichment result in cache."""
    ioc_cache[cache_key] = {
        "result": result,
        "expires_at": datetime.utcnow() + timedelta(seconds=ttl_seconds),
    }


def _check_rate_limit(source: ThreatIntelSourceEnum) -> bool:
    """Check if we're within rate limits for a source."""
    config = source_configs.get(source)
    if not config:
        return False

    tracker = rate_limit_tracker[source.value]
    now = datetime.utcnow()

    # Reset minute counter if needed
    if (now - tracker["minute_reset"]).total_seconds() >= 60:
        tracker["minute_count"] = 0
        tracker["minute_reset"] = now

    # Reset day counter if needed
    if (now - tracker["day_reset"]).total_seconds() >= 86400:
        tracker["day_count"] = 0
        tracker["day_reset"] = now

    # Check limits
    if tracker["minute_count"] >= config.rate_limit_per_minute:
        return False
    if tracker["day_count"] >= config.rate_limit_per_day:
        return False

    return True


def _record_query(source: ThreatIntelSourceEnum):
    """Record a query for rate limiting."""
    tracker = rate_limit_tracker[source.value]
    tracker["minute_count"] += 1
    tracker["day_count"] += 1
    query_stats["source_queries"][source.value] += 1


def _aggregate_results(source_results: List[SourceResult]) -> Tuple[ReputationScoreEnum, int, int]:
    """Aggregate results from multiple sources into overall verdict."""
    if not source_results:
        return ReputationScoreEnum.UNKNOWN, 0, 0

    # Count reputations
    malicious_count = 0
    suspicious_count = 0
    clean_count = 0
    total_scores = []
    total_confidence = []

    for result in source_results:
        if not result.success:
            continue

        if result.reputation == ReputationScoreEnum.MALICIOUS:
            malicious_count += 1
        elif result.reputation == ReputationScoreEnum.SUSPICIOUS:
            suspicious_count += 1
        elif result.reputation == ReputationScoreEnum.CLEAN:
            clean_count += 1

        if result.risk_score is not None:
            total_scores.append(result.risk_score)
        if result.confidence is not None:
            total_confidence.append(result.confidence)

    # Determine overall reputation
    if malicious_count >= 2 or (malicious_count >= 1 and suspicious_count >= 1):
        overall_reputation = ReputationScoreEnum.MALICIOUS
    elif malicious_count >= 1 or suspicious_count >= 2:
        overall_reputation = ReputationScoreEnum.SUSPICIOUS
    elif clean_count >= 2:
        overall_reputation = ReputationScoreEnum.CLEAN
    elif clean_count >= 1:
        overall_reputation = ReputationScoreEnum.NEUTRAL
    else:
        overall_reputation = ReputationScoreEnum.UNKNOWN

    # Calculate average scores
    avg_risk = int(sum(total_scores) / len(total_scores)) if total_scores else 50
    avg_confidence = int(sum(total_confidence) / len(total_confidence)) if total_confidence else 50

    return overall_reputation, avg_risk, avg_confidence


def _generate_recommendations(
    ioc_type: IOCTypeEnum,
    reputation: ReputationScoreEnum,
    risk_score: int,
    categories: List[ThreatCategoryEnum]
) -> Tuple[List[str], bool]:
    """Generate action recommendations based on enrichment results."""
    recommendations = []
    block_recommended = False

    if reputation == ReputationScoreEnum.MALICIOUS:
        block_recommended = True
        recommendations.append("IMMEDIATE: Block this IOC at perimeter/endpoint")

        if ioc_type == IOCTypeEnum.IP:
            recommendations.append("Add IP to firewall blocklist")
            recommendations.append("Check for existing connections to this IP")
        elif ioc_type == IOCTypeEnum.DOMAIN:
            recommendations.append("Add domain to DNS sinkhole")
            recommendations.append("Block at web proxy")
        elif ioc_type in [IOCTypeEnum.FILE_HASH_MD5, IOCTypeEnum.FILE_HASH_SHA1, IOCTypeEnum.FILE_HASH_SHA256]:
            recommendations.append("Add hash to EDR blocklist")
            recommendations.append("Search endpoints for this file hash")

        if ThreatCategoryEnum.RANSOMWARE in categories:
            recommendations.append("CRITICAL: Initiate ransomware response playbook")
        if ThreatCategoryEnum.C2 in categories:
            recommendations.append("Hunt for lateral movement from affected hosts")

    elif reputation == ReputationScoreEnum.SUSPICIOUS:
        if risk_score >= 70:
            block_recommended = True
            recommendations.append("RECOMMENDED: Consider blocking this IOC")
        recommendations.append("Increase monitoring for this IOC")
        recommendations.append("Investigate any connections/detections involving this IOC")

    elif reputation == ReputationScoreEnum.CLEAN:
        recommendations.append("No immediate action required")
        recommendations.append("Continue routine monitoring")

    elif reputation == ReputationScoreEnum.UNKNOWN:
        recommendations.append("Manual analysis recommended - insufficient data")
        recommendations.append("Submit to sandbox for analysis if file hash")

    return recommendations, block_recommended


# ============================================================================
# Source-Specific Query Functions
# ============================================================================

async def _query_virustotal(
    client: httpx.AsyncClient,
    ioc: str,
    ioc_type: IOCTypeEnum
) -> SourceResult:
    """Query VirusTotal for IOC information."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return SourceResult(
            source=ThreatIntelSourceEnum.VIRUSTOTAL,
            queried_at=datetime.utcnow(),
            success=False,
            error_message="API key not configured",
        )

    try:
        headers = {"x-apikey": api_key}
        base_url = "https://www.virustotal.com/api/v3"

        # Determine endpoint based on IOC type
        if ioc_type == IOCTypeEnum.IP:
            url = f"{base_url}/ip_addresses/{ioc}"
        elif ioc_type == IOCTypeEnum.DOMAIN:
            url = f"{base_url}/domains/{ioc}"
        elif ioc_type == IOCTypeEnum.URL:
            # URL needs to be base64 encoded
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            url = f"{base_url}/urls/{url_id}"
        elif ioc_type in [IOCTypeEnum.FILE_HASH_MD5, IOCTypeEnum.FILE_HASH_SHA1, IOCTypeEnum.FILE_HASH_SHA256]:
            url = f"{base_url}/files/{ioc}"
        else:
            return SourceResult(
                source=ThreatIntelSourceEnum.VIRUSTOTAL,
                queried_at=datetime.utcnow(),
                success=False,
                error_message=f"Unsupported IOC type: {ioc_type}",
            )

        _record_query(ThreatIntelSourceEnum.VIRUSTOTAL)
        response = await client.get(url, headers=headers, timeout=30)

        if response.status_code == 404:
            return SourceResult(
                source=ThreatIntelSourceEnum.VIRUSTOTAL,
                queried_at=datetime.utcnow(),
                success=True,
                reputation=ReputationScoreEnum.UNKNOWN,
                confidence=0,
            )

        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})

        # Parse detection stats
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # Determine reputation
        if total > 0:
            mal_ratio = malicious / total
            if mal_ratio >= 0.3:
                reputation = ReputationScoreEnum.MALICIOUS
            elif mal_ratio >= 0.1 or suspicious >= 3:
                reputation = ReputationScoreEnum.SUSPICIOUS
            elif harmless >= total * 0.5:
                reputation = ReputationScoreEnum.CLEAN
            else:
                reputation = ReputationScoreEnum.NEUTRAL
        else:
            reputation = ReputationScoreEnum.UNKNOWN

        # Calculate risk score
        risk_score = min(100, int((malicious * 10 + suspicious * 5) / max(total, 1) * 100))

        # Extract categories
        categories = []
        vt_categories = data.get("categories", {})
        for cat_val in vt_categories.values():
            cat_lower = cat_val.lower()
            if "malware" in cat_lower:
                categories.append(ThreatCategoryEnum.MALWARE)
            if "phishing" in cat_lower:
                categories.append(ThreatCategoryEnum.PHISHING)
            if "botnet" in cat_lower:
                categories.append(ThreatCategoryEnum.BOTNET)

        return SourceResult(
            source=ThreatIntelSourceEnum.VIRUSTOTAL,
            queried_at=datetime.utcnow(),
            success=True,
            reputation=reputation,
            confidence=min(100, total * 2),
            risk_score=risk_score,
            malicious_count=malicious,
            suspicious_count=suspicious,
            clean_count=harmless,
            total_engines=total,
            categories=list(set(categories)),
            first_seen=None,
            last_seen=None,
            raw_data={"stats": stats},
        )

    except httpx.HTTPStatusError as e:
        return SourceResult(
            source=ThreatIntelSourceEnum.VIRUSTOTAL,
            queried_at=datetime.utcnow(),
            success=False,
            error_message=f"HTTP {e.response.status_code}: {e.response.text[:200]}",
        )
    except Exception as e:
        return SourceResult(
            source=ThreatIntelSourceEnum.VIRUSTOTAL,
            queried_at=datetime.utcnow(),
            success=False,
            error_message=str(e),
        )


async def _query_abuseipdb(
    client: httpx.AsyncClient,
    ioc: str,
    ioc_type: IOCTypeEnum
) -> SourceResult:
    """Query AbuseIPDB for IP reputation."""
    if ioc_type != IOCTypeEnum.IP:
        return SourceResult(
            source=ThreatIntelSourceEnum.ABUSEIPDB,
            queried_at=datetime.utcnow(),
            success=False,
            error_message="AbuseIPDB only supports IP addresses",
        )

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return SourceResult(
            source=ThreatIntelSourceEnum.ABUSEIPDB,
            queried_at=datetime.utcnow(),
            success=False,
            error_message="API key not configured",
        )

    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ioc, "maxAgeInDays": 90, "verbose": True}

        _record_query(ThreatIntelSourceEnum.ABUSEIPDB)
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=30,
        )
        response.raise_for_status()

        data = response.json().get("data", {})
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        is_public = data.get("isPublic", True)

        # Determine reputation
        if abuse_score >= 80:
            reputation = ReputationScoreEnum.MALICIOUS
        elif abuse_score >= 50:
            reputation = ReputationScoreEnum.SUSPICIOUS
        elif abuse_score >= 20:
            reputation = ReputationScoreEnum.NEUTRAL
        elif is_public and total_reports == 0:
            reputation = ReputationScoreEnum.CLEAN
        else:
            reputation = ReputationScoreEnum.UNKNOWN

        # Extract categories from reports
        categories = []
        reports = data.get("reports", [])
        for report in reports[:10]:  # Check first 10 reports
            report_categories = report.get("categories", [])
            for cat_id in report_categories:
                # AbuseIPDB category mappings
                if cat_id in [14, 15, 16]:  # Port Scan, Hacking, Brute-Force
                    categories.append(ThreatCategoryEnum.BRUTE_FORCE)
                elif cat_id in [10, 11]:  # Web spam, Email spam
                    categories.append(ThreatCategoryEnum.SPAM)
                elif cat_id == 19:  # Phishing
                    categories.append(ThreatCategoryEnum.PHISHING)
                elif cat_id in [20, 21]:  # Fraud
                    categories.append(ThreatCategoryEnum.MALWARE)

        return SourceResult(
            source=ThreatIntelSourceEnum.ABUSEIPDB,
            queried_at=datetime.utcnow(),
            success=True,
            reputation=reputation,
            confidence=min(100, abuse_score + 20),
            risk_score=abuse_score,
            report_count=total_reports,
            categories=list(set(categories)),
            tags=[data.get("usageType", "")],
            raw_data={
                "abuseConfidenceScore": abuse_score,
                "totalReports": total_reports,
                "countryCode": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
            },
        )

    except Exception as e:
        return SourceResult(
            source=ThreatIntelSourceEnum.ABUSEIPDB,
            queried_at=datetime.utcnow(),
            success=False,
            error_message=str(e),
        )


async def _query_alienvault_otx(
    client: httpx.AsyncClient,
    ioc: str,
    ioc_type: IOCTypeEnum
) -> SourceResult:
    """Query AlienVault OTX for threat intelligence."""
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return SourceResult(
            source=ThreatIntelSourceEnum.ALIENVAULT_OTX,
            queried_at=datetime.utcnow(),
            success=False,
            error_message="API key not configured",
        )

    try:
        headers = {"X-OTX-API-KEY": api_key}
        base_url = "https://otx.alienvault.com/api/v1"

        # Determine endpoint
        if ioc_type == IOCTypeEnum.IP:
            url = f"{base_url}/indicators/IPv4/{ioc}/general"
        elif ioc_type == IOCTypeEnum.DOMAIN:
            url = f"{base_url}/indicators/domain/{ioc}/general"
        elif ioc_type == IOCTypeEnum.URL:
            url = f"{base_url}/indicators/url/{ioc}/general"
        elif ioc_type in [IOCTypeEnum.FILE_HASH_MD5, IOCTypeEnum.FILE_HASH_SHA1, IOCTypeEnum.FILE_HASH_SHA256]:
            url = f"{base_url}/indicators/file/{ioc}/general"
        else:
            return SourceResult(
                source=ThreatIntelSourceEnum.ALIENVAULT_OTX,
                queried_at=datetime.utcnow(),
                success=False,
                error_message=f"Unsupported IOC type: {ioc_type}",
            )

        _record_query(ThreatIntelSourceEnum.ALIENVAULT_OTX)
        response = await client.get(url, headers=headers, timeout=30)

        if response.status_code == 404:
            return SourceResult(
                source=ThreatIntelSourceEnum.ALIENVAULT_OTX,
                queried_at=datetime.utcnow(),
                success=True,
                reputation=ReputationScoreEnum.UNKNOWN,
                confidence=0,
            )

        response.raise_for_status()
        data = response.json()

        # Count pulses (threat reports)
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])

        # Determine reputation
        if pulse_count >= 5:
            reputation = ReputationScoreEnum.MALICIOUS
        elif pulse_count >= 2:
            reputation = ReputationScoreEnum.SUSPICIOUS
        elif pulse_count >= 1:
            reputation = ReputationScoreEnum.NEUTRAL
        else:
            reputation = ReputationScoreEnum.UNKNOWN

        # Extract categories from pulses
        categories = []
        tags = []
        for pulse in pulses[:5]:
            pulse_tags = pulse.get("tags", [])
            tags.extend(pulse_tags)
            for tag in pulse_tags:
                tag_lower = tag.lower()
                if "malware" in tag_lower:
                    categories.append(ThreatCategoryEnum.MALWARE)
                elif "phishing" in tag_lower:
                    categories.append(ThreatCategoryEnum.PHISHING)
                elif "ransomware" in tag_lower:
                    categories.append(ThreatCategoryEnum.RANSOMWARE)
                elif "c2" in tag_lower or "c&c" in tag_lower:
                    categories.append(ThreatCategoryEnum.C2)
                elif "apt" in tag_lower:
                    categories.append(ThreatCategoryEnum.APT)

        return SourceResult(
            source=ThreatIntelSourceEnum.ALIENVAULT_OTX,
            queried_at=datetime.utcnow(),
            success=True,
            reputation=reputation,
            confidence=min(100, pulse_count * 15),
            risk_score=min(100, pulse_count * 20),
            report_count=pulse_count,
            categories=list(set(categories)),
            tags=list(set(tags))[:10],
            raw_data={"pulse_count": pulse_count},
        )

    except Exception as e:
        return SourceResult(
            source=ThreatIntelSourceEnum.ALIENVAULT_OTX,
            queried_at=datetime.utcnow(),
            success=False,
            error_message=str(e),
        )


async def _query_greynoise(
    client: httpx.AsyncClient,
    ioc: str,
    ioc_type: IOCTypeEnum
) -> SourceResult:
    """Query GreyNoise for IP reputation (scanners, bots, etc.)."""
    if ioc_type != IOCTypeEnum.IP:
        return SourceResult(
            source=ThreatIntelSourceEnum.GREYNOISE,
            queried_at=datetime.utcnow(),
            success=False,
            error_message="GreyNoise only supports IP addresses",
        )

    api_key = os.getenv("GREYNOISE_API_KEY")
    # GreyNoise community API doesn't require a key
    headers = {}
    if api_key:
        headers["key"] = api_key

    try:
        _record_query(ThreatIntelSourceEnum.GREYNOISE)

        # Use community API endpoint
        url = f"https://api.greynoise.io/v3/community/{ioc}"
        response = await client.get(url, headers=headers, timeout=30)

        if response.status_code == 404:
            # IP not observed by GreyNoise
            return SourceResult(
                source=ThreatIntelSourceEnum.GREYNOISE,
                queried_at=datetime.utcnow(),
                success=True,
                reputation=ReputationScoreEnum.UNKNOWN,
                confidence=30,
                risk_score=20,
            )

        response.raise_for_status()
        data = response.json()

        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "unknown")
        name = data.get("name", "")

        # Determine reputation
        if riot:
            # Known benign (e.g., Google DNS, Cloudflare)
            reputation = ReputationScoreEnum.CLEAN
            risk_score = 0
        elif classification == "malicious":
            reputation = ReputationScoreEnum.MALICIOUS
            risk_score = 85
        elif classification == "benign":
            reputation = ReputationScoreEnum.CLEAN
            risk_score = 10
        elif noise:
            reputation = ReputationScoreEnum.SUSPICIOUS
            risk_score = 50
        else:
            reputation = ReputationScoreEnum.NEUTRAL
            risk_score = 30

        categories = []
        if noise:
            categories.append(ThreatCategoryEnum.SCANNER)

        return SourceResult(
            source=ThreatIntelSourceEnum.GREYNOISE,
            queried_at=datetime.utcnow(),
            success=True,
            reputation=reputation,
            confidence=70 if noise else 40,
            risk_score=risk_score,
            categories=categories,
            tags=[name] if name else [],
            raw_data={
                "noise": noise,
                "riot": riot,
                "classification": classification,
                "name": name,
            },
        )

    except Exception as e:
        return SourceResult(
            source=ThreatIntelSourceEnum.GREYNOISE,
            queried_at=datetime.utcnow(),
            success=False,
            error_message=str(e),
        )


async def _enrich_single_ioc(
    ioc: str,
    ioc_type: IOCTypeEnum,
    sources: List[ThreatIntelSourceEnum],
    include_whois: bool = False,
    include_passive_dns: bool = False,
) -> IOCEnrichmentResult:
    """Enrich a single IOC from multiple sources."""
    source_results = []

    async with httpx.AsyncClient() as client:
        # Query each source concurrently
        tasks = []

        for source in sources:
            if not _check_rate_limit(source):
                source_results.append(SourceResult(
                    source=source,
                    queried_at=datetime.utcnow(),
                    success=False,
                    error_message="Rate limited",
                ))
                continue

            config = source_configs.get(source)
            if not config or not config.enabled:
                continue

            if source == ThreatIntelSourceEnum.VIRUSTOTAL:
                tasks.append(_query_virustotal(client, ioc, ioc_type))
            elif source == ThreatIntelSourceEnum.ABUSEIPDB:
                tasks.append(_query_abuseipdb(client, ioc, ioc_type))
            elif source == ThreatIntelSourceEnum.ALIENVAULT_OTX:
                tasks.append(_query_alienvault_otx(client, ioc, ioc_type))
            elif source == ThreatIntelSourceEnum.GREYNOISE:
                tasks.append(_query_greynoise(client, ioc, ioc_type))

        # Execute all queries concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, SourceResult):
                    source_results.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"[-] Query failed: {result}")

    # Aggregate results
    overall_reputation, overall_risk, confidence = _aggregate_results(source_results)

    # Collect all categories and tags
    all_categories = []
    all_tags = []
    for result in source_results:
        if result.success:
            all_categories.extend(result.categories)
            all_tags.extend(result.tags)

    # Generate recommendations
    recommendations, block_recommended = _generate_recommendations(
        ioc_type, overall_reputation, overall_risk, list(set(all_categories))
    )

    # Build GeoIP data for IPs
    geoip = None
    if ioc_type == IOCTypeEnum.IP:
        for result in source_results:
            if result.raw_data and "countryCode" in result.raw_data:
                geoip = GeoIPData(
                    country_code=result.raw_data.get("countryCode"),
                    isp=result.raw_data.get("isp"),
                    asn_org=result.raw_data.get("domain"),
                )
                break

    return IOCEnrichmentResult(
        ioc=ioc,
        ioc_type=ioc_type,
        enriched_at=datetime.utcnow(),
        overall_reputation=overall_reputation,
        overall_risk_score=overall_risk,
        confidence=confidence,
        threat_categories=list(set(all_categories)),
        tags=list(set(all_tags))[:20],
        source_results=source_results,
        geoip=geoip,
        recommended_actions=recommendations,
        block_recommended=block_recommended,
    )


# ============================================================================
# API Endpoints
# ============================================================================

@router.post("/enrich", response_model=BulkEnrichmentResponse)
async def enrich_iocs(
    request: IOCEnrichmentRequest,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_active_user),
):
    """
    Enrich one or more IOCs with threat intelligence.

    Queries multiple sources (VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise)
    and returns aggregated reputation, risk scores, and recommendations.

    Features:
    - Auto-detects IOC type if not specified
    - Caches results for 1 hour
    - Rate limiting per source
    - Concurrent queries for performance
    """
    start_time = time.time()
    request_id = f"ENR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8].upper()}"

    query_stats["total_queries"] += 1

    results = []
    enriched_count = 0
    failed_count = 0

    for ioc in request.iocs:
        ioc = ioc.strip()
        if not ioc:
            continue

        # Detect or use provided IOC type
        ioc_type = request.ioc_type or _detect_ioc_type(ioc)

        # Check cache first
        cache_key = _get_cache_key(ioc, ioc_type, request.sources)
        cached_result = _check_cache(cache_key)

        if cached_result:
            results.append(cached_result)
            enriched_count += 1
            continue

        try:
            # Enrich the IOC
            result = await _enrich_single_ioc(
                ioc=ioc,
                ioc_type=ioc_type,
                sources=request.sources,
                include_whois=request.include_whois,
                include_passive_dns=request.include_passive_dns,
            )

            # Store in cache
            _store_cache(cache_key, result)

            results.append(result)
            enriched_count += 1

        except Exception as e:
            logger.error(f"[-] Failed to enrich IOC {ioc}: {e}")
            failed_count += 1

    processing_time = int((time.time() - start_time) * 1000)
    query_stats["query_times"].append(processing_time)

    # Keep only last 100 query times for averaging
    if len(query_stats["query_times"]) > 100:
        query_stats["query_times"] = query_stats["query_times"][-100:]

    return BulkEnrichmentResponse(
        request_id=request_id,
        total_iocs=len(request.iocs),
        enriched_count=enriched_count,
        failed_count=failed_count,
        results=results,
        processing_time_ms=processing_time,
        sources_queried=request.sources,
    )


@router.get("/enrich/{ioc}", response_model=IOCEnrichmentResult)
async def enrich_single_ioc(
    ioc: str,
    ioc_type: Optional[IOCTypeEnum] = Query(None, description="IOC type (auto-detected if not specified)"),
    sources: Optional[str] = Query(
        "virustotal,abuseipdb",
        description="Comma-separated list of sources to query"
    ),
    current_user: str = Depends(get_current_active_user),
):
    """
    Enrich a single IOC with threat intelligence.

    Quick endpoint for single IOC lookup. For bulk enrichment, use POST /enrich.
    """
    query_stats["total_queries"] += 1

    # Parse sources
    source_list = [
        ThreatIntelSourceEnum(s.strip())
        for s in sources.split(",")
        if s.strip() in [e.value for e in ThreatIntelSourceEnum]
    ]

    if not source_list:
        source_list = [ThreatIntelSourceEnum.VIRUSTOTAL, ThreatIntelSourceEnum.ABUSEIPDB]

    # Detect IOC type
    detected_type = ioc_type or _detect_ioc_type(ioc)

    # Check cache
    cache_key = _get_cache_key(ioc, detected_type, source_list)
    cached_result = _check_cache(cache_key)

    if cached_result:
        return cached_result

    # Enrich
    result = await _enrich_single_ioc(
        ioc=ioc,
        ioc_type=detected_type,
        sources=source_list,
    )

    # Cache result
    _store_cache(cache_key, result)

    return result


@router.get("/sources", response_model=List[ThreatIntelSourceStatus])
async def get_source_status(
    current_user: str = Depends(get_current_active_user),
):
    """
    Get status of all threat intelligence sources.

    Shows which sources are configured, enabled, and their rate limit status.
    """
    statuses = []

    for source, config in source_configs.items():
        tracker = rate_limit_tracker[source.value]

        # Calculate remaining queries
        queries_remaining_minute = max(0, config.rate_limit_per_minute - tracker["minute_count"])
        queries_remaining_day = max(0, config.rate_limit_per_day - tracker["day_count"])

        statuses.append(ThreatIntelSourceStatus(
            source=source,
            enabled=config.enabled,
            api_key_configured=config.api_key_configured,
            queries_today=tracker["day_count"],
            queries_remaining=min(queries_remaining_minute, queries_remaining_day),
            rate_limited=(queries_remaining_minute == 0 or queries_remaining_day == 0),
        ))

    return statuses


@router.get("/stats", response_model=ThreatIntelStats)
async def get_stats(
    current_user: str = Depends(get_current_active_user),
):
    """
    Get threat intelligence system statistics.

    Includes cache statistics, query counts, and source status.
    """
    # Count IOCs by type and category
    iocs_by_type: Dict[str, int] = defaultdict(int)
    iocs_by_category: Dict[str, int] = defaultdict(int)
    iocs_by_reputation: Dict[str, int] = defaultdict(int)

    for entry in ioc_cache.values():
        result = entry.get("result")
        if result:
            iocs_by_type[result.ioc_type.value] += 1
            iocs_by_reputation[result.overall_reputation.value] += 1
            for cat in result.threat_categories:
                iocs_by_category[cat.value] += 1

    # Get source statuses
    source_statuses = []
    for source, config in source_configs.items():
        tracker = rate_limit_tracker[source.value]
        source_statuses.append(ThreatIntelSourceStatus(
            source=source,
            enabled=config.enabled,
            api_key_configured=config.api_key_configured,
            queries_today=tracker["day_count"],
            queries_remaining=max(0, config.rate_limit_per_day - tracker["day_count"]),
            rate_limited=tracker["day_count"] >= config.rate_limit_per_day,
        ))

    # Calculate cache hit rate
    total_queries = query_stats["total_queries"]
    cache_hits = query_stats["cache_hits"]
    cache_hit_rate = cache_hits / total_queries if total_queries > 0 else 0

    # Calculate average enrichment time
    query_times = query_stats["query_times"]
    avg_time = int(sum(query_times) / len(query_times)) if query_times else 0

    return ThreatIntelStats(
        total_iocs_cached=len(ioc_cache),
        iocs_by_type=dict(iocs_by_type),
        iocs_by_category=dict(iocs_by_category),
        iocs_by_reputation=dict(iocs_by_reputation),
        sources_status=source_statuses,
        cache_hit_rate=cache_hit_rate,
        queries_last_hour=sum(query_stats["source_queries"].values()),  # Simplified
        queries_last_24h=sum(query_stats["source_queries"].values()),
        average_enrichment_time_ms=avg_time,
    )


@router.delete("/cache", response_model=APIResponse)
async def clear_cache(
    current_user: str = Depends(require_write_scope),
):
    """
    Clear the IOC enrichment cache.

    Use this to force fresh queries for all IOCs.
    """
    cache_count = len(ioc_cache)
    ioc_cache.clear()

    logger.info(f"[+] Cache cleared by {current_user}: {cache_count} entries removed")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Cache cleared: {cache_count} entries removed",
    )


# ============================================================================
# Threat Intel Feed Management
# ============================================================================

@router.get("/feeds", response_model=ThreatIntelFeedList)
async def list_feeds(
    current_user: str = Depends(get_current_active_user),
):
    """List configured threat intelligence feeds."""
    feeds = list(feeds_db.values())
    return ThreatIntelFeedList(feeds=feeds, total=len(feeds))


@router.post("/feeds", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def create_feed(
    feed: ThreatIntelFeed,
    current_user: str = Depends(require_write_scope),
):
    """Create a new threat intelligence feed configuration."""
    feed.feed_id = f"FEED-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    feed.created_at = datetime.utcnow()
    feed.updated_at = datetime.utcnow()

    feeds_db[feed.feed_id] = feed

    logger.info(f"[+] Feed created: {feed.feed_id} ({feed.name})")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Feed created successfully",
        data={"feed_id": feed.feed_id},
    )


@router.delete("/feeds/{feed_id}", response_model=APIResponse)
async def delete_feed(
    feed_id: str,
    current_user: str = Depends(require_write_scope),
):
    """Delete a threat intelligence feed."""
    if feed_id not in feeds_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feed '{feed_id}' not found",
        )

    del feeds_db[feed_id]

    logger.info(f"[+] Feed deleted: {feed_id}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Feed deleted successfully",
    )


# ============================================================================
# IOC Type Detection Endpoint
# ============================================================================

@router.get("/detect-type/{ioc}")
async def detect_ioc_type(
    ioc: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Detect the type of an IOC.

    Useful for determining how to query an IOC before enrichment.
    """
    detected_type = _detect_ioc_type(ioc)

    return {
        "ioc": ioc,
        "detected_type": detected_type.value,
        "supported_sources": _get_supported_sources(detected_type),
    }


def _get_supported_sources(ioc_type: IOCTypeEnum) -> List[str]:
    """Get list of sources that support a given IOC type."""
    support_matrix = {
        IOCTypeEnum.IP: ["virustotal", "abuseipdb", "alienvault_otx", "greynoise", "shodan"],
        IOCTypeEnum.DOMAIN: ["virustotal", "alienvault_otx", "urlscan"],
        IOCTypeEnum.URL: ["virustotal", "alienvault_otx", "urlscan"],
        IOCTypeEnum.FILE_HASH_MD5: ["virustotal", "alienvault_otx", "hybrid_analysis"],
        IOCTypeEnum.FILE_HASH_SHA1: ["virustotal", "alienvault_otx", "hybrid_analysis"],
        IOCTypeEnum.FILE_HASH_SHA256: ["virustotal", "alienvault_otx", "hybrid_analysis"],
        IOCTypeEnum.EMAIL: ["alienvault_otx"],
        IOCTypeEnum.CVE: ["alienvault_otx"],
    }
    return support_matrix.get(ioc_type, [])
