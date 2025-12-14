"""
SIEM Integration Router (v1.7.5)

Provides unified API for querying and managing open-source SIEM platforms:
- Wazuh (OSSEC-based)
- Elastic SIEM / Security
- OpenSearch Security Analytics
- Graylog
- Splunk (basic support)

Based on SIEM integration best practices 2025:
- https://documentation.wazuh.com/current/integrations-guide/index.html
- https://wazuh.com/blog/detection-with-opensearch-integration/
"""

import base64
import logging
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Type

import httpx
from defensive_toolkit.api.auth import get_current_active_user
from defensive_toolkit.api.config import get_settings
from defensive_toolkit.api.models import (
    APIResponse,
    SIEMAgentInfo,
    SIEMAgentListResponse,
    SIEMAggregationBucket,
    SIEMAggregationRequest,
    SIEMAggregationResponse,
    SIEMAlert,
    SIEMAuthTypeEnum,
    SIEMBulkHealthCheck,
    SIEMConnectionConfig,
    SIEMConnectionConfigList,
    SIEMConnectionStatus,
    SIEMConnectionStatusEnum,
    SIEMDashboardStats,
    SIEMHealthCheck,
    SIEMIndexInfo,
    SIEMIndexListResponse,
    SIEMPlatformTypeEnum,
    SIEMQueryRequest,
    SIEMQueryResponse,
    SIEMRuleInfo,
    SIEMRuleListResponse,
    StatusEnum,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status

settings = get_settings()
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/siem", tags=["SIEM Integration"])


# ============================================================================
# In-Memory Storage (Replace with database in production)
# ============================================================================

# Connection configurations
_siem_connections: Dict[str, SIEMConnectionConfig] = {}

# Connection status cache
_connection_status_cache: Dict[str, SIEMConnectionStatus] = {}

# HTTP client pool
_http_clients: Dict[str, httpx.AsyncClient] = {}


# ============================================================================
# Abstract SIEM Client Base Class
# ============================================================================


class BaseSIEMClient(ABC):
    """Abstract base class for SIEM platform clients"""

    def __init__(self, config: SIEMConnectionConfig):
        self.config = config
        self.client: Optional[httpx.AsyncClient] = None

    @property
    def base_url(self) -> str:
        """Construct base URL from config"""
        protocol = "https" if self.config.use_ssl else "http"
        return f"{protocol}://{self.config.host}:{self.config.port}"

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self.client is None or self.client.is_closed:
            self.client = httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                verify=self.config.verify_ssl,
                limits=httpx.Limits(
                    max_connections=self.config.pool_connections,
                    max_keepalive_connections=self.config.pool_connections // 2,
                ),
            )
        return self.client

    async def close(self):
        """Close HTTP client"""
        if self.client and not self.client.is_closed:
            await self.client.aclose()
            self.client = None

    @abstractmethod
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for requests"""
        pass

    @abstractmethod
    async def test_connection(self) -> SIEMConnectionStatus:
        """Test connection to SIEM platform"""
        pass

    @abstractmethod
    async def query_alerts(self, request: SIEMQueryRequest) -> SIEMQueryResponse:
        """Query alerts from SIEM"""
        pass

    @abstractmethod
    async def get_agents(self, limit: int = 100, offset: int = 0) -> SIEMAgentListResponse:
        """Get list of agents"""
        pass

    @abstractmethod
    async def get_rules(self, limit: int = 100, offset: int = 0) -> SIEMRuleListResponse:
        """Get list of detection rules"""
        pass

    @abstractmethod
    async def get_indices(self) -> SIEMIndexListResponse:
        """Get list of indices"""
        pass

    @abstractmethod
    async def get_dashboard_stats(self, hours: int = 24) -> SIEMDashboardStats:
        """Get dashboard statistics"""
        pass

    def _map_severity(self, level: int) -> str:
        """Map numeric level to severity string"""
        if level >= 12:
            return "critical"
        elif level >= 8:
            return "high"
        elif level >= 4:
            return "medium"
        else:
            return "low"


# ============================================================================
# Wazuh Client Implementation
# ============================================================================


class WazuhClient(BaseSIEMClient):
    """Client for Wazuh SIEM API"""

    def __init__(self, config: SIEMConnectionConfig):
        super().__init__(config)
        self._jwt_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    def get_auth_headers(self) -> Dict[str, str]:
        """Get Wazuh authentication headers"""
        if self.config.auth_type == SIEMAuthTypeEnum.TOKEN and self._jwt_token:
            return {"Authorization": f"Bearer {self._jwt_token}"}
        elif self.config.auth_type == SIEMAuthTypeEnum.BASIC:
            credentials = base64.b64encode(
                f"{self.config.username}:{self.config.password}".encode()
            ).decode()
            return {"Authorization": f"Basic {credentials}"}
        return {}

    async def _authenticate(self) -> str:
        """Authenticate with Wazuh API and get JWT token"""
        client = await self.get_client()
        credentials = base64.b64encode(
            f"{self.config.username}:{self.config.password}".encode()
        ).decode()

        try:
            response = await client.post(
                f"{self.base_url}/security/user/authenticate",
                headers={"Authorization": f"Basic {credentials}"},
            )
            response.raise_for_status()
            data = response.json()
            self._jwt_token = data.get("data", {}).get("token")
            self._token_expiry = datetime.utcnow() + timedelta(minutes=15)
            return self._jwt_token
        except Exception as e:
            logger.error(f"Wazuh authentication failed: {e}")
            raise

    async def _ensure_authenticated(self):
        """Ensure we have a valid JWT token"""
        if not self._jwt_token or (self._token_expiry and datetime.utcnow() >= self._token_expiry):
            await self._authenticate()

    async def test_connection(self) -> SIEMConnectionStatus:
        """Test connection to Wazuh"""
        start_time = time.time()
        try:
            await self._ensure_authenticated()
            client = await self.get_client()

            # Get cluster info
            response = await client.get(
                f"{self.base_url}/cluster/status", headers=self.get_auth_headers()
            )
            response.raise_for_status()

            # Get manager info
            info_response = await client.get(
                f"{self.base_url}/manager/info", headers=self.get_auth_headers()
            )
            info_data = info_response.json().get("data", {}).get("affected_items", [{}])[0]

            latency = int((time.time() - start_time) * 1000)

            return SIEMConnectionStatus(
                connection_id=self.config.connection_id,
                name=self.config.name,
                platform=SIEMPlatformTypeEnum.WAZUH,
                status=SIEMConnectionStatusEnum.CONNECTED,
                last_check=datetime.utcnow(),
                latency_ms=latency,
                version=info_data.get("version"),
                cluster_name=info_data.get("cluster", {}).get("name"),
                node_count=1,  # Would need cluster/nodes endpoint for actual count
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return SIEMConnectionStatus(
                    connection_id=self.config.connection_id,
                    name=self.config.name,
                    platform=SIEMPlatformTypeEnum.WAZUH,
                    status=SIEMConnectionStatusEnum.UNAUTHORIZED,
                    last_check=datetime.utcnow(),
                    error_message="Authentication failed",
                )
            raise
        except Exception as e:
            return SIEMConnectionStatus(
                connection_id=self.config.connection_id,
                name=self.config.name,
                platform=SIEMPlatformTypeEnum.WAZUH,
                status=SIEMConnectionStatusEnum.ERROR,
                last_check=datetime.utcnow(),
                error_message=str(e),
            )

    async def query_alerts(self, request: SIEMQueryRequest) -> SIEMQueryResponse:
        """Query alerts from Wazuh indexer"""
        start_time = time.time()
        await self._ensure_authenticated()
        client = await self.get_client()

        # Build Elasticsearch DSL query for Wazuh indexer
        must_clauses = []

        # Time range
        time_to = request.time_to or datetime.utcnow()
        must_clauses.append(
            {
                "range": {
                    request.time_field: {
                        "gte": request.time_from.isoformat(),
                        "lte": time_to.isoformat(),
                    }
                }
            }
        )

        # Query string
        if request.query:
            must_clauses.append({"query_string": {"query": request.query}})

        # Filters
        if request.rule_ids:
            must_clauses.append({"terms": {"rule.id": request.rule_ids}})
        if request.agent_ids:
            must_clauses.append({"terms": {"agent.id": request.agent_ids}})
        if request.source_ips:
            must_clauses.append({"terms": {"data.srcip": request.source_ips}})
        if request.mitre_tactics:
            must_clauses.append({"terms": {"rule.mitre.tactic": request.mitre_tactics}})
        if request.mitre_techniques:
            must_clauses.append({"terms": {"rule.mitre.id": request.mitre_techniques}})

        query_body = {
            "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
            "size": request.size,
            "from": request.from_offset,
            "sort": [{request.sort_field: {"order": request.sort_order}}],
        }

        if request.query_dsl:
            query_body = request.query_dsl

        # Query Wazuh indexer (OpenSearch/Elasticsearch)
        indexer_url = (
            f"{self.base_url.replace(':55000', ':9200')}/{self.config.index_pattern}/_search"
        )

        try:
            response = await client.post(
                indexer_url, json=query_body, headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"Wazuh indexer query failed: {e}")
            # Fallback: try Wazuh API for recent alerts
            response = await client.get(
                f"{self.base_url}/alerts",
                params={"limit": request.size, "offset": request.from_offset},
                headers=self.get_auth_headers(),
            )
            response.raise_for_status()
            data = {"hits": {"total": {"value": 0}, "hits": []}}

        # Parse results
        hits = data.get("hits", {})
        total_hits = hits.get("total", {})
        if isinstance(total_hits, dict):
            total_hits = total_hits.get("value", 0)

        alerts = []
        for hit in hits.get("hits", []):
            source = hit.get("_source", {})
            alerts.append(self._parse_wazuh_alert(hit.get("_id", ""), source))

        query_time = int((time.time() - start_time) * 1000)

        return SIEMQueryResponse(
            connection_id=self.config.connection_id,
            platform=SIEMPlatformTypeEnum.WAZUH,
            query_time_ms=query_time,
            total_hits=total_hits,
            returned_count=len(alerts),
            alerts=alerts,
            raw_response=data if request.include_raw else None,
        )

    def _parse_wazuh_alert(self, alert_id: str, source: Dict[str, Any]) -> SIEMAlert:
        """Parse Wazuh alert document to normalized format"""
        rule = source.get("rule", {})
        agent = source.get("agent", {})
        data = source.get("data", {})
        mitre = rule.get("mitre", {})

        return SIEMAlert(
            alert_id=alert_id,
            timestamp=datetime.fromisoformat(
                source.get("timestamp", datetime.utcnow().isoformat()).replace("Z", "+00:00")
            ),
            platform=SIEMPlatformTypeEnum.WAZUH,
            rule_id=rule.get("id"),
            rule_name=rule.get("description"),
            rule_description=rule.get("description"),
            rule_level=rule.get("level"),
            rule_groups=rule.get("groups", []),
            severity=self._map_severity(rule.get("level", 0)),
            severity_score=float(rule.get("level", 0)),
            agent_id=agent.get("id"),
            agent_name=agent.get("name"),
            agent_ip=agent.get("ip"),
            manager_name=source.get("manager", {}).get("name"),
            source_ip=data.get("srcip") or data.get("src_ip"),
            destination_ip=data.get("dstip") or data.get("dst_ip"),
            source_port=data.get("srcport"),
            destination_port=data.get("dstport"),
            protocol=data.get("protocol"),
            action=data.get("action"),
            user=data.get("dstuser") or data.get("srcuser"),
            src_user=data.get("srcuser"),
            dst_user=data.get("dstuser"),
            file_path=source.get("syscheck", {}).get("path"),
            file_hash=source.get("syscheck", {}).get("sha256"),
            process_name=data.get("process_name"),
            command_line=data.get("command"),
            mitre_tactics=mitre.get("tactic", []),
            mitre_techniques=mitre.get("technique", []),
            mitre_ids=mitre.get("id", []),
            full_log=source.get("full_log"),
            decoder_name=source.get("decoder", {}).get("name"),
            location=source.get("location"),
            data=data,
        )

    async def get_agents(self, limit: int = 100, offset: int = 0) -> SIEMAgentListResponse:
        """Get list of Wazuh agents"""
        await self._ensure_authenticated()
        client = await self.get_client()

        response = await client.get(
            f"{self.base_url}/agents",
            params={"limit": limit, "offset": offset},
            headers=self.get_auth_headers(),
        )
        response.raise_for_status()
        data = response.json()

        agents = []
        for item in data.get("data", {}).get("affected_items", []):
            agents.append(
                SIEMAgentInfo(
                    agent_id=item.get("id", ""),
                    name=item.get("name", ""),
                    ip=item.get("ip"),
                    os_name=item.get("os", {}).get("name"),
                    os_version=item.get("os", {}).get("version"),
                    os_platform=item.get("os", {}).get("platform"),
                    version=item.get("version"),
                    status=item.get("status", "unknown"),
                    last_keep_alive=(
                        datetime.fromisoformat(item["lastKeepAlive"].replace("Z", "+00:00"))
                        if item.get("lastKeepAlive")
                        else None
                    ),
                    date_add=(
                        datetime.fromisoformat(item["dateAdd"].replace("Z", "+00:00"))
                        if item.get("dateAdd")
                        else None
                    ),
                    group=item.get("group", []),
                    manager=item.get("manager"),
                    node_name=item.get("node_name"),
                )
            )

        return SIEMAgentListResponse(
            connection_id=self.config.connection_id,
            platform=SIEMPlatformTypeEnum.WAZUH,
            total_agents=data.get("data", {}).get("total_affected_items", len(agents)),
            agents=agents,
            affected_items=len(agents),
            failed_items=data.get("data", {}).get("total_failed_items", 0),
        )

    async def get_rules(self, limit: int = 100, offset: int = 0) -> SIEMRuleListResponse:
        """Get list of Wazuh detection rules"""
        await self._ensure_authenticated()
        client = await self.get_client()

        response = await client.get(
            f"{self.base_url}/rules",
            params={"limit": limit, "offset": offset},
            headers=self.get_auth_headers(),
        )
        response.raise_for_status()
        data = response.json()

        rules = []
        for item in data.get("data", {}).get("affected_items", []):
            rules.append(
                SIEMRuleInfo(
                    rule_id=str(item.get("id", "")),
                    level=item.get("level", 0),
                    description=item.get("description", ""),
                    groups=item.get("groups", []),
                    pci_dss=item.get("pci_dss", []),
                    gpg13=item.get("gpg13", []),
                    gdpr=item.get("gdpr", []),
                    hipaa=item.get("hipaa", []),
                    nist_800_53=item.get("nist_800_53", []),
                    tsc=item.get("tsc", []),
                    mitre=item.get("mitre", {}),
                    file=item.get("filename"),
                    path=item.get("relative_dirname"),
                    status="enabled" if item.get("status") == "enabled" else "disabled",
                )
            )

        return SIEMRuleListResponse(
            connection_id=self.config.connection_id,
            platform=SIEMPlatformTypeEnum.WAZUH,
            total_rules=data.get("data", {}).get("total_affected_items", len(rules)),
            rules=rules,
        )

    async def get_indices(self) -> SIEMIndexListResponse:
        """Get list of Wazuh indices"""
        client = await self.get_client()

        # Query Wazuh indexer
        indexer_url = (
            f"{self.base_url.replace(':55000', ':9200')}/_cat/indices/{self.config.index_pattern}"
        )

        response = await client.get(
            indexer_url,
            params={
                "format": "json",
                "h": "index,status,health,docs.count,store.size,pri,rep,creation.date.string",
            },
        )
        response.raise_for_status()
        data = response.json()

        indices = []
        total_docs = 0
        total_size = 0

        for item in data:
            doc_count = int(item.get("docs.count", 0) or 0)
            store_size = item.get("store.size", "0b")
            size_bytes = self._parse_size_string(store_size)

            total_docs += doc_count
            total_size += size_bytes

            indices.append(
                SIEMIndexInfo(
                    index_name=item.get("index", ""),
                    status=item.get("status", "unknown"),
                    health=item.get("health", "unknown"),
                    doc_count=doc_count,
                    store_size_bytes=size_bytes,
                    store_size_human=store_size,
                    primary_shards=int(item.get("pri", 0) or 0),
                    replica_shards=int(item.get("rep", 0) or 0),
                )
            )

        return SIEMIndexListResponse(
            connection_id=self.config.connection_id,
            platform=SIEMPlatformTypeEnum.WAZUH,
            total_indices=len(indices),
            indices=indices,
            total_docs=total_docs,
            total_size_bytes=total_size,
            total_size_human=self._format_size(total_size),
        )

    def _parse_size_string(self, size_str: str) -> int:
        """Parse size string like '1.2gb' to bytes"""
        if not size_str:
            return 0

        size_str = size_str.lower().strip()
        multipliers = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}

        for suffix, multiplier in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    return int(float(size_str[: -len(suffix)]) * multiplier)
                except ValueError:
                    return 0
        return 0

    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human readable string"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f}PB"

    async def get_dashboard_stats(self, hours: int = 24) -> SIEMDashboardStats:
        """Get dashboard statistics from Wazuh"""
        await self._ensure_authenticated()
        client = await self.get_client()

        time_from = datetime.utcnow() - timedelta(hours=hours)

        # Get agent stats
        agents_response = await client.get(
            f"{self.base_url}/agents/summary/status", headers=self.get_auth_headers()
        )
        agents_data = agents_response.json().get("data", {})

        # Query indexer for alert stats
        query_request = SIEMQueryRequest(
            connection_id=self.config.connection_id,
            time_from=time_from,
            size=0,  # Just aggregations
        )

        # This would run actual aggregation queries in production
        # For now, return placeholder data
        return SIEMDashboardStats(
            connection_id=self.config.connection_id,
            platform=SIEMPlatformTypeEnum.WAZUH,
            time_range_hours=hours,
            generated_at=datetime.utcnow(),
            total_alerts=0,
            alerts_by_severity={"low": 0, "medium": 0, "high": 0, "critical": 0},
            alerts_by_hour=[],
            top_rules=[],
            top_agents=[],
            top_source_ips=[],
            top_mitre_tactics=[],
            top_mitre_techniques=[],
            total_agents=agents_data.get("total", 0),
            active_agents=agents_data.get("active", 0),
            disconnected_agents=agents_data.get("disconnected", 0),
            cluster_status="green",
        )


# ============================================================================
# Elastic/OpenSearch Client Implementation
# ============================================================================


class ElasticClient(BaseSIEMClient):
    """Client for Elastic SIEM / OpenSearch Security Analytics"""

    def __init__(self, config: SIEMConnectionConfig):
        super().__init__(config)
        self.is_opensearch = config.platform == SIEMPlatformTypeEnum.OPENSEARCH

    def get_auth_headers(self) -> Dict[str, str]:
        """Get Elastic/OpenSearch authentication headers"""
        headers = {"Content-Type": "application/json"}

        if self.config.auth_type == SIEMAuthTypeEnum.API_KEY:
            headers["Authorization"] = f"ApiKey {self.config.api_key}"
        elif self.config.auth_type == SIEMAuthTypeEnum.BASIC:
            credentials = base64.b64encode(
                f"{self.config.username}:{self.config.password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"

        return headers

    async def test_connection(self) -> SIEMConnectionStatus:
        """Test connection to Elastic/OpenSearch"""
        start_time = time.time()
        try:
            client = await self.get_client()
            response = await client.get(f"{self.base_url}/", headers=self.get_auth_headers())
            response.raise_for_status()
            data = response.json()

            # Get cluster health
            health_response = await client.get(
                f"{self.base_url}/_cluster/health", headers=self.get_auth_headers()
            )
            health_data = health_response.json()

            latency = int((time.time() - start_time) * 1000)

            return SIEMConnectionStatus(
                connection_id=self.config.connection_id,
                name=self.config.name,
                platform=self.config.platform,
                status=SIEMConnectionStatusEnum.CONNECTED,
                last_check=datetime.utcnow(),
                latency_ms=latency,
                version=data.get("version", {}).get("number"),
                cluster_name=data.get("cluster_name"),
                node_count=health_data.get("number_of_nodes"),
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return SIEMConnectionStatus(
                    connection_id=self.config.connection_id,
                    name=self.config.name,
                    platform=self.config.platform,
                    status=SIEMConnectionStatusEnum.UNAUTHORIZED,
                    last_check=datetime.utcnow(),
                    error_message="Authentication failed",
                )
            raise
        except Exception as e:
            return SIEMConnectionStatus(
                connection_id=self.config.connection_id,
                name=self.config.name,
                platform=self.config.platform,
                status=SIEMConnectionStatusEnum.ERROR,
                last_check=datetime.utcnow(),
                error_message=str(e),
            )

    async def query_alerts(self, request: SIEMQueryRequest) -> SIEMQueryResponse:
        """Query alerts from Elastic/OpenSearch"""
        start_time = time.time()
        client = await self.get_client()

        # Build query
        must_clauses = []
        time_to = request.time_to or datetime.utcnow()

        must_clauses.append(
            {
                "range": {
                    request.time_field: {
                        "gte": request.time_from.isoformat(),
                        "lte": time_to.isoformat(),
                    }
                }
            }
        )

        if request.query:
            must_clauses.append({"query_string": {"query": request.query}})

        query_body = {
            "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
            "size": request.size,
            "from": request.from_offset,
            "sort": [{request.sort_field: {"order": request.sort_order}}],
        }

        if request.query_dsl:
            query_body = request.query_dsl

        response = await client.post(
            f"{self.base_url}/{self.config.index_pattern}/_search",
            json=query_body,
            headers=self.get_auth_headers(),
        )
        response.raise_for_status()
        data = response.json()

        hits = data.get("hits", {})
        total_hits = hits.get("total", {})
        if isinstance(total_hits, dict):
            total_hits = total_hits.get("value", 0)

        alerts = []
        for hit in hits.get("hits", []):
            source = hit.get("_source", {})
            alerts.append(self._parse_elastic_alert(hit.get("_id", ""), source))

        query_time = int((time.time() - start_time) * 1000)

        return SIEMQueryResponse(
            connection_id=self.config.connection_id,
            platform=self.config.platform,
            query_time_ms=query_time,
            total_hits=total_hits,
            returned_count=len(alerts),
            alerts=alerts,
            aggregations=data.get("aggregations"),
            raw_response=data if request.include_raw else None,
        )

    def _parse_elastic_alert(self, alert_id: str, source: Dict[str, Any]) -> SIEMAlert:
        """Parse Elastic Security alert to normalized format"""
        # Elastic Security uses different field names
        signal = source.get("signal", source.get("kibana.alert", {}))
        rule = signal.get("rule", source.get("rule", {}))

        return SIEMAlert(
            alert_id=alert_id,
            timestamp=datetime.fromisoformat(
                source.get("@timestamp", datetime.utcnow().isoformat()).replace("Z", "+00:00")
            ),
            platform=self.config.platform,
            rule_id=rule.get("id"),
            rule_name=rule.get("name"),
            rule_description=rule.get("description"),
            rule_level=rule.get("risk_score"),
            severity=rule.get("severity", "medium"),
            severity_score=float(rule.get("risk_score", 50)),
            source_ip=source.get("source", {}).get("ip"),
            destination_ip=source.get("destination", {}).get("ip"),
            source_port=source.get("source", {}).get("port"),
            destination_port=source.get("destination", {}).get("port"),
            user=source.get("user", {}).get("name"),
            process_name=source.get("process", {}).get("name"),
            process_id=source.get("process", {}).get("pid"),
            command_line=source.get("process", {}).get("command_line"),
            file_path=source.get("file", {}).get("path"),
            file_hash=source.get("file", {}).get("hash", {}).get("sha256"),
            mitre_tactics=(
                rule.get("threat", [{}])[0].get("tactic", {}).get("name", [])
                if rule.get("threat")
                else []
            ),
            mitre_techniques=(
                [t.get("name", "") for t in rule.get("threat", [{}])[0].get("technique", [])]
                if rule.get("threat")
                else []
            ),
            data=source,
        )

    async def get_agents(self, limit: int = 100, offset: int = 0) -> SIEMAgentListResponse:
        """Get list of agents (Elastic Agent / Fleet)"""
        # Elastic Fleet API would be used here
        return SIEMAgentListResponse(
            connection_id=self.config.connection_id,
            platform=self.config.platform,
            total_agents=0,
            agents=[],
            affected_items=0,
            failed_items=0,
        )

    async def get_rules(self, limit: int = 100, offset: int = 0) -> SIEMRuleListResponse:
        """Get list of Elastic Security detection rules"""
        client = await self.get_client()

        # Elastic Security rules API
        response = await client.get(
            f"{self.base_url}/api/detection_engine/rules/_find",
            params={"per_page": limit, "page": offset // limit + 1},
            headers=self.get_auth_headers(),
        )

        if response.status_code == 404:
            return SIEMRuleListResponse(
                connection_id=self.config.connection_id,
                platform=self.config.platform,
                total_rules=0,
                rules=[],
            )

        response.raise_for_status()
        data = response.json()

        rules = []
        for item in data.get("data", []):
            rules.append(
                SIEMRuleInfo(
                    rule_id=item.get("id", ""),
                    level=item.get("risk_score", 50),
                    description=item.get("description", ""),
                    groups=item.get("tags", []),
                    mitre={
                        "tactic": [
                            t.get("tactic", {}).get("name", "") for t in item.get("threat", [])
                        ],
                        "technique": [
                            tech.get("name", "")
                            for t in item.get("threat", [])
                            for tech in t.get("technique", [])
                        ],
                    },
                    status="enabled" if item.get("enabled") else "disabled",
                )
            )

        return SIEMRuleListResponse(
            connection_id=self.config.connection_id,
            platform=self.config.platform,
            total_rules=data.get("total", len(rules)),
            rules=rules,
        )

    async def get_indices(self) -> SIEMIndexListResponse:
        """Get list of indices"""
        client = await self.get_client()

        response = await client.get(
            f"{self.base_url}/_cat/indices/{self.config.index_pattern}",
            params={"format": "json", "h": "index,status,health,docs.count,store.size,pri,rep"},
            headers=self.get_auth_headers(),
        )
        response.raise_for_status()
        data = response.json()

        indices = []
        total_docs = 0
        total_size = 0

        for item in data:
            doc_count = int(item.get("docs.count", 0) or 0)
            store_size = item.get("store.size", "0b")
            size_bytes = self._parse_size_string(store_size)

            total_docs += doc_count
            total_size += size_bytes

            indices.append(
                SIEMIndexInfo(
                    index_name=item.get("index", ""),
                    status=item.get("status", "unknown"),
                    health=item.get("health", "unknown"),
                    doc_count=doc_count,
                    store_size_bytes=size_bytes,
                    store_size_human=store_size,
                    primary_shards=int(item.get("pri", 0) or 0),
                    replica_shards=int(item.get("rep", 0) or 0),
                )
            )

        return SIEMIndexListResponse(
            connection_id=self.config.connection_id,
            platform=self.config.platform,
            total_indices=len(indices),
            indices=indices,
            total_docs=total_docs,
            total_size_bytes=total_size,
            total_size_human=self._format_size(total_size),
        )

    def _parse_size_string(self, size_str: str) -> int:
        """Parse size string to bytes"""
        if not size_str:
            return 0
        size_str = size_str.lower().strip()
        multipliers = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}
        for suffix, mult in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    return int(float(size_str[: -len(suffix)]) * mult)
                except ValueError:
                    return 0
        return 0

    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human readable"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f}PB"

    async def get_dashboard_stats(self, hours: int = 24) -> SIEMDashboardStats:
        """Get dashboard statistics"""
        # Run aggregation queries
        return SIEMDashboardStats(
            connection_id=self.config.connection_id,
            platform=self.config.platform,
            time_range_hours=hours,
            generated_at=datetime.utcnow(),
            total_alerts=0,
            alerts_by_severity={},
            alerts_by_hour=[],
            top_rules=[],
            top_agents=[],
            top_source_ips=[],
            top_mitre_tactics=[],
            top_mitre_techniques=[],
            total_agents=0,
            active_agents=0,
            disconnected_agents=0,
        )


# ============================================================================
# Client Factory
# ============================================================================


def get_siem_client(config: SIEMConnectionConfig) -> BaseSIEMClient:
    """Factory function to get appropriate SIEM client"""
    clients: Dict[SIEMPlatformTypeEnum, Type[BaseSIEMClient]] = {
        SIEMPlatformTypeEnum.WAZUH: WazuhClient,
        SIEMPlatformTypeEnum.ELASTIC: ElasticClient,
        SIEMPlatformTypeEnum.OPENSEARCH: ElasticClient,
    }

    client_class = clients.get(config.platform)
    if not client_class:
        raise ValueError(f"Unsupported SIEM platform: {config.platform}")

    return client_class(config)


# ============================================================================
# API Endpoints
# ============================================================================


@router.get("/connections", response_model=SIEMConnectionConfigList)
async def list_connections(current_user: str = Depends(get_current_active_user)):
    """
    List all configured SIEM connections.

    Returns connection configurations (without sensitive credentials).
    """
    # Return sanitized configs without passwords
    sanitized = []
    for conn in _siem_connections.values():
        config_dict = conn.model_dump()
        config_dict["password"] = "***" if conn.password else None
        config_dict["api_key"] = "***" if conn.api_key else None
        config_dict["token"] = "***" if conn.token else None
        sanitized.append(SIEMConnectionConfig(**config_dict))

    return SIEMConnectionConfigList(connections=sanitized, total=len(sanitized))


@router.get("/connections/{connection_id}", response_model=SIEMConnectionConfig)
async def get_connection(connection_id: str, current_user: str = Depends(get_current_active_user)):
    """Get details of a specific SIEM connection."""
    if connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    conn = _siem_connections[connection_id]
    config_dict = conn.model_dump()
    config_dict["password"] = "***" if conn.password else None
    config_dict["api_key"] = "***" if conn.api_key else None
    config_dict["token"] = "***" if conn.token else None

    return SIEMConnectionConfig(**config_dict)


@router.post("/connections", response_model=SIEMConnectionConfig)
async def create_connection(
    config: SIEMConnectionConfig, current_user: str = Depends(get_current_active_user)
):
    """
    Create a new SIEM connection configuration.

    Supports: Wazuh, Elastic SIEM, OpenSearch, Graylog, Splunk.
    """
    connection_id = f"SIEM-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    config.connection_id = connection_id
    config.created_at = datetime.utcnow()
    config.updated_at = datetime.utcnow()
    config.created_by = current_user

    _siem_connections[connection_id] = config

    logger.info(f"Created SIEM connection: {connection_id} ({config.platform.value})")

    # Return sanitized config
    config_dict = config.model_dump()
    config_dict["password"] = "***" if config.password else None
    config_dict["api_key"] = "***" if config.api_key else None
    config_dict["token"] = "***" if config.token else None

    return SIEMConnectionConfig(**config_dict)


@router.put("/connections/{connection_id}", response_model=SIEMConnectionConfig)
async def update_connection(
    connection_id: str,
    config: SIEMConnectionConfig,
    current_user: str = Depends(get_current_active_user),
):
    """Update an existing SIEM connection configuration."""
    if connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    existing = _siem_connections[connection_id]
    config.connection_id = connection_id
    config.created_at = existing.created_at
    config.updated_at = datetime.utcnow()
    config.created_by = existing.created_by

    # Preserve existing credentials if not provided
    if config.password == "***":
        config.password = existing.password
    if config.api_key == "***":
        config.api_key = existing.api_key
    if config.token == "***":
        config.token = existing.token

    _siem_connections[connection_id] = config

    logger.info(f"Updated SIEM connection: {connection_id}")

    # Return sanitized config
    config_dict = config.model_dump()
    config_dict["password"] = "***" if config.password else None
    config_dict["api_key"] = "***" if config.api_key else None
    config_dict["token"] = "***" if config.token else None

    return SIEMConnectionConfig(**config_dict)


@router.delete("/connections/{connection_id}", response_model=APIResponse)
async def delete_connection(
    connection_id: str, current_user: str = Depends(get_current_active_user)
):
    """Delete a SIEM connection configuration."""
    if connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    del _siem_connections[connection_id]

    # Close any open clients
    if connection_id in _http_clients:
        await _http_clients[connection_id].aclose()
        del _http_clients[connection_id]

    logger.info(f"Deleted SIEM connection: {connection_id}")

    return APIResponse(status=StatusEnum.SUCCESS, message=f"Connection {connection_id} deleted")


@router.get("/connections/{connection_id}/status", response_model=SIEMConnectionStatus)
async def get_connection_status(
    connection_id: str, current_user: str = Depends(get_current_active_user)
):
    """
    Test connection and get current status of a SIEM platform.

    Performs connectivity test, authentication check, and retrieves basic info.
    """
    if connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    config = _siem_connections[connection_id]
    client = get_siem_client(config)

    try:
        status_result = await client.test_connection()
        _connection_status_cache[connection_id] = status_result
        return status_result
    finally:
        await client.close()


@router.get("/health", response_model=SIEMBulkHealthCheck)
async def health_check_all(current_user: str = Depends(get_current_active_user)):
    """
    Health check for all configured SIEM connections.

    Tests connectivity, authentication, and basic operations for each connection.
    """
    results = []
    healthy_count = 0

    for conn_id, config in _siem_connections.items():
        client = get_siem_client(config)
        try:
            status_result = await client.test_connection()

            health = SIEMHealthCheck(
                connection_id=conn_id,
                name=config.name,
                platform=config.platform,
                healthy=status_result.status == SIEMConnectionStatusEnum.CONNECTED,
                checks={
                    "connectivity": status_result.status != SIEMConnectionStatusEnum.ERROR,
                    "authentication": status_result.status != SIEMConnectionStatusEnum.UNAUTHORIZED,
                },
                latency_ms=status_result.latency_ms or 0,
                version=status_result.version,
                cluster_health=status_result.cluster_name,
                error_message=status_result.error_message,
                checked_at=datetime.utcnow(),
            )

            if health.healthy:
                healthy_count += 1

            results.append(health)
        except Exception as e:
            results.append(
                SIEMHealthCheck(
                    connection_id=conn_id,
                    name=config.name,
                    platform=config.platform,
                    healthy=False,
                    checks={"connectivity": False, "authentication": False},
                    latency_ms=0,
                    error_message=str(e),
                    checked_at=datetime.utcnow(),
                )
            )
        finally:
            await client.close()

    return SIEMBulkHealthCheck(
        total_connections=len(_siem_connections),
        healthy_count=healthy_count,
        unhealthy_count=len(_siem_connections) - healthy_count,
        results=results,
        checked_at=datetime.utcnow(),
    )


@router.post("/query", response_model=SIEMQueryResponse)
async def query_alerts(
    request: SIEMQueryRequest, current_user: str = Depends(get_current_active_user)
):
    """
    Query alerts from a SIEM platform.

    Supports Lucene/KQL query syntax and Elasticsearch DSL.
    Results are normalized to a common format across all SIEM platforms.
    """
    if request.connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    config = _siem_connections[request.connection_id]
    client = get_siem_client(config)

    try:
        return await client.query_alerts(request)
    finally:
        await client.close()


@router.post("/aggregate", response_model=SIEMAggregationResponse)
async def aggregate_alerts(
    request: SIEMAggregationRequest, current_user: str = Depends(get_current_active_user)
):
    """
    Run aggregation query on SIEM data.

    Supports: terms, date_histogram, histogram, stats, cardinality.
    """
    if request.connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    config = _siem_connections[request.connection_id]
    client = get_siem_client(config)

    try:
        # Build aggregation query
        http_client = await client.get_client()
        time_to = request.time_to or datetime.utcnow()

        agg_body = {request.aggregation_type: {"field": request.field, "size": request.size}}

        if request.aggregation_type == "date_histogram":
            agg_body["date_histogram"] = {
                "field": request.field,
                "fixed_interval": request.interval or "1h",
                "min_doc_count": request.min_doc_count,
            }
            del agg_body["date_histogram"]["size"]

        query_body = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                request.time_field: {
                                    "gte": request.time_from.isoformat(),
                                    "lte": time_to.isoformat(),
                                }
                            }
                        }
                    ]
                }
            },
            "size": 0,
            "aggs": {"result": agg_body},
        }

        if request.query:
            query_body["query"]["bool"]["must"].append({"query_string": {"query": request.query}})

        start_time = time.time()
        response = await http_client.post(
            f"{client.base_url}/{config.index_pattern}/_search",
            json=query_body,
            headers=client.get_auth_headers(),
        )
        response.raise_for_status()
        data = response.json()
        query_time = int((time.time() - start_time) * 1000)

        # Parse buckets
        agg_result = data.get("aggregations", {}).get("result", {})
        buckets = [
            SIEMAggregationBucket(
                key=b.get("key"),
                key_as_string=b.get("key_as_string"),
                doc_count=b.get("doc_count", 0),
            )
            for b in agg_result.get("buckets", [])
        ]

        return SIEMAggregationResponse(
            connection_id=request.connection_id,
            platform=config.platform,
            query_time_ms=query_time,
            aggregation_type=request.aggregation_type,
            field=request.field,
            total_docs=data.get("hits", {}).get("total", {}).get("value", 0),
            buckets=buckets,
        )
    finally:
        await client.close()


@router.get("/connections/{connection_id}/agents", response_model=SIEMAgentListResponse)
async def list_agents(
    connection_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: str = Depends(get_current_active_user),
):
    """
    List agents/hosts from a SIEM platform.

    For Wazuh: Returns Wazuh agents.
    For Elastic: Returns Fleet agents.
    """
    if connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    config = _siem_connections[connection_id]
    client = get_siem_client(config)

    try:
        return await client.get_agents(limit=limit, offset=offset)
    finally:
        await client.close()


@router.get("/connections/{connection_id}/rules", response_model=SIEMRuleListResponse)
async def list_rules(
    connection_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: str = Depends(get_current_active_user),
):
    """
    List detection rules from a SIEM platform.

    Returns normalized rule information including MITRE ATT&CK mappings.
    """
    if connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    config = _siem_connections[connection_id]
    client = get_siem_client(config)

    try:
        return await client.get_rules(limit=limit, offset=offset)
    finally:
        await client.close()


@router.get("/connections/{connection_id}/indices", response_model=SIEMIndexListResponse)
async def list_indices(connection_id: str, current_user: str = Depends(get_current_active_user)):
    """
    List indices for a SIEM connection.

    Shows index health, document counts, and storage usage.
    """
    if connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    config = _siem_connections[connection_id]
    client = get_siem_client(config)

    try:
        return await client.get_indices()
    finally:
        await client.close()


@router.get("/connections/{connection_id}/dashboard", response_model=SIEMDashboardStats)
async def get_dashboard_stats(
    connection_id: str,
    hours: int = Query(24, ge=1, le=720, description="Time range in hours"),
    current_user: str = Depends(get_current_active_user),
):
    """
    Get dashboard statistics from a SIEM platform.

    Includes: alert counts, top rules, top agents, MITRE tactics, etc.
    """
    if connection_id not in _siem_connections:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    config = _siem_connections[connection_id]
    client = get_siem_client(config)

    try:
        return await client.get_dashboard_stats(hours=hours)
    finally:
        await client.close()


@router.get("/platforms", response_model=List[Dict[str, Any]])
async def list_supported_platforms(current_user: str = Depends(get_current_active_user)):
    """
    List supported SIEM platforms and their default configurations.

    Provides guidance for setting up new connections.
    """
    return [
        {
            "platform": SIEMPlatformTypeEnum.WAZUH.value,
            "name": "Wazuh",
            "description": "Open-source SIEM and XDR platform based on OSSEC",
            "default_port": 55000,
            "default_index_pattern": "wazuh-alerts-*",
            "auth_types": ["basic", "token"],
            "features": ["agents", "rules", "compliance", "file_integrity", "vulnerability"],
        },
        {
            "platform": SIEMPlatformTypeEnum.ELASTIC.value,
            "name": "Elastic SIEM / Security",
            "description": "Elastic Security for threat detection and response",
            "default_port": 9200,
            "default_index_pattern": ".siem-signals-*",
            "auth_types": ["basic", "api_key"],
            "features": ["rules", "timeline", "cases", "network", "endpoint"],
        },
        {
            "platform": SIEMPlatformTypeEnum.OPENSEARCH.value,
            "name": "OpenSearch Security Analytics",
            "description": "Open-source search and analytics with security features",
            "default_port": 9200,
            "default_index_pattern": "security-*",
            "auth_types": ["basic", "api_key"],
            "features": ["detectors", "findings", "rules", "alerts"],
        },
        {
            "platform": SIEMPlatformTypeEnum.GRAYLOG.value,
            "name": "Graylog",
            "description": "Log management and SIEM platform",
            "default_port": 9000,
            "default_index_pattern": "graylog_*",
            "auth_types": ["basic", "token"],
            "features": ["streams", "alerts", "dashboards", "extractors"],
        },
        {
            "platform": SIEMPlatformTypeEnum.SPLUNK.value,
            "name": "Splunk",
            "description": "Enterprise security information and event management",
            "default_port": 8089,
            "default_index_pattern": "main",
            "auth_types": ["basic", "token"],
            "features": ["search", "alerts", "dashboards", "reports"],
        },
    ]
