"""
Threat Hunting Service

Provides query loading, caching, and execution against SIEM platforms.
Supports KQL, SPL, EQL, and Wazuh query formats.

Author: Defensive Toolkit
Date: 2025-12-28
"""

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class QueryLanguage(str, Enum):
    """Supported query languages"""

    KQL = "kql"
    SPL = "spl"
    EQL = "eql"
    WAZUH = "wazuh"
    LUCENE = "lucene"


@dataclass
class ThreatHuntingQuery:
    """Parsed threat hunting query"""

    query_id: str
    name: str
    description: str
    language: QueryLanguage
    query_text: str
    mitre_techniques: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    file_path: Optional[str] = None
    category: Optional[str] = None


@dataclass
class QueryExecutionResult:
    """Result from executing a threat hunting query"""

    query_id: str
    query_name: str
    platform: str
    success: bool
    results_count: int
    results: List[Dict[str, Any]]
    execution_time_ms: int
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


class ThreatHuntingService:
    """Service for loading and executing threat hunting queries"""

    def __init__(self, queries_base_path: Optional[Path] = None):
        """
        Initialize the threat hunting service.

        Args:
            queries_base_path: Base path for query files. If None, uses default.
        """
        if queries_base_path is None:
            # Default path relative to this file
            self.queries_base_path = (
                Path(__file__).parent.parent.parent
                / "threat_hunting"
                / "queries"
            )
        else:
            self.queries_base_path = queries_base_path

        self._query_cache: Dict[str, ThreatHuntingQuery] = {}
        self._last_load_time: Optional[datetime] = None

    def _parse_query_file(self, file_path: Path) -> List[ThreatHuntingQuery]:
        """
        Parse a query file and extract individual queries.

        Args:
            file_path: Path to the query file

        Returns:
            List of parsed queries
        """
        queries = []
        content = file_path.read_text(encoding="utf-8")

        # Determine language from file extension
        ext = file_path.suffix.lower()
        language_map = {
            ".kql": QueryLanguage.KQL,
            ".spl": QueryLanguage.SPL,
            ".eql": QueryLanguage.EQL,
            ".wazuh": QueryLanguage.WAZUH,
            ".lucene": QueryLanguage.LUCENE,
        }
        language = language_map.get(ext, QueryLanguage.LUCENE)

        # Extract category from path
        category = file_path.parent.name

        # Parse individual queries based on language
        if language == QueryLanguage.KQL:
            queries.extend(self._parse_kql_file(content, file_path, category))
        elif language == QueryLanguage.SPL:
            queries.extend(self._parse_spl_file(content, file_path, category))
        elif language == QueryLanguage.EQL:
            queries.extend(self._parse_eql_file(content, file_path, category))
        else:
            # Generic parsing
            queries.extend(self._parse_generic_file(content, file_path, category, language))

        return queries

    def _parse_kql_file(
        self, content: str, file_path: Path, category: str
    ) -> List[ThreatHuntingQuery]:
        """Parse KQL query file"""
        queries = []
        # Pattern: // Query N: Title
        query_blocks = re.split(r"(?=// Query \d+:)", content)

        for block in query_blocks:
            if not block.strip() or not block.startswith("// Query"):
                continue

            # Extract query number and title
            header_match = re.match(r"// Query (\d+):\s*(.+)", block)
            if not header_match:
                continue

            query_num = header_match.group(1)
            title = header_match.group(2).strip()

            # Extract MITRE technique
            mitre_match = re.search(r"// MITRE:\s*(.+)", block)
            mitre = mitre_match.group(1).strip() if mitre_match else ""
            mitre_techniques = [t.strip() for t in mitre.split(",") if t.strip()]

            # Extract description
            desc_match = re.search(r"// Description:\s*(.+)", block)
            description = desc_match.group(1).strip() if desc_match else title

            # Extract query text (lines not starting with //)
            lines = block.split("\n")
            query_lines = []
            in_query = False
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith("//"):
                    in_query = True
                    query_lines.append(line)
                elif in_query and stripped.startswith("//"):
                    break

            query_text = "\n".join(query_lines).strip()
            if not query_text:
                continue

            query_id = f"{file_path.stem}_kql_{query_num}"
            queries.append(
                ThreatHuntingQuery(
                    query_id=query_id,
                    name=title,
                    description=description,
                    language=QueryLanguage.KQL,
                    query_text=query_text,
                    mitre_techniques=mitre_techniques,
                    file_path=str(file_path),
                    category=category,
                )
            )

        return queries

    def _parse_spl_file(
        self, content: str, file_path: Path, category: str
    ) -> List[ThreatHuntingQuery]:
        """Parse SPL query file"""
        queries = []
        # Pattern: # Query N: Title
        query_blocks = re.split(r"(?=# Query \d+:)", content)

        for block in query_blocks:
            if not block.strip() or not block.startswith("# Query"):
                continue

            # Extract query number and title
            header_match = re.match(r"# Query (\d+):\s*(.+)", block)
            if not header_match:
                continue

            query_num = header_match.group(1)
            title = header_match.group(2).strip()

            # Extract MITRE technique
            mitre_match = re.search(r"# MITRE:\s*(.+)", block)
            mitre = mitre_match.group(1).strip() if mitre_match else ""
            mitre_techniques = [t.strip() for t in mitre.split(",") if t.strip()]

            # Extract description
            desc_match = re.search(r"# Description:\s*(.+)", block)
            description = desc_match.group(1).strip() if desc_match else title

            # Extract query text (lines not starting with #)
            lines = block.split("\n")
            query_lines = []
            in_query = False
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    in_query = True
                    query_lines.append(line)
                elif in_query and stripped.startswith("# ---"):
                    break

            query_text = "\n".join(query_lines).strip()
            if not query_text:
                continue

            query_id = f"{file_path.stem}_spl_{query_num}"
            queries.append(
                ThreatHuntingQuery(
                    query_id=query_id,
                    name=title,
                    description=description,
                    language=QueryLanguage.SPL,
                    query_text=query_text,
                    mitre_techniques=mitre_techniques,
                    file_path=str(file_path),
                    category=category,
                )
            )

        return queries

    def _parse_eql_file(
        self, content: str, file_path: Path, category: str
    ) -> List[ThreatHuntingQuery]:
        """Parse EQL query file"""
        queries = []
        # Pattern: // Query N: Title
        query_blocks = re.split(r"(?=// Query \d+:)", content)

        for block in query_blocks:
            if not block.strip() or not block.startswith("// Query"):
                continue

            # Extract query number and title
            header_match = re.match(r"// Query (\d+):\s*(.+)", block)
            if not header_match:
                continue

            query_num = header_match.group(1)
            title = header_match.group(2).strip()

            # Extract MITRE technique
            mitre_match = re.search(r"// MITRE:\s*(.+)", block)
            mitre = mitre_match.group(1).strip() if mitre_match else ""
            mitre_techniques = [t.strip() for t in mitre.split(",") if t.strip()]

            # Extract description
            desc_match = re.search(r"// Description:\s*(.+)", block)
            description = desc_match.group(1).strip() if desc_match else title

            # Extract query text (lines not starting with //)
            lines = block.split("\n")
            query_lines = []
            in_query = False
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith("//"):
                    in_query = True
                    query_lines.append(line)
                elif in_query and stripped.startswith("// ---"):
                    break

            query_text = "\n".join(query_lines).strip()
            if not query_text:
                continue

            query_id = f"{file_path.stem}_eql_{query_num}"
            queries.append(
                ThreatHuntingQuery(
                    query_id=query_id,
                    name=title,
                    description=description,
                    language=QueryLanguage.EQL,
                    query_text=query_text,
                    mitre_techniques=mitre_techniques,
                    file_path=str(file_path),
                    category=category,
                )
            )

        return queries

    def _parse_generic_file(
        self, content: str, file_path: Path, category: str, language: QueryLanguage
    ) -> List[ThreatHuntingQuery]:
        """Parse a generic query file"""
        # For now, treat entire file as one query
        query_id = file_path.stem
        return [
            ThreatHuntingQuery(
                query_id=query_id,
                name=file_path.stem.replace("_", " ").title(),
                description=f"Query from {file_path.name}",
                language=language,
                query_text=content.strip(),
                file_path=str(file_path),
                category=category,
            )
        ]

    def load_queries(self, force_reload: bool = False) -> int:
        """
        Load all queries from the queries directory.

        Args:
            force_reload: If True, reload even if already loaded

        Returns:
            Number of queries loaded
        """
        if not force_reload and self._query_cache:
            return len(self._query_cache)

        self._query_cache.clear()

        if not self.queries_base_path.exists():
            logger.warning(f"Queries directory not found: {self.queries_base_path}")
            return 0

        # Scan all query files
        extensions = [".kql", ".spl", ".eql", ".wazuh", ".lucene"]
        for ext in extensions:
            for query_file in self.queries_base_path.rglob(f"*{ext}"):
                try:
                    queries = self._parse_query_file(query_file)
                    for query in queries:
                        self._query_cache[query.query_id] = query
                    logger.debug(f"Loaded {len(queries)} queries from {query_file}")
                except Exception as e:
                    logger.error(f"Error parsing {query_file}: {e}")

        self._last_load_time = datetime.utcnow()
        logger.info(f"Loaded {len(self._query_cache)} total threat hunting queries")
        return len(self._query_cache)

    def get_query(self, query_id: str) -> Optional[ThreatHuntingQuery]:
        """Get a specific query by ID"""
        if not self._query_cache:
            self.load_queries()
        return self._query_cache.get(query_id)

    def list_queries(
        self,
        language: Optional[QueryLanguage] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[ThreatHuntingQuery]:
        """
        List available queries with optional filtering.

        Args:
            language: Filter by query language
            category: Filter by category (kql, spl, eql, etc.)
            search: Search in name/description

        Returns:
            List of matching queries
        """
        if not self._query_cache:
            self.load_queries()

        queries = list(self._query_cache.values())

        if language:
            queries = [q for q in queries if q.language == language]

        if category:
            queries = [q for q in queries if q.category == category]

        if search:
            search_lower = search.lower()
            queries = [
                q for q in queries
                if search_lower in q.name.lower() or search_lower in q.description.lower()
            ]

        return queries

    def get_query_summary(self) -> Dict[str, Any]:
        """Get summary of loaded queries"""
        if not self._query_cache:
            self.load_queries()

        # Count by language
        by_language: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        mitre_techniques: set = set()

        for query in self._query_cache.values():
            lang = query.language.value
            by_language[lang] = by_language.get(lang, 0) + 1

            if query.category:
                by_category[query.category] = by_category.get(query.category, 0) + 1

            mitre_techniques.update(query.mitre_techniques)

        return {
            "total_queries": len(self._query_cache),
            "by_language": by_language,
            "by_category": by_category,
            "mitre_techniques_count": len(mitre_techniques),
            "last_load_time": self._last_load_time.isoformat() if self._last_load_time else None,
        }

    async def execute_query(
        self,
        query_id: str,
        siem_client: Any,
        time_range: str = "24h",
        max_results: int = 100,
    ) -> QueryExecutionResult:
        """
        Execute a threat hunting query against a SIEM platform.

        Args:
            query_id: ID of the query to execute
            siem_client: SIEM client to use for execution
            time_range: Time range for the query
            max_results: Maximum results to return

        Returns:
            QueryExecutionResult with results or error
        """
        query = self.get_query(query_id)
        if not query:
            return QueryExecutionResult(
                query_id=query_id,
                query_name="Unknown",
                platform="unknown",
                success=False,
                results_count=0,
                results=[],
                execution_time_ms=0,
                error_message=f"Query not found: {query_id}",
            )

        start_time = time.time()

        try:
            # Execute based on query language
            if query.language == QueryLanguage.EQL:
                results = await self._execute_eql_query(
                    siem_client, query.query_text, time_range, max_results
                )
            elif query.language == QueryLanguage.KQL:
                results = await self._execute_kql_query(
                    siem_client, query.query_text, time_range, max_results
                )
            elif query.language == QueryLanguage.SPL:
                results = await self._execute_spl_query(
                    siem_client, query.query_text, time_range, max_results
                )
            else:
                # Lucene/generic
                results = await self._execute_lucene_query(
                    siem_client, query.query_text, time_range, max_results
                )

            execution_time = int((time.time() - start_time) * 1000)

            return QueryExecutionResult(
                query_id=query_id,
                query_name=query.name,
                platform=getattr(siem_client, "platform", "unknown"),
                success=True,
                results_count=len(results),
                results=results,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(f"Error executing query {query_id}: {e}")
            return QueryExecutionResult(
                query_id=query_id,
                query_name=query.name,
                platform=getattr(siem_client, "platform", "unknown"),
                success=False,
                results_count=0,
                results=[],
                execution_time_ms=execution_time,
                error_message=str(e),
            )

    async def _execute_eql_query(
        self, siem_client: Any, query_text: str, time_range: str, max_results: int
    ) -> List[Dict[str, Any]]:
        """Execute an EQL query against Elastic"""
        # Use the SIEM client's EQL endpoint
        if hasattr(siem_client, "execute_eql"):
            response = await siem_client.execute_eql(query_text, time_range, max_results)
            return response.get("hits", {}).get("events", [])
        raise NotImplementedError("SIEM client does not support EQL")

    async def _execute_kql_query(
        self, siem_client: Any, query_text: str, time_range: str, max_results: int
    ) -> List[Dict[str, Any]]:
        """Execute a KQL query"""
        # KQL is typically Azure Sentinel - would need Azure client
        # For Elastic, convert to Lucene
        if hasattr(siem_client, "execute_kql"):
            response = await siem_client.execute_kql(query_text, time_range, max_results)
            return response.get("results", [])
        raise NotImplementedError("SIEM client does not support KQL")

    async def _execute_spl_query(
        self, siem_client: Any, query_text: str, time_range: str, max_results: int
    ) -> List[Dict[str, Any]]:
        """Execute an SPL query against Splunk"""
        if hasattr(siem_client, "execute_spl"):
            response = await siem_client.execute_spl(query_text, time_range, max_results)
            return response.get("results", [])
        raise NotImplementedError("SIEM client does not support SPL")

    async def _execute_lucene_query(
        self, siem_client: Any, query_text: str, time_range: str, max_results: int
    ) -> List[Dict[str, Any]]:
        """Execute a Lucene query"""
        if hasattr(siem_client, "search"):
            response = await siem_client.search(query_text, size=max_results)
            return response.get("hits", {}).get("hits", [])
        raise NotImplementedError("SIEM client does not support search")


# Global service instance
_threat_hunting_service: Optional[ThreatHuntingService] = None


def get_threat_hunting_service() -> ThreatHuntingService:
    """Get or create the threat hunting service singleton"""
    global _threat_hunting_service
    if _threat_hunting_service is None:
        _threat_hunting_service = ThreatHuntingService()
    return _threat_hunting_service
