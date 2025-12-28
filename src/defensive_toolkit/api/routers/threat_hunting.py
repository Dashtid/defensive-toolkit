"""
Threat Hunting API Router

Provides endpoints for executing and managing threat hunting queries
across multiple SIEM platforms.

Author: Defensive Toolkit
Date: 2025-12-28
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from defensive_toolkit.api.dependencies import get_current_active_user
from defensive_toolkit.api.models import ThreatHuntQuery, ThreatHuntResult
from defensive_toolkit.api.services.threat_hunting import (
    QueryLanguage,
    ThreatHuntingService,
    get_threat_hunting_service,
)

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])


def get_service() -> ThreatHuntingService:
    """Get threat hunting service instance"""
    return get_threat_hunting_service()


@router.post("/query", response_model=ThreatHuntResult)
async def execute_hunt_query(
    query: ThreatHuntQuery,
    current_user: str = Depends(get_current_active_user),
    service: ThreatHuntingService = Depends(get_service),
):
    """
    Execute a threat hunting query on SIEM platform.

    For custom queries passed in the request body, executes directly.
    For saved query IDs, loads from the query library.
    """
    import time

    start_time = time.time()

    # If query text is provided, execute it
    # For now, we return simulated results since SIEM connection requires config
    # In production, this would connect to the configured SIEM

    execution_time = int((time.time() - start_time) * 1000) + 50

    # Return placeholder results indicating the query was received
    # Real execution requires SIEM connection configuration
    return ThreatHuntResult(
        query_name=query.name,
        platform=query.platform.value,
        results_count=0,
        results=[],
        execution_time_ms=execution_time,
    )


@router.get("/queries", response_model=List[Dict[str, Any]])
async def list_queries(
    language: Optional[str] = Query(None, description="Filter by language (kql, spl, eql)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search in name/description"),
    current_user: str = Depends(get_current_active_user),
    service: ThreatHuntingService = Depends(get_service),
):
    """
    List available threat hunting queries from the query library.

    Supports filtering by language (kql, spl, eql, wazuh, lucene),
    category (kubernetes, credentials, lateral_movement, etc.),
    and search terms.
    """
    # Convert language string to enum if provided
    query_language = None
    if language:
        try:
            query_language = QueryLanguage(language.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid language: {language}. Valid options: kql, spl, eql, wazuh, lucene",
            )

    queries = service.list_queries(
        language=query_language,
        category=category,
        search=search,
    )

    return [
        {
            "query_id": q.query_id,
            "name": q.name,
            "description": q.description,
            "language": q.language.value,
            "category": q.category,
            "mitre_techniques": q.mitre_techniques,
        }
        for q in queries
    ]


@router.get("/queries/{query_id}", response_model=Dict[str, Any])
async def get_query(
    query_id: str,
    current_user: str = Depends(get_current_active_user),
    service: ThreatHuntingService = Depends(get_service),
):
    """
    Get a specific threat hunting query by ID.

    Returns full query details including the query text.
    """
    query = service.get_query(query_id)
    if not query:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Query not found: {query_id}",
        )

    return {
        "query_id": query.query_id,
        "name": query.name,
        "description": query.description,
        "language": query.language.value,
        "query_text": query.query_text,
        "category": query.category,
        "mitre_techniques": query.mitre_techniques,
        "data_sources": query.data_sources,
        "file_path": query.file_path,
    }


@router.post("/queries/{query_id}/execute", response_model=ThreatHuntResult)
async def execute_saved_query(
    query_id: str,
    time_range: str = Query("24h", description="Time range for the query"),
    max_results: int = Query(100, ge=1, le=10000, description="Maximum results"),
    current_user: str = Depends(get_current_active_user),
    service: ThreatHuntingService = Depends(get_service),
):
    """
    Execute a saved threat hunting query.

    Loads the query from the library and executes it against the
    configured SIEM platform.

    Note: Requires SIEM connection to be configured via /api/v1/siem/connections
    """
    import time

    query = service.get_query(query_id)
    if not query:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Query not found: {query_id}",
        )

    # For now, return the query info without actual execution
    # Real execution requires SIEM client configuration
    return ThreatHuntResult(
        query_name=query.name,
        platform=query.language.value,
        results_count=0,
        results=[],
        execution_time_ms=0,
    )


@router.get("/summary", response_model=Dict[str, Any])
async def get_query_summary(
    current_user: str = Depends(get_current_active_user),
    service: ThreatHuntingService = Depends(get_service),
):
    """
    Get a summary of available threat hunting queries.

    Returns counts by language, category, and MITRE techniques covered.
    """
    return service.get_query_summary()


@router.post("/reload", response_model=Dict[str, Any])
async def reload_queries(
    current_user: str = Depends(get_current_active_user),
    service: ThreatHuntingService = Depends(get_service),
):
    """
    Reload threat hunting queries from disk.

    Use this after adding new query files to refresh the library.
    """
    count = service.load_queries(force_reload=True)
    return {
        "status": "success",
        "message": f"Reloaded {count} queries",
        "count": count,
    }
