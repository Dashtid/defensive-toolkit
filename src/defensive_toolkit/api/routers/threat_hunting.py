"""Threat Hunting API Router"""


from api.dependencies import get_current_active_user
from api.models import ThreatHuntQuery, ThreatHuntResult
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])

@router.post("/query", response_model=ThreatHuntResult)
async def execute_hunt_query(
    query: ThreatHuntQuery,
    current_user: str = Depends(get_current_active_user),
):
    """Execute a threat hunting query on SIEM platform."""
    return ThreatHuntResult(
        query_name=query.name,
        platform=query.platform.value,
        results_count=0,
        results=[],
        execution_time_ms=150
    )

@router.get("/queries", response_model=list)
async def list_queries(current_user: str = Depends(get_current_active_user)):
    """List available threat hunting queries."""
    return [
        {"name": "Suspicious PowerShell", "platform": "sentinel"},
        {"name": "Lateral Movement Detection", "platform": "elastic"}
    ]
