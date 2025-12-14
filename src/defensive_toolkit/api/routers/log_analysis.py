"""Log Analysis API Router"""

import uuid

from defensive_toolkit.api.dependencies import get_current_active_user
from defensive_toolkit.api.models import LogAnalysisRequest, LogAnalysisResult
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/log-analysis", tags=["Log Analysis"])


@router.post("/analyze", response_model=LogAnalysisResult)
async def analyze_logs(
    request: LogAnalysisRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Analyze logs for anomalies and patterns."""
    return LogAnalysisResult(
        analysis_id=str(uuid.uuid4()),
        log_source=request.log_source.value,
        analysis_type=request.analysis_type,
        entries_processed=0,
        anomalies_detected=0,
        parsed_entries=[],
        anomalies=[],
    )


@router.get("/sources", response_model=list)
async def list_log_sources(current_user: str = Depends(get_current_active_user)):
    """List supported log sources."""
    return ["syslog", "windows_event", "apache", "nginx", "firewall", "ids_ips", "application"]
