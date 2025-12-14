"""Forensics API Router"""

from fastapi import APIRouter, Depends
from api.models import ForensicsAnalysisRequest, ForensicsAnalysisResult, APIResponse, StatusEnum
from api.dependencies import get_current_active_user
from datetime import datetime
import uuid

router = APIRouter(prefix="/forensics", tags=["Forensics"])

@router.post("/analyze", response_model=ForensicsAnalysisResult)
async def analyze_artifact(
    request: ForensicsAnalysisRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Perform forensics analysis on artifact."""
    return ForensicsAnalysisResult(
        analysis_id=str(uuid.uuid4()),
        artifact_type=request.artifact_type.value,
        artifact_path=request.artifact_path,
        findings=[],
        timeline=[],
        chain_of_custody=[]
    )

@router.get("/artifacts/types", response_model=list)
async def list_artifact_types(current_user: str = Depends(get_current_active_user)):
    """List supported artifact types."""
    return ["memory", "disk", "network", "registry", "file_system", "browser", "event_log"]
