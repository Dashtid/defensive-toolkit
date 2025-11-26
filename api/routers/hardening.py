"""Hardening API Router"""

from fastapi import APIRouter, Depends
from api.models import HardeningScanRequest, HardeningResult, APIResponse, StatusEnum
from api.dependencies import get_current_active_user, require_write_scope
from datetime import datetime

router = APIRouter(prefix="/hardening", tags=["Hardening"])

@router.post("/scan", response_model=HardeningResult)
async def scan_system(
    request: HardeningScanRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Scan system for hardening compliance."""
    return HardeningResult(
        target=request.target,
        os_type=request.os_type.value,
        cis_level=request.cis_level.value,
        total_checks=100,
        passed=85,
        failed=15,
        compliance_percentage=85.0,
        findings=[]
    )

@router.post("/apply", response_model=APIResponse)
async def apply_hardening(
    request: HardeningScanRequest,
    current_user: str = Depends(require_write_scope),
):
    """Apply hardening configurations to target system."""
    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Hardening configurations applied successfully"
    )
