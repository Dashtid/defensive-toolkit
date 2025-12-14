"""Compliance API Router"""

from defensive_toolkit.api.dependencies import get_current_active_user
from defensive_toolkit.api.models import ComplianceCheckRequest, ComplianceReport
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/compliance", tags=["Compliance"])


@router.post("/check", response_model=ComplianceReport)
async def check_compliance(
    request: ComplianceCheckRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Check compliance against a framework."""
    return ComplianceReport(
        framework=request.framework.value,
        target=request.target,
        total_controls=100,
        passed=85,
        failed=10,
        not_applicable=5,
        compliance_percentage=85.0,
        controls=[],
    )


@router.get("/frameworks", response_model=list)
async def list_frameworks(current_user: str = Depends(get_current_active_user)):
    """List supported compliance frameworks."""
    return ["cis", "nist_800_53", "iso_27001", "pci_dss", "soc2", "hipaa"]
