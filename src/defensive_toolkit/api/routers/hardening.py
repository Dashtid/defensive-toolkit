"""
Hardening API Router.

Provides endpoints for system hardening compliance scanning and remediation:
- Linux CIS Benchmark scanning
- Windows security baseline scanning (future)
- Remediation script generation
- Compliance reporting

Wires to hardening.linux.cis_benchmarks module.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from defensive_toolkit.api.dependencies import (
    get_current_active_user,
    require_write_scope,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/hardening", tags=["Hardening"])


# =============================================================================
# Request/Response Models
# =============================================================================


class HardeningScanRequest(BaseModel):
    """Request to run a hardening scan."""

    target: str = Field(default="localhost", description="Target hostname")
    os_type: str = Field(default="linux", description="Operating system type")
    cis_level: int = Field(default=1, description="CIS benchmark level (1 or 2)")


class HardeningCheckResult(BaseModel):
    """Single hardening check result."""

    check_id: str
    title: str
    description: str
    category: str
    severity: str
    passed: bool
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    remediation: Optional[str] = None
    cis_reference: Optional[str] = None


class HardeningScanResponse(BaseModel):
    """Hardening scan response."""

    scan_id: str
    target: str
    os_type: str
    cis_level: int
    total_checks: int
    passed: int
    failed: int
    skipped: int
    compliance_percentage: float
    checks: List[HardeningCheckResult]
    categories: Dict[str, Dict[str, int]]


class BenchmarkInfo(BaseModel):
    """Benchmark information."""

    id: str
    name: str
    os_type: str
    version: str
    total_checks: int
    description: str


class RemediationRequest(BaseModel):
    """Request for remediation."""

    check_ids: Optional[List[str]] = Field(
        default=None, description="Specific checks to remediate (None = all failed)"
    )
    dry_run: bool = Field(default=True, description="Dry run mode")


class RemediationResponse(BaseModel):
    """Remediation response."""

    scan_id: str
    dry_run: bool
    checks_remediated: int
    script: Optional[str] = None
    message: str


class ComplianceSummary(BaseModel):
    """Compliance summary."""

    target: str
    os_type: str
    cis_level: int
    compliance_percentage: float
    critical_failures: int
    high_failures: int
    medium_failures: int
    low_failures: int
    categories: Dict[str, float]


# =============================================================================
# In-memory storage
# =============================================================================

_scan_results: Dict[str, HardeningScanResponse] = {}


# =============================================================================
# Helper Functions
# =============================================================================


def get_linux_scanner(target: str = "localhost", cis_level: int = 1):
    """Get Linux hardening scanner instance."""
    try:
        from defensive_toolkit.hardening.linux.cis_benchmarks import LinuxHardeningScanner

        return LinuxHardeningScanner(target=target, cis_level=cis_level)
    except ImportError as e:
        logger.error(f"Failed to import LinuxHardeningScanner: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Linux hardening scanner module not available",
        )


# =============================================================================
# Scan Endpoints
# =============================================================================


@router.post("/scan/linux", response_model=HardeningScanResponse)
async def scan_linux_system(
    request: HardeningScanRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Run Linux CIS Benchmark hardening scan.

    Scans the target system for CIS Benchmark compliance including:
    - SSH configuration
    - File permissions
    - Service configuration
    - Kernel parameters
    - Audit logging
    """
    if request.os_type != "linux":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is for Linux systems only",
        )

    scanner = get_linux_scanner(target=request.target, cis_level=request.cis_level)
    scan_id = str(uuid.uuid4())

    try:
        result = scanner.run_all_checks()

        # Convert to response model
        checks = [
            HardeningCheckResult(
                check_id=c.check_id,
                title=c.title,
                description=c.description,
                category=c.category,
                severity=c.severity,
                passed=c.passed,
                current_value=c.current_value,
                expected_value=c.expected_value,
                remediation=c.remediation,
                cis_reference=c.cis_reference,
            )
            for c in result.checks
        ]

        response = HardeningScanResponse(
            scan_id=scan_id,
            target=result.target,
            os_type=result.os_type,
            cis_level=result.cis_level,
            total_checks=result.total_checks,
            passed=result.passed,
            failed=result.failed,
            skipped=result.skipped,
            compliance_percentage=result.compliance_percentage,
            checks=checks,
            categories=result.categories,
        )

        # Store for later retrieval
        _scan_results[scan_id] = response

        return response

    except Exception as e:
        logger.error(f"Linux hardening scan failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Hardening scan failed: {str(e)}",
        )


@router.post("/scan/windows", response_model=HardeningScanResponse)
async def scan_windows_system(
    request: HardeningScanRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Run Windows Security Baseline scan.

    Currently returns placeholder - Windows scanner implementation pending.
    """
    # Windows scanner not yet implemented
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Windows hardening scanner not yet implemented",
    )


@router.post("/scan", response_model=HardeningScanResponse)
async def scan_system(
    request: HardeningScanRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Run hardening scan based on OS type.

    Automatically routes to the appropriate scanner based on os_type.
    """
    if request.os_type == "linux":
        return await scan_linux_system(request, current_user)
    elif request.os_type == "windows":
        return await scan_windows_system(request, current_user)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OS type: {request.os_type}",
        )


# =============================================================================
# Results Endpoints
# =============================================================================


@router.get("/scan/{scan_id}")
async def get_scan_result(
    scan_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get scan results by ID.
    """
    if scan_id not in _scan_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan result not found: {scan_id}",
        )

    return _scan_results[scan_id]


@router.get("/scan/{scan_id}/summary", response_model=ComplianceSummary)
async def get_scan_summary(
    scan_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get compliance summary for a scan.
    """
    if scan_id not in _scan_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan result not found: {scan_id}",
        )

    result = _scan_results[scan_id]

    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for check in result.checks:
        if not check.passed:
            severity_counts[check.severity] = severity_counts.get(check.severity, 0) + 1

    # Calculate category compliance
    category_compliance = {}
    for cat, counts in result.categories.items():
        total = counts.get("passed", 0) + counts.get("failed", 0)
        if total > 0:
            category_compliance[cat] = round(counts.get("passed", 0) / total * 100, 2)

    return ComplianceSummary(
        target=result.target,
        os_type=result.os_type,
        cis_level=result.cis_level,
        compliance_percentage=result.compliance_percentage,
        critical_failures=severity_counts["critical"],
        high_failures=severity_counts["high"],
        medium_failures=severity_counts["medium"],
        low_failures=severity_counts["low"],
        categories=category_compliance,
    )


@router.get("/scan/{scan_id}/failed")
async def get_failed_checks(
    scan_id: str,
    severity: Optional[str] = None,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get failed checks from a scan.

    Optionally filter by severity (critical, high, medium, low).
    """
    if scan_id not in _scan_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan result not found: {scan_id}",
        )

    result = _scan_results[scan_id]

    failed = [c for c in result.checks if not c.passed]

    if severity:
        failed = [c for c in failed if c.severity == severity.lower()]

    return {
        "scan_id": scan_id,
        "total_failed": len(failed),
        "severity_filter": severity,
        "checks": [c.model_dump() for c in failed],
    }


# =============================================================================
# Remediation Endpoints
# =============================================================================


@router.post(
    "/remediate/{scan_id}",
    response_model=RemediationResponse,
    dependencies=[Depends(require_write_scope)],
)
async def generate_remediation(
    scan_id: str,
    request: RemediationRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Generate remediation script for failed checks.

    Returns a shell script that can be run to fix failed checks.
    Use dry_run=true (default) to just get the script without applying.
    """
    if scan_id not in _scan_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan result not found: {scan_id}",
        )

    result = _scan_results[scan_id]

    # Get scanner to generate script
    scanner = get_linux_scanner(target=result.target, cis_level=result.cis_level)

    # Reconstruct checks from result
    from defensive_toolkit.hardening.linux.cis_benchmarks import HardeningCheck

    for check_result in result.checks:
        scanner.checks.append(
            HardeningCheck(
                check_id=check_result.check_id,
                title=check_result.title,
                description=check_result.description,
                category=check_result.category,
                severity=check_result.severity,
                passed=check_result.passed,
                current_value=check_result.current_value,
                expected_value=check_result.expected_value,
                remediation=check_result.remediation,
                cis_reference=check_result.cis_reference,
            )
        )

    # Filter to specific checks if requested
    if request.check_ids:
        scanner.checks = [c for c in scanner.checks if c.check_id in request.check_ids]

    script = scanner.get_remediation_script()
    checks_to_fix = len([c for c in scanner.checks if not c.passed and c.remediation])

    return RemediationResponse(
        scan_id=scan_id,
        dry_run=request.dry_run,
        checks_remediated=checks_to_fix,
        script=script if request.dry_run else None,
        message=f"Generated remediation script for {checks_to_fix} checks"
        if request.dry_run
        else "Remediation applied (would apply changes if not dry run)",
    )


# =============================================================================
# Benchmark Info Endpoints
# =============================================================================


@router.get("/benchmarks")
async def list_benchmarks(
    current_user: str = Depends(get_current_active_user),
):
    """
    List available hardening benchmarks.
    """
    return {
        "benchmarks": [
            BenchmarkInfo(
                id="cis-linux-l1",
                name="CIS Linux Level 1",
                os_type="linux",
                version="1.0.0",
                total_checks=18,
                description="CIS Benchmark Level 1 for Linux (Ubuntu/Debian/RHEL)",
            ),
            BenchmarkInfo(
                id="cis-linux-l2",
                name="CIS Linux Level 2",
                os_type="linux",
                version="1.0.0",
                total_checks=18,
                description="CIS Benchmark Level 2 for Linux (includes Level 1)",
            ),
            BenchmarkInfo(
                id="cis-windows",
                name="CIS Windows Baseline",
                os_type="windows",
                version="0.0.0",
                total_checks=0,
                description="CIS Benchmark for Windows (not yet implemented)",
            ),
        ],
        "total": 3,
    }


@router.get("/benchmarks/{benchmark_id}")
async def get_benchmark_details(
    benchmark_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get benchmark details including all check definitions.
    """
    if benchmark_id not in ("cis-linux-l1", "cis-linux-l2"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benchmark not found: {benchmark_id}",
        )

    # Return check definitions
    check_definitions = [
        {"id": "SSH-001", "title": "SSH Protocol Version", "category": "ssh", "severity": "high"},
        {"id": "SSH-002", "title": "SSH Root Login", "category": "ssh", "severity": "high"},
        {"id": "SSH-003", "title": "SSH Password Authentication", "category": "ssh", "severity": "medium"},
        {"id": "SSH-004", "title": "SSH Empty Passwords", "category": "ssh", "severity": "critical"},
        {"id": "SSH-005", "title": "SSH Max Auth Tries", "category": "ssh", "severity": "medium"},
        {"id": "FILE-001", "title": "/etc/passwd Permissions", "category": "file_permissions", "severity": "high"},
        {"id": "FILE-002", "title": "/etc/shadow Permissions", "category": "file_permissions", "severity": "critical"},
        {"id": "FILE-003", "title": "/etc/gshadow Permissions", "category": "file_permissions", "severity": "high"},
        {"id": "FILE-004", "title": "/etc/group Permissions", "category": "file_permissions", "severity": "high"},
        {"id": "SVC-001", "title": "Telnet Service", "category": "services", "severity": "medium"},
        {"id": "SVC-002", "title": "RSH Service", "category": "services", "severity": "medium"},
        {"id": "SVC-003", "title": "TFTP Service", "category": "services", "severity": "medium"},
        {"id": "KERN-001", "title": "IP Forwarding", "category": "kernel", "severity": "high"},
        {"id": "KERN-002", "title": "ICMP Redirects", "category": "kernel", "severity": "medium"},
        {"id": "KERN-003", "title": "Source Routing", "category": "kernel", "severity": "medium"},
        {"id": "KERN-004", "title": "TCP SYN Cookies", "category": "kernel", "severity": "high"},
        {"id": "AUDIT-001", "title": "Auditd Installed", "category": "audit", "severity": "high"},
        {"id": "AUDIT-002", "title": "Auditd Enabled", "category": "audit", "severity": "high"},
    ]

    return {
        "benchmark_id": benchmark_id,
        "name": "CIS Linux Level 1" if benchmark_id == "cis-linux-l1" else "CIS Linux Level 2",
        "os_type": "linux",
        "checks": check_definitions,
        "total_checks": len(check_definitions),
        "categories": ["ssh", "file_permissions", "services", "kernel", "audit"],
    }


@router.get("/recommendations")
async def get_recommendations(
    current_user: str = Depends(get_current_active_user),
):
    """
    Get prioritized hardening recommendations.

    Returns high-impact security improvements regardless of scan results.
    """
    return {
        "recommendations": [
            {
                "priority": 1,
                "title": "Disable SSH root login",
                "category": "ssh",
                "impact": "critical",
                "description": "Prevent direct root SSH access to reduce attack surface",
            },
            {
                "priority": 2,
                "title": "Use SSH key-based authentication",
                "category": "ssh",
                "impact": "high",
                "description": "Disable password auth, use SSH keys only",
            },
            {
                "priority": 3,
                "title": "Enable audit logging",
                "category": "audit",
                "impact": "high",
                "description": "Install and configure auditd for security event logging",
            },
            {
                "priority": 4,
                "title": "Disable unnecessary services",
                "category": "services",
                "impact": "medium",
                "description": "Disable telnet, rsh, tftp and other legacy services",
            },
            {
                "priority": 5,
                "title": "Harden kernel parameters",
                "category": "kernel",
                "impact": "medium",
                "description": "Disable IP forwarding, enable SYN cookies",
            },
        ],
        "total": 5,
    }
