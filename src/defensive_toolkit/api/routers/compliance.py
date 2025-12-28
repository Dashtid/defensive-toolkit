"""
Compliance API Router

Provides endpoints for compliance checking against CIS, NIST 800-53,
and other frameworks. Includes control mapping, policy validation,
and configuration drift detection.

Author: Defensive Toolkit
Date: 2025-12-28
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from defensive_toolkit.api.dependencies import (
    get_current_active_user,
    require_write_scope,
)
from defensive_toolkit.api.models import (
    APIResponse,
    ComplianceCheckRequest,
    ComplianceControl,
    ComplianceFrameworkEnum,
    ComplianceReport,
    StatusEnum,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["Compliance"])


# ============================================================================
# Additional Request/Response Models
# ============================================================================


class CISCheckRequest(BaseModel):
    """Request for CIS compliance check"""

    controls: Optional[List[int]] = Field(
        None, description="Specific controls to check (1-18). If None, checks all."
    )
    output_format: str = Field("json", pattern="^(json|text|html)$")


class NISTCheckRequest(BaseModel):
    """Request for NIST 800-53 compliance check"""

    families: Optional[List[str]] = Field(
        None,
        description="Control families to check (AC, AU, CM, IA, SC, SI). If None, checks all.",
    )
    impact_level: str = Field(
        "moderate", pattern="^(low|moderate|high)$", description="FIPS 199 impact level"
    )
    output_format: str = Field("json", pattern="^(json|text)$")


class ControlMappingResponse(BaseModel):
    """Response for control mapping lookup"""

    control_id: str
    title: str
    mappings: Dict[str, List[str]]


class CoverageMatrixResponse(BaseModel):
    """Response for coverage matrix"""

    target_framework: str
    coverage: Dict[str, Any]
    coverage_percentage: float


class PolicyValidationRequest(BaseModel):
    """Request for policy validation"""

    policy_file: str = Field(..., description="Path to YAML policy file")


class DriftBaselineRequest(BaseModel):
    """Request to create configuration baseline"""

    config_files: List[str] = Field(
        ..., description="List of config file paths to baseline"
    )
    baseline_name: str = Field(..., min_length=1, max_length=100)


class DriftDetectionRequest(BaseModel):
    """Request to detect configuration drift"""

    baseline_file: str = Field(..., description="Path to baseline JSON file")


class DriftResult(BaseModel):
    """Result of drift detection"""

    file_path: str
    status: str  # "unchanged", "modified", "added", "removed"
    current_hash: Optional[str] = None
    baseline_hash: Optional[str] = None


class ReportGenerationRequest(BaseModel):
    """Request to generate compliance report"""

    framework: ComplianceFrameworkEnum
    output_format: str = Field("html", pattern="^(json|text|html)$")
    include_evidence: bool = True


# ============================================================================
# Helper Functions
# ============================================================================


def get_cis_checker():
    """Get CIS checker instance"""
    try:
        from defensive_toolkit.compliance.frameworks.cis_checker import CISChecker

        return CISChecker()
    except ImportError as e:
        logger.error(f"Failed to import CISChecker: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CIS Checker module not available",
        )


def get_nist_checker(impact_level: str = "moderate"):
    """Get NIST checker instance"""
    try:
        from defensive_toolkit.compliance.frameworks.nist_checker import NISTChecker

        return NISTChecker(impact_level=impact_level)
    except ImportError as e:
        logger.error(f"Failed to import NISTChecker: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NIST Checker module not available",
        )


def get_framework_mapper():
    """Get framework mapper instance"""
    try:
        from defensive_toolkit.compliance.frameworks.framework_mapper import (
            FrameworkMapper,
        )

        return FrameworkMapper()
    except ImportError as e:
        logger.error(f"Failed to import FrameworkMapper: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Framework Mapper module not available",
        )


def get_policy_checker(policy_file: str):
    """Get policy checker instance"""
    try:
        from defensive_toolkit.compliance.policy.policy_checker import PolicyChecker

        return PolicyChecker(policy_file)
    except ImportError as e:
        logger.error(f"Failed to import PolicyChecker: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Policy Checker module not available",
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy file not found: {policy_file}",
        )


def get_drift_detector(baseline_file: Optional[str] = None):
    """Get drift detector instance"""
    try:
        from defensive_toolkit.compliance.policy.config_drift import DriftDetector

        return DriftDetector(baseline_file)
    except ImportError as e:
        logger.error(f"Failed to import DriftDetector: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Drift Detector module not available",
        )


# ============================================================================
# CIS Compliance Endpoints
# ============================================================================


@router.post("/cis/run", response_model=Dict[str, Any])
async def run_cis_checks(
    request: CISCheckRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Run CIS Controls v8 compliance checks.

    Executes automated checks against CIS Controls and returns detailed results
    including pass/fail status for each safeguard.
    """
    try:
        checker = get_cis_checker()

        if request.controls:
            # Run specific controls
            results = checker.run_all_checks(controls=request.controls)
        else:
            # Run all controls
            results = checker.run_all_checks()

        return results
    except Exception as e:
        logger.error(f"CIS check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CIS compliance check failed: {str(e)}",
        )


@router.get("/cis/controls", response_model=List[Dict[str, Any]])
async def list_cis_controls(
    current_user: str = Depends(get_current_active_user),
):
    """
    List available CIS Controls v8 with descriptions.
    """
    controls = [
        {"id": 1, "title": "Inventory and Control of Enterprise Assets"},
        {"id": 2, "title": "Inventory and Control of Software Assets"},
        {"id": 3, "title": "Data Protection"},
        {"id": 4, "title": "Secure Configuration of Enterprise Assets and Software"},
        {"id": 5, "title": "Account Management"},
        {"id": 6, "title": "Access Control Management"},
        {"id": 7, "title": "Continuous Vulnerability Management"},
        {"id": 8, "title": "Audit Log Management"},
        {"id": 9, "title": "Email and Web Browser Protections"},
        {"id": 10, "title": "Malware Defenses"},
        {"id": 11, "title": "Data Recovery"},
        {"id": 12, "title": "Network Infrastructure Management"},
        {"id": 13, "title": "Network Monitoring and Defense"},
        {"id": 14, "title": "Security Awareness and Skills Training"},
        {"id": 15, "title": "Service Provider Management"},
        {"id": 16, "title": "Application Software Security"},
        {"id": 17, "title": "Incident Response Management"},
        {"id": 18, "title": "Penetration Testing"},
    ]
    return controls


# ============================================================================
# NIST 800-53 Compliance Endpoints
# ============================================================================


@router.post("/nist/run", response_model=Dict[str, Any])
async def run_nist_checks(
    request: NISTCheckRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Run NIST 800-53 Rev 5 compliance checks.

    Executes automated checks against NIST security controls based on the
    specified impact level (low, moderate, high).
    """
    try:
        checker = get_nist_checker(impact_level=request.impact_level)

        if request.families:
            # Run specific control families
            results = checker.run_all_checks(families=request.families)
        else:
            # Run all families
            results = checker.run_all_checks()

        return results
    except Exception as e:
        logger.error(f"NIST check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"NIST compliance check failed: {str(e)}",
        )


@router.get("/nist/families", response_model=List[Dict[str, str]])
async def list_nist_families(
    current_user: str = Depends(get_current_active_user),
):
    """
    List NIST 800-53 control families.
    """
    families = [
        {"id": "AC", "title": "Access Control"},
        {"id": "AU", "title": "Audit and Accountability"},
        {"id": "CM", "title": "Configuration Management"},
        {"id": "IA", "title": "Identification and Authentication"},
        {"id": "SC", "title": "System and Communications Protection"},
        {"id": "SI", "title": "System and Information Integrity"},
    ]
    return families


# ============================================================================
# Framework Mapping Endpoints
# ============================================================================


@router.get("/mapping/{control_id}", response_model=ControlMappingResponse)
async def get_control_mapping(
    control_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get cross-framework mappings for a specific control.

    Maps controls between CIS, NIST 800-53, ISO 27001, PCI-DSS, and SOC2.
    Example control_id: "CIS-1", "NIST-AC", "PCI-8"
    """
    try:
        mapper = get_framework_mapper()
        mapping = mapper.map_control(control_id.upper())

        if not mapping:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Control {control_id} not found in mapping database",
            )

        return ControlMappingResponse(
            control_id=control_id.upper(),
            title=mapping.get("title", "Unknown"),
            mappings=mapping.get("mappings", {}),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Control mapping failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Control mapping lookup failed: {str(e)}",
        )


@router.get("/mapping/overlaps", response_model=Dict[str, Any])
async def get_framework_overlaps(
    frameworks: str = Query(
        ...,
        description="Comma-separated framework names (CIS,NIST,ISO,PCI,SOC2)",
    ),
    current_user: str = Depends(get_current_active_user),
):
    """
    Find control overlaps between multiple frameworks.

    Useful for organizations pursuing multiple certifications to identify
    controls that satisfy requirements across frameworks.
    """
    try:
        mapper = get_framework_mapper()
        framework_list = [f.strip().upper() for f in frameworks.split(",")]
        overlaps = mapper.find_overlaps(framework_list)
        return {"frameworks": framework_list, "overlaps": overlaps}
    except Exception as e:
        logger.error(f"Framework overlap analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Framework overlap analysis failed: {str(e)}",
        )


@router.get("/mapping/coverage", response_model=CoverageMatrixResponse)
async def get_coverage_matrix(
    target_framework: str = Query(
        ..., description="Target framework (CIS, NIST, ISO, PCI, SOC2)"
    ),
    current_user: str = Depends(get_current_active_user),
):
    """
    Generate coverage matrix for a target framework.

    Shows which controls in the target framework are covered by
    controls from other frameworks you may already have implemented.
    """
    try:
        mapper = get_framework_mapper()
        coverage = mapper.generate_coverage_matrix(target_framework.upper())

        # Calculate coverage percentage
        total_controls = len(coverage) if coverage else 0
        covered = sum(1 for c in coverage.values() if c.get("covered", False))
        percentage = (covered / total_controls * 100) if total_controls > 0 else 0

        return CoverageMatrixResponse(
            target_framework=target_framework.upper(),
            coverage=coverage,
            coverage_percentage=round(percentage, 2),
        )
    except Exception as e:
        logger.error(f"Coverage matrix generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Coverage matrix generation failed: {str(e)}",
        )


@router.get("/mapping/recommendations", response_model=List[Dict[str, Any]])
async def get_implementation_recommendations(
    frameworks: str = Query(
        ...,
        description="Comma-separated target frameworks",
    ),
    current_user: str = Depends(get_current_active_user),
):
    """
    Get recommended control implementation order.

    Returns controls prioritized by how many frameworks they satisfy,
    helping organizations maximize compliance coverage efficiently.
    """
    try:
        mapper = get_framework_mapper()
        framework_list = [f.strip().upper() for f in frameworks.split(",")]
        recommendations = mapper.recommend_implementation_order(framework_list)
        return recommendations
    except Exception as e:
        logger.error(f"Recommendation generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Recommendation generation failed: {str(e)}",
        )


# ============================================================================
# Policy Validation Endpoints
# ============================================================================


@router.post("/policy/validate", response_model=Dict[str, Any])
async def validate_policy(
    request: PolicyValidationRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Validate system against a YAML security policy.

    The policy file defines checks including file permissions,
    service states, registry values, and command outputs.
    """
    try:
        checker = get_policy_checker(request.policy_file)
        results = checker.check_all_policies()
        report = checker.generate_report()
        return {"policy_file": request.policy_file, "results": results, "report": report}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Policy validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy validation failed: {str(e)}",
        )


# ============================================================================
# Configuration Drift Detection Endpoints
# ============================================================================


@router.post("/drift/create-baseline", response_model=APIResponse)
async def create_drift_baseline(
    request: DriftBaselineRequest,
    current_user: str = Depends(require_write_scope),
):
    """
    Create a configuration baseline for drift detection.

    Takes a snapshot of specified configuration files that will be used
    as reference for future drift detection.
    """
    try:
        detector = get_drift_detector()
        output_file = f"baselines/{request.baseline_name}.json"

        # Ensure baselines directory exists
        Path("baselines").mkdir(exist_ok=True)

        baseline = detector.create_baseline(request.config_files, output_file)

        return APIResponse(
            status=StatusEnum.SUCCESS,
            message=f"Baseline created: {output_file}",
            data={
                "baseline_file": output_file,
                "files_baselined": len(request.config_files),
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Baseline creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Baseline creation failed: {str(e)}",
        )


@router.post("/drift/detect", response_model=Dict[str, Any])
async def detect_drift(
    request: DriftDetectionRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Detect configuration drift from baseline.

    Compares current file hashes against the baseline to identify
    files that have been modified, added, or removed.
    """
    try:
        if not Path(request.baseline_file).exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Baseline file not found: {request.baseline_file}",
            )

        detector = get_drift_detector(request.baseline_file)
        drift_results = detector.detect_drift()
        report = detector.generate_report()

        return {
            "baseline_file": request.baseline_file,
            "drift_detected": any(
                r.get("status") != "unchanged" for r in drift_results
            ),
            "results": drift_results,
            "report": report,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Drift detection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Drift detection failed: {str(e)}",
        )


@router.get("/drift/diff", response_model=Dict[str, Any])
async def get_drift_diff(
    baseline_file: str = Query(..., description="Path to baseline file"),
    file_path: str = Query(..., description="Path to file to diff"),
    current_user: str = Depends(get_current_active_user),
):
    """
    Get unified diff between baseline and current file state.
    """
    try:
        if not Path(baseline_file).exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Baseline file not found: {baseline_file}",
            )

        detector = get_drift_detector(baseline_file)
        diff = detector.generate_diff(file_path)

        return {"file_path": file_path, "diff": diff}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Diff generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Diff generation failed: {str(e)}",
        )


# ============================================================================
# Reporting Endpoints
# ============================================================================


@router.post("/report/generate", response_model=APIResponse)
async def generate_compliance_report(
    request: ReportGenerationRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Generate compliance report for a framework.

    Runs compliance checks and generates a report in the specified format
    (JSON, text, or HTML dashboard).
    """
    try:
        # Run the appropriate checker based on framework
        if request.framework == ComplianceFrameworkEnum.CIS:
            checker = get_cis_checker()
            results = checker.run_all_checks()
            report = checker.generate_report(
                output_format=request.output_format,
                output_file=None,  # Return content instead of writing
            )
        elif request.framework == ComplianceFrameworkEnum.NIST_800_53:
            checker = get_nist_checker()
            results = checker.run_all_checks()
            report = checker.generate_report()
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Report generation not supported for framework: {request.framework.value}",
            )

        return APIResponse(
            status=StatusEnum.SUCCESS,
            message=f"Report generated for {request.framework.value}",
            data={
                "framework": request.framework.value,
                "format": request.output_format,
                "report": report,
                "summary": results.get("compliance_summary", {}),
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}",
        )


# ============================================================================
# Summary & Status Endpoints
# ============================================================================


@router.get("/summary", response_model=Dict[str, Any])
async def get_compliance_summary(
    current_user: str = Depends(get_current_active_user),
):
    """
    Get quick compliance summary across all frameworks.

    Returns high-level compliance percentages without running full checks.
    Uses cached results if available.
    """
    # This would ideally pull from cached/stored results
    # For now, return structure that frontend can display
    return {
        "last_updated": datetime.utcnow().isoformat(),
        "frameworks": {
            "cis_v8": {
                "status": "not_assessed",
                "compliance_percentage": None,
                "last_check": None,
            },
            "nist_800_53": {
                "status": "not_assessed",
                "compliance_percentage": None,
                "last_check": None,
            },
        },
        "overall_status": "needs_assessment",
        "message": "Run compliance checks to get current status",
    }


@router.get("/frameworks", response_model=List[str])
async def list_frameworks(current_user: str = Depends(get_current_active_user)):
    """List supported compliance frameworks."""
    return ["cis", "nist_800_53", "iso_27001", "pci_dss", "soc2", "hipaa"]


# Legacy endpoint for backwards compatibility
@router.post("/check", response_model=ComplianceReport)
async def check_compliance(
    request: ComplianceCheckRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Check compliance against a framework.

    Legacy endpoint - use /cis/run or /nist/run for more detailed results.
    """
    try:
        if request.framework == ComplianceFrameworkEnum.CIS:
            checker = get_cis_checker()
            results = checker.run_all_checks()
        elif request.framework == ComplianceFrameworkEnum.NIST_800_53:
            checker = get_nist_checker()
            results = checker.run_all_checks()
        else:
            # Return placeholder for frameworks not yet implemented
            return ComplianceReport(
                framework=request.framework.value,
                target=request.target,
                total_controls=0,
                passed=0,
                failed=0,
                not_applicable=0,
                compliance_percentage=0.0,
                controls=[],
            )

        summary = results.get("compliance_summary", {})

        # Convert results to ComplianceControl objects
        controls = []
        for control_data in results.get("controls_checked", []):
            for check in control_data.get("checks", []):
                controls.append(
                    ComplianceControl(
                        control_id=f"{control_data.get('control')}.{check.get('safeguard', '')}",
                        title=check.get("title", ""),
                        description=check.get("details", ""),
                        status=check.get("status", "").lower(),
                        evidence=check.get("details"),
                    )
                )

        return ComplianceReport(
            framework=request.framework.value,
            target=request.target,
            total_controls=summary.get("total", 0),
            passed=summary.get("passed", 0),
            failed=summary.get("failed", 0),
            not_applicable=summary.get("not_applicable", 0),
            compliance_percentage=summary.get("compliance_percentage", 0.0),
            controls=controls,
        )
    except Exception as e:
        logger.error(f"Compliance check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compliance check failed: {str(e)}",
        )
