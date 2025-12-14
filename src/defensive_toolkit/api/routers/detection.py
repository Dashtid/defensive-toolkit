"""
Detection Rules API Router

Endpoints for managing Sigma and YARA detection rules.
"""

import glob
import os
import uuid
from datetime import datetime

from defensive_toolkit.api.dependencies import get_current_active_user, require_write_scope
from defensive_toolkit.api.models import APIResponse, DeployRuleRequest, DetectionRule, DetectionRuleList, StatusEnum
from fastapi import APIRouter, Depends, HTTPException, status

router = APIRouter(prefix="/detection", tags=["Detection Rules"])


# Mock database for rules (replace with actual database)
rules_db = {}


@router.get("/rules", response_model=DetectionRuleList)
async def list_rules(
    rule_type: str = None,
    severity: str = None,
    current_user: str = Depends(get_current_active_user),
):
    """
    List all detection rules with optional filters.

    Args:
        rule_type: Filter by rule type (sigma, yara, snort, custom)
        severity: Filter by severity (low, medium, high, critical)
        current_user: Authenticated user

    Returns:
        DetectionRuleList: List of detection rules
    """
    # Load rules from filesystem
    rules = []
    rules_dir = "./rules"

    if os.path.exists(rules_dir):
        # Load Sigma rules
        sigma_files = glob.glob(f"{rules_dir}/sigma/*.yml")
        for file_path in sigma_files:
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                    rules.append(
                        DetectionRule(
                            id=str(uuid.uuid4()),
                            name=os.path.basename(file_path),
                            description=f"Sigma rule from {file_path}",
                            rule_type="sigma",
                            content=content,
                            severity="medium",
                            created_at=datetime.utcnow(),
                        )
                    )
            except Exception:
                # Skip files that can't be read
                pass

        # Load YARA rules
        yara_files = glob.glob(f"{rules_dir}/yara/*.yar")
        for file_path in yara_files:
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                    rules.append(
                        DetectionRule(
                            id=str(uuid.uuid4()),
                            name=os.path.basename(file_path),
                            description=f"YARA rule from {file_path}",
                            rule_type="yara",
                            content=content,
                            severity="high",
                            created_at=datetime.utcnow(),
                        )
                    )
            except Exception:
                pass

    # Apply filters
    if rule_type:
        rules = [r for r in rules if r.rule_type == rule_type]

    if severity:
        rules = [r for r in rules if r.severity == severity]

    return DetectionRuleList(rules=rules, total=len(rules))


@router.get("/rules/{rule_id}", response_model=DetectionRule)
async def get_rule(
    rule_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get a specific detection rule by ID.

    Args:
        rule_id: Rule ID
        current_user: Authenticated user

    Returns:
        DetectionRule: Detection rule details

    Raises:
        HTTPException: If rule not found
    """
    if rule_id not in rules_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {rule_id} not found"
        )

    return rules_db[rule_id]


@router.post("/rules", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    rule: DetectionRule,
    current_user: str = Depends(require_write_scope),
):
    """
    Create a new detection rule.

    Args:
        rule: Detection rule to create
        current_user: Authenticated user with write scope

    Returns:
        APIResponse: Success response with rule ID
    """
    rule.id = str(uuid.uuid4())
    rule.created_at = datetime.utcnow()
    rule.updated_at = datetime.utcnow()

    rules_db[rule.id] = rule

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Detection rule created successfully",
        data={"rule_id": rule.id},
    )


@router.put("/rules/{rule_id}", response_model=APIResponse)
async def update_rule(
    rule_id: str,
    rule: DetectionRule,
    current_user: str = Depends(require_write_scope),
):
    """
    Update an existing detection rule.

    Args:
        rule_id: Rule ID to update
        rule: Updated rule data
        current_user: Authenticated user with write scope

    Returns:
        APIResponse: Success response

    Raises:
        HTTPException: If rule not found
    """
    if rule_id not in rules_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {rule_id} not found"
        )

    rule.id = rule_id
    rule.updated_at = datetime.utcnow()
    rules_db[rule_id] = rule

    return APIResponse(status=StatusEnum.SUCCESS, message="Detection rule updated successfully")


@router.delete("/rules/{rule_id}", response_model=APIResponse)
async def delete_rule(
    rule_id: str,
    current_user: str = Depends(require_write_scope),
):
    """
    Delete a detection rule.

    Args:
        rule_id: Rule ID to delete
        current_user: Authenticated user with write scope

    Returns:
        APIResponse: Success response

    Raises:
        HTTPException: If rule not found
    """
    if rule_id not in rules_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {rule_id} not found"
        )

    del rules_db[rule_id]

    return APIResponse(status=StatusEnum.SUCCESS, message="Detection rule deleted successfully")


@router.post("/rules/{rule_id}/deploy", response_model=APIResponse)
async def deploy_rule(
    rule_id: str,
    request: DeployRuleRequest,
    current_user: str = Depends(require_write_scope),
):
    """
    Deploy a detection rule to a SIEM platform.

    Args:
        rule_id: Rule ID to deploy
        request: Deployment configuration
        current_user: Authenticated user with write scope

    Returns:
        APIResponse: Deployment result

    Raises:
        HTTPException: If rule not found or deployment fails
    """
    if rule_id not in rules_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {rule_id} not found"
        )

    rule = rules_db[rule_id]

    # Here you would integrate with actual SIEM deployment logic
    # For now, simulate deployment
    deployment_id = str(uuid.uuid4())

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Rule deployed to {request.siem_platform} successfully",
        data={
            "deployment_id": deployment_id,
            "siem_platform": request.siem_platform,
            "rule_id": rule_id,
            "rule_name": rule.name,
        },
    )


@router.post("/rules/validate", response_model=APIResponse)
async def validate_rule(
    rule: DetectionRule,
    current_user: str = Depends(get_current_active_user),
):
    """
    Validate a detection rule syntax.

    Args:
        rule: Detection rule to validate
        current_user: Authenticated user

    Returns:
        APIResponse: Validation result
    """
    # Here you would integrate with actual rule validation logic
    # For Sigma: use sigma-cli
    # For YARA: use yara-python
    # For now, simulate validation

    is_valid = True
    errors = []

    # Basic validation
    if not rule.content:
        is_valid = False
        errors.append("Rule content is empty")

    if not rule.name:
        is_valid = False
        errors.append("Rule name is required")

    return APIResponse(
        status=StatusEnum.SUCCESS if is_valid else StatusEnum.FAILED,
        message="Rule validation completed",
        data={"valid": is_valid, "errors": errors},
    )
