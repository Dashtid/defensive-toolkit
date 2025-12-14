"""
Incident Response API Router

Endpoints for managing security incidents and executing IR runbooks.
Integrates with the RunbookEngine for automated incident response.

Version: 1.7.1
Author: Defensive Toolkit
"""

import asyncio
import glob
import json
import logging
import os
import platform
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, JSONResponse

from api.models import (
    APIResponse,
    ApprovalDecision,
    EvidenceChainResponse,
    EvidenceItem,
    Incident,
    IncidentStatusEnum,
    PendingApproval,
    PlaybookExecutionRequest,
    PlaybookExecutionResponse,
    RollbackRequest,
    RunbookDetail,
    RunbookExecuteRequest,
    RunbookExecutionModeEnum,
    RunbookExecutionResponse,
    RunbookExecutionStatus,
    RunbookListResponse,
    RunbookStepResult,
    RunbookStepStatusEnum,
    RunbookSummary,
    SeverityEnum,
    StatusEnum,
)
from api.dependencies import get_current_active_user, require_write_scope

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incident-response", tags=["Incident Response"])

# In-memory storage (replace with database in production)
incidents_db: Dict[str, Incident] = {}
executions_db: Dict[str, Dict[str, Any]] = {}
approvals_db: Dict[str, PendingApproval] = {}

# Path to runbook templates
RUNBOOKS_DIR = Path(__file__).parent.parent.parent / "incident-response" / "runbooks" / "templates"
IR_OUTPUT_DIR = Path(__file__).parent.parent.parent / "ir-output"

# Try to import YAML parser
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.warning("[!] PyYAML not installed - runbook features limited")


# ============================================================================
# Incident Management Endpoints
# ============================================================================

@router.get("/incidents", response_model=List[Incident])
async def list_incidents(
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    severity_filter: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: str = Depends(get_current_active_user),
):
    """
    List all incidents with optional filters.

    Args:
        status_filter: Filter by incident status (new, investigating, contained, etc.)
        severity_filter: Filter by severity (low, medium, high, critical)
        limit: Maximum number of results to return
        offset: Number of results to skip

    Returns:
        List of incidents matching filters
    """
    incidents = list(incidents_db.values())

    if status_filter:
        incidents = [i for i in incidents if i.status.value == status_filter]
    if severity_filter:
        incidents = [i for i in incidents if i.severity.value == severity_filter]

    # Sort by created_at descending (newest first)
    incidents.sort(key=lambda x: x.created_at or datetime.min, reverse=True)

    return incidents[offset:offset + limit]


@router.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident(
    incident_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get incident details by ID.

    Args:
        incident_id: Unique incident identifier

    Returns:
        Incident details

    Raises:
        HTTPException 404: If incident not found
    """
    if incident_id not in incidents_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found"
        )
    return incidents_db[incident_id]


@router.post("/incidents", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident: Incident,
    current_user: str = Depends(require_write_scope),
):
    """
    Create a new security incident.

    Args:
        incident: Incident details

    Returns:
        APIResponse with incident ID
    """
    incident.id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    incident.created_at = datetime.utcnow()
    incident.updated_at = datetime.utcnow()
    incident.status = IncidentStatusEnum.NEW

    incidents_db[incident.id] = incident

    logger.info(f"[+] Incident created: {incident.id} - {incident.title}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Incident created successfully",
        data={"incident_id": incident.id}
    )


@router.put("/incidents/{incident_id}", response_model=APIResponse)
async def update_incident(
    incident_id: str,
    incident: Incident,
    current_user: str = Depends(require_write_scope),
):
    """
    Update an existing incident.

    Args:
        incident_id: Incident ID to update
        incident: Updated incident data

    Returns:
        APIResponse confirming update

    Raises:
        HTTPException 404: If incident not found
    """
    if incident_id not in incidents_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found"
        )

    incident.id = incident_id
    incident.updated_at = datetime.utcnow()

    # Preserve original creation time
    incident.created_at = incidents_db[incident_id].created_at

    # Set closed_at if transitioning to closed
    if incident.status == IncidentStatusEnum.CLOSED and not incident.closed_at:
        incident.closed_at = datetime.utcnow()

    incidents_db[incident_id] = incident

    logger.info(f"[+] Incident updated: {incident_id}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Incident updated successfully"
    )


@router.delete("/incidents/{incident_id}", response_model=APIResponse)
async def delete_incident(
    incident_id: str,
    current_user: str = Depends(require_write_scope),
):
    """
    Delete an incident (soft delete recommended in production).

    Args:
        incident_id: Incident ID to delete

    Returns:
        APIResponse confirming deletion

    Raises:
        HTTPException 404: If incident not found
    """
    if incident_id not in incidents_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found"
        )

    del incidents_db[incident_id]

    logger.info(f"[+] Incident deleted: {incident_id}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Incident deleted successfully"
    )


# ============================================================================
# Runbook Management Endpoints
# ============================================================================

def _load_runbook_yaml(file_path: Path) -> Optional[Dict[str, Any]]:
    """Load and parse a runbook YAML file."""
    if not YAML_AVAILABLE:
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"[-] Failed to load runbook {file_path}: {e}")
        return None


def _get_runbook_summary(file_path: Path, runbook: Dict[str, Any]) -> RunbookSummary:
    """Convert runbook dict to summary model."""
    metadata = runbook.get("metadata", {})
    runbook_id = file_path.stem  # filename without extension

    return RunbookSummary(
        id=runbook_id,
        name=runbook.get("name", runbook_id),
        description=runbook.get("description", ""),
        version=runbook.get("version", "1.0.0"),
        author=runbook.get("author"),
        severity=metadata.get("severity", "medium"),
        estimated_duration=metadata.get("estimated_duration"),
        mitre_attack=metadata.get("mitre_attack", []),
        steps_count=len(runbook.get("steps", [])),
        file_path=str(file_path),
        created=runbook.get("created"),
        updated=runbook.get("updated"),
    )


@router.get("/runbooks", response_model=RunbookListResponse)
async def list_runbooks(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    current_user: str = Depends(get_current_active_user),
):
    """
    List all available IR runbooks.

    Scans the runbooks/templates directory for YAML files and returns
    their metadata.

    Args:
        severity: Optional filter by severity (low, medium, high, critical)

    Returns:
        RunbookListResponse with list of available runbooks
    """
    if not YAML_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PyYAML not installed. Install with: pip install pyyaml"
        )

    runbooks = []

    # Scan for YAML files
    if RUNBOOKS_DIR.exists():
        for yaml_file in RUNBOOKS_DIR.glob("*.yaml"):
            runbook_data = _load_runbook_yaml(yaml_file)
            if runbook_data:
                summary = _get_runbook_summary(yaml_file, runbook_data)

                # Apply severity filter
                if severity and summary.severity != severity:
                    continue

                runbooks.append(summary)

        # Also check for .yml extension
        for yaml_file in RUNBOOKS_DIR.glob("*.yml"):
            runbook_data = _load_runbook_yaml(yaml_file)
            if runbook_data:
                summary = _get_runbook_summary(yaml_file, runbook_data)

                if severity and summary.severity != severity:
                    continue

                runbooks.append(summary)

    # Sort by name
    runbooks.sort(key=lambda x: x.name)

    return RunbookListResponse(runbooks=runbooks, total=len(runbooks))


@router.get("/runbooks/{runbook_id}", response_model=RunbookDetail)
async def get_runbook(
    runbook_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get detailed information about a specific runbook.

    Args:
        runbook_id: Runbook identifier (filename without extension)

    Returns:
        RunbookDetail with full runbook definition including steps

    Raises:
        HTTPException 404: If runbook not found
    """
    if not YAML_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PyYAML not installed"
        )

    # Try both extensions
    yaml_file = RUNBOOKS_DIR / f"{runbook_id}.yaml"
    if not yaml_file.exists():
        yaml_file = RUNBOOKS_DIR / f"{runbook_id}.yml"

    if not yaml_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Runbook '{runbook_id}' not found"
        )

    runbook_data = _load_runbook_yaml(yaml_file)
    if not runbook_data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse runbook '{runbook_id}'"
        )

    return RunbookDetail(
        id=runbook_id,
        name=runbook_data.get("name", runbook_id),
        description=runbook_data.get("description", ""),
        version=runbook_data.get("version", "1.0.0"),
        author=runbook_data.get("author"),
        metadata=runbook_data.get("metadata", {}),
        variables=runbook_data.get("variables", {}),
        steps=runbook_data.get("steps", []),
        file_path=str(yaml_file),
    )


# ============================================================================
# Runbook Execution Endpoints
# ============================================================================

async def _execute_runbook_background(
    execution_id: str,
    runbook_data: Dict[str, Any],
    request: RunbookExecuteRequest,
    analyst: str,
):
    """
    Background task for runbook execution.

    Updates execution status in executions_db as steps complete.
    """
    execution = executions_db[execution_id]
    steps = runbook_data.get("steps", [])

    try:
        for i, step in enumerate(steps):
            # Update current step
            execution["current_step"] = i + 1
            execution["updated_at"] = datetime.utcnow().isoformat()

            step_name = step.get("name", f"Step {i + 1}")
            action = step.get("action", "unknown")
            severity = step.get("severity", "medium")

            step_result = RunbookStepResult(
                step_name=step_name,
                action=action,
                status=RunbookStepStatusEnum.RUNNING,
                severity=severity,
                executed_at=datetime.utcnow(),
            )

            # Check conditions
            condition = step.get("when")
            if condition:
                # Simplified condition check
                if condition.endswith("!= 'skip'"):
                    var_name = condition.split()[0]
                    if execution["variables"].get(var_name) == "skip":
                        step_result.status = RunbookStepStatusEnum.SKIPPED
                        step_result.message = "Condition not met - skipped"
                        execution["steps_skipped"] += 1
                        execution["step_results"].append(step_result.model_dump())
                        continue

            # Dry run mode - simulate execution
            if request.mode == RunbookExecutionModeEnum.DRY_RUN:
                step_result.status = RunbookStepStatusEnum.COMPLETED
                step_result.message = f"[DRY RUN] Would execute: {action}"
                step_result.duration_ms = 50
                execution["steps_completed"] += 1

            # Normal or auto-approve mode
            elif request.mode in (RunbookExecutionModeEnum.NORMAL, RunbookExecutionModeEnum.AUTO_APPROVE):
                # Check if action needs approval
                severity_order = ["low", "medium", "high", "critical"]
                auto_level = request.auto_approve_level or "low"

                if severity_order.index(severity) > severity_order.index(auto_level):
                    # Need approval - create pending approval
                    approval_id = str(uuid.uuid4())[:8]
                    approval = PendingApproval(
                        approval_id=approval_id,
                        execution_id=execution_id,
                        step_name=step_name,
                        action=action,
                        severity=severity,
                        description=step.get("description", ""),
                        parameters=step.get("parameters", {}),
                        requested_at=datetime.utcnow(),
                        expires_at=datetime.utcnow() + timedelta(hours=1),
                    )
                    approvals_db[approval_id] = approval

                    step_result.status = RunbookStepStatusEnum.AWAITING_APPROVAL
                    step_result.message = f"Awaiting approval (approval_id: {approval_id})"
                    execution["steps_awaiting"] += 1
                    execution["status"] = StatusEnum.PENDING.value

                    # Wait for approval (in production, this would be event-driven)
                    # For API demo, we'll mark as awaiting and continue
                    execution["step_results"].append(step_result.model_dump())
                    continue

                # Auto-approved - simulate execution
                step_result.status = RunbookStepStatusEnum.COMPLETED
                step_result.message = f"Executed: {action}"
                step_result.duration_ms = 100
                execution["steps_completed"] += 1

            execution["step_results"].append(step_result.model_dump())

            # Small delay to simulate work
            await asyncio.sleep(0.1)

        # Mark execution as complete
        execution["status"] = StatusEnum.SUCCESS.value
        execution["completed_at"] = datetime.utcnow().isoformat()

    except Exception as e:
        logger.error(f"[-] Runbook execution failed: {e}")
        execution["status"] = StatusEnum.FAILED.value
        execution["step_results"].append({
            "step_name": "ERROR",
            "action": "error",
            "status": RunbookStepStatusEnum.FAILED.value,
            "severity": "critical",
            "message": str(e),
            "executed_at": datetime.utcnow().isoformat(),
        })

    execution["updated_at"] = datetime.utcnow().isoformat()


@router.post("/runbooks/execute", response_model=RunbookExecutionResponse)
async def execute_runbook(
    request: RunbookExecuteRequest,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(require_write_scope),
):
    """
    Execute an IR runbook.

    Initiates asynchronous runbook execution and returns immediately
    with an execution ID for monitoring.

    Args:
        request: Execution request with runbook ID, mode, and variables

    Returns:
        RunbookExecutionResponse with execution ID and monitor URL

    Raises:
        HTTPException 404: If runbook not found
        HTTPException 503: If PyYAML not installed
    """
    if not YAML_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PyYAML not installed"
        )

    # Load runbook
    yaml_file = RUNBOOKS_DIR / f"{request.runbook_id}.yaml"
    if not yaml_file.exists():
        yaml_file = RUNBOOKS_DIR / f"{request.runbook_id}.yml"

    if not yaml_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Runbook '{request.runbook_id}' not found"
        )

    runbook_data = _load_runbook_yaml(yaml_file)
    if not runbook_data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse runbook"
        )

    # Generate execution and incident IDs
    execution_id = f"EXE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8].upper()}"
    incident_id = request.incident_id or f"IR-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    # Merge variables
    variables = {
        "incident_id": incident_id,
        "hostname": platform.node(),
        "timestamp": datetime.utcnow().isoformat(),
        "analyst": current_user,
        "target_host": request.target_host,
        **runbook_data.get("variables", {}),
        **request.variables,
    }

    # Initialize execution record
    steps = runbook_data.get("steps", [])
    executions_db[execution_id] = {
        "execution_id": execution_id,
        "runbook_name": runbook_data.get("name", request.runbook_id),
        "runbook_version": runbook_data.get("version", "1.0.0"),
        "incident_id": incident_id,
        "status": StatusEnum.IN_PROGRESS.value,
        "mode": request.mode.value,
        "started_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "current_step": 0,
        "total_steps": len(steps),
        "steps_completed": 0,
        "steps_failed": 0,
        "steps_skipped": 0,
        "steps_awaiting": 0,
        "step_results": [],
        "variables": variables,
        "analyst": current_user,
        "target_host": request.target_host,
    }

    # Start background execution
    background_tasks.add_task(
        _execute_runbook_background,
        execution_id,
        runbook_data,
        request,
        current_user,
    )

    logger.info(f"[+] Runbook execution started: {execution_id}")

    return RunbookExecutionResponse(
        execution_id=execution_id,
        incident_id=incident_id,
        runbook_name=runbook_data.get("name", request.runbook_id),
        status=StatusEnum.IN_PROGRESS,
        message=f"Runbook execution started in {request.mode.value} mode",
        monitor_url=f"/api/v1/incident-response/executions/{execution_id}",
    )


@router.get("/executions", response_model=List[RunbookExecutionStatus])
async def list_executions(
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500),
    current_user: str = Depends(get_current_active_user),
):
    """
    List all runbook executions.

    Args:
        status_filter: Optional filter by status
        limit: Maximum results to return

    Returns:
        List of execution status records
    """
    executions = list(executions_db.values())

    if status_filter:
        executions = [e for e in executions if e["status"] == status_filter]

    # Sort by started_at descending
    executions.sort(key=lambda x: x["started_at"], reverse=True)

    # Convert to response models
    result = []
    for exe in executions[:limit]:
        result.append(RunbookExecutionStatus(
            execution_id=exe["execution_id"],
            runbook_name=exe["runbook_name"],
            runbook_version=exe["runbook_version"],
            incident_id=exe["incident_id"],
            status=StatusEnum(exe["status"]),
            mode=RunbookExecutionModeEnum(exe["mode"]),
            started_at=datetime.fromisoformat(exe["started_at"]),
            updated_at=datetime.fromisoformat(exe["updated_at"]),
            completed_at=datetime.fromisoformat(exe["completed_at"]) if exe["completed_at"] else None,
            current_step=exe["current_step"],
            total_steps=exe["total_steps"],
            steps_completed=exe["steps_completed"],
            steps_failed=exe["steps_failed"],
            steps_skipped=exe["steps_skipped"],
            steps_awaiting=exe["steps_awaiting"],
            step_results=[RunbookStepResult(**r) for r in exe.get("step_results", [])],
            variables=exe["variables"],
            analyst=exe["analyst"],
            target_host=exe["target_host"],
        ))

    return result


@router.get("/executions/{execution_id}", response_model=RunbookExecutionStatus)
async def get_execution_status(
    execution_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get detailed status of a runbook execution.

    Args:
        execution_id: Execution identifier

    Returns:
        RunbookExecutionStatus with step-by-step results

    Raises:
        HTTPException 404: If execution not found
    """
    if execution_id not in executions_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution '{execution_id}' not found"
        )

    exe = executions_db[execution_id]

    return RunbookExecutionStatus(
        execution_id=exe["execution_id"],
        runbook_name=exe["runbook_name"],
        runbook_version=exe["runbook_version"],
        incident_id=exe["incident_id"],
        status=StatusEnum(exe["status"]),
        mode=RunbookExecutionModeEnum(exe["mode"]),
        started_at=datetime.fromisoformat(exe["started_at"]),
        updated_at=datetime.fromisoformat(exe["updated_at"]),
        completed_at=datetime.fromisoformat(exe["completed_at"]) if exe["completed_at"] else None,
        current_step=exe["current_step"],
        total_steps=exe["total_steps"],
        steps_completed=exe["steps_completed"],
        steps_failed=exe["steps_failed"],
        steps_skipped=exe["steps_skipped"],
        steps_awaiting=exe["steps_awaiting"],
        step_results=[RunbookStepResult(**r) for r in exe.get("step_results", [])],
        variables=exe["variables"],
        analyst=exe["analyst"],
        target_host=exe["target_host"],
    )


# ============================================================================
# Approval Endpoints
# ============================================================================

@router.get("/approvals", response_model=List[PendingApproval])
async def list_pending_approvals(
    current_user: str = Depends(get_current_active_user),
):
    """
    List all pending approval requests.

    Returns:
        List of pending approvals for high-severity actions
    """
    approvals = list(approvals_db.values())

    # Filter expired
    now = datetime.utcnow()
    active = [a for a in approvals if not a.expires_at or a.expires_at > now]

    return active


@router.get("/approvals/{approval_id}", response_model=PendingApproval)
async def get_approval(
    approval_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get details of a pending approval request.

    Args:
        approval_id: Approval identifier

    Returns:
        PendingApproval details

    Raises:
        HTTPException 404: If approval not found
    """
    if approval_id not in approvals_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval '{approval_id}' not found"
        )

    return approvals_db[approval_id]


@router.post("/approvals/{approval_id}/decide", response_model=APIResponse)
async def decide_approval(
    approval_id: str,
    decision: ApprovalDecision,
    current_user: str = Depends(require_write_scope),
):
    """
    Approve or deny a pending action.

    Args:
        approval_id: Approval identifier
        decision: Approval decision (approved: true/false)

    Returns:
        APIResponse confirming decision

    Raises:
        HTTPException 404: If approval not found
    """
    if approval_id not in approvals_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval '{approval_id}' not found"
        )

    approval = approvals_db[approval_id]
    execution_id = approval.execution_id

    if execution_id in executions_db:
        execution = executions_db[execution_id]

        if decision.approved:
            # Find and update the step
            for step_result in execution["step_results"]:
                if step_result["step_name"] == approval.step_name:
                    step_result["status"] = RunbookStepStatusEnum.COMPLETED.value
                    step_result["message"] = f"Approved by {current_user}"
                    break

            execution["steps_awaiting"] -= 1
            execution["steps_completed"] += 1
            logger.info(f"[+] Approval granted: {approval_id} by {current_user}")

        else:
            # Mark as skipped
            for step_result in execution["step_results"]:
                if step_result["step_name"] == approval.step_name:
                    step_result["status"] = RunbookStepStatusEnum.SKIPPED.value
                    step_result["message"] = f"Denied by {current_user}: {decision.reason or 'No reason'}"
                    break

            execution["steps_awaiting"] -= 1
            execution["steps_skipped"] += 1
            logger.info(f"[-] Approval denied: {approval_id} by {current_user}")

        execution["updated_at"] = datetime.utcnow().isoformat()

        # Check if execution can continue
        if execution["steps_awaiting"] == 0 and execution["status"] == StatusEnum.PENDING.value:
            execution["status"] = StatusEnum.IN_PROGRESS.value

    # Remove processed approval
    del approvals_db[approval_id]

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Approval {'granted' if decision.approved else 'denied'}",
        data={
            "approval_id": approval_id,
            "decision": "approved" if decision.approved else "denied",
            "decided_by": current_user,
        }
    )


# ============================================================================
# Evidence Endpoints
# ============================================================================

@router.get("/executions/{execution_id}/evidence", response_model=EvidenceChainResponse)
async def get_evidence_chain(
    execution_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get chain of custody for evidence collected during execution.

    Args:
        execution_id: Execution identifier

    Returns:
        EvidenceChainResponse with all collected evidence items

    Raises:
        HTTPException 404: If execution not found or no evidence
    """
    if execution_id not in executions_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution '{execution_id}' not found"
        )

    execution = executions_db[execution_id]
    incident_id = execution["incident_id"]

    # Check for evidence chain file
    evidence_dir = IR_OUTPUT_DIR / incident_id
    chain_file = evidence_dir / "chain_of_custody.json"

    if chain_file.exists():
        with open(chain_file, "r") as f:
            chain_data = json.load(f)

        evidence_items = []
        for item in chain_data.get("evidence", []):
            evidence_items.append(EvidenceItem(
                evidence_id=item.get("evidence_id", ""),
                incident_id=item.get("incident_id", incident_id),
                evidence_type=item.get("type", ""),
                source=item.get("source", ""),
                description=item.get("description", ""),
                collected_at=datetime.fromisoformat(item["collected_at"]),
                collected_by=item.get("collected_by", ""),
                hostname=item.get("hostname", ""),
                file_path=item.get("file_path"),
                file_size=item.get("file_size"),
                sha256=item.get("sha256"),
            ))

        return EvidenceChainResponse(
            incident_id=incident_id,
            created_at=datetime.fromisoformat(chain_data.get("created_at", datetime.utcnow().isoformat())),
            evidence_count=len(evidence_items),
            evidence=evidence_items,
        )

    # No evidence yet - return empty chain
    return EvidenceChainResponse(
        incident_id=incident_id,
        created_at=datetime.utcnow(),
        evidence_count=0,
        evidence=[],
    )


@router.get("/executions/{execution_id}/evidence/download")
async def download_evidence_package(
    execution_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Download the forensic evidence package for an execution.

    Args:
        execution_id: Execution identifier

    Returns:
        FileResponse with ZIP package

    Raises:
        HTTPException 404: If execution or package not found
    """
    if execution_id not in executions_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution '{execution_id}' not found"
        )

    execution = executions_db[execution_id]
    incident_id = execution["incident_id"]

    # Look for forensic package
    evidence_dir = IR_OUTPUT_DIR / incident_id

    if not evidence_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No evidence package available for this execution"
        )

    # Find zip file
    zip_files = list(evidence_dir.glob("*_package.zip"))
    if not zip_files:
        zip_files = list(evidence_dir.glob("*.zip"))

    if not zip_files:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Forensic package not yet created"
        )

    zip_file = zip_files[0]

    logger.info(f"[+] Evidence download: {zip_file.name} by {current_user}")

    return FileResponse(
        path=str(zip_file),
        filename=zip_file.name,
        media_type="application/zip",
    )


# ============================================================================
# Rollback Endpoint
# ============================================================================

@router.post("/executions/{execution_id}/rollback", response_model=APIResponse)
async def rollback_execution(
    execution_id: str,
    request: RollbackRequest,
    current_user: str = Depends(require_write_scope),
):
    """
    Rollback actions performed during execution.

    This attempts to undo containment actions like IP blocks,
    account disables, etc.

    Args:
        execution_id: Execution identifier
        request: Rollback confirmation

    Returns:
        APIResponse with rollback status

    Raises:
        HTTPException 404: If execution not found
        HTTPException 400: If rollback not confirmed
    """
    if execution_id not in executions_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution '{execution_id}' not found"
        )

    if not request.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rollback must be confirmed (confirm: true)"
        )

    execution = executions_db[execution_id]

    # In a real implementation, this would:
    # 1. Load rollback info from execution log
    # 2. Reverse containment actions
    # 3. Log all rollback operations

    logger.warning(f"[!] Rollback initiated for {execution_id} by {current_user}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Rollback initiated. Check execution log for details.",
        data={
            "execution_id": execution_id,
            "rollback_initiated_by": current_user,
            "note": "Rollback operations logged to incident output directory",
        }
    )


# ============================================================================
# Legacy Playbook Endpoints (for backward compatibility)
# ============================================================================

@router.post("/playbooks/execute", response_model=PlaybookExecutionResponse)
async def execute_playbook_legacy(
    request: PlaybookExecutionRequest,
    current_user: str = Depends(require_write_scope),
):
    """
    Execute an incident response playbook (legacy endpoint).

    This endpoint is maintained for backward compatibility.
    Use /runbooks/execute for new integrations.
    """
    execution_id = str(uuid.uuid4())

    # Simulate playbook execution
    execution = PlaybookExecutionResponse(
        execution_id=execution_id,
        playbook_name=request.playbook_name,
        status=StatusEnum.SUCCESS,
        steps_completed=5,
        steps_total=5,
        start_time=datetime.utcnow(),
        end_time=datetime.utcnow(),
        results={
            "containment": "successful",
            "evidence_collected": True,
            "notifications_sent": ["security@example.com"]
        }
    )

    return execution


@router.get("/playbooks", response_model=List[dict])
async def list_playbooks_legacy(
    current_user: str = Depends(get_current_active_user),
):
    """
    List available IR playbooks (legacy endpoint).

    Use /runbooks for new integrations.
    """
    # Return runbooks in legacy format
    if YAML_AVAILABLE and RUNBOOKS_DIR.exists():
        playbooks = []
        for yaml_file in RUNBOOKS_DIR.glob("*.yaml"):
            runbook_data = _load_runbook_yaml(yaml_file)
            if runbook_data:
                playbooks.append({
                    "name": yaml_file.stem,
                    "description": runbook_data.get("description", ""),
                    "steps": len(runbook_data.get("steps", []))
                })
        return playbooks

    # Fallback to hardcoded list
    return [
        {
            "name": "ransomware-response",
            "description": "Response playbook for ransomware incidents",
            "steps": 8
        },
        {
            "name": "malware-response",
            "description": "Response playbook for malware infections",
            "steps": 6
        },
        {
            "name": "credential-compromise",
            "description": "Response playbook for compromised credentials",
            "steps": 7
        }
    ]
