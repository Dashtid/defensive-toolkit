"""
Automation (SOAR) API Router.

Provides endpoints for security orchestration, automation, and response:
- Playbook management and execution
- Containment actions (isolate host, block IP, quarantine file)
- Enrichment actions (IOC lookup, geolocation)
- Notification actions (email, Slack, webhook)

Wires to automation.playbooks.playbook_engine and automation.actions modules.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from defensive_toolkit.api.dependencies import (
    get_current_active_user,
    require_write_scope,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/automation", tags=["Automation"])


# =============================================================================
# Request/Response Models
# =============================================================================


class PlaybookTask(BaseModel):
    """Single task in a playbook."""

    name: str = Field(..., description="Task name")
    action: str = Field(..., description="Action to execute")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    continue_on_failure: bool = Field(default=False)


class PlaybookDefinition(BaseModel):
    """Playbook definition."""

    name: str = Field(..., description="Playbook name")
    description: str = Field(..., description="Playbook description")
    tasks: List[PlaybookTask] = Field(default_factory=list)
    variables: Dict[str, Any] = Field(default_factory=dict)


class PlaybookExecuteRequest(BaseModel):
    """Request to execute a playbook."""

    playbook: PlaybookDefinition
    variables: Dict[str, Any] = Field(
        default_factory=dict, description="Runtime variables"
    )
    dry_run: bool = Field(default=False, description="Dry run mode")


class ExecutionLog(BaseModel):
    """Execution log entry."""

    timestamp: str
    task: Optional[str]
    action: str
    parameters: Dict[str, Any]
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None


class PlaybookExecutionResult(BaseModel):
    """Playbook execution result."""

    execution_id: str
    playbook_name: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    tasks_completed: int
    tasks_total: int
    dry_run: bool
    execution_log: List[ExecutionLog] = Field(default_factory=list)
    variables: Dict[str, Any] = Field(default_factory=dict)


class IsolateHostRequest(BaseModel):
    """Request to isolate a host."""

    hostname: str = Field(..., description="Target hostname or IP")
    method: str = Field(default="firewall", description="Isolation method")
    dry_run: bool = Field(default=False)


class BlockIPRequest(BaseModel):
    """Request to block an IP."""

    ip_address: str = Field(..., description="IP to block")
    direction: str = Field(default="both", description="inbound, outbound, or both")
    duration: Optional[int] = Field(default=None, description="Duration in seconds")
    dry_run: bool = Field(default=False)


class QuarantineFileRequest(BaseModel):
    """Request to quarantine a file."""

    file_path: str = Field(..., description="Path to file")
    quarantine_dir: str = Field(default="/quarantine")
    dry_run: bool = Field(default=False)


class TerminateProcessRequest(BaseModel):
    """Request to terminate a process."""

    process_name: Optional[str] = Field(default=None)
    pid: Optional[int] = Field(default=None)
    dry_run: bool = Field(default=False)


class DisableUserRequest(BaseModel):
    """Request to disable a user account."""

    username: str = Field(..., description="Username to disable")
    dry_run: bool = Field(default=False)


class EnrichIOCRequest(BaseModel):
    """Request to enrich an IOC."""

    ioc: str = Field(..., description="Indicator of compromise")
    ioc_type: str = Field(..., description="Type: ip, domain, hash, url")
    sources: List[str] = Field(
        default=["virustotal", "abuseipdb"],
        description="TI sources to query",
    )


class EnrichIOCResponse(BaseModel):
    """IOC enrichment response."""

    ioc: str
    type: str
    reputation: str
    sources: Dict[str, Dict[str, Any]]


class LookupDomainResponse(BaseModel):
    """Domain lookup response."""

    domain: str
    resolved_ips: List[str]
    whois: Dict[str, Any]


class GeolocateIPResponse(BaseModel):
    """IP geolocation response."""

    ip: str
    country: str
    city: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class SendEmailRequest(BaseModel):
    """Request to send email."""

    to: str = Field(..., description="Recipient email")
    subject: str = Field(..., description="Email subject")
    body: str = Field(..., description="Email body")
    smtp_server: Optional[str] = Field(default=None)
    dry_run: bool = Field(default=False)


class SendSlackRequest(BaseModel):
    """Request to send Slack message."""

    webhook_url: str = Field(..., description="Slack webhook URL")
    message: str = Field(..., description="Message text")
    dry_run: bool = Field(default=False)


class SendWebhookRequest(BaseModel):
    """Request to send generic webhook."""

    url: str = Field(..., description="Webhook URL")
    payload: Dict[str, Any] = Field(..., description="Payload data")
    dry_run: bool = Field(default=False)


class ActionResult(BaseModel):
    """Generic action result."""

    action: str
    success: bool
    message: str
    dry_run: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# In-memory storage
# =============================================================================

_playbooks: Dict[str, PlaybookDefinition] = {}
_executions: Dict[str, PlaybookExecutionResult] = {}


# =============================================================================
# Helper Functions
# =============================================================================


def get_playbook_engine(dry_run: bool = False):
    """Get PlaybookEngine instance."""
    try:
        from defensive_toolkit.automation.playbooks.playbook_engine import (
            PlaybookEngine,
        )

        return PlaybookEngine(dry_run=dry_run)
    except ImportError as e:
        logger.error(f"Failed to import PlaybookEngine: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Playbook engine module not available",
        )


def get_containment_actions():
    """Get containment action functions."""
    try:
        from defensive_toolkit.automation.actions import containment

        return containment
    except ImportError as e:
        logger.error(f"Failed to import containment actions: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Containment actions module not available",
        )


def get_enrichment_actions():
    """Get enrichment action functions."""
    try:
        from defensive_toolkit.automation.actions import enrichment

        return enrichment
    except ImportError as e:
        logger.error(f"Failed to import enrichment actions: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enrichment actions module not available",
        )


def get_notification_actions():
    """Get notification action functions."""
    try:
        from defensive_toolkit.automation.actions import notification

        return notification
    except ImportError as e:
        logger.error(f"Failed to import notification actions: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Notification actions module not available",
        )


# =============================================================================
# Playbook Management Endpoints
# =============================================================================


@router.get("/playbooks")
async def list_playbooks(
    current_user: str = Depends(get_current_active_user),
):
    """
    List all registered playbooks.
    """
    return {
        "playbooks": [
            {
                "id": pid,
                "name": p.name,
                "description": p.description,
                "tasks_count": len(p.tasks),
            }
            for pid, p in _playbooks.items()
        ],
        "total": len(_playbooks),
    }


@router.post(
    "/playbooks",
    dependencies=[Depends(require_write_scope)],
)
async def create_playbook(
    playbook: PlaybookDefinition,
    current_user: str = Depends(get_current_active_user),
):
    """
    Create a new playbook.
    """
    playbook_id = str(uuid.uuid4())
    _playbooks[playbook_id] = playbook

    return {
        "playbook_id": playbook_id,
        "name": playbook.name,
        "status": "created",
        "tasks_count": len(playbook.tasks),
    }


@router.get("/playbooks/{playbook_id}")
async def get_playbook(
    playbook_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get playbook details.
    """
    if playbook_id not in _playbooks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook not found: {playbook_id}",
        )

    playbook = _playbooks[playbook_id]
    return {
        "playbook_id": playbook_id,
        "name": playbook.name,
        "description": playbook.description,
        "tasks": [t.model_dump() for t in playbook.tasks],
        "variables": playbook.variables,
    }


@router.delete(
    "/playbooks/{playbook_id}",
    dependencies=[Depends(require_write_scope)],
)
async def delete_playbook(
    playbook_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Delete a playbook.
    """
    if playbook_id not in _playbooks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook not found: {playbook_id}",
        )

    del _playbooks[playbook_id]
    return {"status": "deleted", "playbook_id": playbook_id}


# =============================================================================
# Playbook Execution Endpoints
# =============================================================================


@router.post(
    "/execute",
    response_model=PlaybookExecutionResult,
    dependencies=[Depends(require_write_scope)],
)
async def execute_playbook(
    request: PlaybookExecuteRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Execute a playbook.

    Executes all tasks in the playbook sequentially.
    Supports dry run mode for testing without side effects.
    """
    engine = get_playbook_engine(dry_run=request.dry_run)
    execution_id = str(uuid.uuid4())

    # Merge variables
    engine.variables = {**request.playbook.variables, **request.variables}

    started_at = datetime.utcnow()

    try:
        # Convert playbook to engine format
        playbook_dict = {
            "name": request.playbook.name,
            "description": request.playbook.description,
            "tasks": [t.model_dump() for t in request.playbook.tasks],
        }

        # Execute playbook
        success = engine.execute_playbook(playbook_dict)
        completed_at = datetime.utcnow()

        # Count completed tasks
        tasks_completed = len([log for log in engine.execution_log if log.get("success")])

        # Build execution log
        execution_log = [
            ExecutionLog(
                timestamp=log.get("timestamp", ""),
                task=log.get("task"),
                action=log.get("action", ""),
                parameters=log.get("parameters", {}),
                success=log.get("success", False),
                result=log.get("result"),
                error=log.get("error"),
            )
            for log in engine.execution_log
        ]

        result = PlaybookExecutionResult(
            execution_id=execution_id,
            playbook_name=request.playbook.name,
            status="completed" if success else "failed",
            started_at=started_at,
            completed_at=completed_at,
            tasks_completed=tasks_completed,
            tasks_total=len(request.playbook.tasks),
            dry_run=request.dry_run,
            execution_log=execution_log,
            variables=engine.variables,
        )

        # Store execution
        _executions[execution_id] = result

        return result

    except Exception as e:
        logger.error(f"Playbook execution failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Playbook execution failed: {str(e)}",
        )


@router.get("/execute/{execution_id}/status")
async def get_execution_status(
    execution_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get execution status.
    """
    if execution_id not in _executions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution not found: {execution_id}",
        )

    execution = _executions[execution_id]
    return {
        "execution_id": execution_id,
        "playbook_name": execution.playbook_name,
        "status": execution.status,
        "tasks_completed": execution.tasks_completed,
        "tasks_total": execution.tasks_total,
        "started_at": execution.started_at.isoformat(),
        "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
    }


@router.get("/execute/{execution_id}/logs")
async def get_execution_logs(
    execution_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get execution logs.
    """
    if execution_id not in _executions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution not found: {execution_id}",
        )

    execution = _executions[execution_id]
    return {
        "execution_id": execution_id,
        "playbook_name": execution.playbook_name,
        "logs": [log.model_dump() for log in execution.execution_log],
    }


@router.post("/preview")
async def preview_playbook(
    request: PlaybookExecuteRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Preview playbook execution (dry run).

    Shows what actions would be executed without actually running them.
    """
    # Force dry run for preview
    request.dry_run = True

    result = await execute_playbook(request, current_user)

    return {
        "preview": True,
        "playbook_name": result.playbook_name,
        "tasks": [
            {
                "task": log.task,
                "action": log.action,
                "parameters": log.parameters,
            }
            for log in result.execution_log
        ],
    }


# =============================================================================
# Containment Action Endpoints
# =============================================================================


@router.post(
    "/actions/containment/isolate",
    response_model=ActionResult,
    dependencies=[Depends(require_write_scope)],
)
async def isolate_host(
    request: IsolateHostRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Isolate a host from the network.

    Supports firewall-based or EDR-based isolation.
    """
    containment = get_containment_actions()

    try:
        success = containment.isolate_host(
            hostname=request.hostname,
            method=request.method,
            dry_run=request.dry_run,
        )

        return ActionResult(
            action="isolate_host",
            success=success,
            message=f"Host {request.hostname} {'would be' if request.dry_run else ''} isolated"
            if success
            else f"Failed to isolate host {request.hostname}",
            dry_run=request.dry_run,
            details={"hostname": request.hostname, "method": request.method},
        )

    except Exception as e:
        logger.error(f"Isolate host failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Isolate host failed: {str(e)}",
        )


@router.post(
    "/actions/containment/block-ip",
    response_model=ActionResult,
    dependencies=[Depends(require_write_scope)],
)
async def block_ip(
    request: BlockIPRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Block an IP address at the firewall.
    """
    containment = get_containment_actions()

    try:
        success = containment.block_ip(
            ip_address=request.ip_address,
            direction=request.direction,
            duration=request.duration,
            dry_run=request.dry_run,
        )

        return ActionResult(
            action="block_ip",
            success=success,
            message=f"IP {request.ip_address} {'would be' if request.dry_run else ''} blocked"
            if success
            else f"Failed to block IP {request.ip_address}",
            dry_run=request.dry_run,
            details={
                "ip_address": request.ip_address,
                "direction": request.direction,
                "duration": request.duration,
            },
        )

    except Exception as e:
        logger.error(f"Block IP failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Block IP failed: {str(e)}",
        )


@router.post(
    "/actions/containment/quarantine",
    response_model=ActionResult,
    dependencies=[Depends(require_write_scope)],
)
async def quarantine_file(
    request: QuarantineFileRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Quarantine a suspicious file.
    """
    containment = get_containment_actions()

    try:
        success = containment.quarantine_file(
            file_path=request.file_path,
            quarantine_dir=request.quarantine_dir,
            dry_run=request.dry_run,
        )

        return ActionResult(
            action="quarantine_file",
            success=success,
            message=f"File {request.file_path} {'would be' if request.dry_run else ''} quarantined"
            if success
            else f"Failed to quarantine file {request.file_path}",
            dry_run=request.dry_run,
            details={
                "file_path": request.file_path,
                "quarantine_dir": request.quarantine_dir,
            },
        )

    except Exception as e:
        logger.error(f"Quarantine file failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Quarantine file failed: {str(e)}",
        )


@router.post(
    "/actions/containment/terminate",
    response_model=ActionResult,
    dependencies=[Depends(require_write_scope)],
)
async def terminate_process(
    request: TerminateProcessRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Terminate a suspicious process.
    """
    containment = get_containment_actions()

    if not request.process_name and not request.pid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must specify process_name or pid",
        )

    try:
        success = containment.terminate_process(
            process_name=request.process_name,
            pid=request.pid,
            dry_run=request.dry_run,
        )

        identifier = request.process_name or f"PID {request.pid}"

        return ActionResult(
            action="terminate_process",
            success=success,
            message=f"Process {identifier} {'would be' if request.dry_run else ''} terminated"
            if success
            else f"Failed to terminate process {identifier}",
            dry_run=request.dry_run,
            details={"process_name": request.process_name, "pid": request.pid},
        )

    except Exception as e:
        logger.error(f"Terminate process failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Terminate process failed: {str(e)}",
        )


@router.post(
    "/actions/containment/disable-user",
    response_model=ActionResult,
    dependencies=[Depends(require_write_scope)],
)
async def disable_user(
    request: DisableUserRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Disable a compromised user account.
    """
    containment = get_containment_actions()

    try:
        success = containment.disable_user_account(
            username=request.username,
            dry_run=request.dry_run,
        )

        return ActionResult(
            action="disable_user_account",
            success=success,
            message=f"User {request.username} {'would be' if request.dry_run else ''} disabled"
            if success
            else f"Failed to disable user {request.username}",
            dry_run=request.dry_run,
            details={"username": request.username},
        )

    except Exception as e:
        logger.error(f"Disable user failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Disable user failed: {str(e)}",
        )


# =============================================================================
# Enrichment Action Endpoints
# =============================================================================


@router.post("/actions/enrichment/ioc", response_model=EnrichIOCResponse)
async def enrich_ioc(
    request: EnrichIOCRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Enrich an IOC with threat intelligence.

    Queries multiple threat intel sources for reputation data.
    """
    enrichment = get_enrichment_actions()

    try:
        result = enrichment.enrich_ioc(
            ioc=request.ioc,
            ioc_type=request.ioc_type,
            sources=request.sources,
        )

        return EnrichIOCResponse(
            ioc=result.get("ioc", request.ioc),
            type=result.get("type", request.ioc_type),
            reputation=result.get("reputation", "unknown"),
            sources=result.get("sources", {}),
        )

    except Exception as e:
        logger.error(f"IOC enrichment failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"IOC enrichment failed: {str(e)}",
        )


@router.get("/actions/enrichment/domain/{domain}", response_model=LookupDomainResponse)
async def lookup_domain(
    domain: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Perform DNS and WHOIS lookup on a domain.
    """
    enrichment = get_enrichment_actions()

    try:
        result = enrichment.lookup_domain(domain)

        return LookupDomainResponse(
            domain=result.get("domain", domain),
            resolved_ips=result.get("resolved_ips", []),
            whois=result.get("whois", {}),
        )

    except Exception as e:
        logger.error(f"Domain lookup failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Domain lookup failed: {str(e)}",
        )


@router.get("/actions/enrichment/geolocate/{ip}", response_model=GeolocateIPResponse)
async def geolocate_ip(
    ip: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Geolocate an IP address.
    """
    enrichment = get_enrichment_actions()

    try:
        result = enrichment.geolocate_ip(ip)

        return GeolocateIPResponse(
            ip=result.get("ip", ip),
            country=result.get("country", "Unknown"),
            city=result.get("city", "Unknown"),
            latitude=result.get("latitude"),
            longitude=result.get("longitude"),
        )

    except Exception as e:
        logger.error(f"Geolocation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Geolocation failed: {str(e)}",
        )


# =============================================================================
# Notification Action Endpoints
# =============================================================================


@router.post(
    "/actions/notification/email",
    response_model=ActionResult,
    dependencies=[Depends(require_write_scope)],
)
async def send_email(
    request: SendEmailRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Send email notification.
    """
    notification = get_notification_actions()

    try:
        success = notification.send_email(
            to=request.to,
            subject=request.subject,
            body=request.body,
            smtp_server=request.smtp_server,
            dry_run=request.dry_run,
        )

        return ActionResult(
            action="send_email",
            success=success,
            message=f"Email {'would be' if request.dry_run else ''} sent to {request.to}"
            if success
            else f"Failed to send email to {request.to}",
            dry_run=request.dry_run,
            details={"to": request.to, "subject": request.subject},
        )

    except Exception as e:
        logger.error(f"Send email failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Send email failed: {str(e)}",
        )


@router.post(
    "/actions/notification/slack",
    response_model=ActionResult,
    dependencies=[Depends(require_write_scope)],
)
async def send_slack(
    request: SendSlackRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Send Slack notification.
    """
    notification = get_notification_actions()

    try:
        success = notification.send_slack(
            webhook_url=request.webhook_url,
            message=request.message,
            dry_run=request.dry_run,
        )

        return ActionResult(
            action="send_slack",
            success=success,
            message=f"Slack message {'would be' if request.dry_run else ''} sent"
            if success
            else "Failed to send Slack message",
            dry_run=request.dry_run,
            details={"message_preview": request.message[:100]},
        )

    except Exception as e:
        logger.error(f"Send Slack failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Send Slack failed: {str(e)}",
        )


@router.post(
    "/actions/notification/webhook",
    response_model=ActionResult,
    dependencies=[Depends(require_write_scope)],
)
async def send_webhook(
    request: SendWebhookRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Send generic webhook notification.
    """
    notification = get_notification_actions()

    try:
        success = notification.send_webhook(
            url=request.url,
            payload=request.payload,
            dry_run=request.dry_run,
        )

        return ActionResult(
            action="send_webhook",
            success=success,
            message=f"Webhook {'would be' if request.dry_run else ''} sent to {request.url}"
            if success
            else f"Failed to send webhook to {request.url}",
            dry_run=request.dry_run,
            details={"url": request.url},
        )

    except Exception as e:
        logger.error(f"Send webhook failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Send webhook failed: {str(e)}",
        )


# =============================================================================
# Available Actions Endpoint
# =============================================================================


@router.get("/actions")
async def list_available_actions(
    current_user: str = Depends(get_current_active_user),
):
    """
    List all available automation actions.
    """
    return {
        "actions": {
            "containment": [
                {
                    "name": "isolate_host",
                    "description": "Isolate host from network",
                    "endpoint": "/actions/containment/isolate",
                },
                {
                    "name": "block_ip",
                    "description": "Block IP at firewall",
                    "endpoint": "/actions/containment/block-ip",
                },
                {
                    "name": "quarantine_file",
                    "description": "Quarantine suspicious file",
                    "endpoint": "/actions/containment/quarantine",
                },
                {
                    "name": "terminate_process",
                    "description": "Terminate suspicious process",
                    "endpoint": "/actions/containment/terminate",
                },
                {
                    "name": "disable_user",
                    "description": "Disable compromised user account",
                    "endpoint": "/actions/containment/disable-user",
                },
            ],
            "enrichment": [
                {
                    "name": "enrich_ioc",
                    "description": "Enrich IOC with threat intelligence",
                    "endpoint": "/actions/enrichment/ioc",
                },
                {
                    "name": "lookup_domain",
                    "description": "DNS and WHOIS lookup",
                    "endpoint": "/actions/enrichment/domain/{domain}",
                },
                {
                    "name": "geolocate_ip",
                    "description": "Geolocate IP address",
                    "endpoint": "/actions/enrichment/geolocate/{ip}",
                },
            ],
            "notification": [
                {
                    "name": "send_email",
                    "description": "Send email notification",
                    "endpoint": "/actions/notification/email",
                },
                {
                    "name": "send_slack",
                    "description": "Send Slack message",
                    "endpoint": "/actions/notification/slack",
                },
                {
                    "name": "send_webhook",
                    "description": "Send generic webhook",
                    "endpoint": "/actions/notification/webhook",
                },
            ],
        },
        "total": 11,
    }
