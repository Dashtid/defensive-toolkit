"""
Incident Response API Router

Endpoints for managing security incidents and executing IR playbooks.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime
import uuid

from api.models import (
    Incident, PlaybookExecutionRequest, PlaybookExecutionResponse,
    APIResponse, StatusEnum, IncidentStatusEnum
)
from api.dependencies import get_current_active_user, require_write_scope

router = APIRouter(prefix="/incident-response", tags=["Incident Response"])

# Mock database
incidents_db = {}
executions_db = {}


@router.get("/incidents", response_model=List[Incident])
async def list_incidents(
    status_filter: str = None,
    severity_filter: str = None,
    current_user: str = Depends(get_current_active_user),
):
    """List all incidents with optional filters."""
    incidents = list(incidents_db.values())

    if status_filter:
        incidents = [i for i in incidents if i.status == status_filter]
    if severity_filter:
        incidents = [i for i in incidents if i.severity == severity_filter]

    return incidents


@router.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident(
    incident_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get incident details."""
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
    """Create a new security incident."""
    incident.id = str(uuid.uuid4())
    incident.created_at = datetime.utcnow()
    incident.updated_at = datetime.utcnow()
    incident.status = IncidentStatusEnum.NEW

    incidents_db[incident.id] = incident

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
    """Update an existing incident."""
    if incident_id not in incidents_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found"
        )

    incident.id = incident_id
    incident.updated_at = datetime.utcnow()
    incidents_db[incident_id] = incident

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Incident updated successfully"
    )


@router.post("/playbooks/execute", response_model=PlaybookExecutionResponse)
async def execute_playbook(
    request: PlaybookExecutionRequest,
    current_user: str = Depends(require_write_scope),
):
    """Execute an incident response playbook."""
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

    executions_db[execution_id] = execution
    return execution


@router.get("/playbooks", response_model=List[dict])
async def list_playbooks(
    current_user: str = Depends(get_current_active_user),
):
    """List available IR playbooks."""
    return [
        {
            "name": "ransomware-response",
            "description": "Response playbook for ransomware incidents",
            "steps": 8
        },
        {
            "name": "phishing-response",
            "description": "Response playbook for phishing attacks",
            "steps": 6
        }
    ]
