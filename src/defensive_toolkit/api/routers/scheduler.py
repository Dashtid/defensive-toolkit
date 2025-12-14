"""
Scheduler API Router

Provides cron-like job scheduling for automated security operations including
vulnerability scans, compliance checks, SIEM health monitoring, and reporting.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status

from defensive_toolkit.api.auth import get_current_active_user
from defensive_toolkit.api.models import (
    APIResponse,
    BulkJobActionRequest,
    BulkJobActionResponse,
    CronValidationRequest,
    CronValidationResponse,
    JobCancelResponse,
    JobDependency,
    JobDependencyResponse,
    JobExecution,
    JobExecutionListResponse,
    JobExecutionResponse,
    JobExecutionStatusEnum,
    JobTypeInfo,
    JobTypeListResponse,
    ScheduledJobConfig,
    ScheduledJobCreateRequest,
    ScheduledJobListResponse,
    ScheduledJobResponse,
    ScheduledJobStatusEnum,
    ScheduledJobTypeEnum,
    ScheduledJobUpdateRequest,
    SchedulerHealthCheck,
    SchedulerStats,
    ScheduleTypeEnum,
    StatusEnum,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scheduler", tags=["Scheduler"])


# ============================================================================
# In-Memory Storage (Production: Use database + Redis for queue)
# ============================================================================

scheduled_jobs: Dict[str, ScheduledJobConfig] = {}
job_executions: Dict[str, JobExecution] = {}
job_dependencies: Dict[str, List[JobDependency]] = {}
job_stats: Dict[str, Dict[str, int]] = {}  # job_id -> {total, success, failed}

# Scheduler state
scheduler_state = {
    "status": "running",
    "started_at": datetime.utcnow(),
    "last_heartbeat": datetime.utcnow(),
    "worker_count": 4,
}

# Execution queue (production: use Redis or RabbitMQ)
execution_queue: List[str] = []
running_executions: Dict[str, str] = {}  # execution_id -> job_id


# ============================================================================
# Job Type Definitions
# ============================================================================

JOB_TYPE_INFO: Dict[ScheduledJobTypeEnum, Dict[str, Any]] = {
    ScheduledJobTypeEnum.VULNERABILITY_SCAN: {
        "name": "Vulnerability Scan",
        "description": "Run vulnerability scans using configured scanners",
        "category": "Security Scans",
        "required_parameters": ["target"],
        "optional_parameters": ["scanner", "scan_type", "severity_threshold"],
        "parameter_schema": {
            "target": {"type": "string", "description": "Target IP, hostname, or CIDR"},
            "scanner": {"type": "string", "enum": ["trivy", "openvas", "nmap"]},
            "scan_type": {"type": "string", "enum": ["quick", "full", "compliance"]},
            "severity_threshold": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        },
        "default_timeout_seconds": 3600,
        "supports_concurrent": True,
        "example_parameters": {
            "target": "192.168.1.0/24",
            "scanner": "trivy",
            "scan_type": "full",
        },
    },
    ScheduledJobTypeEnum.COMPLIANCE_CHECK: {
        "name": "Compliance Check",
        "description": "Run compliance checks against security frameworks",
        "category": "Security Scans",
        "required_parameters": ["framework"],
        "optional_parameters": ["target_systems", "controls"],
        "parameter_schema": {
            "framework": {"type": "string", "enum": ["cis", "nist", "pci-dss", "hipaa", "soc2"]},
            "target_systems": {"type": "array", "items": {"type": "string"}},
            "controls": {"type": "array", "items": {"type": "string"}},
        },
        "default_timeout_seconds": 1800,
        "supports_concurrent": True,
        "example_parameters": {
            "framework": "cis",
            "target_systems": ["server-01", "server-02"],
        },
    },
    ScheduledJobTypeEnum.HARDENING_AUDIT: {
        "name": "Hardening Audit",
        "description": "Audit system hardening configuration",
        "category": "Security Scans",
        "required_parameters": [],
        "optional_parameters": ["target_hosts", "audit_level"],
        "parameter_schema": {
            "target_hosts": {"type": "array", "items": {"type": "string"}},
            "audit_level": {"type": "string", "enum": ["basic", "standard", "comprehensive"]},
        },
        "default_timeout_seconds": 1800,
        "supports_concurrent": True,
        "example_parameters": {
            "audit_level": "standard",
        },
    },
    ScheduledJobTypeEnum.SIEM_HEALTH_CHECK: {
        "name": "SIEM Health Check",
        "description": "Check health of all configured SIEM connections",
        "category": "SIEM Operations",
        "required_parameters": [],
        "optional_parameters": ["connection_ids", "include_metrics"],
        "parameter_schema": {
            "connection_ids": {"type": "array", "items": {"type": "string"}},
            "include_metrics": {"type": "boolean"},
        },
        "default_timeout_seconds": 300,
        "supports_concurrent": False,
        "example_parameters": {
            "include_metrics": True,
        },
    },
    ScheduledJobTypeEnum.SIEM_ALERT_DIGEST: {
        "name": "SIEM Alert Digest",
        "description": "Generate digest of SIEM alerts for specified period",
        "category": "SIEM Operations",
        "required_parameters": ["connection_id"],
        "optional_parameters": ["hours", "severity_min", "send_email"],
        "parameter_schema": {
            "connection_id": {"type": "string"},
            "hours": {"type": "integer", "minimum": 1, "maximum": 168},
            "severity_min": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "send_email": {"type": "boolean"},
        },
        "default_timeout_seconds": 600,
        "supports_concurrent": True,
        "example_parameters": {
            "connection_id": "SIEM-001",
            "hours": 24,
            "severity_min": "medium",
        },
    },
    ScheduledJobTypeEnum.SIEM_AGENT_STATUS: {
        "name": "SIEM Agent Status",
        "description": "Check status of SIEM agents and report disconnected",
        "category": "SIEM Operations",
        "required_parameters": ["connection_id"],
        "optional_parameters": ["alert_on_disconnected", "disconnected_threshold_minutes"],
        "parameter_schema": {
            "connection_id": {"type": "string"},
            "alert_on_disconnected": {"type": "boolean"},
            "disconnected_threshold_minutes": {"type": "integer", "minimum": 5},
        },
        "default_timeout_seconds": 300,
        "supports_concurrent": True,
        "example_parameters": {
            "connection_id": "SIEM-001",
            "alert_on_disconnected": True,
            "disconnected_threshold_minutes": 30,
        },
    },
    ScheduledJobTypeEnum.IOC_ENRICHMENT: {
        "name": "IOC Enrichment",
        "description": "Enrich IOCs from threat intel feeds or SIEM alerts",
        "category": "Threat Intelligence",
        "required_parameters": ["source"],
        "optional_parameters": ["ioc_types", "sources", "max_iocs"],
        "parameter_schema": {
            "source": {"type": "string", "enum": ["siem_alerts", "threat_feed", "manual_list"]},
            "ioc_types": {"type": "array", "items": {"type": "string"}},
            "sources": {"type": "array", "items": {"type": "string"}},
            "max_iocs": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        "default_timeout_seconds": 1800,
        "supports_concurrent": False,
        "example_parameters": {
            "source": "siem_alerts",
            "ioc_types": ["ip", "domain", "hash"],
            "max_iocs": 100,
        },
    },
    ScheduledJobTypeEnum.THREAT_FEED_UPDATE: {
        "name": "Threat Feed Update",
        "description": "Update threat intelligence feeds",
        "category": "Threat Intelligence",
        "required_parameters": [],
        "optional_parameters": ["feed_ids", "force_refresh"],
        "parameter_schema": {
            "feed_ids": {"type": "array", "items": {"type": "string"}},
            "force_refresh": {"type": "boolean"},
        },
        "default_timeout_seconds": 600,
        "supports_concurrent": False,
        "example_parameters": {
            "force_refresh": False,
        },
    },
    ScheduledJobTypeEnum.SECURITY_REPORT: {
        "name": "Security Report",
        "description": "Generate comprehensive security report",
        "category": "Reporting",
        "required_parameters": ["report_type"],
        "optional_parameters": ["format", "recipients", "include_sections"],
        "parameter_schema": {
            "report_type": {"type": "string", "enum": ["daily", "weekly", "monthly", "executive"]},
            "format": {"type": "string", "enum": ["pdf", "html", "json"]},
            "recipients": {"type": "array", "items": {"type": "string", "format": "email"}},
            "include_sections": {"type": "array", "items": {"type": "string"}},
        },
        "default_timeout_seconds": 1800,
        "supports_concurrent": True,
        "example_parameters": {
            "report_type": "weekly",
            "format": "pdf",
            "recipients": ["security@company.com"],
        },
    },
    ScheduledJobTypeEnum.INCIDENT_SUMMARY: {
        "name": "Incident Summary",
        "description": "Generate summary of incidents for specified period",
        "category": "Reporting",
        "required_parameters": [],
        "optional_parameters": ["hours", "status_filter", "severity_filter"],
        "parameter_schema": {
            "hours": {"type": "integer", "minimum": 1, "maximum": 720},
            "status_filter": {"type": "array", "items": {"type": "string"}},
            "severity_filter": {"type": "array", "items": {"type": "string"}},
        },
        "default_timeout_seconds": 600,
        "supports_concurrent": True,
        "example_parameters": {
            "hours": 24,
        },
    },
    ScheduledJobTypeEnum.METRICS_EXPORT: {
        "name": "Metrics Export",
        "description": "Export security metrics to external systems",
        "category": "Reporting",
        "required_parameters": ["destination"],
        "optional_parameters": ["metrics", "format"],
        "parameter_schema": {
            "destination": {
                "type": "string",
                "enum": ["prometheus", "influxdb", "elasticsearch", "file"],
            },
            "metrics": {"type": "array", "items": {"type": "string"}},
            "format": {"type": "string", "enum": ["json", "csv", "prometheus"]},
        },
        "default_timeout_seconds": 300,
        "supports_concurrent": True,
        "example_parameters": {
            "destination": "prometheus",
        },
    },
    ScheduledJobTypeEnum.LOG_CLEANUP: {
        "name": "Log Cleanup",
        "description": "Clean up old logs and temporary files",
        "category": "Maintenance",
        "required_parameters": [],
        "optional_parameters": ["retention_days", "log_types", "dry_run"],
        "parameter_schema": {
            "retention_days": {"type": "integer", "minimum": 1, "maximum": 365},
            "log_types": {"type": "array", "items": {"type": "string"}},
            "dry_run": {"type": "boolean"},
        },
        "default_timeout_seconds": 1800,
        "supports_concurrent": False,
        "example_parameters": {
            "retention_days": 30,
            "dry_run": True,
        },
    },
    ScheduledJobTypeEnum.CACHE_CLEANUP: {
        "name": "Cache Cleanup",
        "description": "Clean expired cache entries",
        "category": "Maintenance",
        "required_parameters": [],
        "optional_parameters": ["cache_types", "force_all"],
        "parameter_schema": {
            "cache_types": {"type": "array", "items": {"type": "string"}},
            "force_all": {"type": "boolean"},
        },
        "default_timeout_seconds": 300,
        "supports_concurrent": False,
        "example_parameters": {
            "cache_types": ["ioc_cache", "siem_cache"],
        },
    },
    ScheduledJobTypeEnum.BACKUP: {
        "name": "Backup",
        "description": "Backup configuration and data",
        "category": "Maintenance",
        "required_parameters": ["backup_type"],
        "optional_parameters": ["destination", "compress", "encrypt"],
        "parameter_schema": {
            "backup_type": {"type": "string", "enum": ["full", "incremental", "config_only"]},
            "destination": {"type": "string"},
            "compress": {"type": "boolean"},
            "encrypt": {"type": "boolean"},
        },
        "default_timeout_seconds": 3600,
        "supports_concurrent": False,
        "example_parameters": {
            "backup_type": "full",
            "compress": True,
        },
    },
    ScheduledJobTypeEnum.RUNBOOK_EXECUTION: {
        "name": "Runbook Execution",
        "description": "Execute an incident response runbook on schedule",
        "category": "Runbooks",
        "required_parameters": ["runbook_id"],
        "optional_parameters": ["variables", "mode", "auto_approve"],
        "parameter_schema": {
            "runbook_id": {"type": "string"},
            "variables": {"type": "object"},
            "mode": {"type": "string", "enum": ["dry_run", "normal", "auto"]},
            "auto_approve": {"type": "string", "enum": ["none", "low", "medium", "high"]},
        },
        "default_timeout_seconds": 3600,
        "supports_concurrent": False,
        "example_parameters": {
            "runbook_id": "credential_compromise",
            "mode": "dry_run",
        },
    },
    ScheduledJobTypeEnum.WEBHOOK_CALL: {
        "name": "Webhook Call",
        "description": "Call an external webhook on schedule",
        "category": "Custom",
        "required_parameters": ["url"],
        "optional_parameters": ["method", "headers", "body", "timeout"],
        "parameter_schema": {
            "url": {"type": "string", "format": "uri"},
            "method": {"type": "string", "enum": ["GET", "POST", "PUT"]},
            "headers": {"type": "object"},
            "body": {"type": "object"},
            "timeout": {"type": "integer", "minimum": 5, "maximum": 300},
        },
        "default_timeout_seconds": 60,
        "supports_concurrent": True,
        "example_parameters": {
            "url": "https://api.example.com/webhook",
            "method": "POST",
        },
    },
    ScheduledJobTypeEnum.CUSTOM_SCRIPT: {
        "name": "Custom Script",
        "description": "Execute a custom script (Python or shell)",
        "category": "Custom",
        "required_parameters": ["script_path"],
        "optional_parameters": ["arguments", "environment", "working_directory"],
        "parameter_schema": {
            "script_path": {"type": "string"},
            "arguments": {"type": "array", "items": {"type": "string"}},
            "environment": {"type": "object"},
            "working_directory": {"type": "string"},
        },
        "default_timeout_seconds": 1800,
        "supports_concurrent": False,
        "example_parameters": {
            "script_path": "/opt/scripts/custom_check.py",
            "arguments": ["--verbose"],
        },
    },
}


# ============================================================================
# Helper Functions
# ============================================================================


def generate_job_id() -> str:
    """Generate unique job ID"""
    import uuid

    timestamp = datetime.utcnow().strftime("%Y%m%d")
    short_uuid = str(uuid.uuid4())[:8].upper()
    return f"JOB-{timestamp}-{short_uuid}"


def generate_execution_id() -> str:
    """Generate unique execution ID"""
    import uuid

    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    short_uuid = str(uuid.uuid4())[:6].upper()
    return f"EXEC-{timestamp}-{short_uuid}"


def parse_cron_expression(cron_expr: str) -> Dict[str, Any]:
    """Parse and validate cron expression"""
    # Simple cron parser (production: use croniter library)
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError("Cron expression must have 5 parts: minute hour day month weekday")

    field_names = ["minute", "hour", "day", "month", "weekday"]
    result = {}

    for i, (part, name) in enumerate(zip(parts, field_names)):
        result[name] = part

    return result


def get_next_run_time(job: ScheduledJobConfig) -> Optional[datetime]:
    """Calculate next run time for a job"""
    now = datetime.utcnow()

    if job.schedule_type == ScheduleTypeEnum.ONCE:
        if job.run_at and job.run_at > now:
            return job.run_at
        return None

    elif job.schedule_type == ScheduleTypeEnum.INTERVAL:
        if job.interval_seconds:
            if job.last_run_at:
                return job.last_run_at + timedelta(seconds=job.interval_seconds)
            return now + timedelta(seconds=job.interval_seconds)

    elif job.schedule_type == ScheduleTypeEnum.CRON:
        # Simplified: return next hour (production: use croniter)
        if job.cron_expression:
            next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
            return next_run

    return None


def describe_cron(cron_expr: str) -> str:
    """Generate human-readable description of cron expression"""
    # Simplified descriptions (production: use cron-descriptor library)
    common_patterns = {
        "* * * * *": "Every minute",
        "*/5 * * * *": "Every 5 minutes",
        "*/15 * * * *": "Every 15 minutes",
        "*/30 * * * *": "Every 30 minutes",
        "0 * * * *": "Every hour",
        "0 */2 * * *": "Every 2 hours",
        "0 */6 * * *": "Every 6 hours",
        "0 */12 * * *": "Every 12 hours",
        "0 0 * * *": "Daily at midnight",
        "0 6 * * *": "Daily at 6:00 AM",
        "0 0 * * 0": "Weekly on Sunday at midnight",
        "0 0 * * 1": "Weekly on Monday at midnight",
        "0 0 1 * *": "Monthly on the 1st at midnight",
    }

    if cron_expr in common_patterns:
        return common_patterns[cron_expr]

    return f"Custom schedule: {cron_expr}"


async def execute_job(job: ScheduledJobConfig, execution: JobExecution) -> Dict[str, Any]:
    """Execute a scheduled job (simulated)"""
    # In production, this would dispatch to actual job handlers
    logger.info(f"Executing job {job.job_id}: {job.name} (type: {job.job_type})")

    # Simulate job execution
    await asyncio.sleep(1)

    # Return simulated result
    return {
        "status": "completed",
        "items_processed": 10,
        "items_succeeded": 9,
        "items_failed": 1,
        "details": f"Simulated execution of {job.job_type.value}",
    }


# ============================================================================
# Job Management Endpoints
# ============================================================================


@router.get("/jobs", response_model=ScheduledJobListResponse)
async def list_scheduled_jobs(
    status: Optional[ScheduledJobStatusEnum] = None,
    job_type: Optional[ScheduledJobTypeEnum] = None,
    tag: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: str = Depends(get_current_active_user),
):
    """List all scheduled jobs with optional filtering."""
    jobs_list = list(scheduled_jobs.values())

    # Apply filters
    if status:
        jobs_list = [j for j in jobs_list if j.status == status]
    if job_type:
        jobs_list = [j for j in jobs_list if j.job_type == job_type]
    if tag:
        jobs_list = [j for j in jobs_list if tag in j.tags]

    # Calculate counts
    active_count = len(
        [j for j in scheduled_jobs.values() if j.status == ScheduledJobStatusEnum.ACTIVE]
    )
    paused_count = len(
        [j for j in scheduled_jobs.values() if j.status == ScheduledJobStatusEnum.PAUSED]
    )
    disabled_count = len(
        [j for j in scheduled_jobs.values() if j.status == ScheduledJobStatusEnum.DISABLED]
    )

    # Paginate
    total = len(jobs_list)
    jobs_list = jobs_list[offset : offset + limit]

    # Convert to response format
    job_responses = []
    for job in jobs_list:
        stats = job_stats.get(job.job_id, {"total": 0, "success": 0, "failed": 0})
        last_exec = None
        last_status = None

        # Find last execution
        job_execs = [e for e in job_executions.values() if e.job_id == job.job_id]
        if job_execs:
            last_exec_obj = max(job_execs, key=lambda x: x.scheduled_at)
            last_exec = last_exec_obj.completed_at or last_exec_obj.started_at
            last_status = last_exec_obj.status

        job_responses.append(
            ScheduledJobResponse(
                job_id=job.job_id,
                name=job.name,
                description=job.description,
                job_type=job.job_type,
                status=job.status,
                priority=job.priority,
                schedule_type=job.schedule_type,
                cron_expression=job.cron_expression,
                interval_seconds=job.interval_seconds,
                timezone=job.timezone,
                next_run_at=get_next_run_time(job),
                last_run_at=last_exec,
                last_run_status=last_status,
                total_runs=stats["total"],
                successful_runs=stats["success"],
                failed_runs=stats["failed"],
                created_at=job.created_at or datetime.utcnow(),
                updated_at=job.updated_at,
                created_by=job.created_by,
            )
        )

    return ScheduledJobListResponse(
        jobs=job_responses,
        total=total,
        active_count=active_count,
        paused_count=paused_count,
        disabled_count=disabled_count,
    )


@router.get("/jobs/{job_id}", response_model=ScheduledJobConfig)
async def get_scheduled_job(
    job_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get details of a specific scheduled job."""
    if job_id not in scheduled_jobs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")

    job = scheduled_jobs[job_id]
    job.next_run_at = get_next_run_time(job)
    return job


@router.post("/jobs", response_model=ScheduledJobResponse, status_code=status.HTTP_201_CREATED)
async def create_scheduled_job(
    request: ScheduledJobCreateRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Create a new scheduled job."""
    # Validate schedule configuration
    if request.schedule_type == ScheduleTypeEnum.CRON:
        if not request.cron_expression:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cron_expression required for cron schedule type",
            )
        try:
            parse_cron_expression(request.cron_expression)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid cron expression: {str(e)}"
            )

    elif request.schedule_type == ScheduleTypeEnum.INTERVAL:
        if not request.interval_seconds:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="interval_seconds required for interval schedule type",
            )

    elif request.schedule_type == ScheduleTypeEnum.ONCE:
        if not request.run_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="run_at required for one-time schedule",
            )
        if request.run_at <= datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="run_at must be in the future"
            )

    # Create job
    job_id = generate_job_id()
    now = datetime.utcnow()

    job = ScheduledJobConfig(
        job_id=job_id,
        name=request.name,
        description=request.description,
        job_type=request.job_type,
        status=ScheduledJobStatusEnum.ACTIVE,
        priority=request.priority,
        schedule_type=request.schedule_type,
        cron_expression=request.cron_expression,
        interval_seconds=request.interval_seconds,
        run_at=request.run_at,
        timezone=request.timezone,
        timeout_seconds=request.timeout_seconds,
        max_retries=request.max_retries,
        retry_delay_seconds=request.retry_delay_seconds,
        concurrent_allowed=request.concurrent_allowed,
        parameters=request.parameters,
        notify_on_success=request.notify_on_success,
        notify_on_failure=request.notify_on_failure,
        notification_channels=request.notification_channels,
        notification_emails=request.notification_emails,
        valid_from=request.valid_from,
        valid_until=request.valid_until,
        tags=request.tags,
        created_at=now,
        created_by=current_user,
    )

    scheduled_jobs[job_id] = job
    job_stats[job_id] = {"total": 0, "success": 0, "failed": 0}

    logger.info(f"Created scheduled job {job_id}: {job.name}")

    return ScheduledJobResponse(
        job_id=job_id,
        name=job.name,
        description=job.description,
        job_type=job.job_type,
        status=job.status,
        priority=job.priority,
        schedule_type=job.schedule_type,
        cron_expression=job.cron_expression,
        interval_seconds=job.interval_seconds,
        timezone=job.timezone,
        next_run_at=get_next_run_time(job),
        last_run_at=None,
        last_run_status=None,
        total_runs=0,
        successful_runs=0,
        failed_runs=0,
        created_at=now,
        updated_at=None,
        created_by=current_user,
    )


@router.put("/jobs/{job_id}", response_model=ScheduledJobResponse)
async def update_scheduled_job(
    job_id: str,
    request: ScheduledJobUpdateRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Update an existing scheduled job."""
    if job_id not in scheduled_jobs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")

    job = scheduled_jobs[job_id]
    now = datetime.utcnow()

    # Update fields if provided
    if request.name is not None:
        job.name = request.name
    if request.description is not None:
        job.description = request.description
    if request.status is not None:
        job.status = request.status
    if request.priority is not None:
        job.priority = request.priority
    if request.cron_expression is not None:
        try:
            parse_cron_expression(request.cron_expression)
            job.cron_expression = request.cron_expression
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid cron expression: {str(e)}"
            )
    if request.interval_seconds is not None:
        job.interval_seconds = request.interval_seconds
    if request.run_at is not None:
        job.run_at = request.run_at
    if request.timezone is not None:
        job.timezone = request.timezone
    if request.timeout_seconds is not None:
        job.timeout_seconds = request.timeout_seconds
    if request.max_retries is not None:
        job.max_retries = request.max_retries
    if request.retry_delay_seconds is not None:
        job.retry_delay_seconds = request.retry_delay_seconds
    if request.concurrent_allowed is not None:
        job.concurrent_allowed = request.concurrent_allowed
    if request.parameters is not None:
        job.parameters = request.parameters
    if request.notify_on_success is not None:
        job.notify_on_success = request.notify_on_success
    if request.notify_on_failure is not None:
        job.notify_on_failure = request.notify_on_failure
    if request.notification_channels is not None:
        job.notification_channels = request.notification_channels
    if request.notification_emails is not None:
        job.notification_emails = request.notification_emails
    if request.valid_from is not None:
        job.valid_from = request.valid_from
    if request.valid_until is not None:
        job.valid_until = request.valid_until
    if request.tags is not None:
        job.tags = request.tags

    job.updated_at = now

    stats = job_stats.get(job_id, {"total": 0, "success": 0, "failed": 0})

    logger.info(f"Updated scheduled job {job_id}")

    return ScheduledJobResponse(
        job_id=job_id,
        name=job.name,
        description=job.description,
        job_type=job.job_type,
        status=job.status,
        priority=job.priority,
        schedule_type=job.schedule_type,
        cron_expression=job.cron_expression,
        interval_seconds=job.interval_seconds,
        timezone=job.timezone,
        next_run_at=get_next_run_time(job),
        last_run_at=job.last_run_at,
        last_run_status=None,
        total_runs=stats["total"],
        successful_runs=stats["success"],
        failed_runs=stats["failed"],
        created_at=job.created_at or now,
        updated_at=now,
        created_by=job.created_by,
    )


@router.delete("/jobs/{job_id}", response_model=APIResponse)
async def delete_scheduled_job(
    job_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Delete a scheduled job."""
    if job_id not in scheduled_jobs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")

    # Check for running executions
    running = [
        e
        for e in job_executions.values()
        if e.job_id == job_id and e.status == JobExecutionStatusEnum.RUNNING
    ]
    if running:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete job with running executions. Cancel them first.",
        )

    job = scheduled_jobs.pop(job_id)
    job_stats.pop(job_id, None)

    logger.info(f"Deleted scheduled job {job_id}: {job.name}")

    return APIResponse(status=StatusEnum.SUCCESS, message=f"Job {job_id} deleted successfully")


@router.post("/jobs/{job_id}/pause", response_model=APIResponse)
async def pause_job(
    job_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Pause a scheduled job."""
    if job_id not in scheduled_jobs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")

    job = scheduled_jobs[job_id]
    job.status = ScheduledJobStatusEnum.PAUSED
    job.updated_at = datetime.utcnow()

    logger.info(f"Paused job {job_id}")

    return APIResponse(status=StatusEnum.SUCCESS, message=f"Job {job_id} paused")


@router.post("/jobs/{job_id}/resume", response_model=APIResponse)
async def resume_job(
    job_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Resume a paused scheduled job."""
    if job_id not in scheduled_jobs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")

    job = scheduled_jobs[job_id]
    if job.status != ScheduledJobStatusEnum.PAUSED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Job is not paused (current status: {job.status})",
        )

    job.status = ScheduledJobStatusEnum.ACTIVE
    job.updated_at = datetime.utcnow()

    logger.info(f"Resumed job {job_id}")

    return APIResponse(status=StatusEnum.SUCCESS, message=f"Job {job_id} resumed")


# ============================================================================
# Job Execution Endpoints
# ============================================================================


@router.post("/jobs/{job_id}/run", response_model=JobExecutionResponse)
async def trigger_job(
    job_id: str,
    background_tasks: BackgroundTasks,
    parameters: Optional[Dict[str, Any]] = None,
    skip_queue: bool = False,
    current_user: str = Depends(get_current_active_user),
):
    """Manually trigger a job execution."""
    if job_id not in scheduled_jobs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")

    job = scheduled_jobs[job_id]

    # Check if concurrent execution is allowed
    if not job.concurrent_allowed:
        running = [
            e
            for e in job_executions.values()
            if e.job_id == job_id and e.status == JobExecutionStatusEnum.RUNNING
        ]
        if running:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Job is already running and concurrent execution is disabled",
            )

    # Create execution record
    execution_id = generate_execution_id()
    now = datetime.utcnow()

    execution = JobExecution(
        execution_id=execution_id,
        job_id=job_id,
        job_name=job.name,
        job_type=job.job_type,
        status=JobExecutionStatusEnum.PENDING,
        priority=job.priority,
        scheduled_at=now,
        triggered_by="manual",
        parameters=parameters or job.parameters,
    )

    job_executions[execution_id] = execution

    # Execute in background
    async def run_job():
        exec_record = job_executions[execution_id]
        exec_record.status = JobExecutionStatusEnum.RUNNING
        exec_record.started_at = datetime.utcnow()
        running_executions[execution_id] = job_id

        try:
            result = await execute_job(job, exec_record)
            exec_record.status = JobExecutionStatusEnum.COMPLETED
            exec_record.result = result
            exec_record.items_processed = result.get("items_processed")
            exec_record.items_succeeded = result.get("items_succeeded")
            exec_record.items_failed = result.get("items_failed")

            # Update stats
            stats = job_stats.setdefault(job_id, {"total": 0, "success": 0, "failed": 0})
            stats["total"] += 1
            stats["success"] += 1

        except Exception as e:
            exec_record.status = JobExecutionStatusEnum.FAILED
            exec_record.error_message = str(e)

            stats = job_stats.setdefault(job_id, {"total": 0, "success": 0, "failed": 0})
            stats["total"] += 1
            stats["failed"] += 1

        finally:
            exec_record.completed_at = datetime.utcnow()
            exec_record.duration_seconds = (
                exec_record.completed_at - exec_record.started_at
            ).total_seconds()
            running_executions.pop(execution_id, None)
            job.last_run_at = exec_record.completed_at

    background_tasks.add_task(run_job)

    logger.info(f"Triggered job {job_id}, execution {execution_id}")

    return JobExecutionResponse(
        execution_id=execution_id,
        job_id=job_id,
        job_name=job.name,
        status=JobExecutionStatusEnum.PENDING,
        scheduled_at=now,
        message="Job triggered successfully",
    )


@router.get("/executions", response_model=JobExecutionListResponse)
async def list_executions(
    job_id: Optional[str] = None,
    status_filter: Optional[JobExecutionStatusEnum] = None,
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: str = Depends(get_current_active_user),
):
    """List job executions with filtering."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    execs = [e for e in job_executions.values() if e.scheduled_at >= cutoff]

    if job_id:
        execs = [e for e in execs if e.job_id == job_id]
    if status_filter:
        execs = [e for e in execs if e.status == status_filter]

    # Sort by scheduled_at descending
    execs.sort(key=lambda x: x.scheduled_at, reverse=True)

    total = len(execs)
    running_count = len([e for e in execs if e.status == JobExecutionStatusEnum.RUNNING])
    pending_count = len([e for e in execs if e.status == JobExecutionStatusEnum.PENDING])

    execs = execs[offset : offset + limit]

    return JobExecutionListResponse(
        executions=execs,
        total=total,
        running_count=running_count,
        pending_count=pending_count,
    )


@router.get("/executions/{execution_id}", response_model=JobExecution)
async def get_execution(
    execution_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get details of a specific execution."""
    if execution_id not in job_executions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Execution {execution_id} not found"
        )

    return job_executions[execution_id]


@router.post("/executions/{execution_id}/cancel", response_model=JobCancelResponse)
async def cancel_execution(
    execution_id: str,
    reason: Optional[str] = None,
    current_user: str = Depends(get_current_active_user),
):
    """Cancel a running or pending execution."""
    if execution_id not in job_executions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Execution {execution_id} not found"
        )

    execution = job_executions[execution_id]
    previous_status = execution.status

    if execution.status not in [JobExecutionStatusEnum.PENDING, JobExecutionStatusEnum.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel execution in status {execution.status}",
        )

    execution.status = JobExecutionStatusEnum.CANCELLED
    execution.completed_at = datetime.utcnow()
    execution.error_message = reason or "Cancelled by user"
    running_executions.pop(execution_id, None)

    logger.info(f"Cancelled execution {execution_id}")

    return JobCancelResponse(
        execution_id=execution_id,
        cancelled=True,
        message="Execution cancelled successfully",
        previous_status=previous_status,
    )


# ============================================================================
# Scheduler Management Endpoints
# ============================================================================


@router.get("/stats", response_model=SchedulerStats)
async def get_scheduler_stats(
    current_user: str = Depends(get_current_active_user),
):
    """Get scheduler statistics."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    hour_start = now.replace(minute=0, second=0, microsecond=0)

    # Calculate execution stats
    today_execs = [e for e in job_executions.values() if e.scheduled_at >= today_start]
    hour_execs = [e for e in job_executions.values() if e.scheduled_at >= hour_start]

    executions_by_type = {}
    failures_by_type = {}
    for e in today_execs:
        type_name = e.job_type.value
        executions_by_type[type_name] = executions_by_type.get(type_name, 0) + 1
        if e.status == JobExecutionStatusEnum.FAILED:
            failures_by_type[type_name] = failures_by_type.get(type_name, 0) + 1

    # Calculate average execution time
    completed = [e for e in today_execs if e.duration_seconds is not None]
    avg_execution_time = 0.0
    if completed:
        avg_execution_time = sum(e.duration_seconds for e in completed) / len(completed)

    # Find next scheduled job
    next_job = None
    next_time = None
    for job in scheduled_jobs.values():
        if job.status == ScheduledJobStatusEnum.ACTIVE:
            next_run = get_next_run_time(job)
            if next_run and (next_time is None or next_run < next_time):
                next_time = next_run
                next_job = job.name

    uptime = (now - scheduler_state["started_at"]).total_seconds()

    return SchedulerStats(
        scheduler_status=scheduler_state["status"],
        uptime_seconds=int(uptime),
        jobs_total=len(scheduled_jobs),
        jobs_active=len(
            [j for j in scheduled_jobs.values() if j.status == ScheduledJobStatusEnum.ACTIVE]
        ),
        jobs_paused=len(
            [j for j in scheduled_jobs.values() if j.status == ScheduledJobStatusEnum.PAUSED]
        ),
        jobs_disabled=len(
            [j for j in scheduled_jobs.values() if j.status == ScheduledJobStatusEnum.DISABLED]
        ),
        executions_today=len(today_execs),
        executions_this_hour=len(hour_execs),
        successful_today=len(
            [e for e in today_execs if e.status == JobExecutionStatusEnum.COMPLETED]
        ),
        failed_today=len([e for e in today_execs if e.status == JobExecutionStatusEnum.FAILED]),
        cancelled_today=len(
            [e for e in today_execs if e.status == JobExecutionStatusEnum.CANCELLED]
        ),
        queue_length=len(execution_queue),
        running_jobs=len(running_executions),
        pending_jobs=len(
            [e for e in job_executions.values() if e.status == JobExecutionStatusEnum.PENDING]
        ),
        average_execution_time_seconds=avg_execution_time,
        average_wait_time_seconds=0.0,  # Would need queue timing
        jobs_per_hour=len(hour_execs),
        executions_by_type=executions_by_type,
        failures_by_type=failures_by_type,
        last_execution_at=max(
            (e.completed_at for e in job_executions.values() if e.completed_at), default=None
        ),
        next_scheduled_job=next_job,
        next_scheduled_at=next_time,
    )


@router.get("/health", response_model=SchedulerHealthCheck)
async def scheduler_health_check(
    current_user: str = Depends(get_current_active_user),
):
    """Check scheduler health."""
    checks = {
        "scheduler_running": scheduler_state["status"] == "running",
        "queue_accessible": True,  # Would check Redis/RabbitMQ in production
        "storage_accessible": True,  # Would check database in production
        "workers_healthy": scheduler_state["worker_count"] > 0,
    }

    healthy = all(checks.values())

    return SchedulerHealthCheck(
        healthy=healthy,
        status=scheduler_state["status"],
        checks=checks,
        message="All checks passed" if healthy else "Some checks failed",
        last_heartbeat=scheduler_state["last_heartbeat"],
        worker_count=scheduler_state["worker_count"],
        queue_healthy=checks["queue_accessible"],
        storage_healthy=checks["storage_accessible"],
    )


@router.post("/pause", response_model=APIResponse)
async def pause_scheduler(
    current_user: str = Depends(get_current_active_user),
):
    """Pause the scheduler (stops scheduling new jobs)."""
    scheduler_state["status"] = "paused"
    logger.info("Scheduler paused")

    return APIResponse(
        status=StatusEnum.SUCCESS, message="Scheduler paused. Running jobs will complete."
    )


@router.post("/resume", response_model=APIResponse)
async def resume_scheduler(
    current_user: str = Depends(get_current_active_user),
):
    """Resume a paused scheduler."""
    scheduler_state["status"] = "running"
    scheduler_state["last_heartbeat"] = datetime.utcnow()
    logger.info("Scheduler resumed")

    return APIResponse(status=StatusEnum.SUCCESS, message="Scheduler resumed")


# ============================================================================
# Utility Endpoints
# ============================================================================


@router.post("/cron/validate", response_model=CronValidationResponse)
async def validate_cron(
    request: CronValidationRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Validate a cron expression and show next run times."""
    try:
        parse_cron_expression(request.cron_expression)
        valid = True
        error = None
        description = describe_cron(request.cron_expression)

        # Generate next run times (simplified)
        now = datetime.utcnow()
        next_runs = []
        for i in range(request.count):
            next_run = now + timedelta(hours=i + 1)
            next_runs.append(next_run)

    except ValueError as e:
        valid = False
        error = str(e)
        description = ""
        next_runs = []

    return CronValidationResponse(
        valid=valid,
        expression=request.cron_expression,
        description=description,
        timezone=request.timezone,
        next_runs=next_runs,
        error=error,
    )


@router.get("/job-types", response_model=JobTypeListResponse)
async def list_job_types(
    current_user: str = Depends(get_current_active_user),
):
    """List all available job types with their parameters."""
    job_types = []
    categories = set()

    for job_type, info in JOB_TYPE_INFO.items():
        categories.add(info["category"])
        job_types.append(
            JobTypeInfo(
                job_type=job_type,
                name=info["name"],
                description=info["description"],
                category=info["category"],
                required_parameters=info["required_parameters"],
                optional_parameters=info["optional_parameters"],
                parameter_schema=info["parameter_schema"],
                default_timeout_seconds=info["default_timeout_seconds"],
                supports_concurrent=info["supports_concurrent"],
                example_parameters=info["example_parameters"],
            )
        )

    return JobTypeListResponse(
        job_types=job_types,
        categories=sorted(list(categories)),
    )


@router.post("/bulk-action", response_model=BulkJobActionResponse)
async def bulk_job_action(
    request: BulkJobActionRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Perform bulk action on multiple jobs."""
    results = []
    succeeded = 0
    failed = 0

    for job_id in request.job_ids:
        try:
            if job_id not in scheduled_jobs:
                results.append({"job_id": job_id, "success": False, "error": "Not found"})
                failed += 1
                continue

            job = scheduled_jobs[job_id]

            if request.action == "pause":
                job.status = ScheduledJobStatusEnum.PAUSED
            elif request.action == "resume":
                job.status = ScheduledJobStatusEnum.ACTIVE
            elif request.action == "disable":
                job.status = ScheduledJobStatusEnum.DISABLED
            elif request.action == "delete":
                scheduled_jobs.pop(job_id)
                job_stats.pop(job_id, None)

            job.updated_at = datetime.utcnow()
            results.append({"job_id": job_id, "success": True})
            succeeded += 1

        except Exception as e:
            results.append({"job_id": job_id, "success": False, "error": str(e)})
            failed += 1

    return BulkJobActionResponse(
        action=request.action,
        total_requested=len(request.job_ids),
        succeeded=succeeded,
        failed=failed,
        results=results,
    )


# ============================================================================
# Job Dependencies
# ============================================================================


@router.get("/jobs/{job_id}/dependencies", response_model=JobDependencyResponse)
async def get_job_dependencies(
    job_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get job dependencies."""
    if job_id not in scheduled_jobs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")

    dependencies = job_dependencies.get(job_id, [])

    # Find dependents (jobs that depend on this job)
    dependents = []
    for other_job_id, deps in job_dependencies.items():
        for dep in deps:
            if dep.depends_on_job_id == job_id:
                dependents.append(other_job_id)

    return JobDependencyResponse(
        job_id=job_id,
        dependencies=dependencies,
        dependents=dependents,
    )


@router.post("/jobs/{job_id}/dependencies", response_model=APIResponse)
async def add_job_dependency(
    job_id: str,
    dependency: JobDependency,
    current_user: str = Depends(get_current_active_user),
):
    """Add a dependency to a job."""
    if job_id not in scheduled_jobs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")

    if dependency.depends_on_job_id not in scheduled_jobs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dependency job {dependency.depends_on_job_id} not found",
        )

    if job_id not in job_dependencies:
        job_dependencies[job_id] = []

    # Check for circular dependency
    def has_circular(current: str, target: str, visited: set) -> bool:
        if current == target:
            return True
        if current in visited:
            return False
        visited.add(current)
        for dep in job_dependencies.get(current, []):
            if has_circular(dep.depends_on_job_id, target, visited):
                return True
        return False

    if has_circular(dependency.depends_on_job_id, job_id, set()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Circular dependency detected"
        )

    dependency.job_id = job_id
    job_dependencies[job_id].append(dependency)

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Dependency added: {job_id} depends on {dependency.depends_on_job_id}",
    )


@router.delete("/jobs/{job_id}/dependencies/{depends_on_job_id}", response_model=APIResponse)
async def remove_job_dependency(
    job_id: str,
    depends_on_job_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Remove a dependency from a job."""
    if job_id not in job_dependencies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No dependencies found for job {job_id}"
        )

    deps = job_dependencies[job_id]
    original_len = len(deps)
    job_dependencies[job_id] = [d for d in deps if d.depends_on_job_id != depends_on_job_id]

    if len(job_dependencies[job_id]) == original_len:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dependency on {depends_on_job_id} not found",
        )

    return APIResponse(status=StatusEnum.SUCCESS, message="Dependency removed")
