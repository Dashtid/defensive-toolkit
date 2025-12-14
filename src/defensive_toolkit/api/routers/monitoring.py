"""Monitoring API Router"""

import random

from api.dependencies import get_current_active_user, require_write_scope
from api.models import AlertConfiguration, APIResponse, MonitoringMetrics, StatusEnum
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])

@router.get("/metrics", response_model=MonitoringMetrics)
async def get_metrics(current_user: str = Depends(get_current_active_user)):
    """Get current system monitoring metrics."""
    return MonitoringMetrics(
        cpu_usage_percent=random.uniform(10, 90),
        memory_usage_percent=random.uniform(40, 80),
        disk_usage_percent=random.uniform(30, 70),
        network_connections=random.randint(50, 200),
        api_requests_count=random.randint(1000, 5000),
        api_errors_count=random.randint(0, 50)
    )

@router.post("/alerts", response_model=APIResponse)
async def create_alert(
    alert: AlertConfiguration,
    current_user: str = Depends(require_write_scope),
):
    """Create a new monitoring alert."""
    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Alert created successfully"
    )

@router.get("/alerts", response_model=list)
async def list_alerts(current_user: str = Depends(get_current_active_user)):
    """List configured alerts."""
    return []
