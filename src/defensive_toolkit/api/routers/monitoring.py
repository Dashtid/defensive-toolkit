"""
Monitoring API Router

Provides endpoints for system metrics collection, alert management,
and threshold-based monitoring.

Author: Defensive Toolkit
Date: 2025-12-28
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from defensive_toolkit.api.dependencies import get_current_active_user, require_write_scope
from defensive_toolkit.api.models import (
    AlertConfiguration,
    APIResponse,
    MonitoringMetrics,
    StatusEnum,
)
from defensive_toolkit.api.services.monitoring import (
    AlertCondition,
    AlertSeverity,
    MetricType,
    MonitoringService,
    get_monitoring_service,
)

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


def get_service() -> MonitoringService:
    """Get monitoring service instance"""
    return get_monitoring_service()


@router.get("/metrics", response_model=MonitoringMetrics)
async def get_metrics(
    current_user: str = Depends(get_current_active_user),
    service: MonitoringService = Depends(get_service),
):
    """
    Get current system monitoring metrics.

    Returns real-time CPU, memory, disk, network, and process metrics
    collected via psutil.
    """
    metrics = service.collect_metrics()

    return MonitoringMetrics(
        cpu_usage_percent=metrics.cpu_usage_percent,
        memory_usage_percent=metrics.memory_usage_percent,
        disk_usage_percent=metrics.disk_usage_percent,
        network_connections=metrics.network_connections,
        api_requests_count=0,  # Would need request counter middleware
        api_errors_count=0,  # Would need error counter middleware
    )


@router.get("/metrics/detailed", response_model=Dict[str, Any])
async def get_detailed_metrics(
    current_user: str = Depends(get_current_active_user),
    service: MonitoringService = Depends(get_service),
):
    """
    Get detailed system metrics including memory sizes and uptime.
    """
    metrics = service.collect_metrics()
    return metrics.to_dict()


@router.get("/metrics/history", response_model=List[Dict[str, Any]])
async def get_metrics_history(
    minutes: int = Query(60, ge=1, le=1440, description="History duration in minutes"),
    current_user: str = Depends(get_current_active_user),
    service: MonitoringService = Depends(get_service),
):
    """
    Get historical metrics for graphing and trend analysis.
    """
    return service.get_metrics_history(minutes=minutes)


@router.post("/alerts", response_model=APIResponse)
async def create_alert(
    alert: AlertConfiguration,
    current_user: str = Depends(require_write_scope),
    service: MonitoringService = Depends(get_service),
):
    """
    Create a new monitoring alert rule.

    Alerts are evaluated each time metrics are collected.
    When a threshold is crossed, the alert is triggered and
    notifications are sent to configured channels.
    """
    # Map condition string to enum
    condition_map = {
        "gt": AlertCondition.GREATER_THAN,
        "lt": AlertCondition.LESS_THAN,
        "eq": AlertCondition.EQUAL,
        "gte": AlertCondition.GREATER_EQUAL,
        "lte": AlertCondition.LESS_EQUAL,
    }
    condition = condition_map.get(alert.condition)
    if not condition:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid condition: {alert.condition}",
        )

    # Map metric string to enum
    try:
        metric = MetricType(alert.metric)
    except ValueError:
        valid_metrics = [m.value for m in MetricType]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid metric: {alert.metric}. Valid options: {valid_metrics}",
        )

    # Create the alert rule
    rule = service.create_alert_rule(
        name=alert.alert_name,
        metric=metric,
        condition=condition,
        threshold=alert.threshold,
        severity=AlertSeverity.WARNING,
        notification_channels=[alert.notification_channel] if alert.notification_channel else [],
    )

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Alert rule created: {rule.rule_id}",
    )


@router.get("/alerts", response_model=List[Dict[str, Any]])
async def list_alerts(
    active_only: bool = Query(False, description="Show only active alerts"),
    current_user: str = Depends(get_current_active_user),
    service: MonitoringService = Depends(get_service),
):
    """
    List configured alert rules and their current status.
    """
    rules = service.list_alert_rules()
    active_alerts = {a.rule_id: a for a in service.get_active_alerts()}

    result = []
    for rule in rules:
        active = active_alerts.get(rule.rule_id)
        if active_only and not active:
            continue

        result.append({
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "metric": rule.metric.value,
            "condition": rule.condition.value,
            "threshold": rule.threshold,
            "severity": rule.severity.value,
            "enabled": rule.enabled,
            "is_triggered": active is not None,
            "current_value": active.current_value if active else None,
            "triggered_at": active.triggered_at.isoformat() if active else None,
            "last_triggered": rule.last_triggered.isoformat() if rule.last_triggered else None,
        })

    return result


@router.get("/alerts/active", response_model=List[Dict[str, Any]])
async def get_active_alerts(
    current_user: str = Depends(get_current_active_user),
    service: MonitoringService = Depends(get_service),
):
    """
    Get currently active alerts (triggered and not resolved).
    """
    alerts = service.get_active_alerts()
    return [
        {
            "alert_id": a.alert_id,
            "rule_id": a.rule_id,
            "rule_name": a.rule_name,
            "metric": a.metric,
            "current_value": a.current_value,
            "threshold": a.threshold,
            "condition": a.condition,
            "severity": a.severity.value,
            "status": a.status.value,
            "message": a.message,
            "triggered_at": a.triggered_at.isoformat(),
            "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        }
        for a in alerts
    ]


@router.post("/alerts/{rule_id}/acknowledge", response_model=APIResponse)
async def acknowledge_alert(
    rule_id: str,
    current_user: str = Depends(require_write_scope),
    service: MonitoringService = Depends(get_service),
):
    """
    Acknowledge an active alert.
    """
    alert = service.acknowledge_alert(rule_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active alert for rule: {rule_id}",
        )

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Alert acknowledged: {alert.rule_name}",
    )


@router.get("/alerts/history", response_model=List[Dict[str, Any]])
async def get_alert_history(
    limit: int = Query(100, ge=1, le=1000, description="Maximum alerts to return"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    current_user: str = Depends(get_current_active_user),
    service: MonitoringService = Depends(get_service),
):
    """
    Get alert history.
    """
    sev = None
    if severity:
        try:
            sev = AlertSeverity(severity.lower())
        except ValueError:
            pass

    history = service.get_alert_history(limit=limit, severity=sev)
    return [
        {
            "alert_id": a.alert_id,
            "rule_name": a.rule_name,
            "metric": a.metric,
            "current_value": a.current_value,
            "threshold": a.threshold,
            "severity": a.severity.value,
            "status": a.status.value,
            "triggered_at": a.triggered_at.isoformat(),
            "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
        }
        for a in history
    ]


@router.delete("/alerts/{rule_id}", response_model=APIResponse)
async def delete_alert_rule(
    rule_id: str,
    current_user: str = Depends(require_write_scope),
    service: MonitoringService = Depends(get_service),
):
    """
    Delete an alert rule.
    """
    if not service.delete_alert_rule(rule_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert rule not found: {rule_id}",
        )

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Alert rule deleted: {rule_id}",
    )


@router.patch("/alerts/{rule_id}", response_model=APIResponse)
async def update_alert_rule(
    rule_id: str,
    enabled: Optional[bool] = None,
    threshold: Optional[float] = None,
    current_user: str = Depends(require_write_scope),
    service: MonitoringService = Depends(get_service),
):
    """
    Update an alert rule (enable/disable, change threshold).
    """
    rule = service.update_alert_rule(
        rule_id=rule_id,
        enabled=enabled,
        threshold=threshold,
    )
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert rule not found: {rule_id}",
        )

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Alert rule updated: {rule.name}",
    )


@router.get("/summary", response_model=Dict[str, Any])
async def get_monitoring_summary(
    current_user: str = Depends(get_current_active_user),
    service: MonitoringService = Depends(get_service),
):
    """
    Get monitoring system summary.
    """
    return service.get_summary()
