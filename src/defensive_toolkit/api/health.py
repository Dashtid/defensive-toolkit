"""
Health Check Module

Comprehensive health checks for all API components including:
- API responsiveness
- Redis connectivity (if enabled)
- Webhook system status
- Notification channels status
- System resources (memory, disk)

Supports Kubernetes liveness and readiness probes.
"""

import asyncio
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from defensive_toolkit.api.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Track application start time for uptime calculation
_start_time: Optional[datetime] = None


def set_start_time():
    """Set application start time. Call during startup."""
    global _start_time
    _start_time = datetime.utcnow()


def get_uptime_seconds() -> float:
    """Get application uptime in seconds."""
    if _start_time is None:
        return 0.0
    return (datetime.utcnow() - _start_time).total_seconds()


# ============================================================================
# Health Check Results
# ============================================================================


@dataclass
class ComponentHealth:
    """Health status of a single component."""

    name: str
    status: str  # healthy, degraded, unhealthy, disabled
    latency_ms: Optional[float] = None
    message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthCheckResult:
    """Complete health check result."""

    status: str  # healthy, degraded, unhealthy
    version: str
    uptime_seconds: float
    timestamp: str
    components: Dict[str, Dict[str, Any]]
    checks: Dict[str, str]
    system: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON response."""
        return {
            "status": self.status,
            "version": self.version,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "timestamp": self.timestamp,
            "components": self.components,
            "checks": self.checks,
            "system": self.system,
        }


# ============================================================================
# Component Health Checks
# ============================================================================


async def check_redis_health() -> ComponentHealth:
    """Check Redis connectivity and latency."""
    if not settings.redis_enabled:
        return ComponentHealth(
            name="redis",
            status="disabled",
            message="Redis is not enabled",
        )

    try:
        import redis

        start = time.monotonic()
        client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            password=settings.redis_password or None,
            socket_timeout=2.0,
            socket_connect_timeout=2.0,
        )
        client.ping()
        latency = (time.monotonic() - start) * 1000

        # Get Redis info
        info = client.info("memory")
        client.close()

        return ComponentHealth(
            name="redis",
            status="healthy",
            latency_ms=round(latency, 2),
            details={
                "used_memory_human": info.get("used_memory_human", "unknown"),
                "connected_clients": info.get("connected_clients", 0),
            },
        )

    except ImportError:
        return ComponentHealth(
            name="redis",
            status="disabled",
            message="Redis library not installed",
        )
    except Exception as e:
        logger.warning(f"Redis health check failed: {e}")
        return ComponentHealth(
            name="redis",
            status="unhealthy",
            message=str(e),
        )


def check_webhooks_health() -> ComponentHealth:
    """Check webhook system status."""
    try:
        from defensive_toolkit.api.routers import webhooks

        active_webhooks = len(
            [w for w in webhooks.webhooks_db.values() if w.get("status") == "active"]
        )
        total_webhooks = len(webhooks.webhooks_db)

        # Check for any circuit breakers that might be open
        # (This would integrate with the webhook_delivery service)
        circuit_breakers_open = 0

        return ComponentHealth(
            name="webhooks",
            status="healthy",
            details={
                "total_configured": total_webhooks,
                "active": active_webhooks,
                "circuit_breakers_open": circuit_breakers_open,
            },
        )
    except Exception as e:
        logger.warning(f"Webhook health check failed: {e}")
        return ComponentHealth(
            name="webhooks",
            status="degraded",
            message=str(e),
        )


def check_notifications_health() -> ComponentHealth:
    """Check notification system status."""
    try:
        from defensive_toolkit.api.routers import notifications

        active_channels = len(
            [
                c
                for c in notifications.channels_db.values()
                if c.get("enabled", False)
            ]
        )
        total_channels = len(notifications.channels_db)
        pending_notifications = len(notifications.notifications_db)

        return ComponentHealth(
            name="notifications",
            status="healthy",
            details={
                "total_channels": total_channels,
                "active_channels": active_channels,
                "pending_notifications": pending_notifications,
            },
        )
    except Exception as e:
        logger.warning(f"Notification health check failed: {e}")
        return ComponentHealth(
            name="notifications",
            status="degraded",
            message=str(e),
        )


def check_rate_limiting_health() -> ComponentHealth:
    """Check rate limiting status."""
    if not settings.rate_limit_enabled:
        return ComponentHealth(
            name="rate_limiting",
            status="disabled",
            message="Rate limiting is not enabled",
        )

    return ComponentHealth(
        name="rate_limiting",
        status="healthy",
        details={
            "default_limit": settings.rate_limit_default,
            "auth_limit": settings.rate_limit_auth,
            "heavy_limit": settings.rate_limit_heavy,
            "backend": "redis" if settings.redis_enabled else "in_memory",
        },
    )


# ============================================================================
# System Checks
# ============================================================================


def check_memory() -> Dict[str, Any]:
    """Check system memory usage."""
    try:
        import psutil

        memory = psutil.virtual_memory()
        return {
            "status": "healthy" if memory.percent < 90 else "warning",
            "percent_used": round(memory.percent, 1),
            "available_gb": round(memory.available / (1024**3), 2),
        }
    except ImportError:
        return {"status": "unknown", "message": "psutil not installed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_disk() -> Dict[str, Any]:
    """Check disk space."""
    try:
        import psutil

        disk = psutil.disk_usage("/")
        return {
            "status": "healthy" if disk.percent < 90 else "warning",
            "percent_used": round(disk.percent, 1),
            "free_gb": round(disk.free / (1024**3), 2),
        }
    except ImportError:
        return {"status": "unknown", "message": "psutil not installed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_system_info() -> Dict[str, Any]:
    """Get system information."""
    return {
        "platform": platform.system(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
        "pid": os.getpid(),
    }


# ============================================================================
# Main Health Check Functions
# ============================================================================


async def perform_health_check(
    include_system: bool = True,
    include_details: bool = True,
) -> HealthCheckResult:
    """
    Perform comprehensive health check.

    Args:
        include_system: Include system resource checks
        include_details: Include detailed component info

    Returns:
        HealthCheckResult with all component statuses
    """
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Check components concurrently
    redis_health = await check_redis_health()
    webhooks_health = check_webhooks_health()
    notifications_health = check_notifications_health()
    rate_limiting_health = check_rate_limiting_health()

    # Compile component statuses
    components = {
        "api": {
            "status": "healthy",
            "latency_ms": 0.1,
        },
        "redis": {
            "status": redis_health.status,
            "latency_ms": redis_health.latency_ms,
            **(redis_health.details if include_details else {}),
            **({"message": redis_health.message} if redis_health.message else {}),
        },
        "webhooks": {
            "status": webhooks_health.status,
            **(webhooks_health.details if include_details else {}),
        },
        "notifications": {
            "status": notifications_health.status,
            **(notifications_health.details if include_details else {}),
        },
        "rate_limiting": {
            "status": rate_limiting_health.status,
            **(rate_limiting_health.details if include_details else {}),
        },
    }

    # System checks
    checks = {}
    system_info = {}

    if include_system:
        memory_status = check_memory()
        disk_status = check_disk()
        checks = {
            "memory": memory_status.get("status", "unknown"),
            "disk": disk_status.get("status", "unknown"),
        }
        system_info = {
            **get_system_info(),
            "memory": memory_status,
            "disk": disk_status,
        }

    # Determine overall status
    statuses = [c.get("status") for c in components.values()]
    if "unhealthy" in statuses:
        overall_status = "unhealthy"
    elif "degraded" in statuses or "warning" in checks.values():
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    return HealthCheckResult(
        status=overall_status,
        version=settings.app_version,
        uptime_seconds=get_uptime_seconds(),
        timestamp=timestamp,
        components=components,
        checks=checks,
        system=system_info,
    )


async def perform_liveness_check() -> Dict[str, Any]:
    """
    Simple liveness check for Kubernetes.

    Returns minimal response to indicate the process is alive.
    """
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


async def perform_readiness_check() -> Dict[str, Any]:
    """
    Readiness check for Kubernetes.

    Checks if the application is ready to receive traffic.
    """
    # Check critical components
    redis_health = await check_redis_health()

    # If Redis is enabled but unhealthy, not ready
    if settings.redis_enabled and redis_health.status == "unhealthy":
        return {
            "status": "not_ready",
            "reason": "Redis unavailable",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

    return {
        "status": "ready",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
