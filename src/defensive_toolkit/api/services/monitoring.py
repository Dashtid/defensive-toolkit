"""
Monitoring Service

Provides real system metrics collection, alert management, and threshold evaluation.

Author: Defensive Toolkit
Date: 2025-12-28
"""

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


class MetricType(str, Enum):
    """Types of metrics that can be monitored"""

    CPU_USAGE = "cpu_usage_percent"
    MEMORY_USAGE = "memory_usage_percent"
    DISK_USAGE = "disk_usage_percent"
    NETWORK_CONNECTIONS = "network_connections"
    NETWORK_BYTES_SENT = "network_bytes_sent"
    NETWORK_BYTES_RECV = "network_bytes_recv"
    PROCESS_COUNT = "process_count"
    SWAP_USAGE = "swap_usage_percent"
    LOAD_AVERAGE = "load_average"


class AlertCondition(str, Enum):
    """Alert condition operators"""

    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    EQUAL = "eq"
    GREATER_EQUAL = "gte"
    LESS_EQUAL = "lte"


class AlertSeverity(str, Enum):
    """Alert severity levels"""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Alert status"""

    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass
class SystemMetrics:
    """System monitoring metrics"""

    cpu_usage_percent: float
    memory_usage_percent: float
    memory_available_gb: float
    memory_total_gb: float
    disk_usage_percent: float
    disk_available_gb: float
    disk_total_gb: float
    network_connections: int
    network_bytes_sent: int
    network_bytes_recv: int
    process_count: int
    swap_usage_percent: float
    boot_time: datetime
    uptime_seconds: int
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "cpu_usage_percent": self.cpu_usage_percent,
            "memory_usage_percent": self.memory_usage_percent,
            "memory_available_gb": self.memory_available_gb,
            "memory_total_gb": self.memory_total_gb,
            "disk_usage_percent": self.disk_usage_percent,
            "disk_available_gb": self.disk_available_gb,
            "disk_total_gb": self.disk_total_gb,
            "network_connections": self.network_connections,
            "network_bytes_sent": self.network_bytes_sent,
            "network_bytes_recv": self.network_bytes_recv,
            "process_count": self.process_count,
            "swap_usage_percent": self.swap_usage_percent,
            "boot_time": self.boot_time.isoformat(),
            "uptime_seconds": self.uptime_seconds,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class AlertRule:
    """Alert rule configuration"""

    rule_id: str
    name: str
    description: str
    metric: MetricType
    condition: AlertCondition
    threshold: float
    severity: AlertSeverity
    enabled: bool = True
    cooldown_seconds: int = 300  # Minimum time between alerts
    notification_channels: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_triggered: Optional[datetime] = None


@dataclass
class Alert:
    """Active alert instance"""

    alert_id: str
    rule_id: str
    rule_name: str
    metric: str
    current_value: float
    threshold: float
    condition: str
    severity: AlertSeverity
    status: AlertStatus
    message: str
    triggered_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


class MonitoringService:
    """Service for collecting system metrics and managing alerts"""

    def __init__(self):
        self._alert_rules: Dict[str, AlertRule] = {}
        self._active_alerts: Dict[str, Alert] = {}
        self._alert_history: List[Alert] = []
        self._notification_handlers: Dict[str, Callable[[Alert], None]] = {}
        self._metrics_history: List[SystemMetrics] = []
        self._max_history_size = 1000
        self._lock = threading.Lock()

    def collect_metrics(self) -> SystemMetrics:
        """
        Collect current system metrics.

        Returns:
            SystemMetrics with current values
        """
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available, returning placeholder metrics")
            metrics = self._get_placeholder_metrics()
            # Still store in history for consistency
            with self._lock:
                self._metrics_history.append(metrics)
                if len(self._metrics_history) > self._max_history_size:
                    self._metrics_history = self._metrics_history[-self._max_history_size:]
            return metrics

        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=0.1)

            # Memory
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available_gb = memory.available / (1024**3)
            memory_total_gb = memory.total / (1024**3)

            # Disk (root partition)
            try:
                disk = psutil.disk_usage("/")
            except Exception:
                # Windows fallback
                disk = psutil.disk_usage("C:\\")

            disk_percent = disk.percent
            disk_available_gb = disk.free / (1024**3)
            disk_total_gb = disk.total / (1024**3)

            # Network
            net_connections = len(psutil.net_connections())
            net_io = psutil.net_io_counters()
            bytes_sent = net_io.bytes_sent
            bytes_recv = net_io.bytes_recv

            # Processes
            process_count = len(psutil.pids())

            # Swap
            swap = psutil.swap_memory()
            swap_percent = swap.percent

            # Boot time and uptime
            boot_timestamp = psutil.boot_time()
            boot_time = datetime.fromtimestamp(boot_timestamp)
            uptime = int(time.time() - boot_timestamp)

            metrics = SystemMetrics(
                cpu_usage_percent=cpu_percent,
                memory_usage_percent=memory_percent,
                memory_available_gb=round(memory_available_gb, 2),
                memory_total_gb=round(memory_total_gb, 2),
                disk_usage_percent=disk_percent,
                disk_available_gb=round(disk_available_gb, 2),
                disk_total_gb=round(disk_total_gb, 2),
                network_connections=net_connections,
                network_bytes_sent=bytes_sent,
                network_bytes_recv=bytes_recv,
                process_count=process_count,
                swap_usage_percent=swap_percent,
                boot_time=boot_time,
                uptime_seconds=uptime,
            )

            # Store in history
            with self._lock:
                self._metrics_history.append(metrics)
                if len(self._metrics_history) > self._max_history_size:
                    self._metrics_history = self._metrics_history[-self._max_history_size:]

            # Evaluate alert rules
            self._evaluate_alerts(metrics)

            return metrics

        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return self._get_placeholder_metrics()

    def _get_placeholder_metrics(self) -> SystemMetrics:
        """Return placeholder metrics when psutil is unavailable"""
        return SystemMetrics(
            cpu_usage_percent=0.0,
            memory_usage_percent=0.0,
            memory_available_gb=0.0,
            memory_total_gb=0.0,
            disk_usage_percent=0.0,
            disk_available_gb=0.0,
            disk_total_gb=0.0,
            network_connections=0,
            network_bytes_sent=0,
            network_bytes_recv=0,
            process_count=0,
            swap_usage_percent=0.0,
            boot_time=datetime.utcnow(),
            uptime_seconds=0,
        )

    def _evaluate_alerts(self, metrics: SystemMetrics) -> None:
        """Evaluate all alert rules against current metrics"""
        metrics_dict = metrics.to_dict()

        for rule in self._alert_rules.values():
            if not rule.enabled:
                continue

            metric_value = metrics_dict.get(rule.metric.value)
            if metric_value is None:
                continue

            # Check cooldown
            if rule.last_triggered:
                cooldown_end = rule.last_triggered + timedelta(seconds=rule.cooldown_seconds)
                if datetime.utcnow() < cooldown_end:
                    continue

            # Evaluate condition
            triggered = self._evaluate_condition(metric_value, rule.condition, rule.threshold)

            if triggered:
                self._trigger_alert(rule, metric_value)
            else:
                # Check if we should resolve an existing alert
                self._maybe_resolve_alert(rule.rule_id)

    def _evaluate_condition(
        self, value: float, condition: AlertCondition, threshold: float
    ) -> bool:
        """Evaluate an alert condition"""
        if condition == AlertCondition.GREATER_THAN:
            return value > threshold
        elif condition == AlertCondition.LESS_THAN:
            return value < threshold
        elif condition == AlertCondition.EQUAL:
            return value == threshold
        elif condition == AlertCondition.GREATER_EQUAL:
            return value >= threshold
        elif condition == AlertCondition.LESS_EQUAL:
            return value <= threshold
        return False

    def _trigger_alert(self, rule: AlertRule, current_value: float) -> None:
        """Trigger an alert for a rule"""
        # Check if alert already exists
        if rule.rule_id in self._active_alerts:
            return

        alert_id = str(uuid.uuid4())
        alert = Alert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            metric=rule.metric.value,
            current_value=current_value,
            threshold=rule.threshold,
            condition=rule.condition.value,
            severity=rule.severity,
            status=AlertStatus.ACTIVE,
            message=f"{rule.name}: {rule.metric.value} is {current_value} ({rule.condition.value} {rule.threshold})",
            triggered_at=datetime.utcnow(),
        )

        with self._lock:
            self._active_alerts[rule.rule_id] = alert
            self._alert_history.append(alert)
            rule.last_triggered = datetime.utcnow()

        logger.warning(f"Alert triggered: {alert.message}")

        # Call notification handlers
        for handler in self._notification_handlers.values():
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in notification handler: {e}")

    def _maybe_resolve_alert(self, rule_id: str) -> None:
        """Resolve an alert if it's no longer active"""
        if rule_id not in self._active_alerts:
            return

        alert = self._active_alerts[rule_id]
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.utcnow()

        with self._lock:
            del self._active_alerts[rule_id]

        logger.info(f"Alert resolved: {alert.rule_name}")

    # Alert Rule Management

    def create_alert_rule(
        self,
        name: str,
        metric: MetricType,
        condition: AlertCondition,
        threshold: float,
        severity: AlertSeverity = AlertSeverity.WARNING,
        description: str = "",
        cooldown_seconds: int = 300,
        notification_channels: Optional[List[str]] = None,
    ) -> AlertRule:
        """Create a new alert rule"""
        rule_id = str(uuid.uuid4())
        rule = AlertRule(
            rule_id=rule_id,
            name=name,
            description=description or f"Alert when {metric.value} {condition.value} {threshold}",
            metric=metric,
            condition=condition,
            threshold=threshold,
            severity=severity,
            cooldown_seconds=cooldown_seconds,
            notification_channels=notification_channels or [],
        )

        with self._lock:
            self._alert_rules[rule_id] = rule

        logger.info(f"Created alert rule: {name}")
        return rule

    def update_alert_rule(
        self,
        rule_id: str,
        enabled: Optional[bool] = None,
        threshold: Optional[float] = None,
        severity: Optional[AlertSeverity] = None,
    ) -> Optional[AlertRule]:
        """Update an existing alert rule"""
        rule = self._alert_rules.get(rule_id)
        if not rule:
            return None

        if enabled is not None:
            rule.enabled = enabled
        if threshold is not None:
            rule.threshold = threshold
        if severity is not None:
            rule.severity = severity

        return rule

    def delete_alert_rule(self, rule_id: str) -> bool:
        """Delete an alert rule"""
        with self._lock:
            if rule_id in self._alert_rules:
                del self._alert_rules[rule_id]
                # Also remove any active alerts for this rule
                if rule_id in self._active_alerts:
                    del self._active_alerts[rule_id]
                return True
        return False

    def list_alert_rules(self) -> List[AlertRule]:
        """List all alert rules"""
        return list(self._alert_rules.values())

    def get_alert_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Get a specific alert rule"""
        return self._alert_rules.get(rule_id)

    # Active Alerts

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        return list(self._active_alerts.values())

    def acknowledge_alert(self, rule_id: str) -> Optional[Alert]:
        """Acknowledge an active alert"""
        alert = self._active_alerts.get(rule_id)
        if alert:
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.utcnow()
        return alert

    def get_alert_history(
        self, limit: int = 100, severity: Optional[AlertSeverity] = None
    ) -> List[Alert]:
        """Get alert history with optional filtering"""
        history = self._alert_history[-limit:]
        if severity:
            history = [a for a in history if a.severity == severity]
        return history

    # Notification Handlers

    def register_notification_handler(
        self, name: str, handler: Callable[[Alert], None]
    ) -> None:
        """Register a notification handler for alerts"""
        self._notification_handlers[name] = handler
        logger.info(f"Registered notification handler: {name}")

    def unregister_notification_handler(self, name: str) -> None:
        """Unregister a notification handler"""
        if name in self._notification_handlers:
            del self._notification_handlers[name]

    # Metrics History

    def get_metrics_history(
        self, minutes: int = 60, interval_seconds: int = 60
    ) -> List[Dict[str, Any]]:
        """Get metrics history for graphing"""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        history = [m for m in self._metrics_history if m.timestamp > cutoff]

        # Sample at intervals if needed
        if len(history) > minutes:
            # Take every Nth sample
            step = len(history) // minutes
            history = history[::step]

        return [m.to_dict() for m in history]

    def get_summary(self) -> Dict[str, Any]:
        """Get monitoring summary"""
        return {
            "psutil_available": PSUTIL_AVAILABLE,
            "total_alert_rules": len(self._alert_rules),
            "enabled_rules": len([r for r in self._alert_rules.values() if r.enabled]),
            "active_alerts": len(self._active_alerts),
            "active_alerts_by_severity": {
                severity.value: len([a for a in self._active_alerts.values() if a.severity == severity])
                for severity in AlertSeverity
            },
            "metrics_history_size": len(self._metrics_history),
            "notification_handlers": list(self._notification_handlers.keys()),
        }


# Global service instance
_monitoring_service: Optional[MonitoringService] = None


def get_monitoring_service() -> MonitoringService:
    """Get or create the monitoring service singleton"""
    global _monitoring_service
    if _monitoring_service is None:
        _monitoring_service = MonitoringService()
    return _monitoring_service
