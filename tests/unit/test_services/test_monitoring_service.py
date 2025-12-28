"""
Unit tests for Monitoring Service.

Tests metrics collection, alert management, and threshold evaluation.

Author: Defensive Toolkit
Date: 2025-12-28
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from defensive_toolkit.api.services.monitoring import (
    Alert,
    AlertCondition,
    AlertRule,
    AlertSeverity,
    AlertStatus,
    MetricType,
    MonitoringService,
    SystemMetrics,
    get_monitoring_service,
)


class TestMonitoringServiceInit:
    """Test service initialization."""

    def test_service_creates_successfully(self):
        """Test service initializes with empty state."""
        service = MonitoringService()
        assert service._alert_rules == {}
        assert service._active_alerts == {}
        assert service._alert_history == []
        assert service._metrics_history == []

    def test_singleton_returns_same_instance(self):
        """Test singleton pattern returns same instance."""
        service1 = get_monitoring_service()
        service2 = get_monitoring_service()
        assert service1 is service2


class TestSystemMetrics:
    """Test SystemMetrics dataclass."""

    def test_metrics_to_dict(self):
        """Test metrics serialization to dictionary."""
        metrics = SystemMetrics(
            cpu_usage_percent=45.5,
            memory_usage_percent=62.3,
            memory_available_gb=8.5,
            memory_total_gb=16.0,
            disk_usage_percent=55.0,
            disk_available_gb=200.0,
            disk_total_gb=500.0,
            network_connections=150,
            network_bytes_sent=1000000,
            network_bytes_recv=2000000,
            process_count=250,
            swap_usage_percent=10.0,
            boot_time=datetime(2025, 12, 1, 8, 0, 0),
            uptime_seconds=86400,
        )

        result = metrics.to_dict()

        assert result["cpu_usage_percent"] == 45.5
        assert result["memory_usage_percent"] == 62.3
        assert result["disk_usage_percent"] == 55.0
        assert result["network_connections"] == 150
        assert result["process_count"] == 250
        assert "timestamp" in result


class TestMetricsCollection:
    """Test metrics collection functionality."""

    @pytest.fixture
    def service(self):
        """Create fresh service instance."""
        return MonitoringService()

    def test_collect_metrics_returns_system_metrics(self, service):
        """Test collect_metrics returns SystemMetrics object."""
        metrics = service.collect_metrics()
        assert isinstance(metrics, SystemMetrics)

    def test_collect_metrics_stores_in_history(self, service):
        """Test metrics are stored in history."""
        service.collect_metrics()
        assert len(service._metrics_history) >= 1

    def test_metrics_history_respects_max_size(self, service):
        """Test history doesn't exceed max size."""
        service._max_history_size = 5
        for _ in range(10):
            service.collect_metrics()
        assert len(service._metrics_history) <= 5

    def test_get_metrics_history(self, service):
        """Test retrieving metrics history."""
        service.collect_metrics()
        history = service.get_metrics_history(minutes=60)
        assert isinstance(history, list)


class TestAlertRuleManagement:
    """Test alert rule CRUD operations."""

    @pytest.fixture
    def service(self):
        """Create fresh service instance."""
        return MonitoringService()

    def test_create_alert_rule(self, service):
        """Test creating an alert rule."""
        rule = service.create_alert_rule(
            name="High CPU Alert",
            metric=MetricType.CPU_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
            severity=AlertSeverity.WARNING,
        )

        assert rule.name == "High CPU Alert"
        assert rule.metric == MetricType.CPU_USAGE
        assert rule.condition == AlertCondition.GREATER_THAN
        assert rule.threshold == 80.0
        assert rule.severity == AlertSeverity.WARNING
        assert rule.enabled is True

    def test_create_alert_rule_with_all_options(self, service):
        """Test creating alert rule with all options."""
        rule = service.create_alert_rule(
            name="Low Memory Alert",
            metric=MetricType.MEMORY_USAGE,
            condition=AlertCondition.GREATER_EQUAL,
            threshold=90.0,
            severity=AlertSeverity.CRITICAL,
            description="Memory usage is critically high",
            cooldown_seconds=600,
            notification_channels=["email", "slack"],
        )

        assert rule.description == "Memory usage is critically high"
        assert rule.cooldown_seconds == 600
        assert "email" in rule.notification_channels

    def test_list_alert_rules(self, service):
        """Test listing all alert rules."""
        service.create_alert_rule(
            name="Rule 1",
            metric=MetricType.CPU_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )
        service.create_alert_rule(
            name="Rule 2",
            metric=MetricType.MEMORY_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=85.0,
        )

        rules = service.list_alert_rules()
        assert len(rules) == 2

    def test_get_alert_rule(self, service):
        """Test getting a specific alert rule."""
        rule = service.create_alert_rule(
            name="Test Rule",
            metric=MetricType.DISK_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=90.0,
        )

        retrieved = service.get_alert_rule(rule.rule_id)
        assert retrieved is not None
        assert retrieved.name == "Test Rule"

    def test_get_nonexistent_rule(self, service):
        """Test getting non-existent rule returns None."""
        result = service.get_alert_rule("nonexistent_id")
        assert result is None

    def test_update_alert_rule(self, service):
        """Test updating an alert rule."""
        rule = service.create_alert_rule(
            name="Update Test",
            metric=MetricType.CPU_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )

        updated = service.update_alert_rule(
            rule_id=rule.rule_id,
            enabled=False,
            threshold=90.0,
        )

        assert updated is not None
        assert updated.enabled is False
        assert updated.threshold == 90.0

    def test_update_nonexistent_rule(self, service):
        """Test updating non-existent rule returns None."""
        result = service.update_alert_rule(
            rule_id="nonexistent",
            enabled=False,
        )
        assert result is None

    def test_delete_alert_rule(self, service):
        """Test deleting an alert rule."""
        rule = service.create_alert_rule(
            name="Delete Test",
            metric=MetricType.CPU_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )

        result = service.delete_alert_rule(rule.rule_id)
        assert result is True
        assert service.get_alert_rule(rule.rule_id) is None

    def test_delete_nonexistent_rule(self, service):
        """Test deleting non-existent rule returns False."""
        result = service.delete_alert_rule("nonexistent")
        assert result is False


class TestAlertConditionEvaluation:
    """Test alert condition evaluation logic."""

    @pytest.fixture
    def service(self):
        """Create fresh service instance."""
        return MonitoringService()

    def test_greater_than_condition(self, service):
        """Test GREATER_THAN condition."""
        assert service._evaluate_condition(85.0, AlertCondition.GREATER_THAN, 80.0) is True
        assert service._evaluate_condition(75.0, AlertCondition.GREATER_THAN, 80.0) is False
        assert service._evaluate_condition(80.0, AlertCondition.GREATER_THAN, 80.0) is False

    def test_less_than_condition(self, service):
        """Test LESS_THAN condition."""
        assert service._evaluate_condition(75.0, AlertCondition.LESS_THAN, 80.0) is True
        assert service._evaluate_condition(85.0, AlertCondition.LESS_THAN, 80.0) is False
        assert service._evaluate_condition(80.0, AlertCondition.LESS_THAN, 80.0) is False

    def test_equal_condition(self, service):
        """Test EQUAL condition."""
        assert service._evaluate_condition(80.0, AlertCondition.EQUAL, 80.0) is True
        assert service._evaluate_condition(79.0, AlertCondition.EQUAL, 80.0) is False

    def test_greater_equal_condition(self, service):
        """Test GREATER_EQUAL condition."""
        assert service._evaluate_condition(85.0, AlertCondition.GREATER_EQUAL, 80.0) is True
        assert service._evaluate_condition(80.0, AlertCondition.GREATER_EQUAL, 80.0) is True
        assert service._evaluate_condition(75.0, AlertCondition.GREATER_EQUAL, 80.0) is False

    def test_less_equal_condition(self, service):
        """Test LESS_EQUAL condition."""
        assert service._evaluate_condition(75.0, AlertCondition.LESS_EQUAL, 80.0) is True
        assert service._evaluate_condition(80.0, AlertCondition.LESS_EQUAL, 80.0) is True
        assert service._evaluate_condition(85.0, AlertCondition.LESS_EQUAL, 80.0) is False


class TestAlertTriggering:
    """Test alert triggering and resolution."""

    @pytest.fixture
    def service(self):
        """Create fresh service instance."""
        return MonitoringService()

    def test_trigger_alert_creates_active_alert(self, service):
        """Test that triggering creates an active alert."""
        rule = service.create_alert_rule(
            name="CPU Alert",
            metric=MetricType.CPU_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )

        service._trigger_alert(rule, 95.0)

        alerts = service.get_active_alerts()
        assert len(alerts) == 1
        assert alerts[0].rule_name == "CPU Alert"
        assert alerts[0].current_value == 95.0

    def test_duplicate_alert_not_created(self, service):
        """Test that duplicate alerts are not created."""
        rule = service.create_alert_rule(
            name="CPU Alert",
            metric=MetricType.CPU_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )

        service._trigger_alert(rule, 95.0)
        service._trigger_alert(rule, 98.0)  # Second trigger

        alerts = service.get_active_alerts()
        assert len(alerts) == 1  # Still only one alert

    def test_alert_added_to_history(self, service):
        """Test that triggered alerts are added to history."""
        rule = service.create_alert_rule(
            name="Memory Alert",
            metric=MetricType.MEMORY_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )

        service._trigger_alert(rule, 90.0)

        history = service.get_alert_history()
        assert len(history) >= 1

    def test_resolve_alert(self, service):
        """Test resolving an active alert."""
        rule = service.create_alert_rule(
            name="Disk Alert",
            metric=MetricType.DISK_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )

        service._trigger_alert(rule, 90.0)
        assert len(service.get_active_alerts()) == 1

        service._maybe_resolve_alert(rule.rule_id)
        assert len(service.get_active_alerts()) == 0


class TestAlertAcknowledgement:
    """Test alert acknowledgement functionality."""

    @pytest.fixture
    def service_with_alert(self):
        """Create service with an active alert."""
        service = MonitoringService()
        rule = service.create_alert_rule(
            name="Test Alert",
            metric=MetricType.CPU_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )
        service._trigger_alert(rule, 90.0)
        return service, rule

    def test_acknowledge_alert(self, service_with_alert):
        """Test acknowledging an active alert."""
        service, rule = service_with_alert

        alert = service.acknowledge_alert(rule.rule_id)

        assert alert is not None
        assert alert.status == AlertStatus.ACKNOWLEDGED
        assert alert.acknowledged_at is not None

    def test_acknowledge_nonexistent_alert(self, service_with_alert):
        """Test acknowledging non-existent alert returns None."""
        service, _ = service_with_alert
        result = service.acknowledge_alert("nonexistent")
        assert result is None


class TestAlertHistory:
    """Test alert history functionality."""

    @pytest.fixture
    def service_with_history(self):
        """Create service with alert history."""
        service = MonitoringService()

        # Create multiple alerts with different severities
        for i, severity in enumerate([AlertSeverity.INFO, AlertSeverity.WARNING, AlertSeverity.CRITICAL]):
            rule = service.create_alert_rule(
                name=f"Alert {i}",
                metric=MetricType.CPU_USAGE,
                condition=AlertCondition.GREATER_THAN,
                threshold=50.0 + i * 10,
                severity=severity,
            )
            service._trigger_alert(rule, 90.0)

        return service

    def test_get_alert_history_all(self, service_with_history):
        """Test getting all alert history."""
        history = service_with_history.get_alert_history()
        assert len(history) == 3

    def test_get_alert_history_with_limit(self, service_with_history):
        """Test getting limited alert history."""
        history = service_with_history.get_alert_history(limit=2)
        assert len(history) == 2

    def test_get_alert_history_by_severity(self, service_with_history):
        """Test filtering history by severity."""
        history = service_with_history.get_alert_history(severity=AlertSeverity.CRITICAL)
        assert len(history) == 1
        assert history[0].severity == AlertSeverity.CRITICAL


class TestNotificationHandlers:
    """Test notification handler registration."""

    @pytest.fixture
    def service(self):
        """Create fresh service instance."""
        return MonitoringService()

    def test_register_notification_handler(self, service):
        """Test registering a notification handler."""
        handler = MagicMock()
        service.register_notification_handler("test_handler", handler)

        assert "test_handler" in service._notification_handlers

    def test_unregister_notification_handler(self, service):
        """Test unregistering a notification handler."""
        handler = MagicMock()
        service.register_notification_handler("test_handler", handler)
        service.unregister_notification_handler("test_handler")

        assert "test_handler" not in service._notification_handlers

    def test_notification_handler_called_on_alert(self, service):
        """Test notification handler is called when alert triggers."""
        handler = MagicMock()
        service.register_notification_handler("test_handler", handler)

        rule = service.create_alert_rule(
            name="Notify Test",
            metric=MetricType.CPU_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )
        service._trigger_alert(rule, 90.0)

        handler.assert_called_once()
        call_arg = handler.call_args[0][0]
        assert isinstance(call_arg, Alert)


class TestMonitoringSummary:
    """Test monitoring summary functionality."""

    @pytest.fixture
    def service(self):
        """Create fresh service instance."""
        return MonitoringService()

    def test_get_summary(self, service):
        """Test getting monitoring summary."""
        # Add some rules
        service.create_alert_rule(
            name="Rule 1",
            metric=MetricType.CPU_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=80.0,
        )
        rule2 = service.create_alert_rule(
            name="Rule 2",
            metric=MetricType.MEMORY_USAGE,
            condition=AlertCondition.GREATER_THAN,
            threshold=85.0,
        )
        # Disable the second rule
        service.update_alert_rule(rule2.rule_id, enabled=False)

        summary = service.get_summary()

        assert "psutil_available" in summary
        assert summary["total_alert_rules"] == 2
        assert summary["enabled_rules"] == 1
        assert "active_alerts" in summary
        assert "active_alerts_by_severity" in summary

    def test_summary_counts_by_severity(self, service):
        """Test summary counts alerts by severity."""
        summary = service.get_summary()

        assert "info" in summary["active_alerts_by_severity"]
        assert "warning" in summary["active_alerts_by_severity"]
        assert "error" in summary["active_alerts_by_severity"]
        assert "critical" in summary["active_alerts_by_severity"]
