"""
Notification Hub Router Tests (v1.7.7)

Comprehensive tests for multi-channel notification management, templates,
routing rules, escalation policies, and delivery tracking.
"""

import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

# auth_token and auth_headers fixtures are provided by tests/api/conftest.py


@pytest.fixture
def sample_email_channel():
    """Sample email channel configuration"""
    return {
        "name": "Security Alerts Email",
        "channel_type": "email",
        "description": "Email channel for security alerts",
        "enabled": True,
        "categories": ["security_alert", "incident"],
        "priority_threshold": "medium",
        "rate_limit_per_minute": 30,
        "rate_limit_per_hour": 200,
        "config": {
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "from_address": "security@example.com",
            "default_recipients": ["soc@example.com"]
        }
    }


@pytest.fixture
def sample_slack_channel():
    """Sample Slack channel configuration"""
    return {
        "name": "SOC Slack Channel",
        "channel_type": "slack",
        "description": "Slack notifications for SOC team",
        "enabled": True,
        "categories": ["security_alert", "system_health"],
        "priority_threshold": "low",
        "rate_limit_per_minute": 60,
        "rate_limit_per_hour": 500,
        "config": {
            "webhook_url": "https://hooks.slack.com/services/xxx/yyy/zzz",
            "default_channel": "#security-alerts",
            "username": "Defensive Toolkit"
        }
    }


@pytest.fixture
def sample_template():
    """Sample notification template"""
    return {
        "name": "Security Alert Template",
        "category": "security_alert",
        "description": "Standard template for security alerts",
        "subject_template": "[{{severity}}] Security Alert: {{alert_name}}",
        "body_template": "Alert Details:\n\nName: {{alert_name}}\nSeverity: {{severity}}\nSource: {{source}}\nTimestamp: {{timestamp}}\n\nDescription:\n{{description}}",
        "html_template": "<h2>Security Alert: {{alert_name}}</h2><p><strong>Severity:</strong> {{severity}}</p><p>{{description}}</p>",
        "variables": [
            {"name": "alert_name", "description": "Name of the alert", "required": True, "default_value": None},
            {"name": "severity", "description": "Alert severity", "required": True, "default_value": "medium"},
            {"name": "source", "description": "Alert source", "required": False, "default_value": "Unknown"},
            {"name": "timestamp", "description": "Alert timestamp", "required": False, "default_value": None},
            {"name": "description", "description": "Alert description", "required": False, "default_value": "No description provided"}
        ],
        "default_priority": "high",
        "channel_overrides": {}
    }


@pytest.fixture
def sample_routing_rule():
    """Sample routing rule configuration"""
    return {
        "name": "Critical Alert Routing",
        "description": "Route critical alerts to all channels",
        "enabled": True,
        "priority": 1,
        "conditions": [
            {"field": "priority", "operator": "equals", "value": "critical"}
        ],
        "condition_logic": "all",
        "actions": [
            {"action_type": "route", "channel_ids": [], "template_id": None, "priority_override": None}
        ],
        "schedule": None
    }


@pytest.fixture
def sample_escalation_policy():
    """Sample escalation policy configuration"""
    return {
        "name": "Critical Incident Escalation",
        "description": "Escalation for critical security incidents",
        "enabled": True,
        "categories": ["incident"],
        "min_priority": "high",
        "steps": [
            {
                "step_number": 1,
                "delay_minutes": 0,
                "channel_ids": [],
                "repeat_count": 1,
                "repeat_interval_minutes": 5
            },
            {
                "step_number": 2,
                "delay_minutes": 15,
                "channel_ids": [],
                "repeat_count": 2,
                "repeat_interval_minutes": 10
            }
        ],
        "acknowledgment_timeout_minutes": 30,
        "total_timeout_minutes": 120
    }


class TestNotificationChannels:
    """Test notification channel CRUD operations"""

    def test_list_channels_empty(self, auth_headers):
        """Test listing channels when none exist"""
        response = client.get("/api/v1/notifications/channels", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "channels" in data
        assert "total" in data
        assert "by_type" in data
        assert "by_status" in data

    def test_create_email_channel(self, auth_headers, sample_email_channel):
        """Test creating an email channel"""
        response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["channel"]["name"] == sample_email_channel["name"]
        assert data["channel"]["channel_type"] == "email"
        assert "id" in data["channel"]

    def test_create_slack_channel(self, auth_headers, sample_slack_channel):
        """Test creating a Slack channel"""
        response = client.post(
            "/api/v1/notifications/channels",
            json=sample_slack_channel,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["channel"]["channel_type"] == "slack"

    def test_get_channel_by_id(self, auth_headers, sample_email_channel):
        """Test getting a specific channel"""
        # Create channel
        create_response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        channel_id = create_response.json()["channel"]["id"]

        # Get channel
        response = client.get(
            f"/api/v1/notifications/channels/{channel_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["channel"]["id"] == channel_id

    def test_get_nonexistent_channel(self, auth_headers):
        """Test getting a channel that doesn't exist"""
        response = client.get(
            "/api/v1/notifications/channels/nonexistent-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_update_channel(self, auth_headers, sample_email_channel):
        """Test updating a channel"""
        # Create channel
        create_response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        channel_id = create_response.json()["channel"]["id"]

        # Update channel
        update_data = {
            "name": "Updated Email Channel",
            "enabled": False,
            "rate_limit_per_minute": 50
        }
        response = client.put(
            f"/api/v1/notifications/channels/{channel_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["channel"]["name"] == "Updated Email Channel"
        assert data["channel"]["enabled"] is False
        assert data["channel"]["rate_limit_per_minute"] == 50

    def test_delete_channel(self, auth_headers, sample_email_channel):
        """Test deleting a channel"""
        # Create channel
        create_response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        channel_id = create_response.json()["channel"]["id"]

        # Delete channel
        response = client.delete(
            f"/api/v1/notifications/channels/{channel_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"

        # Verify deletion
        get_response = client.get(
            f"/api/v1/notifications/channels/{channel_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404

    def test_test_channel(self, auth_headers, sample_email_channel):
        """Test sending a test message to a channel"""
        # Create channel
        create_response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        channel_id = create_response.json()["channel"]["id"]

        # Test channel
        response = client.post(
            f"/api/v1/notifications/channels/{channel_id}/test",
            json={"test_message": "This is a test notification"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["channel_id"] == channel_id
        assert "response_time_ms" in data

    def test_list_channels_with_filters(self, auth_headers, sample_email_channel, sample_slack_channel):
        """Test listing channels with filters"""
        # Create multiple channels
        client.post("/api/v1/notifications/channels", json=sample_email_channel, headers=auth_headers)
        client.post("/api/v1/notifications/channels", json=sample_slack_channel, headers=auth_headers)

        # Filter by type
        response = client.get(
            "/api/v1/notifications/channels?channel_type=email",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        for channel in data["channels"]:
            assert channel["channel_type"] == "email"


class TestNotificationTemplates:
    """Test notification template operations"""

    def test_list_templates_empty(self, auth_headers):
        """Test listing templates when none exist"""
        response = client.get("/api/v1/notifications/templates", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "templates" in data
        assert "total" in data
        assert "by_category" in data

    def test_create_template(self, auth_headers, sample_template):
        """Test creating a notification template"""
        response = client.post(
            "/api/v1/notifications/templates",
            json=sample_template,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["template"]["name"] == sample_template["name"]
        assert "id" in data["template"]

    def test_get_template_by_id(self, auth_headers, sample_template):
        """Test getting a specific template"""
        # Create template
        create_response = client.post(
            "/api/v1/notifications/templates",
            json=sample_template,
            headers=auth_headers
        )
        template_id = create_response.json()["template"]["id"]

        # Get template
        response = client.get(
            f"/api/v1/notifications/templates/{template_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["template"]["id"] == template_id

    def test_get_nonexistent_template(self, auth_headers):
        """Test getting a template that doesn't exist"""
        response = client.get(
            "/api/v1/notifications/templates/nonexistent-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_update_template(self, auth_headers, sample_template):
        """Test updating a template"""
        # Create template
        create_response = client.post(
            "/api/v1/notifications/templates",
            json=sample_template,
            headers=auth_headers
        )
        template_id = create_response.json()["template"]["id"]

        # Update template
        update_data = {
            "name": "Updated Security Alert Template",
            "subject_template": "[ALERT] {{alert_name}}"
        }
        response = client.put(
            f"/api/v1/notifications/templates/{template_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["template"]["name"] == "Updated Security Alert Template"

    def test_delete_template(self, auth_headers, sample_template):
        """Test deleting a template"""
        # Create template
        create_response = client.post(
            "/api/v1/notifications/templates",
            json=sample_template,
            headers=auth_headers
        )
        template_id = create_response.json()["template"]["id"]

        # Delete template
        response = client.delete(
            f"/api/v1/notifications/templates/{template_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"

    def test_render_template(self, auth_headers, sample_template):
        """Test rendering a template with variables"""
        # Create template
        create_response = client.post(
            "/api/v1/notifications/templates",
            json=sample_template,
            headers=auth_headers
        )
        template_id = create_response.json()["template"]["id"]

        # Render template
        render_request = {
            "template_id": template_id,
            "variables": {
                "alert_name": "Suspicious Login Detected",
                "severity": "HIGH",
                "source": "SIEM",
                "timestamp": "2025-01-15T10:30:00Z",
                "description": "Multiple failed login attempts from unknown IP"
            },
            "target_channel": None
        }
        response = client.post(
            "/api/v1/notifications/templates/render",
            json=render_request,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "Suspicious Login Detected" in data["body"]
        assert "HIGH" in data["subject"]

    def test_render_template_missing_variables(self, auth_headers, sample_template):
        """Test rendering a template with missing required variables"""
        # Create template
        create_response = client.post(
            "/api/v1/notifications/templates",
            json=sample_template,
            headers=auth_headers
        )
        template_id = create_response.json()["template"]["id"]

        # Render with missing variables
        render_request = {
            "template_id": template_id,
            "variables": {
                "source": "SIEM"
                # Missing required: alert_name, severity
            }
        }
        response = client.post(
            "/api/v1/notifications/templates/render",
            json=render_request,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "missing_variables" in data
        assert "alert_name" in data["missing_variables"]


class TestRoutingRules:
    """Test notification routing rules"""

    def test_list_routing_rules_empty(self, auth_headers):
        """Test listing routing rules when none exist"""
        response = client.get("/api/v1/notifications/routing-rules", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data
        assert "total" in data

    def test_create_routing_rule(self, auth_headers, sample_routing_rule):
        """Test creating a routing rule"""
        response = client.post(
            "/api/v1/notifications/routing-rules",
            json=sample_routing_rule,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["rule"]["name"] == sample_routing_rule["name"]
        assert "id" in data["rule"]

    def test_get_routing_rule_by_id(self, auth_headers, sample_routing_rule):
        """Test getting a specific routing rule"""
        # Create rule
        create_response = client.post(
            "/api/v1/notifications/routing-rules",
            json=sample_routing_rule,
            headers=auth_headers
        )
        rule_id = create_response.json()["rule"]["id"]

        # Get rule
        response = client.get(
            f"/api/v1/notifications/routing-rules/{rule_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["rule"]["id"] == rule_id

    def test_update_routing_rule(self, auth_headers, sample_routing_rule):
        """Test updating a routing rule"""
        # Create rule
        create_response = client.post(
            "/api/v1/notifications/routing-rules",
            json=sample_routing_rule,
            headers=auth_headers
        )
        rule_id = create_response.json()["rule"]["id"]

        # Update rule
        update_data = {
            "name": "Updated Critical Alert Routing",
            "priority": 2,
            "enabled": False
        }
        response = client.put(
            f"/api/v1/notifications/routing-rules/{rule_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["rule"]["name"] == "Updated Critical Alert Routing"
        assert data["rule"]["priority"] == 2
        assert data["rule"]["enabled"] is False

    def test_delete_routing_rule(self, auth_headers, sample_routing_rule):
        """Test deleting a routing rule"""
        # Create rule
        create_response = client.post(
            "/api/v1/notifications/routing-rules",
            json=sample_routing_rule,
            headers=auth_headers
        )
        rule_id = create_response.json()["rule"]["id"]

        # Delete rule
        response = client.delete(
            f"/api/v1/notifications/routing-rules/{rule_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"

    def test_list_routing_rules_sorted_by_priority(self, auth_headers):
        """Test that routing rules are sorted by priority"""
        # Create rules with different priorities
        rule1 = {
            "name": "Low Priority Rule",
            "enabled": True,
            "priority": 10,
            "conditions": [],
            "condition_logic": "all",
            "actions": []
        }
        rule2 = {
            "name": "High Priority Rule",
            "enabled": True,
            "priority": 1,
            "conditions": [],
            "condition_logic": "all",
            "actions": []
        }

        client.post("/api/v1/notifications/routing-rules", json=rule1, headers=auth_headers)
        client.post("/api/v1/notifications/routing-rules", json=rule2, headers=auth_headers)

        response = client.get("/api/v1/notifications/routing-rules", headers=auth_headers)
        data = response.json()

        # Verify sorted by priority (lower number = higher priority)
        if len(data["rules"]) >= 2:
            priorities = [r["priority"] for r in data["rules"]]
            assert priorities == sorted(priorities)


class TestNotifications:
    """Test notification sending and management"""

    def test_list_notifications_empty(self, auth_headers):
        """Test listing notifications when none exist"""
        response = client.get("/api/v1/notifications/", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "notifications" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data

    def test_send_notification(self, auth_headers, sample_email_channel):
        """Test sending a notification"""
        # Create channel first
        channel_response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        channel_id = channel_response.json()["channel"]["id"]

        # Send notification
        notification = {
            "category": "security_alert",
            "priority": "high",
            "subject": "Test Security Alert",
            "body": "This is a test security alert notification.",
            "source": "test",
            "recipients": [
                {"channel_id": channel_id, "address": "test@example.com"}
            ],
            "tags": ["test", "security"]
        }
        response = client.post(
            "/api/v1/notifications/",
            json=notification,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "notification" in data
        assert "id" in data["notification"]

    def test_get_notification_by_id(self, auth_headers, sample_email_channel):
        """Test getting a specific notification"""
        # Create channel and send notification
        channel_response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        channel_id = channel_response.json()["channel"]["id"]

        notification = {
            "category": "security_alert",
            "priority": "medium",
            "subject": "Test Alert",
            "body": "Test notification body",
            "recipients": [{"channel_id": channel_id}]
        }
        send_response = client.post(
            "/api/v1/notifications/",
            json=notification,
            headers=auth_headers
        )
        notification_id = send_response.json()["notification"]["id"]

        # Get notification
        response = client.get(
            f"/api/v1/notifications/{notification_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["notification"]["id"] == notification_id

    def test_get_nonexistent_notification(self, auth_headers):
        """Test getting a notification that doesn't exist"""
        response = client.get(
            "/api/v1/notifications/nonexistent-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_send_notification_with_deduplication(self, auth_headers, sample_email_channel):
        """Test notification deduplication"""
        # Create channel
        channel_response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        channel_id = channel_response.json()["channel"]["id"]

        # Send first notification with dedupe key
        notification = {
            "category": "security_alert",
            "priority": "high",
            "subject": "Duplicate Test",
            "body": "First notification",
            "dedupe_key": "unique-dedupe-key-123",
            "dedupe_window_seconds": 300,
            "recipients": [{"channel_id": channel_id}]
        }
        first_response = client.post(
            "/api/v1/notifications/",
            json=notification,
            headers=auth_headers
        )
        assert first_response.status_code == 200

        # Send duplicate (same dedupe key)
        notification["body"] = "Duplicate notification"
        second_response = client.post(
            "/api/v1/notifications/",
            json=notification,
            headers=auth_headers
        )
        assert second_response.status_code == 409  # Conflict - duplicate

    def test_send_bulk_notifications(self, auth_headers, sample_email_channel):
        """Test sending bulk notifications"""
        # Create channel
        channel_response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        channel_id = channel_response.json()["channel"]["id"]

        # Send bulk notifications
        bulk_request = {
            "notifications": [
                {
                    "category": "security_alert",
                    "priority": "high",
                    "subject": "Bulk Test 1",
                    "body": "First bulk notification",
                    "recipients": [{"channel_id": channel_id}]
                },
                {
                    "category": "security_alert",
                    "priority": "medium",
                    "subject": "Bulk Test 2",
                    "body": "Second bulk notification",
                    "recipients": [{"channel_id": channel_id}]
                }
            ],
            "fail_on_first_error": False
        }
        response = client.post(
            "/api/v1/notifications/bulk",
            json=bulk_request,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_requested"] == 2
        assert data["succeeded"] >= 0

    def test_list_notifications_with_filters(self, auth_headers, sample_email_channel):
        """Test listing notifications with filters"""
        # Create channel and send notifications
        channel_response = client.post(
            "/api/v1/notifications/channels",
            json=sample_email_channel,
            headers=auth_headers
        )
        channel_id = channel_response.json()["channel"]["id"]

        # Send notifications with different priorities
        for priority in ["low", "medium", "high"]:
            notification = {
                "category": "security_alert",
                "priority": priority,
                "subject": f"{priority.capitalize()} Priority Test",
                "body": f"Test notification with {priority} priority",
                "recipients": [{"channel_id": channel_id}]
            }
            client.post("/api/v1/notifications/", json=notification, headers=auth_headers)

        # Filter by priority
        response = client.get(
            "/api/v1/notifications/?priority=high",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        for notif in data["notifications"]:
            assert notif["priority"] == "high"


class TestEscalationPolicies:
    """Test escalation policy operations"""

    def test_list_escalation_policies_empty(self, auth_headers):
        """Test listing escalation policies when none exist"""
        response = client.get("/api/v1/notifications/escalation-policies", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "policies" in data
        assert "total" in data

    def test_create_escalation_policy(self, auth_headers, sample_escalation_policy):
        """Test creating an escalation policy"""
        response = client.post(
            "/api/v1/notifications/escalation-policies",
            json=sample_escalation_policy,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["policy"]["name"] == sample_escalation_policy["name"]
        assert "id" in data["policy"]

    def test_get_escalation_policy_by_id(self, auth_headers, sample_escalation_policy):
        """Test getting a specific escalation policy"""
        # Create policy
        create_response = client.post(
            "/api/v1/notifications/escalation-policies",
            json=sample_escalation_policy,
            headers=auth_headers
        )
        policy_id = create_response.json()["policy"]["id"]

        # Get policy
        response = client.get(
            f"/api/v1/notifications/escalation-policies/{policy_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["policy"]["id"] == policy_id

    def test_update_escalation_policy(self, auth_headers, sample_escalation_policy):
        """Test updating an escalation policy"""
        # Create policy
        create_response = client.post(
            "/api/v1/notifications/escalation-policies",
            json=sample_escalation_policy,
            headers=auth_headers
        )
        policy_id = create_response.json()["policy"]["id"]

        # Update policy
        update_data = {
            "name": "Updated Escalation Policy",
            "enabled": False,
            "acknowledgment_timeout_minutes": 45
        }
        response = client.put(
            f"/api/v1/notifications/escalation-policies/{policy_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["policy"]["name"] == "Updated Escalation Policy"
        assert data["policy"]["enabled"] is False

    def test_delete_escalation_policy(self, auth_headers, sample_escalation_policy):
        """Test deleting an escalation policy"""
        # Create policy
        create_response = client.post(
            "/api/v1/notifications/escalation-policies",
            json=sample_escalation_policy,
            headers=auth_headers
        )
        policy_id = create_response.json()["policy"]["id"]

        # Delete policy
        response = client.delete(
            f"/api/v1/notifications/escalation-policies/{policy_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"


class TestActiveEscalations:
    """Test active escalation management"""

    def test_list_active_escalations(self, auth_headers):
        """Test listing active escalations"""
        response = client.get("/api/v1/notifications/escalations/active", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "escalations" in data
        assert "total" in data


class TestSubscriptions:
    """Test notification subscriptions"""

    def test_list_subscriptions_empty(self, auth_headers):
        """Test listing subscriptions when none exist"""
        response = client.get("/api/v1/notifications/subscriptions", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "subscriptions" in data
        assert "total" in data

    def test_create_subscription(self, auth_headers):
        """Test creating a subscription"""
        subscription = {
            "subscriber_id": "user-123",
            "subscriber_type": "user",
            "categories": ["security_alert", "incident"],
            "min_priority": "medium",
            "channels": ["email", "slack"],
            "schedule": None
        }
        response = client.post(
            "/api/v1/notifications/subscriptions",
            json=subscription,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["subscription"]["subscriber_id"] == "user-123"

    def test_update_subscription(self, auth_headers):
        """Test updating a subscription"""
        # Create subscription
        subscription = {
            "subscriber_id": "user-456",
            "subscriber_type": "user",
            "categories": ["security_alert"],
            "min_priority": "low",
            "channels": ["email"]
        }
        create_response = client.post(
            "/api/v1/notifications/subscriptions",
            json=subscription,
            headers=auth_headers
        )
        subscription_id = create_response.json()["subscription"]["id"]

        # Update subscription
        update_data = {
            "min_priority": "high",
            "enabled": False
        }
        response = client.put(
            f"/api/v1/notifications/subscriptions/{subscription_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["subscription"]["min_priority"] == "high"
        assert data["subscription"]["enabled"] is False

    def test_delete_subscription(self, auth_headers):
        """Test deleting a subscription"""
        # Create subscription
        subscription = {
            "subscriber_id": "user-789",
            "subscriber_type": "user",
            "categories": ["incident"],
            "min_priority": "medium",
            "channels": ["slack"]
        }
        create_response = client.post(
            "/api/v1/notifications/subscriptions",
            json=subscription,
            headers=auth_headers
        )
        subscription_id = create_response.json()["subscription"]["id"]

        # Delete subscription
        response = client.delete(
            f"/api/v1/notifications/subscriptions/{subscription_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"


class TestNotificationStats:
    """Test notification statistics and health endpoints"""

    def test_get_notification_stats(self, auth_headers):
        """Test getting notification statistics"""
        response = client.get("/api/v1/notifications/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_notifications" in data
        assert "notifications_today" in data
        assert "notifications_this_hour" in data
        assert "by_status" in data
        assert "by_category" in data
        assert "by_priority" in data
        assert "avg_delivery_time_seconds" in data
        assert "success_rate_percent" in data
        assert "channels_active" in data
        assert "queue_depth" in data

    def test_get_notification_health(self, auth_headers):
        """Test getting notification system health"""
        response = client.get("/api/v1/notifications/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in data
        assert "channels_status" in data
        assert "queue_status" in data
        assert "recent_failures" in data
        assert "recommendations" in data


class TestNotificationAuthentication:
    """Test authentication requirements for notification endpoints"""

    def test_list_channels_requires_auth(self):
        """Test that listing channels requires authentication"""
        response = client.get("/api/v1/notifications/channels")
        assert response.status_code == 401

    def test_create_channel_requires_auth(self, sample_email_channel):
        """Test that creating channels requires authentication"""
        response = client.post("/api/v1/notifications/channels", json=sample_email_channel)
        assert response.status_code == 401

    def test_list_notifications_requires_auth(self):
        """Test that listing notifications requires authentication"""
        response = client.get("/api/v1/notifications/")
        assert response.status_code == 401

    def test_send_notification_requires_auth(self):
        """Test that sending notifications requires authentication"""
        notification = {
            "category": "security_alert",
            "priority": "high",
            "subject": "Test",
            "body": "Test"
        }
        response = client.post("/api/v1/notifications/", json=notification)
        assert response.status_code == 401

    def test_stats_requires_auth(self):
        """Test that stats requires authentication"""
        response = client.get("/api/v1/notifications/stats")
        assert response.status_code == 401

    def test_health_requires_auth(self):
        """Test that health requires authentication"""
        response = client.get("/api/v1/notifications/health")
        assert response.status_code == 401


class TestNotificationValidation:
    """Test input validation for notification endpoints"""

    def test_create_channel_invalid_type(self, auth_headers):
        """Test creating channel with invalid type"""
        invalid_channel = {
            "name": "Invalid Channel",
            "channel_type": "invalid_type",
            "enabled": True
        }
        response = client.post(
            "/api/v1/notifications/channels",
            json=invalid_channel,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_send_notification_invalid_priority(self, auth_headers):
        """Test sending notification with invalid priority"""
        notification = {
            "category": "security_alert",
            "priority": "invalid_priority",
            "subject": "Test",
            "body": "Test"
        }
        response = client.post(
            "/api/v1/notifications/",
            json=notification,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_send_notification_invalid_category(self, auth_headers):
        """Test sending notification with invalid category"""
        notification = {
            "category": "invalid_category",
            "priority": "high",
            "subject": "Test",
            "body": "Test"
        }
        response = client.post(
            "/api/v1/notifications/",
            json=notification,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_list_notifications_invalid_page(self, auth_headers):
        """Test listing notifications with invalid page"""
        response = client.get(
            "/api/v1/notifications/?page=0",
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_list_notifications_invalid_page_size(self, auth_headers):
        """Test listing notifications with invalid page size"""
        response = client.get(
            "/api/v1/notifications/?page_size=500",
            headers=auth_headers
        )
        assert response.status_code == 422
