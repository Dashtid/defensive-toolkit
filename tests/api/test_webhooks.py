"""
Webhook Router Integration Tests

Comprehensive test coverage for the webhooks API including:
- CRUD operations for webhook configurations
- Signature verification (SHA256, SHA1)
- IP whitelist enforcement
- Trigger rule matching (exact, contains, regex)
- Rate limiting per rule
- SIEM presets (Wazuh, Elastic, OpenSearch, Graylog)
- Statistics tracking
"""

import hashlib
import hmac
import json
import time
from datetime import datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from defensive_toolkit.api.main import app
from defensive_toolkit.api.routers import webhooks


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_token(client):
    """Get authentication token."""
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "changeme123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Get authentication headers."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture(autouse=True)
def clear_webhooks_db():
    """Clear webhook database before each test."""
    webhooks.webhooks_db.clear()
    webhooks.webhook_stats.clear()
    webhooks.trigger_history.clear()
    webhooks.rate_limit_tracker.clear()
    yield
    # Cleanup after test
    webhooks.webhooks_db.clear()
    webhooks.webhook_stats.clear()


@pytest.fixture
def sample_webhook_config():
    """Sample webhook configuration."""
    return {
        "name": "Test Wazuh Webhook",
        "description": "Test webhook for Wazuh alerts",
        "source": "wazuh",
        "status": "active",
        "secret_key": "test-secret-key-12345",
        "allowed_ips": [],
        "alert_id_field": "id",
        "alert_severity_field": "rule.level",
        "alert_title_field": "rule.description",
        "alert_description_field": "full_log",
        "alert_timestamp_field": "timestamp",
        "default_runbook_id": "test-runbook",
        "default_execution_mode": "dry_run",
        "trigger_rules": [],
    }


@pytest.fixture
def sample_trigger_rule():
    """Sample trigger rule."""
    return {
        "name": "High Severity Rule",
        "description": "Triggers on high severity alerts",
        "enabled": True,
        "match_field": "rule.level",
        "match_pattern": "1[2-5]",
        "match_type": "regex",
        "runbook_id": "high-severity-runbook",
        "execution_mode": "dry_run",
        "cooldown_seconds": 60,
        "max_triggers_per_hour": 10,
        "variable_mappings": {
            "alert_source": "agent.name",
            "src_ip": "data.srcip",
        },
    }


@pytest.fixture
def sample_alert_payload():
    """Sample Wazuh alert payload."""
    return {
        "id": "alert-12345",
        "timestamp": datetime.utcnow().isoformat(),
        "rule": {
            "level": 14,
            "description": "High severity security alert",
            "groups": ["authentication_failed", "credential_access"],
        },
        "agent": {
            "name": "server-01",
            "ip": "192.168.1.100",
        },
        "data": {
            "srcip": "10.0.0.50",
            "srcuser": "attacker",
        },
        "full_log": "Failed login attempt from 10.0.0.50",
    }


# ============================================================================
# Webhook CRUD Tests
# ============================================================================


class TestWebhookCRUD:
    """Test webhook configuration CRUD operations."""

    def test_create_webhook(self, client, auth_headers, sample_webhook_config):
        """Test creating a new webhook configuration."""
        response = client.post(
            "/api/v1/webhooks",
            json=sample_webhook_config,
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "success"
        assert "webhook_id" in data["data"]
        assert data["data"]["webhook_id"].startswith("WH-")

    def test_list_webhooks(self, client, auth_headers, sample_webhook_config):
        """Test listing all webhooks."""
        # Create a webhook first
        client.post("/api/v1/webhooks", json=sample_webhook_config, headers=auth_headers)

        response = client.get("/api/v1/webhooks", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "webhooks" in data
        assert data["total"] >= 1

    def test_get_webhook(self, client, auth_headers, sample_webhook_config):
        """Test getting a specific webhook."""
        # Create webhook
        create_response = client.post(
            "/api/v1/webhooks", json=sample_webhook_config, headers=auth_headers
        )
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Get webhook
        response = client.get(f"/api/v1/webhooks/{webhook_id}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == sample_webhook_config["name"]
        # Secret should be masked
        assert data["secret_key"].startswith("***")

    def test_get_webhook_not_found(self, client, auth_headers):
        """Test getting non-existent webhook."""
        response = client.get("/api/v1/webhooks/WH-NOTFOUND", headers=auth_headers)
        assert response.status_code == 404

    def test_update_webhook(self, client, auth_headers, sample_webhook_config):
        """Test updating a webhook configuration."""
        # Create webhook
        create_response = client.post(
            "/api/v1/webhooks", json=sample_webhook_config, headers=auth_headers
        )
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Update webhook
        updated_config = sample_webhook_config.copy()
        updated_config["name"] = "Updated Webhook Name"
        updated_config["description"] = "Updated description"

        response = client.put(
            f"/api/v1/webhooks/{webhook_id}",
            json=updated_config,
            headers=auth_headers,
        )
        assert response.status_code == 200

        # Verify update
        get_response = client.get(f"/api/v1/webhooks/{webhook_id}", headers=auth_headers)
        assert get_response.json()["name"] == "Updated Webhook Name"

    def test_delete_webhook(self, client, auth_headers, sample_webhook_config):
        """Test deleting a webhook configuration."""
        # Create webhook
        create_response = client.post(
            "/api/v1/webhooks", json=sample_webhook_config, headers=auth_headers
        )
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Delete webhook
        response = client.delete(f"/api/v1/webhooks/{webhook_id}", headers=auth_headers)
        assert response.status_code == 200

        # Verify deletion
        get_response = client.get(f"/api/v1/webhooks/{webhook_id}", headers=auth_headers)
        assert get_response.status_code == 404

    def test_filter_webhooks_by_source(self, client, auth_headers, sample_webhook_config):
        """Test filtering webhooks by source."""
        # Create webhooks with different sources
        client.post("/api/v1/webhooks", json=sample_webhook_config, headers=auth_headers)

        elastic_config = sample_webhook_config.copy()
        elastic_config["name"] = "Elastic Webhook"
        elastic_config["source"] = "elastic"
        client.post("/api/v1/webhooks", json=elastic_config, headers=auth_headers)

        # Filter by source
        response = client.get("/api/v1/webhooks?source=wazuh", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert all(w["source"] == "wazuh" for w in data["webhooks"])


# ============================================================================
# Signature Verification Tests
# ============================================================================


class TestSignatureVerification:
    """Test webhook signature verification."""

    def test_sha256_signature_verification(self, client, auth_headers, sample_webhook_config):
        """Test SHA256 signature verification."""
        # Create webhook with secret
        create_response = client.post(
            "/api/v1/webhooks", json=sample_webhook_config, headers=auth_headers
        )
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Prepare payload and signature
        payload = {"id": "test-alert", "rule": {"level": 10, "description": "Test"}}
        payload_bytes = json.dumps(payload).encode()
        signature = hmac.new(
            sample_webhook_config["secret_key"].encode(),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()

        # Trigger with valid signature
        response = client.post(
            f"/api/v1/webhooks/{webhook_id}/trigger",
            content=payload_bytes,
            headers={"X-Signature-256": f"sha256={signature}"},
        )
        # Should process (may fail on runbook, but signature passes)
        assert response.status_code == 200

    def test_sha1_signature_verification(self, client, auth_headers, sample_webhook_config):
        """Test SHA1 signature verification (legacy support)."""
        create_response = client.post(
            "/api/v1/webhooks", json=sample_webhook_config, headers=auth_headers
        )
        webhook_id = create_response.json()["data"]["webhook_id"]

        payload = {"id": "test-alert", "rule": {"level": 10, "description": "Test"}}
        payload_bytes = json.dumps(payload).encode()
        signature = hmac.new(
            sample_webhook_config["secret_key"].encode(),
            payload_bytes,
            hashlib.sha1,
        ).hexdigest()

        response = client.post(
            f"/api/v1/webhooks/{webhook_id}/trigger",
            content=payload_bytes,
            headers={"X-Signature": f"sha1={signature}"},
        )
        assert response.status_code == 200

    def test_invalid_signature_rejected(self, client, auth_headers, sample_webhook_config):
        """Test that invalid signatures are rejected."""
        create_response = client.post(
            "/api/v1/webhooks", json=sample_webhook_config, headers=auth_headers
        )
        webhook_id = create_response.json()["data"]["webhook_id"]

        payload = {"id": "test-alert"}
        response = client.post(
            f"/api/v1/webhooks/{webhook_id}/trigger",
            json=payload,
            headers={"X-Signature-256": "sha256=invalid_signature"},
        )
        assert response.status_code == 401
        assert "Invalid signature" in response.json()["detail"]

    def test_missing_signature_rejected(self, client, auth_headers, sample_webhook_config):
        """Test that missing signature is rejected when secret is configured."""
        create_response = client.post(
            "/api/v1/webhooks", json=sample_webhook_config, headers=auth_headers
        )
        webhook_id = create_response.json()["data"]["webhook_id"]

        payload = {"id": "test-alert"}
        response = client.post(
            f"/api/v1/webhooks/{webhook_id}/trigger",
            json=payload,
        )
        assert response.status_code == 401
        assert "Signature required" in response.json()["detail"]

    def test_no_signature_required_without_secret(self, client, auth_headers):
        """Test that signature is not required when no secret is configured."""
        config = {
            "name": "No Secret Webhook",
            "source": "generic",
            "secret_key": "",  # No secret
            "alert_id_field": "id",
            "alert_severity_field": "severity",
            "alert_title_field": "title",
            "alert_description_field": "description",
            "alert_timestamp_field": "timestamp",
        }
        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        payload = {"id": "test-alert", "severity": "high", "title": "Test", "timestamp": "now"}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200


# ============================================================================
# IP Whitelist Tests
# ============================================================================


class TestIPWhitelist:
    """Test IP whitelist enforcement."""

    def test_ip_whitelist_allows_valid_ip(self, client, auth_headers):
        """Test that whitelisted IPs are allowed."""
        config = {
            "name": "IP Restricted Webhook",
            "source": "generic",
            "secret_key": "",
            "allowed_ips": ["127.0.0.1", "192.168.1.0/24"],
            "alert_id_field": "id",
            "alert_severity_field": "severity",
            "alert_title_field": "title",
            "alert_description_field": "description",
            "alert_timestamp_field": "timestamp",
        }
        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # TestClient uses 127.0.0.1 by default
        payload = {"id": "test", "severity": "low", "title": "Test", "timestamp": "now"}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200

    def test_ip_whitelist_blocks_invalid_ip(self, client, auth_headers):
        """Test that non-whitelisted IPs are blocked."""
        config = {
            "name": "IP Restricted Webhook",
            "source": "generic",
            "secret_key": "",
            "allowed_ips": ["10.0.0.1"],  # Only allow 10.0.0.1
            "alert_id_field": "id",
            "alert_severity_field": "severity",
            "alert_title_field": "title",
            "alert_description_field": "description",
            "alert_timestamp_field": "timestamp",
        }
        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # TestClient uses testclient which maps to 127.0.0.1
        payload = {"id": "test", "severity": "low", "title": "Test", "timestamp": "now"}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 403
        assert "IP not allowed" in response.json()["detail"]

    def test_cidr_range_whitelist(self, client, auth_headers):
        """Test CIDR range in IP whitelist."""
        config = {
            "name": "CIDR Webhook",
            "source": "generic",
            "secret_key": "",
            "allowed_ips": ["127.0.0.0/8"],  # Allow all localhost
            "alert_id_field": "id",
            "alert_severity_field": "severity",
            "alert_title_field": "title",
            "alert_description_field": "description",
            "alert_timestamp_field": "timestamp",
        }
        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        payload = {"id": "test", "severity": "low", "title": "Test", "timestamp": "now"}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200


# ============================================================================
# Trigger Rule Tests
# ============================================================================


class TestTriggerRules:
    """Test webhook trigger rule matching."""

    def test_exact_match_rule(self, client, auth_headers, sample_webhook_config):
        """Test exact match trigger rule."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""
        config["trigger_rules"] = [
            {
                "name": "Exact Match Rule",
                "enabled": True,
                "match_field": "rule.level",
                "match_pattern": "14",
                "match_type": "exact",
                "runbook_id": "test-runbook",
                "execution_mode": "dry_run",
                "cooldown_seconds": 0,
                "max_triggers_per_hour": 100,
            }
        ]

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Matching payload
        payload = {"id": "alert-1", "rule": {"level": "14", "description": "Test"}}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["matched_rule"] is not None

    def test_contains_match_rule(self, client, auth_headers, sample_webhook_config):
        """Test contains match trigger rule."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""
        config["trigger_rules"] = [
            {
                "name": "Contains Match Rule",
                "enabled": True,
                "match_field": "rule.description",
                "match_pattern": "malware",
                "match_type": "contains",
                "runbook_id": "malware-runbook",
                "execution_mode": "dry_run",
                "cooldown_seconds": 0,
                "max_triggers_per_hour": 100,
            }
        ]

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Matching payload
        payload = {
            "id": "alert-1",
            "rule": {"level": 10, "description": "Detected malware infection"},
        }
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["matched_rule"] is not None

    def test_regex_match_rule(self, client, auth_headers, sample_webhook_config):
        """Test regex match trigger rule."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""
        config["trigger_rules"] = [
            {
                "name": "Regex Match Rule",
                "enabled": True,
                "match_field": "rule.level",
                "match_pattern": "1[2-5]",  # Levels 12-15
                "match_type": "regex",
                "runbook_id": "high-severity-runbook",
                "execution_mode": "dry_run",
                "cooldown_seconds": 0,
                "max_triggers_per_hour": 100,
            }
        ]

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Matching payload (level 14)
        payload = {"id": "alert-1", "rule": {"level": "14", "description": "Critical"}}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["matched_rule"] is not None

    def test_disabled_rule_not_matched(self, client, auth_headers, sample_webhook_config):
        """Test that disabled rules are not matched."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""
        config["trigger_rules"] = [
            {
                "name": "Disabled Rule",
                "enabled": False,
                "match_field": "rule.level",
                "match_pattern": ".*",
                "match_type": "regex",
                "runbook_id": "test-runbook",
                "execution_mode": "dry_run",
                "cooldown_seconds": 0,
                "max_triggers_per_hour": 100,
            }
        ]

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        payload = {"id": "alert-1", "rule": {"level": "14", "description": "Test"}}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["matched_rule"] is None
        assert data["skipped_reason"] == "no_rule_match"

    def test_rule_priority_order(self, client, auth_headers, sample_webhook_config):
        """Test that rules are matched in order."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""
        config["trigger_rules"] = [
            {
                "name": "First Rule",
                "enabled": True,
                "match_field": "rule.level",
                "match_pattern": "14",
                "match_type": "exact",
                "runbook_id": "first-runbook",
                "execution_mode": "dry_run",
                "cooldown_seconds": 0,
                "max_triggers_per_hour": 100,
            },
            {
                "name": "Second Rule",
                "enabled": True,
                "match_field": "rule.level",
                "match_pattern": "1[0-5]",
                "match_type": "regex",
                "runbook_id": "second-runbook",
                "execution_mode": "dry_run",
                "cooldown_seconds": 0,
                "max_triggers_per_hour": 100,
            },
        ]

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Both rules could match level 14, but first should win
        payload = {"id": "alert-1", "rule": {"level": "14", "description": "Test"}}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200
        data = response.json()
        # First matching rule should be used
        assert data["matched_rule"] is not None


# ============================================================================
# Rate Limiting Tests
# ============================================================================


class TestRateLimiting:
    """Test webhook rate limiting per rule."""

    def test_cooldown_enforcement(self, client, auth_headers, sample_webhook_config):
        """Test that cooldown period is enforced."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""
        config["trigger_rules"] = [
            {
                "name": "Cooldown Rule",
                "enabled": True,
                "match_field": "rule.level",
                "match_pattern": ".*",
                "match_type": "regex",
                "runbook_id": "test-runbook",
                "execution_mode": "dry_run",
                "cooldown_seconds": 60,  # 60 second cooldown
                "max_triggers_per_hour": 100,
            }
        ]

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        payload = {"id": "alert-1", "rule": {"level": "10", "description": "Test"}}

        # First trigger should succeed
        response1 = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response1.status_code == 200
        data1 = response1.json()
        assert data1["matched_rule"] is not None

        # Second trigger within cooldown should be rate limited
        response2 = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response2.status_code == 200
        data2 = response2.json()
        assert data2["skipped_reason"] == "rate_limited"

    def test_hourly_limit_enforcement(self, client, auth_headers, sample_webhook_config):
        """Test that hourly trigger limit is enforced."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""
        config["trigger_rules"] = [
            {
                "name": "Limited Rule",
                "enabled": True,
                "match_field": "rule.level",
                "match_pattern": ".*",
                "match_type": "regex",
                "runbook_id": "test-runbook",
                "execution_mode": "dry_run",
                "cooldown_seconds": 0,  # No cooldown
                "max_triggers_per_hour": 3,  # Only 3 per hour
            }
        ]

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Trigger 3 times (should all succeed)
        for i in range(3):
            payload = {"id": f"alert-{i}", "rule": {"level": "10", "description": "Test"}}
            response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
            assert response.status_code == 200
            data = response.json()
            assert data["matched_rule"] is not None, f"Trigger {i+1} should succeed"

        # 4th trigger should be rate limited
        payload = {"id": "alert-4", "rule": {"level": "10", "description": "Test"}}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["skipped_reason"] == "rate_limited"


# ============================================================================
# Webhook Statistics Tests
# ============================================================================


class TestWebhookStats:
    """Test webhook statistics tracking."""

    def test_stats_tracking(self, client, auth_headers, sample_webhook_config):
        """Test that webhook statistics are tracked."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Trigger webhook
        payload = {"id": "alert-1", "rule": {"level": "10", "description": "Test"}}
        client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)

        # Check stats
        response = client.get(f"/api/v1/webhooks/{webhook_id}/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total_received"] >= 1

    def test_stats_not_found(self, client, auth_headers):
        """Test stats for non-existent webhook."""
        response = client.get("/api/v1/webhooks/WH-NOTFOUND/stats", headers=auth_headers)
        assert response.status_code == 404


# ============================================================================
# SIEM Preset Tests
# ============================================================================


class TestSIEMPresets:
    """Test SIEM-specific preset configurations."""

    @pytest.mark.parametrize(
        "source",
        ["wazuh", "elastic", "opensearch", "graylog", "generic"],
    )
    def test_get_preset(self, client, auth_headers, source):
        """Test getting preset configurations for each SIEM source."""
        response = client.get(f"/api/v1/webhooks/presets/{source}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["source"] == source
        assert "alert_id_field" in data
        assert "alert_severity_field" in data

    def test_wazuh_preset_fields(self, client, auth_headers):
        """Test Wazuh preset has correct field mappings."""
        response = client.get("/api/v1/webhooks/presets/wazuh", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["alert_id_field"] == "id"
        assert data["alert_severity_field"] == "rule.level"
        assert data["alert_title_field"] == "rule.description"

    def test_elastic_preset_fields(self, client, auth_headers):
        """Test Elastic preset has correct field mappings."""
        response = client.get("/api/v1/webhooks/presets/elastic", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["alert_id_field"] == "kibana.alert.uuid"
        assert data["alert_severity_field"] == "kibana.alert.severity"


# ============================================================================
# Webhook Test Endpoint Tests
# ============================================================================


class TestWebhookTesting:
    """Test webhook test functionality."""

    def test_webhook_test_endpoint(self, client, auth_headers, sample_webhook_config):
        """Test the webhook test endpoint."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""
        config["trigger_rules"] = [
            {
                "name": "Test Rule",
                "enabled": True,
                "match_field": "rule.level",
                "match_pattern": "1[0-5]",
                "match_type": "regex",
                "runbook_id": "test-runbook",
                "execution_mode": "dry_run",
                "cooldown_seconds": 0,
                "max_triggers_per_hour": 100,
            }
        ]

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Test webhook with sample payload
        test_request = {
            "test_payload": {
                "id": "test-alert",
                "rule": {"level": "12", "description": "Test alert"},
                "timestamp": datetime.utcnow().isoformat(),
            }
        }

        response = client.post(
            f"/api/v1/webhooks/{webhook_id}/test",
            json=test_request,
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["test_passed"] is True
        assert len(data["matched_rules"]) > 0

    def test_webhook_test_with_missing_fields(self, client, auth_headers, sample_webhook_config):
        """Test webhook test with missing required fields shows warnings."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Test with incomplete payload
        test_request = {
            "test_payload": {
                "some_field": "some_value",
            }
        }

        response = client.post(
            f"/api/v1/webhooks/{webhook_id}/test",
            json=test_request,
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        # Should have warnings about missing fields
        assert len(data["warnings"]) > 0


# ============================================================================
# Trigger Rule Management Tests
# ============================================================================


class TestTriggerRuleManagement:
    """Test trigger rule CRUD operations."""

    def test_add_trigger_rule(self, client, auth_headers, sample_webhook_config, sample_trigger_rule):
        """Test adding a trigger rule to webhook."""
        config = sample_webhook_config.copy()
        config["trigger_rules"] = []

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Add rule
        response = client.post(
            f"/api/v1/webhooks/{webhook_id}/rules",
            json=sample_trigger_rule,
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "rule_id" in data["data"]
        assert data["data"]["rule_id"].startswith("RULE-")

    def test_delete_trigger_rule(self, client, auth_headers, sample_webhook_config, sample_trigger_rule):
        """Test deleting a trigger rule from webhook."""
        config = sample_webhook_config.copy()
        config["trigger_rules"] = []

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        # Add rule
        add_response = client.post(
            f"/api/v1/webhooks/{webhook_id}/rules",
            json=sample_trigger_rule,
            headers=auth_headers,
        )
        rule_id = add_response.json()["data"]["rule_id"]

        # Delete rule
        response = client.delete(
            f"/api/v1/webhooks/{webhook_id}/rules/{rule_id}",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_add_invalid_regex_rule(self, client, auth_headers, sample_webhook_config):
        """Test adding rule with invalid regex pattern."""
        config = sample_webhook_config.copy()
        config["trigger_rules"] = []

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        invalid_rule = {
            "name": "Invalid Regex Rule",
            "enabled": True,
            "match_field": "rule.level",
            "match_pattern": "[invalid(regex",  # Invalid regex
            "match_type": "regex",
            "runbook_id": "test-runbook",
            "execution_mode": "dry_run",
            "cooldown_seconds": 0,
            "max_triggers_per_hour": 100,
        }

        response = client.post(
            f"/api/v1/webhooks/{webhook_id}/rules",
            json=invalid_rule,
            headers=auth_headers,
        )
        assert response.status_code == 400
        assert "Invalid regex" in response.json()["detail"]


# ============================================================================
# Disabled Webhook Tests
# ============================================================================


class TestDisabledWebhook:
    """Test disabled webhook behavior."""

    def test_disabled_webhook_returns_message(self, client, auth_headers, sample_webhook_config):
        """Test that disabled webhooks return appropriate message."""
        config = sample_webhook_config.copy()
        config["secret_key"] = ""
        config["status"] = "disabled"

        create_response = client.post("/api/v1/webhooks", json=config, headers=auth_headers)
        webhook_id = create_response.json()["data"]["webhook_id"]

        payload = {"id": "alert-1", "rule": {"level": "10", "description": "Test"}}
        response = client.post(f"/api/v1/webhooks/{webhook_id}/trigger", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["processed"] is False
        assert data["skipped_reason"] == "webhook_disabled"
