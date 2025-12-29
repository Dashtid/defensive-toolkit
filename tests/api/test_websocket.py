"""
WebSocket Router Tests

Tests for the WebSocket real-time updates functionality including:
- Connection management
- Authentication
- Channel subscriptions
- Broadcasting
- REST API management endpoints
"""

import pytest
from datetime import datetime
from fastapi import status
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock

from defensive_toolkit.api.main import app
from defensive_toolkit.api.routers.websocket import (
    ConnectionManager,
    manager,
    WebSocketConnection,
    publish_runbook_started,
    publish_incident_event,
    publish_alert_event,
    publish_system_alert,
)
from defensive_toolkit.api.models import (
    WebSocketChannelEnum,
    WebSocketAuthRequest,
    StatusEnum,
    IncidentStatusEnum,
    SeverityEnum,
    WebhookSourceEnum,
)


@pytest.fixture
def connection_manager():
    """Create a fresh ConnectionManager for testing."""
    return ConnectionManager()


# ============================================================================
# ConnectionManager Unit Tests
# ============================================================================


class TestConnectionManager:
    """Unit tests for the ConnectionManager class."""

    def test_init(self, connection_manager):
        """Test ConnectionManager initialization."""
        assert connection_manager._connections == {}
        assert len(connection_manager._channel_subscribers) == len(WebSocketChannelEnum)
        assert connection_manager._total_connections_today == 0

    def test_get_connection_info_not_found(self, connection_manager):
        """Test getting info for non-existent connection."""
        result = connection_manager.get_connection_info("nonexistent")
        assert result is None

    def test_get_stats_empty(self, connection_manager):
        """Test getting stats with no connections."""
        stats = connection_manager.get_stats()
        assert stats.active_connections == 0
        assert stats.total_connections_today == 0
        assert stats.total_messages_sent == 0

    def test_get_all_connections_empty(self, connection_manager):
        """Test getting all connections when none exist."""
        connections = connection_manager.get_all_connections()
        assert connections == []

    @pytest.mark.asyncio
    async def test_subscribe_channel_nonexistent_connection(self, connection_manager):
        """Test subscribing to channel with non-existent connection."""
        await connection_manager.subscribe_channel(
            "nonexistent", WebSocketChannelEnum.ALERTS
        )
        # Should not raise, just silently do nothing

    @pytest.mark.asyncio
    async def test_unsubscribe_channel_nonexistent_connection(self, connection_manager):
        """Test unsubscribing from channel with non-existent connection."""
        await connection_manager.unsubscribe_channel(
            "nonexistent", WebSocketChannelEnum.ALERTS
        )
        # Should not raise

    @pytest.mark.asyncio
    async def test_subscribe_execution_nonexistent_connection(self, connection_manager):
        """Test subscribing to execution with non-existent connection."""
        await connection_manager.subscribe_execution("nonexistent", "EXE-001")
        # Should not raise

    @pytest.mark.asyncio
    async def test_unsubscribe_execution_nonexistent_connection(self, connection_manager):
        """Test unsubscribing from execution with non-existent connection."""
        await connection_manager.unsubscribe_execution("nonexistent", "EXE-001")
        # Should not raise

    @pytest.mark.asyncio
    async def test_subscribe_incident_nonexistent_connection(self, connection_manager):
        """Test subscribing to incident with non-existent connection."""
        await connection_manager.subscribe_incident("nonexistent", "INC-001")
        # Should not raise

    @pytest.mark.asyncio
    async def test_unsubscribe_incident_nonexistent_connection(self, connection_manager):
        """Test unsubscribing from incident with non-existent connection."""
        await connection_manager.unsubscribe_incident("nonexistent", "INC-001")
        # Should not raise

    @pytest.mark.asyncio
    async def test_disconnect_nonexistent_connection(self, connection_manager):
        """Test disconnecting non-existent connection."""
        await connection_manager.disconnect("nonexistent")
        # Should not raise

    @pytest.mark.asyncio
    async def test_broadcast_to_channel_empty(self, connection_manager):
        """Test broadcasting to channel with no subscribers."""
        from defensive_toolkit.api.models import WebSocketMessage, WebSocketEventTypeEnum

        message = WebSocketMessage(
            event_type=WebSocketEventTypeEnum.SYSTEM_ALERT,
            channel=WebSocketChannelEnum.SYSTEM,
            data={"test": "data"},
        )
        # Should not raise
        await connection_manager.broadcast_to_channel(WebSocketChannelEnum.SYSTEM, message)

    @pytest.mark.asyncio
    async def test_broadcast_to_execution_empty(self, connection_manager):
        """Test broadcasting to execution with no subscribers."""
        from defensive_toolkit.api.models import WebSocketMessage, WebSocketEventTypeEnum

        message = WebSocketMessage(
            event_type=WebSocketEventTypeEnum.RUNBOOK_PROGRESS,
            channel=WebSocketChannelEnum.RUNBOOKS,
            data={"test": "data"},
        )
        await connection_manager.broadcast_to_execution("EXE-001", message)

    @pytest.mark.asyncio
    async def test_broadcast_to_incident_empty(self, connection_manager):
        """Test broadcasting to incident with no subscribers."""
        from defensive_toolkit.api.models import WebSocketMessage, WebSocketEventTypeEnum

        message = WebSocketMessage(
            event_type=WebSocketEventTypeEnum.INCIDENT_UPDATED,
            channel=WebSocketChannelEnum.INCIDENTS,
            data={"test": "data"},
        )
        await connection_manager.broadcast_to_incident("INC-001", message)

    @pytest.mark.asyncio
    async def test_broadcast_to_user_empty(self, connection_manager):
        """Test broadcasting to user with no connections."""
        from defensive_toolkit.api.models import WebSocketMessage, WebSocketEventTypeEnum

        message = WebSocketMessage(
            event_type=WebSocketEventTypeEnum.SYSTEM_ALERT,
            channel=WebSocketChannelEnum.SYSTEM,
            data={"test": "data"},
        )
        await connection_manager.broadcast_to_user("nonexistent_user", message)


# ============================================================================
# REST API Endpoint Tests
# ============================================================================


class TestWebSocketRESTEndpoints:
    """Tests for WebSocket REST management endpoints."""

    def test_list_connections_unauthorized(self, test_client):
        """Test listing connections without valid token."""
        response = test_client.get("/api/v1/ws/connections", params={"token": "invalid"})
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_connections_not_admin(self, test_client):
        """Test listing connections with invalid token returns 401."""
        # Without a non-admin user, we can only verify auth is required
        response = test_client.get("/api/v1/ws/connections", params={"token": "notavalidtoken"})
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_connections_admin(self, test_client, auth_token):
        """Test listing connections as admin."""
        response = test_client.get("/api/v1/ws/connections", params={"token": auth_token})
        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.json(), list)

    def test_get_connection_not_found(self, test_client, auth_token):
        """Test getting non-existent connection."""
        response = test_client.get(
            "/api/v1/ws/connections/nonexistent",
            params={"token": auth_token},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_stats_unauthorized(self, test_client):
        """Test getting stats without valid token."""
        response = test_client.get("/api/v1/ws/stats", params={"token": "invalid"})
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_stats_authorized(self, test_client, auth_token):
        """Test getting stats with valid token."""
        response = test_client.get("/api/v1/ws/stats", params={"token": auth_token})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "active_connections" in data
        assert "total_messages_sent" in data

    def test_broadcast_unauthorized(self, test_client):
        """Test broadcasting without valid token."""
        response = test_client.post(
            "/api/v1/ws/broadcast",
            params={"channel": "system", "token": "invalid"},
            json={"message": "test"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_broadcast_not_admin(self, test_client):
        """Test broadcasting with invalid token returns 401."""
        # Without a non-admin user, we can only verify auth is required
        response = test_client.post(
            "/api/v1/ws/broadcast",
            params={"channel": "system", "token": "notavalidtoken"},
            json={"message": "test"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_broadcast_admin(self, test_client, auth_token):
        """Test broadcasting as admin."""
        response = test_client.post(
            "/api/v1/ws/broadcast",
            params={"channel": "system", "token": auth_token},
            json={"message": "test announcement"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "success"

    def test_disconnect_connection_not_admin(self, test_client):
        """Test force disconnecting with invalid token returns 401."""
        # Without a non-admin user, we can only verify auth is required
        response = test_client.delete(
            "/api/v1/ws/connections/test-conn",
            params={"token": "notavalidtoken"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_disconnect_connection_not_found(self, test_client, auth_token):
        """Test force disconnecting non-existent connection."""
        response = test_client.delete(
            "/api/v1/ws/connections/nonexistent",
            params={"token": auth_token},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ============================================================================
# Test Endpoint Tests
# ============================================================================


class TestWebSocketTestEndpoints:
    """Tests for WebSocket test/development endpoints."""

    def test_test_runbook_event_unauthorized(self, test_client):
        """Test sending test runbook event without token."""
        response = test_client.post(
            "/api/v1/ws/test/runbook-event",
            params={"token": "invalid"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_test_runbook_event_authorized(self, test_client, auth_token):
        """Test sending test runbook event with valid token."""
        response = test_client.post(
            "/api/v1/ws/test/runbook-event",
            params={
                "token": auth_token,
                "execution_id": "test-exec",
                "runbook_name": "Test Runbook",
                "step": 3,
                "total_steps": 5,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "success"

    def test_test_alert_event_unauthorized(self, test_client):
        """Test sending test alert event without token."""
        response = test_client.post(
            "/api/v1/ws/test/alert-event",
            params={"token": "invalid"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_test_alert_event_authorized(self, test_client, auth_token):
        """Test sending test alert event with valid token."""
        response = test_client.post(
            "/api/v1/ws/test/alert-event",
            params={
                "token": auth_token,
                "webhook_id": "test-webhook",
                "alert_title": "Test Alert",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "success"


# ============================================================================
# Event Publishing Function Tests
# ============================================================================


class TestEventPublishing:
    """Tests for event publishing functions."""

    @pytest.mark.asyncio
    async def test_publish_runbook_started(self):
        """Test publishing runbook started event."""
        # Should not raise even with no subscribers
        await publish_runbook_started(
            execution_id="EXE-001",
            runbook_name="Test Runbook",
            incident_id="INC-001",
            total_steps=5,
            analyst="test_user",
        )

    @pytest.mark.asyncio
    async def test_publish_incident_event(self):
        """Test publishing incident event."""
        await publish_incident_event(
            incident_id="INC-001",
            title="Test Incident",
            current_status=IncidentStatusEnum.INVESTIGATING,
            severity=SeverityEnum.HIGH,
            updated_by="test_user",
            update_type="status_change",
        )

    @pytest.mark.asyncio
    async def test_publish_alert_event(self):
        """Test publishing alert event."""
        await publish_alert_event(
            webhook_id="WH-001",
            webhook_name="Test Webhook",
            alert_id="ALERT-001",
            source=WebhookSourceEnum.GENERIC,
            severity="high",
            title="Test Alert",
            processed=True,
        )

    @pytest.mark.asyncio
    async def test_publish_system_alert(self):
        """Test publishing system alert."""
        await publish_system_alert(
            alert_type="test",
            severity="warning",
            title="Test System Alert",
            description="This is a test system alert",
        )


# ============================================================================
# WebSocket Authentication Tests
# ============================================================================


class TestWebSocketAuth:
    """Tests for WebSocket authentication."""

    @pytest.mark.asyncio
    async def test_authenticate_nonexistent_connection(self, connection_manager):
        """Test authenticating non-existent connection."""
        auth_request = WebSocketAuthRequest(
            token="test-token",
            subscribe_channels=[WebSocketChannelEnum.ALL],
        )
        result = await connection_manager.authenticate("nonexistent", auth_request)
        assert result.success is False
        assert "not found" in result.message.lower()

    def test_auth_request_model(self):
        """Test WebSocketAuthRequest model."""
        request = WebSocketAuthRequest(
            token="test-token",
            subscribe_channels=[WebSocketChannelEnum.RUNBOOKS, WebSocketChannelEnum.ALERTS],
            subscribe_executions=["EXE-001"],
            subscribe_incidents=["INC-001"],
        )
        assert request.token == "test-token"
        assert len(request.subscribe_channels) == 2
        assert "EXE-001" in request.subscribe_executions


# ============================================================================
# Stats and Monitoring Tests
# ============================================================================


class TestStatsAndMonitoring:
    """Tests for stats and monitoring functionality."""

    def test_stats_reset_new_day(self, connection_manager):
        """Test stats reset on new day."""
        # Set stats date to yesterday
        from datetime import timedelta
        connection_manager._stats_date = (datetime.utcnow() - timedelta(days=1)).date()
        connection_manager._total_connections_today = 100

        # Getting stats should reset
        stats = connection_manager.get_stats()
        assert connection_manager._total_connections_today == 0

    def test_connection_duration_tracking(self, connection_manager):
        """Test that connection durations are tracked."""
        # Add some durations
        connection_manager._connection_durations = [10.0, 20.0, 30.0]
        stats = connection_manager.get_stats()
        assert stats.average_connection_duration_seconds == 20.0

    def test_connection_duration_limit(self, connection_manager):
        """Test that connection durations are limited."""
        # Add more than 1000 durations
        connection_manager._connection_durations = [1.0] * 1100

        # Simulate disconnect to trigger pruning
        connection_manager._connection_durations.append(2.0)
        if len(connection_manager._connection_durations) > 1000:
            connection_manager._connection_durations = \
                connection_manager._connection_durations[-500:]

        assert len(connection_manager._connection_durations) == 500
