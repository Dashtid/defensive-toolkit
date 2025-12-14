"""
WebSocket Real-Time Updates Router (v1.7.4)

Provides real-time push notifications for:
- Runbook execution progress and step completions
- Incident status updates
- Webhook/alert processing
- IOC enrichment events
- System alerts

Based on FastAPI WebSocket best practices 2025:
- https://fastapi.tiangolo.com/advanced/websockets/
- https://www.videosdk.live/developer-hub/websocket/websocket-authentication
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from defensive_toolkit.api.auth import verify_token
from defensive_toolkit.api.config import get_settings
from defensive_toolkit.api.models import (
    AlertEvent,
    ApprovalRequestEvent,
    IncidentEvent,
    IncidentStatusEnum,
    IOCEnrichmentEvent,
    IOCTypeEnum,
    ReputationScoreEnum,
    RunbookProgressEvent,
    RunbookStepEvent,
    RunbookStepStatusEnum,
    SeverityEnum,
    StatusEnum,
    SystemAlertEvent,
    ThreatIntelSourceEnum,
    WebhookSourceEnum,
    WebSocketAuthRequest,
    WebSocketAuthResponse,
    WebSocketChannelEnum,
    WebSocketConnectionInfo,
    WebSocketConnectionStats,
    WebSocketEventTypeEnum,
    WebSocketHeartbeat,
    WebSocketMessage,
)
from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, status

settings = get_settings()
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["WebSocket"])


# ============================================================================
# Connection Manager
# ============================================================================


@dataclass
class WebSocketConnection:
    """Represents an authenticated WebSocket connection"""

    connection_id: str
    websocket: WebSocket
    user: str
    connected_at: datetime
    last_activity: datetime
    subscribed_channels: Set[WebSocketChannelEnum] = field(default_factory=set)
    subscribed_executions: Set[str] = field(default_factory=set)
    subscribed_incidents: Set[str] = field(default_factory=set)
    messages_sent: int = 0
    messages_received: int = 0
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    heartbeat_sequence: int = 0
    authenticated: bool = False


class ConnectionManager:
    """
    Manages WebSocket connections and message broadcasting.

    Features:
    - Connection tracking by user and channel
    - Targeted broadcasting to specific channels/executions
    - Heartbeat management for connection keep-alive
    - Connection statistics and monitoring

    For production scaling with multiple server instances,
    replace in-memory storage with Redis Pub/Sub.
    """

    def __init__(self):
        # Active connections by connection_id
        self._connections: Dict[str, WebSocketConnection] = {}

        # Index: channel -> set of connection_ids
        self._channel_subscribers: Dict[WebSocketChannelEnum, Set[str]] = {
            channel: set() for channel in WebSocketChannelEnum
        }

        # Index: execution_id -> set of connection_ids
        self._execution_subscribers: Dict[str, Set[str]] = {}

        # Index: incident_id -> set of connection_ids
        self._incident_subscribers: Dict[str, Set[str]] = {}

        # Index: user -> set of connection_ids
        self._user_connections: Dict[str, Set[str]] = {}

        # Statistics
        self._total_connections_today: int = 0
        self._total_messages_sent: int = 0
        self._total_messages_received: int = 0
        self._peak_connections_today: int = 0
        self._stats_date: datetime = datetime.utcnow().date()
        self._connection_durations: List[float] = []

        # Heartbeat task
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._heartbeat_interval: int = 30  # seconds

        logger.info("WebSocket ConnectionManager initialized")

    async def start_heartbeat(self):
        """Start the heartbeat task"""
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            logger.info("WebSocket heartbeat task started")

    async def stop_heartbeat(self):
        """Stop the heartbeat task"""
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            logger.info("WebSocket heartbeat task stopped")

    async def _heartbeat_loop(self):
        """Send periodic heartbeats to all connections"""
        while True:
            try:
                await asyncio.sleep(self._heartbeat_interval)
                await self._send_heartbeats()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")

    async def _send_heartbeats(self):
        """Send heartbeat to all active connections"""
        disconnected = []

        for conn_id, conn in self._connections.items():
            if not conn.authenticated:
                continue

            try:
                conn.heartbeat_sequence += 1
                uptime = int((datetime.utcnow() - conn.connected_at).total_seconds())

                heartbeat = WebSocketHeartbeat(
                    sequence=conn.heartbeat_sequence, connection_uptime_seconds=uptime
                )

                message = WebSocketMessage(
                    event_type=WebSocketEventTypeEnum.HEARTBEAT,
                    channel=WebSocketChannelEnum.SYSTEM,
                    data=heartbeat.model_dump(),
                )

                await conn.websocket.send_json(message.model_dump(mode="json"))
                conn.messages_sent += 1
                self._total_messages_sent += 1

            except Exception as e:
                logger.warning(f"Heartbeat failed for {conn_id}: {e}")
                disconnected.append(conn_id)

        # Clean up disconnected connections
        for conn_id in disconnected:
            await self.disconnect(conn_id)

    async def connect(self, websocket: WebSocket) -> str:
        """
        Accept a new WebSocket connection.
        Returns connection_id. Connection is not authenticated yet.
        """
        await websocket.accept()

        connection_id = str(uuid.uuid4())

        # Extract client info
        client_ip = None
        user_agent = None
        if websocket.client:
            client_ip = websocket.client.host
        if "user-agent" in websocket.headers:
            user_agent = websocket.headers["user-agent"]

        conn = WebSocketConnection(
            connection_id=connection_id,
            websocket=websocket,
            user="anonymous",  # Will be set after authentication
            connected_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            client_ip=client_ip,
            user_agent=user_agent,
        )

        self._connections[connection_id] = conn

        # Update statistics
        self._reset_stats_if_new_day()
        self._total_connections_today += 1
        if len(self._connections) > self._peak_connections_today:
            self._peak_connections_today = len(self._connections)

        logger.info(f"WebSocket connected: {connection_id} from {client_ip}")

        # Send connected message
        await self._send_to_connection(
            connection_id,
            WebSocketMessage(
                event_type=WebSocketEventTypeEnum.CONNECTED,
                channel=WebSocketChannelEnum.SYSTEM,
                data={
                    "connection_id": connection_id,
                    "message": "Connected. Please authenticate with your JWT token.",
                },
            ),
        )

        return connection_id

    async def authenticate(
        self, connection_id: str, auth_request: WebSocketAuthRequest
    ) -> WebSocketAuthResponse:
        """
        Authenticate a WebSocket connection with JWT token.
        """
        conn = self._connections.get(connection_id)
        if not conn:
            return WebSocketAuthResponse(success=False, message="Connection not found")

        try:
            # Verify JWT token
            token_data = verify_token(auth_request.token, token_type="access")
            user = token_data.username

            # Update connection
            conn.user = user
            conn.authenticated = True
            conn.last_activity = datetime.utcnow()

            # Add to user index
            if user not in self._user_connections:
                self._user_connections[user] = set()
            self._user_connections[user].add(connection_id)

            # Subscribe to requested channels
            for channel in auth_request.subscribe_channels:
                await self.subscribe_channel(connection_id, channel)

            # Subscribe to specific executions
            for exec_id in auth_request.subscribe_executions:
                await self.subscribe_execution(connection_id, exec_id)

            # Subscribe to specific incidents
            for inc_id in auth_request.subscribe_incidents:
                await self.subscribe_incident(connection_id, inc_id)

            logger.info(f"WebSocket authenticated: {connection_id} as {user}")

            # Send authenticated message
            await self._send_to_connection(
                connection_id,
                WebSocketMessage(
                    event_type=WebSocketEventTypeEnum.AUTHENTICATED,
                    channel=WebSocketChannelEnum.SYSTEM,
                    data={
                        "user": user,
                        "subscribed_channels": [c.value for c in conn.subscribed_channels],
                        "subscribed_executions": list(conn.subscribed_executions),
                        "subscribed_incidents": list(conn.subscribed_incidents),
                    },
                ),
            )

            return WebSocketAuthResponse(
                success=True,
                message="Authentication successful",
                user=user,
                subscribed_channels=list(conn.subscribed_channels),
                connection_id=connection_id,
            )

        except Exception as e:
            logger.warning(f"WebSocket auth failed for {connection_id}: {e}")

            # Send auth failed message
            await self._send_to_connection(
                connection_id,
                WebSocketMessage(
                    event_type=WebSocketEventTypeEnum.AUTHENTICATION_FAILED,
                    channel=WebSocketChannelEnum.SYSTEM,
                    data={"error": str(e)},
                ),
            )

            return WebSocketAuthResponse(success=False, message=f"Authentication failed: {e}")

    async def disconnect(self, connection_id: str):
        """Remove a WebSocket connection"""
        conn = self._connections.get(connection_id)
        if not conn:
            return

        # Track connection duration
        duration = (datetime.utcnow() - conn.connected_at).total_seconds()
        self._connection_durations.append(duration)
        if len(self._connection_durations) > 1000:
            self._connection_durations = self._connection_durations[-500:]

        # Remove from all indexes
        for channel in conn.subscribed_channels:
            self._channel_subscribers[channel].discard(connection_id)

        for exec_id in conn.subscribed_executions:
            if exec_id in self._execution_subscribers:
                self._execution_subscribers[exec_id].discard(connection_id)
                if not self._execution_subscribers[exec_id]:
                    del self._execution_subscribers[exec_id]

        for inc_id in conn.subscribed_incidents:
            if inc_id in self._incident_subscribers:
                self._incident_subscribers[inc_id].discard(connection_id)
                if not self._incident_subscribers[inc_id]:
                    del self._incident_subscribers[inc_id]

        if conn.user in self._user_connections:
            self._user_connections[conn.user].discard(connection_id)
            if not self._user_connections[conn.user]:
                del self._user_connections[conn.user]

        del self._connections[connection_id]

        logger.info(
            f"WebSocket disconnected: {connection_id} (user={conn.user}, duration={duration:.1f}s)"
        )

    async def subscribe_channel(self, connection_id: str, channel: WebSocketChannelEnum):
        """Subscribe connection to a channel"""
        conn = self._connections.get(connection_id)
        if not conn:
            return

        conn.subscribed_channels.add(channel)
        self._channel_subscribers[channel].add(connection_id)
        conn.last_activity = datetime.utcnow()

    async def unsubscribe_channel(self, connection_id: str, channel: WebSocketChannelEnum):
        """Unsubscribe connection from a channel"""
        conn = self._connections.get(connection_id)
        if not conn:
            return

        conn.subscribed_channels.discard(channel)
        self._channel_subscribers[channel].discard(connection_id)
        conn.last_activity = datetime.utcnow()

    async def subscribe_execution(self, connection_id: str, execution_id: str):
        """Subscribe to updates for a specific runbook execution"""
        conn = self._connections.get(connection_id)
        if not conn:
            return

        conn.subscribed_executions.add(execution_id)
        if execution_id not in self._execution_subscribers:
            self._execution_subscribers[execution_id] = set()
        self._execution_subscribers[execution_id].add(connection_id)
        conn.last_activity = datetime.utcnow()

    async def unsubscribe_execution(self, connection_id: str, execution_id: str):
        """Unsubscribe from execution updates"""
        conn = self._connections.get(connection_id)
        if not conn:
            return

        conn.subscribed_executions.discard(execution_id)
        if execution_id in self._execution_subscribers:
            self._execution_subscribers[execution_id].discard(connection_id)
            if not self._execution_subscribers[execution_id]:
                del self._execution_subscribers[execution_id]
        conn.last_activity = datetime.utcnow()

    async def subscribe_incident(self, connection_id: str, incident_id: str):
        """Subscribe to updates for a specific incident"""
        conn = self._connections.get(connection_id)
        if not conn:
            return

        conn.subscribed_incidents.add(incident_id)
        if incident_id not in self._incident_subscribers:
            self._incident_subscribers[incident_id] = set()
        self._incident_subscribers[incident_id].add(connection_id)
        conn.last_activity = datetime.utcnow()

    async def unsubscribe_incident(self, connection_id: str, incident_id: str):
        """Unsubscribe from incident updates"""
        conn = self._connections.get(connection_id)
        if not conn:
            return

        conn.subscribed_incidents.discard(incident_id)
        if incident_id in self._incident_subscribers:
            self._incident_subscribers[incident_id].discard(connection_id)
            if not self._incident_subscribers[incident_id]:
                del self._incident_subscribers[incident_id]
        conn.last_activity = datetime.utcnow()

    async def _send_to_connection(self, connection_id: str, message: WebSocketMessage):
        """Send message to a specific connection"""
        conn = self._connections.get(connection_id)
        if not conn:
            return

        try:
            await conn.websocket.send_json(message.model_dump(mode="json"))
            conn.messages_sent += 1
            conn.last_activity = datetime.utcnow()
            self._total_messages_sent += 1
        except Exception as e:
            logger.warning(f"Failed to send to {connection_id}: {e}")
            await self.disconnect(connection_id)

    async def broadcast_to_channel(self, channel: WebSocketChannelEnum, message: WebSocketMessage):
        """Broadcast message to all subscribers of a channel"""
        # Also send to ALL channel subscribers
        recipients = self._channel_subscribers.get(channel, set()).copy()
        recipients.update(self._channel_subscribers.get(WebSocketChannelEnum.ALL, set()))

        disconnected = []
        for conn_id in recipients:
            conn = self._connections.get(conn_id)
            if not conn or not conn.authenticated:
                continue

            try:
                await conn.websocket.send_json(message.model_dump(mode="json"))
                conn.messages_sent += 1
                conn.last_activity = datetime.utcnow()
                self._total_messages_sent += 1
            except Exception as e:
                logger.warning(f"Broadcast failed for {conn_id}: {e}")
                disconnected.append(conn_id)

        for conn_id in disconnected:
            await self.disconnect(conn_id)

    async def broadcast_to_execution(self, execution_id: str, message: WebSocketMessage):
        """Broadcast to subscribers of a specific execution"""
        # Send to execution subscribers
        recipients = self._execution_subscribers.get(execution_id, set()).copy()

        # Also send to RUNBOOKS channel subscribers
        recipients.update(self._channel_subscribers.get(WebSocketChannelEnum.RUNBOOKS, set()))
        recipients.update(self._channel_subscribers.get(WebSocketChannelEnum.ALL, set()))

        disconnected = []
        for conn_id in recipients:
            conn = self._connections.get(conn_id)
            if not conn or not conn.authenticated:
                continue

            try:
                await conn.websocket.send_json(message.model_dump(mode="json"))
                conn.messages_sent += 1
                conn.last_activity = datetime.utcnow()
                self._total_messages_sent += 1
            except Exception as e:
                logger.warning(f"Broadcast to execution failed for {conn_id}: {e}")
                disconnected.append(conn_id)

        for conn_id in disconnected:
            await self.disconnect(conn_id)

    async def broadcast_to_incident(self, incident_id: str, message: WebSocketMessage):
        """Broadcast to subscribers of a specific incident"""
        # Send to incident subscribers
        recipients = self._incident_subscribers.get(incident_id, set()).copy()

        # Also send to INCIDENTS channel subscribers
        recipients.update(self._channel_subscribers.get(WebSocketChannelEnum.INCIDENTS, set()))
        recipients.update(self._channel_subscribers.get(WebSocketChannelEnum.ALL, set()))

        disconnected = []
        for conn_id in recipients:
            conn = self._connections.get(conn_id)
            if not conn or not conn.authenticated:
                continue

            try:
                await conn.websocket.send_json(message.model_dump(mode="json"))
                conn.messages_sent += 1
                conn.last_activity = datetime.utcnow()
                self._total_messages_sent += 1
            except Exception as e:
                logger.warning(f"Broadcast to incident failed for {conn_id}: {e}")
                disconnected.append(conn_id)

        for conn_id in disconnected:
            await self.disconnect(conn_id)

    async def broadcast_to_user(self, user: str, message: WebSocketMessage):
        """Send message to all connections for a specific user"""
        conn_ids = self._user_connections.get(user, set()).copy()

        disconnected = []
        for conn_id in conn_ids:
            conn = self._connections.get(conn_id)
            if not conn or not conn.authenticated:
                continue

            try:
                await conn.websocket.send_json(message.model_dump(mode="json"))
                conn.messages_sent += 1
                conn.last_activity = datetime.utcnow()
                self._total_messages_sent += 1
            except Exception as e:
                logger.warning(f"Broadcast to user failed for {conn_id}: {e}")
                disconnected.append(conn_id)

        for conn_id in disconnected:
            await self.disconnect(conn_id)

    def _reset_stats_if_new_day(self):
        """Reset daily statistics if it's a new day"""
        today = datetime.utcnow().date()
        if today != self._stats_date:
            self._stats_date = today
            self._total_connections_today = 0
            self._peak_connections_today = len(self._connections)

    def get_connection_info(self, connection_id: str) -> Optional[WebSocketConnectionInfo]:
        """Get information about a specific connection"""
        conn = self._connections.get(connection_id)
        if not conn:
            return None

        return WebSocketConnectionInfo(
            connection_id=conn.connection_id,
            user=conn.user,
            connected_at=conn.connected_at,
            last_activity=conn.last_activity,
            subscribed_channels=list(conn.subscribed_channels),
            subscribed_executions=list(conn.subscribed_executions),
            subscribed_incidents=list(conn.subscribed_incidents),
            messages_sent=conn.messages_sent,
            messages_received=conn.messages_received,
            client_ip=conn.client_ip,
            user_agent=conn.user_agent,
        )

    def get_stats(self) -> WebSocketConnectionStats:
        """Get WebSocket connection statistics"""
        self._reset_stats_if_new_day()

        # Count connections by channel
        connections_by_channel = {}
        for channel, conn_ids in self._channel_subscribers.items():
            authenticated_count = sum(
                1
                for cid in conn_ids
                if cid in self._connections and self._connections[cid].authenticated
            )
            if authenticated_count > 0:
                connections_by_channel[channel.value] = authenticated_count

        # Calculate average connection duration
        avg_duration = 0.0
        if self._connection_durations:
            avg_duration = sum(self._connection_durations) / len(self._connection_durations)

        # Find last activity
        last_activity = None
        for conn in self._connections.values():
            if conn.authenticated:
                if last_activity is None or conn.last_activity > last_activity:
                    last_activity = conn.last_activity

        authenticated_count = sum(1 for c in self._connections.values() if c.authenticated)

        return WebSocketConnectionStats(
            active_connections=authenticated_count,
            total_connections_today=self._total_connections_today,
            total_messages_sent=self._total_messages_sent,
            total_messages_received=self._total_messages_received,
            connections_by_channel=connections_by_channel,
            average_connection_duration_seconds=avg_duration,
            peak_connections_today=self._peak_connections_today,
            last_activity_at=last_activity,
        )

    def get_all_connections(self) -> List[WebSocketConnectionInfo]:
        """Get information about all active connections"""
        return [
            self.get_connection_info(conn_id)
            for conn_id in self._connections.keys()
            if self._connections[conn_id].authenticated
        ]


# Global connection manager instance
manager = ConnectionManager()


# ============================================================================
# Event Publishing Functions (for use by other routers)
# ============================================================================


async def publish_runbook_started(
    execution_id: str, runbook_name: str, incident_id: str, total_steps: int, analyst: str
):
    """Publish runbook started event"""
    event = RunbookProgressEvent(
        execution_id=execution_id,
        runbook_name=runbook_name,
        incident_id=incident_id,
        current_step=0,
        total_steps=total_steps,
        steps_completed=0,
        steps_failed=0,
        steps_skipped=0,
        steps_awaiting=0,
        percentage_complete=0.0,
        status=StatusEnum.IN_PROGRESS,
    )

    message = WebSocketMessage(
        event_type=WebSocketEventTypeEnum.RUNBOOK_STARTED,
        channel=WebSocketChannelEnum.RUNBOOKS,
        data=event.model_dump(mode="json"),
    )

    await manager.broadcast_to_execution(execution_id, message)
    logger.debug(f"Published runbook_started for {execution_id}")


async def publish_runbook_step_event(
    event_type: WebSocketEventTypeEnum,
    execution_id: str,
    runbook_name: str,
    incident_id: str,
    step_index: int,
    step_name: str,
    action: str,
    severity: str,
    status: RunbookStepStatusEnum,
    message_text: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
    duration_ms: Optional[int] = None,
):
    """Publish runbook step event"""
    event = RunbookStepEvent(
        execution_id=execution_id,
        runbook_name=runbook_name,
        incident_id=incident_id,
        step_index=step_index,
        step_name=step_name,
        action=action,
        severity=severity,
        status=status,
        message=message_text,
        data=data or {},
        started_at=datetime.utcnow() if status == RunbookStepStatusEnum.RUNNING else None,
        completed_at=(
            datetime.utcnow()
            if status
            in [
                RunbookStepStatusEnum.COMPLETED,
                RunbookStepStatusEnum.FAILED,
                RunbookStepStatusEnum.SKIPPED,
            ]
            else None
        ),
        duration_ms=duration_ms,
    )

    message = WebSocketMessage(
        event_type=event_type,
        channel=WebSocketChannelEnum.RUNBOOKS,
        data=event.model_dump(mode="json"),
    )

    await manager.broadcast_to_execution(execution_id, message)
    logger.debug(f"Published {event_type.value} for {execution_id} step {step_index}")


async def publish_runbook_progress(
    execution_id: str,
    runbook_name: str,
    incident_id: str,
    current_step: int,
    total_steps: int,
    steps_completed: int,
    steps_failed: int,
    steps_skipped: int,
    steps_awaiting: int,
    status: StatusEnum,
    current_step_name: Optional[str] = None,
    current_step_action: Optional[str] = None,
):
    """Publish runbook progress update"""
    percentage = (
        (steps_completed + steps_failed + steps_skipped) / total_steps * 100
        if total_steps > 0
        else 0
    )

    event = RunbookProgressEvent(
        execution_id=execution_id,
        runbook_name=runbook_name,
        incident_id=incident_id,
        current_step=current_step,
        total_steps=total_steps,
        steps_completed=steps_completed,
        steps_failed=steps_failed,
        steps_skipped=steps_skipped,
        steps_awaiting=steps_awaiting,
        percentage_complete=round(percentage, 1),
        current_step_name=current_step_name,
        current_step_action=current_step_action,
        status=status,
    )

    message = WebSocketMessage(
        event_type=WebSocketEventTypeEnum.RUNBOOK_PROGRESS,
        channel=WebSocketChannelEnum.RUNBOOKS,
        data=event.model_dump(mode="json"),
    )

    await manager.broadcast_to_execution(execution_id, message)


async def publish_approval_request(
    execution_id: str,
    runbook_name: str,
    incident_id: str,
    approval_id: str,
    step_name: str,
    action: str,
    severity: str,
    description: str,
    parameters: Dict[str, Any],
    requested_by: str,
    expires_at: Optional[datetime] = None,
):
    """Publish approval request event"""
    event = ApprovalRequestEvent(
        execution_id=execution_id,
        runbook_name=runbook_name,
        incident_id=incident_id,
        approval_id=approval_id,
        step_name=step_name,
        action=action,
        severity=severity,
        description=description,
        parameters=parameters,
        requested_by=requested_by,
        requested_at=datetime.utcnow(),
        expires_at=expires_at,
    )

    message = WebSocketMessage(
        event_type=WebSocketEventTypeEnum.RUNBOOK_AWAITING_APPROVAL,
        channel=WebSocketChannelEnum.RUNBOOKS,
        data=event.model_dump(mode="json"),
    )

    await manager.broadcast_to_execution(execution_id, message)
    logger.info(f"Published approval request for {execution_id}: {step_name}")


async def publish_runbook_completed(
    execution_id: str,
    runbook_name: str,
    incident_id: str,
    total_steps: int,
    steps_completed: int,
    steps_failed: int,
    steps_skipped: int,
    success: bool,
):
    """Publish runbook completion event"""
    event = RunbookProgressEvent(
        execution_id=execution_id,
        runbook_name=runbook_name,
        incident_id=incident_id,
        current_step=total_steps,
        total_steps=total_steps,
        steps_completed=steps_completed,
        steps_failed=steps_failed,
        steps_skipped=steps_skipped,
        steps_awaiting=0,
        percentage_complete=100.0,
        status=StatusEnum.SUCCESS if success else StatusEnum.FAILED,
    )

    event_type = (
        WebSocketEventTypeEnum.RUNBOOK_COMPLETED
        if success
        else WebSocketEventTypeEnum.RUNBOOK_FAILED
    )

    message = WebSocketMessage(
        event_type=event_type,
        channel=WebSocketChannelEnum.RUNBOOKS,
        data=event.model_dump(mode="json"),
    )

    await manager.broadcast_to_execution(execution_id, message)
    logger.info(f"Published runbook {'completed' if success else 'failed'} for {execution_id}")


async def publish_incident_event(
    incident_id: str,
    title: str,
    current_status: IncidentStatusEnum,
    severity: SeverityEnum,
    updated_by: str,
    update_type: str,
    previous_status: Optional[IncidentStatusEnum] = None,
    assigned_to: Optional[str] = None,
    comment: Optional[str] = None,
):
    """Publish incident status event"""
    event = IncidentEvent(
        incident_id=incident_id,
        title=title,
        previous_status=previous_status,
        current_status=current_status,
        severity=severity,
        assigned_to=assigned_to,
        updated_by=updated_by,
        update_type=update_type,
        comment=comment,
    )

    # Map update type to event type
    event_type_map = {
        "created": WebSocketEventTypeEnum.INCIDENT_CREATED,
        "status_change": WebSocketEventTypeEnum.INCIDENT_UPDATED,
        "assigned": WebSocketEventTypeEnum.INCIDENT_UPDATED,
        "escalated": WebSocketEventTypeEnum.INCIDENT_ESCALATED,
        "comment": WebSocketEventTypeEnum.INCIDENT_COMMENT,
        "closed": WebSocketEventTypeEnum.INCIDENT_CLOSED,
    }
    event_type = event_type_map.get(update_type, WebSocketEventTypeEnum.INCIDENT_UPDATED)

    message = WebSocketMessage(
        event_type=event_type,
        channel=WebSocketChannelEnum.INCIDENTS,
        data=event.model_dump(mode="json"),
    )

    await manager.broadcast_to_incident(incident_id, message)
    logger.debug(f"Published incident_{update_type} for {incident_id}")


async def publish_alert_event(
    webhook_id: str,
    webhook_name: str,
    alert_id: str,
    source: WebhookSourceEnum,
    severity: str,
    title: str,
    processed: bool,
    triggered_runbook: Optional[str] = None,
    execution_id: Optional[str] = None,
    incident_id: Optional[str] = None,
):
    """Publish webhook alert event"""
    event = AlertEvent(
        webhook_id=webhook_id,
        webhook_name=webhook_name,
        alert_id=alert_id,
        source=source,
        severity=severity,
        title=title,
        received_at=datetime.utcnow(),
        processed=processed,
        triggered_runbook=triggered_runbook,
        execution_id=execution_id,
        incident_id=incident_id,
    )

    event_type = (
        WebSocketEventTypeEnum.ALERT_TRIGGERED_RUNBOOK
        if triggered_runbook
        else (
            WebSocketEventTypeEnum.ALERT_PROCESSED
            if processed
            else WebSocketEventTypeEnum.ALERT_RECEIVED
        )
    )

    message = WebSocketMessage(
        event_type=event_type,
        channel=WebSocketChannelEnum.ALERTS,
        data=event.model_dump(mode="json"),
    )

    await manager.broadcast_to_channel(WebSocketChannelEnum.ALERTS, message)
    logger.debug(f"Published alert event for {alert_id}")


async def publish_ioc_enrichment_event(
    request_id: str,
    ioc: str,
    ioc_type: IOCTypeEnum,
    status: str,
    sources_queried: Optional[List[ThreatIntelSourceEnum]] = None,
    sources_completed: int = 0,
    total_sources: int = 0,
    overall_reputation: Optional[ReputationScoreEnum] = None,
    risk_score: Optional[int] = None,
    processing_time_ms: Optional[int] = None,
):
    """Publish IOC enrichment event"""
    high_risk = overall_reputation == ReputationScoreEnum.MALICIOUS or (
        risk_score and risk_score >= 80
    )

    event = IOCEnrichmentEvent(
        request_id=request_id,
        ioc=ioc,
        ioc_type=ioc_type,
        status=status,
        sources_queried=sources_queried or [],
        sources_completed=sources_completed,
        total_sources=total_sources,
        overall_reputation=overall_reputation,
        risk_score=risk_score,
        high_risk_detected=high_risk,
        completed_at=datetime.utcnow() if status in ["completed", "failed"] else None,
        processing_time_ms=processing_time_ms,
    )

    event_type = (
        WebSocketEventTypeEnum.IOC_HIGH_RISK_DETECTED
        if high_risk
        else (
            WebSocketEventTypeEnum.IOC_ENRICHMENT_COMPLETED
            if status == "completed"
            else WebSocketEventTypeEnum.IOC_ENRICHMENT_STARTED
        )
    )

    message = WebSocketMessage(
        event_type=event_type,
        channel=WebSocketChannelEnum.THREAT_INTEL,
        data=event.model_dump(mode="json"),
    )

    await manager.broadcast_to_channel(WebSocketChannelEnum.THREAT_INTEL, message)

    if high_risk:
        logger.warning(f"High-risk IOC detected: {ioc}")


async def publish_system_alert(
    alert_type: str,
    severity: str,
    title: str,
    description: str,
    affected_component: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
):
    """Publish system alert event"""
    event = SystemAlertEvent(
        alert_type=alert_type,
        severity=severity,
        title=title,
        description=description,
        affected_component=affected_component,
        metadata=metadata or {},
    )

    message = WebSocketMessage(
        event_type=WebSocketEventTypeEnum.SYSTEM_ALERT,
        channel=WebSocketChannelEnum.SYSTEM,
        data=event.model_dump(mode="json"),
    )

    await manager.broadcast_to_channel(WebSocketChannelEnum.SYSTEM, message)
    logger.info(f"Published system alert: {title}")


# ============================================================================
# WebSocket Endpoint
# ============================================================================


@router.websocket("/events")
async def websocket_endpoint(websocket: WebSocket):
    """
    Main WebSocket endpoint for real-time events.

    Connection Protocol:
    1. Connect to ws://host/api/v1/ws/events
    2. Receive "connected" message with connection_id
    3. Send authentication message with JWT token:
       {"type": "auth", "token": "your-jwt-token", "channels": ["all"]}
    4. Receive "authenticated" message on success
    5. Receive real-time events based on subscriptions
    6. Send "subscribe"/"unsubscribe" messages to modify subscriptions
    7. Receive periodic heartbeat messages

    Message Types (client -> server):
    - auth: Authenticate with JWT token
    - subscribe: Subscribe to channels/executions/incidents
    - unsubscribe: Unsubscribe from channels/executions/incidents
    - ping: Keep-alive ping (server responds with pong)

    Event Types (server -> client):
    - See WebSocketEventTypeEnum for all event types
    """
    connection_id = await manager.connect(websocket)

    # Start heartbeat if not running
    await manager.start_heartbeat()

    try:
        while True:
            # Receive message from client
            try:
                data = await websocket.receive_json()
                manager._total_messages_received += 1

                conn = manager._connections.get(connection_id)
                if conn:
                    conn.messages_received += 1
                    conn.last_activity = datetime.utcnow()

            except json.JSONDecodeError:
                await websocket.send_json(
                    {"event_type": "error", "channel": "system", "data": {"error": "Invalid JSON"}}
                )
                continue

            msg_type = data.get("type", "").lower()

            # Handle authentication
            if msg_type == "auth":
                auth_request = WebSocketAuthRequest(
                    token=data.get("token", ""),
                    subscribe_channels=[
                        WebSocketChannelEnum(c)
                        for c in data.get("channels", ["all"])
                        if c in [e.value for e in WebSocketChannelEnum]
                    ],
                    subscribe_executions=data.get("executions", []),
                    subscribe_incidents=data.get("incidents", []),
                )
                await manager.authenticate(connection_id, auth_request)

            # Handle subscription changes
            elif msg_type in ["subscribe", "unsubscribe"]:
                conn = manager._connections.get(connection_id)
                if not conn or not conn.authenticated:
                    await websocket.send_json(
                        {
                            "event_type": "error",
                            "channel": "system",
                            "data": {"error": "Not authenticated"},
                        }
                    )
                    continue

                channels = data.get("channels", [])
                executions = data.get("executions", [])
                incidents = data.get("incidents", [])

                if msg_type == "subscribe":
                    for channel in channels:
                        try:
                            await manager.subscribe_channel(
                                connection_id, WebSocketChannelEnum(channel)
                            )
                        except ValueError:
                            pass
                    for exec_id in executions:
                        await manager.subscribe_execution(connection_id, exec_id)
                    for inc_id in incidents:
                        await manager.subscribe_incident(connection_id, inc_id)
                else:
                    for channel in channels:
                        try:
                            await manager.unsubscribe_channel(
                                connection_id, WebSocketChannelEnum(channel)
                            )
                        except ValueError:
                            pass
                    for exec_id in executions:
                        await manager.unsubscribe_execution(connection_id, exec_id)
                    for inc_id in incidents:
                        await manager.unsubscribe_incident(connection_id, inc_id)

                # Send confirmation
                conn = manager._connections.get(connection_id)
                if conn:
                    await websocket.send_json(
                        {
                            "event_type": (
                                "subscribed" if msg_type == "subscribe" else "unsubscribed"
                            ),
                            "channel": "system",
                            "data": {
                                "channels": [c.value for c in conn.subscribed_channels],
                                "executions": list(conn.subscribed_executions),
                                "incidents": list(conn.subscribed_incidents),
                            },
                        }
                    )

            # Handle ping/pong
            elif msg_type == "ping":
                await websocket.send_json(
                    {
                        "event_type": "pong",
                        "channel": "system",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

            else:
                await websocket.send_json(
                    {
                        "event_type": "error",
                        "channel": "system",
                        "data": {"error": f"Unknown message type: {msg_type}"},
                    }
                )

    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected: {connection_id}")
    except Exception as e:
        logger.error(f"WebSocket error for {connection_id}: {e}")
    finally:
        await manager.disconnect(connection_id)


# ============================================================================
# REST API Endpoints (for management and monitoring)
# ============================================================================


@router.get("/connections", response_model=List[WebSocketConnectionInfo])
async def list_connections(token: str = Query(..., description="JWT token for authentication")):
    """
    List all active WebSocket connections.

    Requires admin authentication.
    """
    try:
        token_data = verify_token(token, token_type="access")
        if token_data.username not in ["admin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    return manager.get_all_connections()


@router.get("/connections/{connection_id}", response_model=WebSocketConnectionInfo)
async def get_connection(
    connection_id: str, token: str = Query(..., description="JWT token for authentication")
):
    """Get details of a specific WebSocket connection."""
    try:
        token_data = verify_token(token, token_type="access")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    conn_info = manager.get_connection_info(connection_id)
    if not conn_info:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    # Users can only view their own connections unless admin
    if token_data.username != "admin" and conn_info.user != token_data.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Cannot view other users' connections"
        )

    return conn_info


@router.get("/stats", response_model=WebSocketConnectionStats)
async def get_websocket_stats(token: str = Query(..., description="JWT token for authentication")):
    """
    Get WebSocket connection statistics.

    Returns aggregate statistics about active connections,
    message counts, and channel subscriptions.
    """
    try:
        verify_token(token, token_type="access")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    return manager.get_stats()


@router.post("/broadcast")
async def broadcast_message(
    channel: WebSocketChannelEnum,
    message_data: Dict[str, Any],
    token: str = Query(..., description="JWT token for authentication"),
):
    """
    Broadcast a custom message to a channel.

    Admin only. Useful for system announcements.
    """
    try:
        token_data = verify_token(token, token_type="access")
        if token_data.username not in ["admin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    message = WebSocketMessage(
        event_type=WebSocketEventTypeEnum.SYSTEM_ALERT, channel=channel, data=message_data
    )

    await manager.broadcast_to_channel(channel, message)

    return {"status": "success", "message": f"Broadcast sent to {channel.value}"}


@router.delete("/connections/{connection_id}")
async def disconnect_connection(
    connection_id: str, token: str = Query(..., description="JWT token for authentication")
):
    """
    Force disconnect a WebSocket connection.

    Admin only.
    """
    try:
        token_data = verify_token(token, token_type="access")
        if token_data.username not in ["admin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
            )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    conn = manager._connections.get(connection_id)
    if not conn:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    # Send disconnect message before closing
    try:
        await conn.websocket.send_json(
            {
                "event_type": "disconnected",
                "channel": "system",
                "data": {"reason": "Disconnected by administrator"},
            }
        )
        await conn.websocket.close()
    except Exception:
        pass

    await manager.disconnect(connection_id)

    return {"status": "success", "message": f"Connection {connection_id} disconnected"}


# ============================================================================
# Test Endpoints (for development/testing)
# ============================================================================


@router.post("/test/runbook-event")
async def test_runbook_event(
    execution_id: str = "test-exec-001",
    runbook_name: str = "Test Runbook",
    incident_id: str = "INC-TEST-001",
    step: int = 1,
    total_steps: int = 5,
    token: str = Query(..., description="JWT token for authentication"),
):
    """
    Send a test runbook progress event.

    For development and testing purposes.
    """
    try:
        verify_token(token, token_type="access")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    await publish_runbook_progress(
        execution_id=execution_id,
        runbook_name=runbook_name,
        incident_id=incident_id,
        current_step=step,
        total_steps=total_steps,
        steps_completed=step,
        steps_failed=0,
        steps_skipped=0,
        steps_awaiting=0,
        status=StatusEnum.IN_PROGRESS,
        current_step_name=f"Test Step {step}",
        current_step_action="test_action",
    )

    return {"status": "success", "message": "Test event sent"}


@router.post("/test/alert-event")
async def test_alert_event(
    webhook_id: str = "test-webhook-001",
    alert_title: str = "Test Alert",
    token: str = Query(..., description="JWT token for authentication"),
):
    """
    Send a test alert event.

    For development and testing purposes.
    """
    try:
        verify_token(token, token_type="access")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    await publish_alert_event(
        webhook_id=webhook_id,
        webhook_name="Test Webhook",
        alert_id=f"alert-{uuid.uuid4().hex[:8]}",
        source=WebhookSourceEnum.GENERIC,
        severity="high",
        title=alert_title,
        processed=True,
    )

    return {"status": "success", "message": "Test alert event sent"}
