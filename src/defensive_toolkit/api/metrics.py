"""
Custom Prometheus Metrics

Business-level metrics for the Defensive Toolkit API including:
- Webhook trigger counts and latency
- Notification delivery metrics
- Circuit breaker status
- Dead letter queue size

Usage:
    from defensive_toolkit.api.metrics import (
        WEBHOOK_TRIGGERS,
        WEBHOOK_DELIVERY_DURATION,
        record_webhook_trigger,
    )

    record_webhook_trigger(webhook_id="WH-123", source="wazuh", rule_id="RULE-ABC")
"""

import logging
from typing import Optional

from prometheus_client import Counter, Gauge, Histogram, Info

logger = logging.getLogger(__name__)

# ============================================================================
# Application Info
# ============================================================================

APP_INFO = Info(
    "defensive_toolkit",
    "Defensive Toolkit application information",
)
APP_INFO.info(
    {
        "version": "1.2.0",
        "component": "api",
    }
)

# ============================================================================
# Webhook Metrics
# ============================================================================

WEBHOOK_TRIGGERS_TOTAL = Counter(
    "webhook_triggers_total",
    "Total number of webhook triggers",
    ["webhook_id", "source", "status"],
)

WEBHOOK_RULE_MATCHES_TOTAL = Counter(
    "webhook_rule_matches_total",
    "Total number of webhook rule matches",
    ["webhook_id", "rule_id", "runbook_id"],
)

WEBHOOK_DELIVERY_DURATION_SECONDS = Histogram(
    "webhook_delivery_duration_seconds",
    "Webhook delivery duration in seconds",
    ["target_host", "status"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)

WEBHOOK_SIGNATURE_VERIFICATION_TOTAL = Counter(
    "webhook_signature_verification_total",
    "Total signature verifications",
    ["webhook_id", "algorithm", "result"],
)

WEBHOOK_RATE_LIMITED_TOTAL = Counter(
    "webhook_rate_limited_total",
    "Total rate-limited webhook triggers",
    ["webhook_id", "rule_id", "reason"],
)

WEBHOOKS_CONFIGURED = Gauge(
    "webhooks_configured_total",
    "Number of configured webhooks",
    ["source", "status"],
)

# ============================================================================
# Notification Metrics
# ============================================================================

NOTIFICATIONS_SENT_TOTAL = Counter(
    "notifications_sent_total",
    "Total notifications sent",
    ["channel_type", "category", "priority", "status"],
)

NOTIFICATION_DELIVERY_DURATION_SECONDS = Histogram(
    "notification_delivery_duration_seconds",
    "Notification delivery duration in seconds",
    ["channel_type"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

NOTIFICATION_RETRIES_TOTAL = Counter(
    "notification_retries_total",
    "Total notification retry attempts",
    ["channel_type", "attempt"],
)

NOTIFICATION_CHANNELS_ACTIVE = Gauge(
    "notification_channels_active",
    "Number of active notification channels",
    ["channel_type"],
)

NOTIFICATION_QUEUE_SIZE = Gauge(
    "notification_queue_size",
    "Current size of notification queue",
)

# ============================================================================
# Circuit Breaker Metrics
# ============================================================================

CIRCUIT_BREAKER_STATE = Gauge(
    "circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=half_open, 2=open)",
    ["endpoint"],
)

CIRCUIT_BREAKER_FAILURES_TOTAL = Counter(
    "circuit_breaker_failures_total",
    "Total circuit breaker recorded failures",
    ["endpoint"],
)

CIRCUIT_BREAKER_TRIPS_TOTAL = Counter(
    "circuit_breaker_trips_total",
    "Total times circuit breaker tripped open",
    ["endpoint"],
)

# ============================================================================
# Dead Letter Queue Metrics
# ============================================================================

DEAD_LETTER_QUEUE_SIZE = Gauge(
    "dead_letter_queue_size",
    "Current size of dead letter queue",
)

DEAD_LETTER_QUEUE_ADDED_TOTAL = Counter(
    "dead_letter_queue_added_total",
    "Total items added to dead letter queue",
    ["reason"],
)

DEAD_LETTER_QUEUE_REPLAYED_TOTAL = Counter(
    "dead_letter_queue_replayed_total",
    "Total items replayed from dead letter queue",
    ["result"],
)

# ============================================================================
# Rate Limiting Metrics
# ============================================================================

RATE_LIMIT_HITS_TOTAL = Counter(
    "rate_limit_hits_total",
    "Total rate limit hits",
    ["endpoint", "client_type"],
)

RATE_LIMIT_REMAINING = Gauge(
    "rate_limit_remaining",
    "Remaining rate limit quota",
    ["endpoint", "client_id"],
)

# ============================================================================
# Helper Functions
# ============================================================================


def record_webhook_trigger(
    webhook_id: str,
    source: str,
    status: str,
    rule_id: Optional[str] = None,
    runbook_id: Optional[str] = None,
):
    """
    Record a webhook trigger event.

    Args:
        webhook_id: Webhook identifier
        source: SIEM source (wazuh, elastic, etc.)
        status: Trigger status (received, processed, triggered, skipped, error)
        rule_id: Optional matched rule ID
        runbook_id: Optional triggered runbook ID
    """
    WEBHOOK_TRIGGERS_TOTAL.labels(
        webhook_id=webhook_id,
        source=source,
        status=status,
    ).inc()

    if rule_id and runbook_id:
        WEBHOOK_RULE_MATCHES_TOTAL.labels(
            webhook_id=webhook_id,
            rule_id=rule_id,
            runbook_id=runbook_id,
        ).inc()


def record_webhook_delivery(
    target_host: str,
    status: str,
    duration_seconds: float,
):
    """
    Record webhook delivery metrics.

    Args:
        target_host: Target host/domain
        status: Delivery status (success, failure, timeout)
        duration_seconds: Delivery duration in seconds
    """
    WEBHOOK_DELIVERY_DURATION_SECONDS.labels(
        target_host=target_host,
        status=status,
    ).observe(duration_seconds)


def record_signature_verification(
    webhook_id: str,
    algorithm: str,
    success: bool,
):
    """
    Record signature verification result.

    Args:
        webhook_id: Webhook identifier
        algorithm: Signature algorithm (sha256, sha1)
        success: Whether verification succeeded
    """
    WEBHOOK_SIGNATURE_VERIFICATION_TOTAL.labels(
        webhook_id=webhook_id,
        algorithm=algorithm,
        result="success" if success else "failure",
    ).inc()


def record_webhook_rate_limited(
    webhook_id: str,
    rule_id: str,
    reason: str,
):
    """
    Record rate-limited webhook trigger.

    Args:
        webhook_id: Webhook identifier
        rule_id: Rule that was rate-limited
        reason: Rate limit reason (cooldown, hourly_limit)
    """
    WEBHOOK_RATE_LIMITED_TOTAL.labels(
        webhook_id=webhook_id,
        rule_id=rule_id,
        reason=reason,
    ).inc()


def record_notification_sent(
    channel_type: str,
    category: str,
    priority: str,
    status: str,
    duration_seconds: Optional[float] = None,
):
    """
    Record notification send metrics.

    Args:
        channel_type: Channel type (email, slack, webhook, etc.)
        category: Notification category
        priority: Notification priority
        status: Delivery status (delivered, failed, rate_limited)
        duration_seconds: Optional delivery duration
    """
    NOTIFICATIONS_SENT_TOTAL.labels(
        channel_type=channel_type,
        category=category,
        priority=priority,
        status=status,
    ).inc()

    if duration_seconds is not None:
        NOTIFICATION_DELIVERY_DURATION_SECONDS.labels(
            channel_type=channel_type,
        ).observe(duration_seconds)


def record_notification_retry(channel_type: str, attempt: int):
    """
    Record notification retry attempt.

    Args:
        channel_type: Channel type
        attempt: Retry attempt number (1, 2, 3, etc.)
    """
    NOTIFICATION_RETRIES_TOTAL.labels(
        channel_type=channel_type,
        attempt=str(attempt),
    ).inc()


def update_circuit_breaker_state(endpoint: str, state: str):
    """
    Update circuit breaker state gauge.

    Args:
        endpoint: Endpoint/host being protected
        state: Circuit state (closed, half_open, open)
    """
    state_map = {"closed": 0, "half_open": 1, "open": 2}
    CIRCUIT_BREAKER_STATE.labels(endpoint=endpoint).set(state_map.get(state, -1))


def record_circuit_breaker_failure(endpoint: str):
    """Record circuit breaker failure."""
    CIRCUIT_BREAKER_FAILURES_TOTAL.labels(endpoint=endpoint).inc()


def record_circuit_breaker_trip(endpoint: str):
    """Record circuit breaker trip to open state."""
    CIRCUIT_BREAKER_TRIPS_TOTAL.labels(endpoint=endpoint).inc()


def update_dead_letter_queue_size(size: int):
    """Update dead letter queue size gauge."""
    DEAD_LETTER_QUEUE_SIZE.set(size)


def record_dead_letter_added(reason: str):
    """Record item added to dead letter queue."""
    DEAD_LETTER_QUEUE_ADDED_TOTAL.labels(reason=reason).inc()


def record_dead_letter_replayed(success: bool):
    """Record dead letter queue replay result."""
    DEAD_LETTER_QUEUE_REPLAYED_TOTAL.labels(
        result="success" if success else "failure"
    ).inc()


def record_rate_limit_hit(endpoint: str, client_type: str):
    """
    Record rate limit hit.

    Args:
        endpoint: API endpoint that was rate limited
        client_type: Client type (user, ip, api_key)
    """
    RATE_LIMIT_HITS_TOTAL.labels(
        endpoint=endpoint,
        client_type=client_type,
    ).inc()


def update_webhooks_configured(source: str, status: str, count: int):
    """
    Update configured webhooks gauge.

    Args:
        source: SIEM source
        status: Webhook status (active, disabled)
        count: Number of webhooks
    """
    WEBHOOKS_CONFIGURED.labels(source=source, status=status).set(count)


def update_notification_channels(channel_type: str, count: int):
    """
    Update active notification channels gauge.

    Args:
        channel_type: Channel type
        count: Number of active channels
    """
    NOTIFICATION_CHANNELS_ACTIVE.labels(channel_type=channel_type).set(count)


def update_notification_queue_size(size: int):
    """Update notification queue size gauge."""
    NOTIFICATION_QUEUE_SIZE.set(size)
