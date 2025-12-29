"""
Webhook Delivery Service Tests

Tests for the webhook delivery service including:
- Exponential backoff calculation
- Circuit breaker state transitions
- Dead letter queue operations
- Batch delivery with concurrency
- HMAC signature generation
"""

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from defensive_toolkit.api.services.webhook_delivery import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    DeadLetterQueue,
    DeliveryResult,
    DeliveryStatus,
    RetryConfig,
    WebhookDeliveryService,
    WebhookPayload,
    get_webhook_service,
)


# ============================================================================
# RetryConfig Tests
# ============================================================================


class TestRetryConfig:
    """Test retry configuration and backoff calculation."""

    def test_default_config(self):
        """Test default retry configuration values."""
        config = RetryConfig()
        assert config.max_retries == 5
        assert config.initial_delay_seconds == 1.0
        assert config.max_delay_seconds == 300.0
        assert config.exponential_base == 2.0
        assert config.jitter_factor == 0.1

    def test_calculate_delay_exponential(self):
        """Test exponential backoff delay calculation."""
        config = RetryConfig(
            initial_delay_seconds=1.0,
            exponential_base=2.0,
            max_delay_seconds=300.0,
            jitter_factor=0.0,  # Disable jitter for predictable testing
        )

        # Attempt 0: 1 * 2^0 = 1 second
        assert config.calculate_delay(0) == 1.0

        # Attempt 1: 1 * 2^1 = 2 seconds
        assert config.calculate_delay(1) == 2.0

        # Attempt 2: 1 * 2^2 = 4 seconds
        assert config.calculate_delay(2) == 4.0

        # Attempt 5: 1 * 2^5 = 32 seconds
        assert config.calculate_delay(5) == 32.0

    def test_calculate_delay_max_cap(self):
        """Test that delay is capped at max_delay_seconds."""
        config = RetryConfig(
            initial_delay_seconds=1.0,
            exponential_base=2.0,
            max_delay_seconds=60.0,
            jitter_factor=0.0,
        )

        # Attempt 10: 1 * 2^10 = 1024, but capped at 60
        assert config.calculate_delay(10) == 60.0

    def test_calculate_delay_with_jitter(self):
        """Test that jitter adds randomness to delay."""
        config = RetryConfig(
            initial_delay_seconds=10.0,
            jitter_factor=0.1,  # 10% jitter
        )

        delays = [config.calculate_delay(0) for _ in range(100)]

        # All delays should be around 10 seconds (within jitter range)
        for delay in delays:
            assert 9.0 <= delay <= 11.0  # 10 +/- 10%


# ============================================================================
# CircuitBreaker Tests
# ============================================================================


class TestCircuitBreaker:
    """Test circuit breaker state machine."""

    def test_initial_state_closed(self):
        """Test circuit breaker starts in closed state."""
        cb = CircuitBreaker("test-endpoint")
        assert cb.state == CircuitState.CLOSED
        assert cb.can_execute()

    def test_trip_to_open_on_failures(self):
        """Test circuit trips to open after failure threshold."""
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test-endpoint", config=config)

        # Record failures
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert not cb.can_execute()

    def test_half_open_after_timeout(self):
        """Test circuit transitions to half-open after timeout."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            timeout_seconds=0.1,  # Short timeout for testing
        )
        cb = CircuitBreaker("test-endpoint", config=config)

        # Trip the circuit
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Wait for timeout
        import time

        time.sleep(0.15)

        # Should transition to half-open on next check
        assert cb.can_execute()
        assert cb.state == CircuitState.HALF_OPEN

    def test_close_on_success_in_half_open(self):
        """Test circuit closes after successes in half-open state."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=2,
            timeout_seconds=0.1,
        )
        cb = CircuitBreaker("test-endpoint", config=config)

        # Trip to open
        cb.record_failure()
        cb.record_failure()

        # Wait for half-open
        import time

        time.sleep(0.15)
        cb.can_execute()  # Trigger transition

        # Record successes
        cb.record_success()
        assert cb.state == CircuitState.HALF_OPEN

        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_reopen_on_failure_in_half_open(self):
        """Test circuit reopens on failure in half-open state."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            timeout_seconds=0.1,
        )
        cb = CircuitBreaker("test-endpoint", config=config)

        # Trip to open
        cb.record_failure()
        cb.record_failure()

        # Wait for half-open
        import time

        time.sleep(0.15)
        cb.can_execute()

        # Fail in half-open
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_success_resets_failure_count(self):
        """Test that success in closed state resets failure count."""
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker("test-endpoint", config=config)

        cb.record_failure()
        cb.record_failure()
        assert cb.failure_count == 2

        cb.record_success()
        assert cb.failure_count == 0

    def test_get_status(self):
        """Test circuit breaker status reporting."""
        cb = CircuitBreaker("test-endpoint")
        cb.record_failure()

        status = cb.get_status()
        assert status["name"] == "test-endpoint"
        assert status["state"] == "closed"
        assert status["failure_count"] == 1
        assert "last_failure_at" in status
        assert "last_state_change" in status


# ============================================================================
# DeadLetterQueue Tests
# ============================================================================


class TestDeadLetterQueue:
    """Test dead letter queue operations."""

    def test_add_to_queue(self):
        """Test adding items to dead letter queue."""
        dlq = DeadLetterQueue(max_size=100)

        payload = WebhookPayload(
            id="test-123",
            url="https://example.com/webhook",
            body={"event": "test"},
        )

        result = DeliveryResult(
            payload_id="test-123",
            status=DeliveryStatus.FAILED,
            attempts=5,
            last_attempt_at=datetime.utcnow(),
            error="Connection refused",
        )

        dlq.add(payload, result, reason="max_retries_exceeded")

        assert dlq.count() == 1
        entry = dlq.get("test-123")
        assert entry is not None
        assert entry["url"] == "https://example.com/webhook"
        assert entry["reason"] == "max_retries_exceeded"

    def test_remove_from_queue(self):
        """Test removing items from dead letter queue."""
        dlq = DeadLetterQueue()

        payload = WebhookPayload(id="test-123", url="https://example.com")
        result = DeliveryResult(
            payload_id="test-123",
            status=DeliveryStatus.FAILED,
            attempts=1,
            last_attempt_at=datetime.utcnow(),
        )

        dlq.add(payload, result)
        assert dlq.count() == 1

        removed = dlq.remove("test-123")
        assert removed is True
        assert dlq.count() == 0

    def test_remove_nonexistent(self):
        """Test removing non-existent item returns False."""
        dlq = DeadLetterQueue()
        assert dlq.remove("nonexistent") is False

    def test_list_all(self):
        """Test listing all dead letter queue entries."""
        dlq = DeadLetterQueue()

        for i in range(5):
            payload = WebhookPayload(id=f"test-{i}", url="https://example.com")
            result = DeliveryResult(
                payload_id=f"test-{i}",
                status=DeliveryStatus.FAILED,
                attempts=1,
                last_attempt_at=datetime.utcnow(),
            )
            dlq.add(payload, result)

        entries = dlq.list_all(limit=3)
        assert len(entries) == 3

        entries = dlq.list_all(limit=10, offset=2)
        assert len(entries) == 3

    def test_max_size_overflow(self):
        """Test that max size is enforced with FIFO eviction."""
        dlq = DeadLetterQueue(max_size=3)

        for i in range(5):
            payload = WebhookPayload(id=f"test-{i}", url="https://example.com")
            result = DeliveryResult(
                payload_id=f"test-{i}",
                status=DeliveryStatus.FAILED,
                attempts=1,
                last_attempt_at=datetime.utcnow(),
            )
            dlq.add(payload, result)

        # Should only have 3 items (oldest removed)
        assert dlq.count() == 3

    def test_stats(self):
        """Test dead letter queue statistics."""
        dlq = DeadLetterQueue()

        # Use unique IDs to avoid DLQ deduplication
        for i, reason in enumerate(["max_retries", "max_retries", "circuit_open"]):
            payload = WebhookPayload(id=f"test-{reason}-{i}", url="https://example.com")
            result = DeliveryResult(
                payload_id=f"test-{reason}-{i}",
                status=DeliveryStatus.FAILED,
                attempts=1,
                last_attempt_at=datetime.utcnow(),
            )
            dlq.add(payload, result, reason=reason)

        stats = dlq.stats()
        assert stats["total"] == 3
        assert stats["by_reason"]["max_retries"] == 2
        assert stats["by_reason"]["circuit_open"] == 1


# ============================================================================
# WebhookPayload Tests
# ============================================================================


class TestWebhookPayload:
    """Test webhook payload model."""

    def test_payload_defaults(self):
        """Test default payload values."""
        payload = WebhookPayload(
            id="test-123",
            url="https://example.com/webhook",
        )

        assert payload.method == "POST"
        assert payload.headers == {}
        assert payload.body is None
        assert payload.secret_key is None
        assert payload.timeout_seconds == 30.0

    def test_payload_with_body(self):
        """Test payload with JSON body."""
        payload = WebhookPayload(
            id="test-123",
            url="https://example.com/webhook",
            body={"event": "alert", "severity": "high"},
            headers={"Content-Type": "application/json"},
        )

        assert payload.body == {"event": "alert", "severity": "high"}


# ============================================================================
# WebhookDeliveryService Tests
# ============================================================================


class TestWebhookDeliveryService:
    """Test webhook delivery service."""

    @pytest.fixture
    def service(self):
        """Create a fresh delivery service for each test."""
        return WebhookDeliveryService(
            retry_config=RetryConfig(max_retries=2, initial_delay_seconds=0.1),
            circuit_breaker_config=CircuitBreakerConfig(failure_threshold=3),
        )

    def test_sign_payload(self, service):
        """Test HMAC payload signing."""
        body = b'{"event": "test"}'
        secret = "my-secret-key"

        signature = service._sign_payload(body, secret)

        assert signature.startswith("sha256=")
        # Verify the signature is correct
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert signature == f"sha256={expected}"

    def test_get_circuit_breaker(self, service):
        """Test circuit breaker creation per endpoint."""
        cb1 = service._get_circuit_breaker("https://api.example.com/webhook")
        cb2 = service._get_circuit_breaker("https://api.example.com/other")
        cb3 = service._get_circuit_breaker("https://different.com/webhook")

        # Same domain should share circuit breaker
        assert cb1 is cb2
        # Different domain should have different circuit breaker
        assert cb1 is not cb3

    @pytest.mark.asyncio
    async def test_deliver_success(self, service):
        """Test successful webhook delivery."""
        payload = WebhookPayload(
            id="test-123",
            url="https://example.com/webhook",
            body={"event": "test"},
        )

        with patch.object(service, "_attempt_delivery") as mock_deliver:
            mock_deliver.return_value = {
                "status_code": 200,
                "headers": {},
                "body": "OK",
            }

            result = await service.deliver(payload)

            assert result.status == DeliveryStatus.DELIVERED
            assert result.attempts == 1
            assert result.response_code == 200

    @pytest.mark.asyncio
    async def test_deliver_with_retry(self, service):
        """Test webhook delivery with retries on failure."""
        payload = WebhookPayload(
            id="test-123",
            url="https://example.com/webhook",
            body={"event": "test"},
        )

        call_count = 0

        async def mock_attempt(p):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return {"status_code": 500, "body": "Error"}
            return {"status_code": 200, "body": "OK"}

        with patch.object(service, "_attempt_delivery", side_effect=mock_attempt):
            result = await service.deliver(payload)

            assert result.status == DeliveryStatus.DELIVERED
            assert result.attempts == 2

    @pytest.mark.asyncio
    async def test_deliver_max_retries_to_dlq(self, service):
        """Test that max retries sends to dead letter queue."""
        payload = WebhookPayload(
            id="test-123",
            url="https://example.com/webhook",
            body={"event": "test"},
        )

        with patch.object(service, "_attempt_delivery") as mock_deliver:
            mock_deliver.return_value = {"status_code": 500, "body": "Error"}

            result = await service.deliver(payload)

            assert result.status == DeliveryStatus.DEAD_LETTER
            assert result.attempts == 3  # Initial + 2 retries
            assert service.dlq.count() == 1

    @pytest.mark.asyncio
    async def test_circuit_breaker_blocks_delivery(self, service):
        """Test that open circuit breaker blocks delivery."""
        payload = WebhookPayload(
            id="test-123",
            url="https://example.com/webhook",
        )

        # Trip the circuit breaker
        cb = service._get_circuit_breaker(payload.url)
        for _ in range(3):
            cb.record_failure()

        assert cb.state == CircuitState.OPEN

        with patch.object(service, "_attempt_delivery") as mock_deliver:
            result = await service.deliver(payload)

            # Should not attempt delivery when circuit is open
            mock_deliver.assert_not_called()
            assert "Circuit breaker open" in result.error

    def test_get_metrics(self, service):
        """Test metrics retrieval."""
        # Simulate some activity
        service._metrics["total_sent"] = 100
        service._metrics["total_delivered"] = 95
        service._metrics["total_failed"] = 5
        service._metrics["delivery_times_ms"] = [10, 20, 30, 40, 50]

        metrics = service.get_metrics()

        assert metrics["total_sent"] == 100
        assert metrics["total_delivered"] == 95
        assert metrics["total_failed"] == 5
        assert metrics["success_rate"] == 95.0
        assert metrics["avg_delivery_time_ms"] == 30.0
        assert metrics["dlq_size"] == 0

    @pytest.mark.asyncio
    async def test_deliver_batch(self, service):
        """Test batch delivery with concurrency control."""
        payloads = [
            WebhookPayload(id=f"test-{i}", url="https://example.com/webhook")
            for i in range(5)
        ]

        with patch.object(service, "_attempt_delivery") as mock_deliver:
            mock_deliver.return_value = {"status_code": 200, "body": "OK"}

            results = await service.deliver_batch(payloads, concurrency=2)

            assert len(results) == 5
            assert all(r.status == DeliveryStatus.DELIVERED for r in results)


# ============================================================================
# Singleton Tests
# ============================================================================


class TestWebhookServiceSingleton:
    """Test webhook service singleton pattern."""

    def test_get_webhook_service_returns_same_instance(self):
        """Test that get_webhook_service returns the same instance."""
        # Reset singleton
        import defensive_toolkit.api.services.webhook_delivery as wd

        wd._webhook_service = None

        service1 = get_webhook_service()
        service2 = get_webhook_service()

        assert service1 is service2

        # Cleanup
        wd._webhook_service = None
