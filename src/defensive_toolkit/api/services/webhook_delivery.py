"""
Webhook Delivery Service

Robust webhook delivery with:
- Exponential backoff retry logic
- Dead letter queue for failed deliveries
- Circuit breaker pattern
- Delivery tracking and metrics

Version: 1.0.0
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class DeliveryStatus(str, Enum):
    """Webhook delivery status."""

    PENDING = "pending"
    SENDING = "sending"
    DELIVERED = "delivered"
    RETRYING = "retrying"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_retries: int = 5
    initial_delay_seconds: float = 1.0
    max_delay_seconds: float = 300.0  # 5 minutes max
    exponential_base: float = 2.0
    jitter_factor: float = 0.1  # 10% jitter

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay with exponential backoff and jitter."""
        delay = min(
            self.initial_delay_seconds * (self.exponential_base**attempt),
            self.max_delay_seconds,
        )
        # Add jitter to prevent thundering herd
        jitter = delay * self.jitter_factor * (2 * secrets.randbelow(1000) / 1000 - 1)
        return max(0, delay + jitter)


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5  # Failures before opening
    success_threshold: int = 3  # Successes in half-open to close
    timeout_seconds: float = 60.0  # Time before trying half-open


@dataclass
class WebhookPayload:
    """Webhook delivery payload."""

    id: str
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Any = None
    secret_key: Optional[str] = None
    signature_header: str = "X-Signature-256"
    timeout_seconds: float = 30.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeliveryResult:
    """Result of a webhook delivery attempt."""

    payload_id: str
    status: DeliveryStatus
    attempts: int
    last_attempt_at: datetime
    response_code: Optional[int] = None
    response_body: Optional[str] = None
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    next_retry_at: Optional[datetime] = None


class CircuitBreaker:
    """
    Circuit breaker implementation for webhook endpoints.

    Prevents overwhelming failing endpoints with requests.
    """

    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_at: Optional[datetime] = None
        self.last_state_change: datetime = datetime.utcnow()

    def can_execute(self) -> bool:
        """Check if request should be allowed."""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if timeout has elapsed
            elapsed = (datetime.utcnow() - self.last_state_change).total_seconds()
            if elapsed >= self.config.timeout_seconds:
                self._transition_to(CircuitState.HALF_OPEN)
                return True
            return False

        # Half-open: allow limited requests
        return True

    def record_success(self):
        """Record a successful request."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self._transition_to(CircuitState.CLOSED)
        else:
            self.failure_count = 0

    def record_failure(self):
        """Record a failed request."""
        self.failure_count += 1
        self.last_failure_at = datetime.utcnow()

        if self.state == CircuitState.HALF_OPEN:
            self._transition_to(CircuitState.OPEN)
        elif self.failure_count >= self.config.failure_threshold:
            self._transition_to(CircuitState.OPEN)

    def _transition_to(self, new_state: CircuitState):
        """Transition to a new state."""
        old_state = self.state
        self.state = new_state
        self.last_state_change = datetime.utcnow()

        if new_state == CircuitState.CLOSED:
            self.failure_count = 0
            self.success_count = 0
        elif new_state == CircuitState.HALF_OPEN:
            self.success_count = 0

        logger.info(f"[i] Circuit breaker '{self.name}': {old_state.value} -> {new_state.value}")

    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_at": self.last_failure_at.isoformat() if self.last_failure_at else None,
            "last_state_change": self.last_state_change.isoformat(),
        }


class DeadLetterQueue:
    """
    Dead letter queue for permanently failed webhooks.

    Stores failed deliveries for manual review and replay.
    """

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._queue: Dict[str, Dict[str, Any]] = {}
        self._created_at: Dict[str, datetime] = {}

    def add(
        self,
        payload: WebhookPayload,
        result: DeliveryResult,
        reason: str = "max_retries_exceeded",
    ):
        """Add a failed delivery to the dead letter queue."""
        if len(self._queue) >= self.max_size:
            # Remove oldest entry
            oldest_id = min(self._created_at, key=self._created_at.get)
            self.remove(oldest_id)
            logger.warning(f"[!] DLQ overflow - removed oldest entry: {oldest_id}")

        entry = {
            "id": payload.id,
            "url": payload.url,
            "method": payload.method,
            "headers": payload.headers,
            "body": payload.body,
            "metadata": payload.metadata,
            "reason": reason,
            "last_error": result.error,
            "attempts": result.attempts,
            "last_attempt_at": result.last_attempt_at.isoformat(),
            "added_at": datetime.utcnow().isoformat(),
        }

        self._queue[payload.id] = entry
        self._created_at[payload.id] = datetime.utcnow()
        logger.info(f"[+] Added to DLQ: {payload.id} ({reason})")

    def remove(self, payload_id: str) -> bool:
        """Remove an entry from the dead letter queue."""
        if payload_id in self._queue:
            del self._queue[payload_id]
            del self._created_at[payload_id]
            return True
        return False

    def get(self, payload_id: str) -> Optional[Dict[str, Any]]:
        """Get a dead letter entry."""
        return self._queue.get(payload_id)

    def list_all(
        self,
        limit: int = 100,
        offset: int = 0,
        reason_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List dead letter queue entries."""
        entries = list(self._queue.values())

        if reason_filter:
            entries = [e for e in entries if e.get("reason") == reason_filter]

        # Sort by added_at descending
        entries.sort(key=lambda x: x.get("added_at", ""), reverse=True)

        return entries[offset : offset + limit]

    def count(self) -> int:
        """Get total count of entries in DLQ."""
        return len(self._queue)

    def stats(self) -> Dict[str, Any]:
        """Get DLQ statistics."""
        by_reason: Dict[str, int] = defaultdict(int)
        for entry in self._queue.values():
            by_reason[entry.get("reason", "unknown")] += 1

        return {
            "total": len(self._queue),
            "max_size": self.max_size,
            "by_reason": dict(by_reason),
        }


class WebhookDeliveryService:
    """
    Service for reliable webhook delivery with retries.

    Features:
    - Exponential backoff with jitter
    - Circuit breaker per endpoint
    - Dead letter queue for failed deliveries
    - Delivery tracking and metrics
    """

    def __init__(
        self,
        retry_config: RetryConfig = None,
        circuit_breaker_config: CircuitBreakerConfig = None,
        dlq_max_size: int = 10000,
    ):
        self.retry_config = retry_config or RetryConfig()
        self.circuit_breaker_config = circuit_breaker_config or CircuitBreakerConfig()
        self.dlq = DeadLetterQueue(max_size=dlq_max_size)

        # Circuit breakers per endpoint (keyed by domain)
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}

        # Pending deliveries
        self._pending: Dict[str, Dict[str, Any]] = {}

        # Metrics
        self._metrics = {
            "total_sent": 0,
            "total_delivered": 0,
            "total_failed": 0,
            "total_retried": 0,
            "delivery_times_ms": [],
        }

        # HTTP client
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
                follow_redirects=True,
            )
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_circuit_breaker(self, url: str) -> CircuitBreaker:
        """Get or create circuit breaker for an endpoint."""
        # Use domain as key
        from urllib.parse import urlparse

        domain = urlparse(url).netloc
        if domain not in self._circuit_breakers:
            self._circuit_breakers[domain] = CircuitBreaker(
                name=domain, config=self.circuit_breaker_config
            )
        return self._circuit_breakers[domain]

    def _sign_payload(self, body: bytes, secret: str) -> str:
        """Generate HMAC signature for payload."""
        signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return f"sha256={signature}"

    async def deliver(
        self,
        payload: WebhookPayload,
        callback: Optional[Callable[[DeliveryResult], None]] = None,
    ) -> DeliveryResult:
        """
        Deliver a webhook with automatic retries.

        Args:
            payload: The webhook payload to deliver
            callback: Optional callback for delivery result

        Returns:
            DeliveryResult with final status
        """
        circuit_breaker = self._get_circuit_breaker(payload.url)
        result = DeliveryResult(
            payload_id=payload.id,
            status=DeliveryStatus.PENDING,
            attempts=0,
            last_attempt_at=datetime.utcnow(),
        )

        for attempt in range(self.retry_config.max_retries + 1):
            result.attempts = attempt + 1
            result.last_attempt_at = datetime.utcnow()

            # Check circuit breaker
            if not circuit_breaker.can_execute():
                result.status = DeliveryStatus.FAILED
                result.error = f"Circuit breaker open for {payload.url}"
                logger.warning(f"[!] Circuit breaker open, skipping delivery: {payload.id}")

                # Calculate next retry time
                if attempt < self.retry_config.max_retries:
                    delay = self.retry_config.calculate_delay(attempt)
                    result.next_retry_at = datetime.utcnow() + timedelta(seconds=delay)
                    result.status = DeliveryStatus.RETRYING

                continue

            # Attempt delivery
            result.status = DeliveryStatus.SENDING
            self._metrics["total_sent"] += 1

            try:
                start_time = time.monotonic()
                delivery_result = await self._attempt_delivery(payload)
                elapsed_ms = (time.monotonic() - start_time) * 1000

                result.response_code = delivery_result["status_code"]
                result.response_body = delivery_result.get("body", "")[:1000]  # Limit size
                result.response_time_ms = elapsed_ms

                if 200 <= delivery_result["status_code"] < 300:
                    # Success
                    result.status = DeliveryStatus.DELIVERED
                    circuit_breaker.record_success()
                    self._metrics["total_delivered"] += 1
                    self._metrics["delivery_times_ms"].append(elapsed_ms)

                    logger.info(
                        f"[+] Webhook delivered: {payload.id} "
                        f"(attempt {attempt + 1}, {elapsed_ms:.0f}ms)"
                    )

                    if callback:
                        callback(result)
                    return result
                else:
                    # Server error - may retry
                    result.error = f"HTTP {delivery_result['status_code']}"
                    circuit_breaker.record_failure()

            except httpx.TimeoutException as e:
                result.error = f"Timeout: {e}"
                circuit_breaker.record_failure()
                logger.warning(f"[!] Webhook timeout: {payload.id} ({e})")

            except httpx.ConnectError as e:
                result.error = f"Connection error: {e}"
                circuit_breaker.record_failure()
                logger.warning(f"[!] Webhook connection error: {payload.id} ({e})")

            except Exception as e:
                result.error = f"Unexpected error: {e}"
                circuit_breaker.record_failure()
                logger.error(f"[-] Webhook delivery error: {payload.id}", exc_info=True)

            # Calculate retry delay
            if attempt < self.retry_config.max_retries:
                delay = self.retry_config.calculate_delay(attempt)
                result.next_retry_at = datetime.utcnow() + timedelta(seconds=delay)
                result.status = DeliveryStatus.RETRYING
                self._metrics["total_retried"] += 1

                logger.info(
                    f"[i] Webhook retry scheduled: {payload.id} "
                    f"(attempt {attempt + 2}/{self.retry_config.max_retries + 1}, "
                    f"delay {delay:.1f}s)"
                )

                await asyncio.sleep(delay)
            else:
                # Max retries exceeded
                result.status = DeliveryStatus.DEAD_LETTER
                self._metrics["total_failed"] += 1

                # Add to dead letter queue
                self.dlq.add(payload, result, reason="max_retries_exceeded")

                logger.error(
                    f"[-] Webhook failed after {result.attempts} attempts: {payload.id} - "
                    f"added to DLQ"
                )

        if callback:
            callback(result)

        return result

    async def _attempt_delivery(self, payload: WebhookPayload) -> Dict[str, Any]:
        """Attempt a single webhook delivery."""
        client = await self._get_client()

        # Prepare headers
        headers = dict(payload.headers)
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("User-Agent", "DefensiveToolkit-Webhook/1.0")

        # Prepare body
        if isinstance(payload.body, (dict, list)):
            import json

            body = json.dumps(payload.body).encode()
        elif isinstance(payload.body, str):
            body = payload.body.encode()
        elif isinstance(payload.body, bytes):
            body = payload.body
        else:
            body = b""

        # Sign payload if secret configured
        if payload.secret_key:
            signature = self._sign_payload(body, payload.secret_key)
            headers[payload.signature_header] = signature

        # Make request
        response = await client.request(
            method=payload.method,
            url=payload.url,
            headers=headers,
            content=body,
            timeout=payload.timeout_seconds,
        )

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
        }

    async def deliver_batch(
        self,
        payloads: List[WebhookPayload],
        concurrency: int = 10,
    ) -> List[DeliveryResult]:
        """Deliver multiple webhooks with controlled concurrency."""
        semaphore = asyncio.Semaphore(concurrency)

        async def deliver_with_limit(payload: WebhookPayload) -> DeliveryResult:
            async with semaphore:
                return await self.deliver(payload)

        tasks = [deliver_with_limit(p) for p in payloads]
        return await asyncio.gather(*tasks)

    async def replay_from_dlq(self, payload_id: str) -> Optional[DeliveryResult]:
        """Replay a failed delivery from the dead letter queue."""
        entry = self.dlq.get(payload_id)
        if not entry:
            return None

        # Reconstruct payload
        payload = WebhookPayload(
            id=f"{entry['id']}-replay-{secrets.token_hex(4)}",
            url=entry["url"],
            method=entry["method"],
            headers=entry["headers"],
            body=entry["body"],
            metadata=entry["metadata"],
        )

        # Attempt delivery
        result = await self.deliver(payload)

        # Remove from DLQ if successful
        if result.status == DeliveryStatus.DELIVERED:
            self.dlq.remove(entry["id"])
            logger.info(f"[+] DLQ replay successful: {payload_id}")

        return result

    def get_metrics(self) -> Dict[str, Any]:
        """Get delivery metrics."""
        delivery_times = self._metrics["delivery_times_ms"]
        avg_time = sum(delivery_times) / len(delivery_times) if delivery_times else 0
        p95_time = sorted(delivery_times)[int(len(delivery_times) * 0.95)] if delivery_times else 0

        return {
            "total_sent": self._metrics["total_sent"],
            "total_delivered": self._metrics["total_delivered"],
            "total_failed": self._metrics["total_failed"],
            "total_retried": self._metrics["total_retried"],
            "success_rate": (
                self._metrics["total_delivered"] / self._metrics["total_sent"] * 100
                if self._metrics["total_sent"] > 0
                else 0
            ),
            "avg_delivery_time_ms": avg_time,
            "p95_delivery_time_ms": p95_time,
            "dlq_size": self.dlq.count(),
            "circuit_breakers": {
                name: cb.get_status() for name, cb in self._circuit_breakers.items()
            },
        }

    def get_circuit_breaker_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all circuit breakers."""
        return {name: cb.get_status() for name, cb in self._circuit_breakers.items()}


# Global service instance (singleton pattern)
_webhook_service: Optional[WebhookDeliveryService] = None


def get_webhook_service() -> WebhookDeliveryService:
    """Get or create the global webhook delivery service."""
    global _webhook_service
    if _webhook_service is None:
        _webhook_service = WebhookDeliveryService()
    return _webhook_service
