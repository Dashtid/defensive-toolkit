"""
API Middleware Components

Implements:
- Rate limiting (in-memory with Redis support)
- CORS (Cross-Origin Resource Sharing)
- Request/Response logging
- Error handling
- Security headers

Following 2025 FastAPI best practices.
"""

import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Callable, Dict, Optional

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware

from defensive_toolkit.api.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

# Optional Redis import
try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.info("Redis not installed - using in-memory rate limiting")


# ============================================================================
# Rate Limiting Middleware
# ============================================================================


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware with Redis and in-memory backends.

    Features:
    - Sliding window algorithm for accurate limiting
    - Per-user limits for authenticated requests
    - Redis backend for distributed deployments
    - Automatic fallback to in-memory if Redis unavailable
    - Burst allowance above base limit

    Rate limit format: "requests/period"
    Examples: "100/minute", "1000/hour", "10000/day"
    """

    def __init__(self, app, default_limit: str = "100/minute"):
        super().__init__(app)
        self.default_limit = default_limit
        self.requests: Dict[str, list] = defaultdict(list)
        self.redis_client: Optional[object] = None
        self._init_redis()

    def _init_redis(self):
        """Initialize Redis client if enabled and available."""
        if settings.redis_enabled and REDIS_AVAILABLE:
            try:
                self.redis_client = redis.Redis(
                    host=settings.redis_host,
                    port=settings.redis_port,
                    db=settings.redis_db,
                    password=settings.redis_password or None,
                    ssl=settings.redis_ssl,
                    decode_responses=True,
                    socket_timeout=1.0,
                    socket_connect_timeout=1.0,
                )
                # Test connection
                self.redis_client.ping()
                logger.info("Redis rate limiting enabled")
            except Exception as e:
                logger.warning(f"Redis connection failed, using in-memory: {e}")
                self.redis_client = None

    def parse_limit(self, limit: str) -> tuple:
        """
        Parse rate limit string.

        Args:
            limit: Rate limit string (e.g., "100/minute")

        Returns:
            tuple: (max_requests, time_window_seconds)
        """
        try:
            count, period = limit.split("/")
            count = int(count)

            period_seconds = {
                "second": 1,
                "minute": 60,
                "hour": 3600,
                "day": 86400,
            }[period]

            return count, period_seconds

        except (ValueError, KeyError):
            logger.warning(f"Invalid rate limit format: {limit}, using default")
            return 100, 60

    def get_client_id(self, request: Request) -> str:
        """
        Get unique client identifier.

        For authenticated requests with per-user limiting enabled,
        extracts user ID from the request state (set by auth middleware).
        Otherwise uses IP address.

        Args:
            request: FastAPI request

        Returns:
            str: Client identifier (user:ID or ip:ADDRESS)
        """
        # Check for authenticated user (set by auth dependency)
        if settings.rate_limit_by_user:
            user = getattr(request.state, "user", None)
            if user and hasattr(user, "id"):
                return f"user:{user.id}"
            # Also check for user_id in state
            user_id = getattr(request.state, "user_id", None)
            if user_id:
                return f"user:{user_id}"

        # Fall back to IP-based limiting
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "unknown"

        return f"ip:{ip}"

    def _check_redis(self, key: str, max_requests: int, window: int) -> tuple:
        """
        Check rate limit using Redis sliding window.

        Args:
            key: Rate limit key
            max_requests: Maximum requests allowed
            window: Time window in seconds

        Returns:
            tuple: (is_allowed, current_count, retry_after)
        """
        now = time.time()
        window_start = now - window

        pipe = self.redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)  # Remove old entries
        pipe.zcard(key)  # Count current entries
        pipe.zadd(key, {str(now): now})  # Add current request
        pipe.expire(key, window + 1)  # Set expiry

        try:
            results = pipe.execute()
            current_count = results[1]

            if current_count >= max_requests:
                # Get oldest timestamp to calculate retry_after
                oldest = self.redis_client.zrange(key, 0, 0, withscores=True)
                if oldest:
                    retry_after = int(window - (now - oldest[0][1]))
                else:
                    retry_after = window
                return False, current_count, retry_after

            return True, current_count + 1, 0

        except Exception as e:
            logger.warning(f"Redis error, falling back to in-memory: {e}")
            return self._check_memory(key, max_requests, window)

    def _check_memory(self, key: str, max_requests: int, window: int) -> tuple:
        """
        Check rate limit using in-memory sliding window.

        Args:
            key: Rate limit key
            max_requests: Maximum requests allowed
            window: Time window in seconds

        Returns:
            tuple: (is_allowed, current_count, retry_after)
        """
        now = time.time()
        request_times = self.requests[key]

        # Clean up old requests
        request_times[:] = [t for t in request_times if now - t < window]

        if len(request_times) >= max_requests:
            retry_after = int(window - (now - request_times[0]))
            return False, len(request_times), retry_after

        request_times.append(now)
        return True, len(request_times), 0

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with rate limiting.

        Args:
            request: Incoming request
            call_next: Next middleware/route handler

        Returns:
            Response: HTTP response

        Raises:
            HTTPException: If rate limit exceeded
        """
        if not settings.rate_limit_enabled:
            return await call_next(request)

        # Get rate limit for this endpoint
        path = request.url.path
        if path.startswith(f"{settings.api_prefix}/auth"):
            limit = settings.rate_limit_auth
        elif any(heavy in path for heavy in ["/scan", "/analyze", "/execute"]):
            limit = settings.rate_limit_heavy
        else:
            limit = settings.rate_limit_default

        max_requests, window = self.parse_limit(limit)

        # Apply burst multiplier
        burst_limit = int(max_requests * settings.rate_limit_burst_multiplier)

        client_id = self.get_client_id(request)
        rate_key = f"ratelimit:{client_id}:{path}"

        # Check rate limit
        if self.redis_client:
            is_allowed, current_count, retry_after = self._check_redis(
                rate_key, burst_limit, window
            )
        else:
            is_allowed, current_count, retry_after = self._check_memory(
                rate_key, burst_limit, window
            )

        if not is_allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Maximum {max_requests} requests per {window}s (burst: {burst_limit})",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Burst"] = str(burst_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, burst_limit - current_count))
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + window))

        return response


# ============================================================================
# Request Logging Middleware
# ============================================================================


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log all API requests and responses.

    Logs:
    - Request method, path, headers
    - Response status code, processing time
    - Client IP address
    - Authenticated user (if available)
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Log request and response.

        Args:
            request: Incoming request
            call_next: Next middleware/route handler

        Returns:
            Response: HTTP response
        """
        start_time = time.time()

        # Get client info
        client_ip = request.client.host
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

        # Log request
        logger.info(
            f"Request started: {request.method} {request.url.path}",
            extra={
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "user_agent": request.headers.get("User-Agent"),
            },
        )

        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(
                f"Request failed: {request.method} {request.url.path}",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                },
                exc_info=True,
            )
            raise

        # Calculate processing time
        process_time = time.time() - start_time

        # Add custom headers
        response.headers["X-Process-Time"] = str(process_time)

        # Log response
        logger.info(
            f"Request completed: {request.method} {request.url.path} - {response.status_code}",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "process_time": process_time,
                "client_ip": client_ip,
            },
        )

        return response


# ============================================================================
# Security Headers Middleware
# ============================================================================


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.

    Headers added:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Strict-Transport-Security (HSTS)
    - Content-Security-Policy
    - Referrer-Policy
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Add security headers to response.

        Args:
            request: Incoming request
            call_next: Next middleware/route handler

        Returns:
            Response: HTTP response with security headers
        """
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response


# ============================================================================
# Exception Handler Middleware
# ============================================================================


async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Custom HTTP exception handler.

    Provides consistent error responses across the API.

    Args:
        request: FastAPI request
        exc: HTTP exception

    Returns:
        JSONResponse: Formatted error response
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "error": exc.detail,
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat(),
        },
        headers=exc.headers,
    )


async def general_exception_handler(request: Request, exc: Exception):
    """
    Handle unexpected exceptions.

    Logs the error and returns a generic 500 error to the client
    without leaking internal details.

    Args:
        request: FastAPI request
        exc: Exception

    Returns:
        JSONResponse: Generic error response
    """
    logger.error(
        f"Unhandled exception in {request.method} {request.url.path}",
        exc_info=True,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "error": "Internal server error",
            "detail": "An unexpected error occurred" if not settings.debug else str(exc),
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


# ============================================================================
# CORS Configuration Helper
# ============================================================================


def configure_cors(app):
    """
    Configure CORS middleware.

    Args:
        app: FastAPI application instance
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )


# ============================================================================
# Middleware Setup Helper
# ============================================================================


def setup_middleware(app):
    """
    Configure all middleware for the application.

    Args:
        app: FastAPI application instance
    """
    # CORS (must be first)
    configure_cors(app)

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # Request logging
    app.add_middleware(RequestLoggingMiddleware)

    # Rate limiting (if enabled)
    if settings.rate_limit_enabled:
        app.add_middleware(
            RateLimitMiddleware,
            default_limit=settings.rate_limit_default,
        )

    logger.info("Middleware configured successfully")
