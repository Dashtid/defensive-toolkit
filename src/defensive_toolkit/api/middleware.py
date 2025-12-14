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
from typing import Callable, Dict

from api.config import get_settings
from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware

settings = get_settings()
logger = logging.getLogger(__name__)


# ============================================================================
# Rate Limiting Middleware
# ============================================================================


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory rate limiting middleware.

    For production with multiple instances, use Redis-backed rate limiting
    via slowapi or fastapi-limiter libraries.

    Rate limit format: "requests/period"
    Examples: "100/minute", "1000/hour", "10000/day"
    """

    def __init__(self, app, default_limit: str = "100/minute"):
        super().__init__(app)
        self.default_limit = default_limit
        self.requests: Dict[str, list] = defaultdict(list)

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
            # Default to 100/minute if parsing fails
            logger.warning(f"Invalid rate limit format: {limit}, using default")
            return 100, 60

    def get_client_id(self, request: Request) -> str:
        """
        Get unique client identifier.

        Uses X-Forwarded-For if behind proxy, otherwise client IP.

        Args:
            request: FastAPI request

        Returns:
            str: Client identifier
        """
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host

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
        client_id = self.get_client_id(request)
        now = time.time()

        # Get request history for this client
        request_times = self.requests[client_id]

        # Clean up old requests outside the window
        request_times[:] = [t for t in request_times if now - t < window]

        # Check if limit exceeded
        if len(request_times) >= max_requests:
            retry_after = int(window - (now - request_times[0]))
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Maximum {max_requests} requests per {window}s",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        # Add current request
        request_times.append(now)

        # Add rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max_requests - len(request_times))
        response.headers["X-RateLimit-Reset"] = str(int(now + window))

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
