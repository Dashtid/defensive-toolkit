"""
Input Validation Utilities

Provides validation functions for API inputs including:
- URL validation (webhook endpoints)
- Payload size limits
- Input sanitization

Security-focused validation to prevent injection and DoS attacks.
"""

import logging
import re
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

# Maximum payload size in bytes (default: 10MB)
MAX_PAYLOAD_SIZE_BYTES = 10 * 1024 * 1024

# Allowed URL schemes for webhooks
ALLOWED_URL_SCHEMES = {"http", "https"}

# Blocked URL patterns (internal networks, localhost)
BLOCKED_URL_PATTERNS = [
    r"^https?://localhost",
    r"^https?://127\.",
    r"^https?://0\.",
    r"^https?://10\.",
    r"^https?://172\.(1[6-9]|2[0-9]|3[01])\.",
    r"^https?://192\.168\.",
    r"^https?://\[::1\]",
    r"^https?://\[fe80:",
    r"^https?://169\.254\.",  # Link-local
    r"^https?://\.internal",
    r"^https?://\.local",
]

# Allowed URL patterns (optional whitelist mode)
ALLOWED_URL_PATTERNS: Optional[List[str]] = None


# ============================================================================
# URL Validation
# ============================================================================


class URLValidationError(Exception):
    """Raised when URL validation fails."""

    pass


def validate_webhook_url(
    url: str,
    allow_internal: bool = False,
    allowed_hosts: Optional[List[str]] = None,
) -> str:
    """
    Validate a webhook URL for security.

    Args:
        url: URL to validate
        allow_internal: Allow internal/private network URLs (default: False)
        allowed_hosts: Optional list of allowed hostnames

    Returns:
        str: Validated URL

    Raises:
        URLValidationError: If URL is invalid or not allowed
    """
    if not url:
        raise URLValidationError("URL is required")

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise URLValidationError(f"Invalid URL format: {e}")

    # Check scheme
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise URLValidationError(
            f"Invalid URL scheme: {parsed.scheme}. "
            f"Allowed schemes: {', '.join(ALLOWED_URL_SCHEMES)}"
        )

    # Check for host
    if not parsed.netloc:
        raise URLValidationError("URL must include a host")

    # Check for blocked patterns (internal networks)
    if not allow_internal:
        for pattern in BLOCKED_URL_PATTERNS:
            if re.match(pattern, url, re.IGNORECASE):
                raise URLValidationError(
                    f"Internal/private network URLs are not allowed: {url}"
                )

    # Check allowed hosts if specified
    if allowed_hosts:
        host = parsed.netloc.split(":")[0]  # Remove port
        if host not in allowed_hosts and not any(
            host.endswith(f".{h}") for h in allowed_hosts
        ):
            raise URLValidationError(
                f"Host not in allowed list: {host}. "
                f"Allowed hosts: {', '.join(allowed_hosts)}"
            )

    # Check for dangerous URL patterns
    if parsed.username or parsed.password:
        raise URLValidationError("URLs with credentials are not allowed")

    # Check for javascript: or data: schemes that might bypass scheme check
    lower_url = url.lower()
    if "javascript:" in lower_url or "data:" in lower_url:
        raise URLValidationError("JavaScript and data URLs are not allowed")

    logger.debug(f"URL validated: {url}")
    return url


def validate_url_or_raise_http(
    url: str,
    allow_internal: bool = False,
    allowed_hosts: Optional[List[str]] = None,
) -> str:
    """
    Validate URL and raise HTTPException on failure.

    Wrapper around validate_webhook_url for FastAPI endpoints.
    """
    try:
        return validate_webhook_url(url, allow_internal, allowed_hosts)
    except URLValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# ============================================================================
# Payload Size Validation
# ============================================================================


async def validate_payload_size(
    request: Request,
    max_size: int = MAX_PAYLOAD_SIZE_BYTES,
) -> bytes:
    """
    Validate request payload size and return body.

    Args:
        request: FastAPI request
        max_size: Maximum allowed size in bytes

    Returns:
        bytes: Request body

    Raises:
        HTTPException: If payload exceeds size limit
    """
    # Check Content-Length header first
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
            if length > max_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Payload too large. Maximum size: {max_size} bytes, "
                    f"received: {length} bytes",
                )
        except ValueError:
            pass  # Invalid content-length, will check actual body

    # Read and validate actual body size
    body = await request.body()
    if len(body) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload too large. Maximum size: {max_size} bytes, "
            f"received: {len(body)} bytes",
        )

    return body


def check_payload_size(
    body: bytes,
    max_size: int = MAX_PAYLOAD_SIZE_BYTES,
) -> None:
    """
    Check if payload bytes exceed size limit.

    Args:
        body: Request body bytes
        max_size: Maximum allowed size

    Raises:
        HTTPException: If payload exceeds limit
    """
    if len(body) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload too large. Maximum size: {max_size} bytes, "
            f"received: {len(body)} bytes",
        )


# ============================================================================
# Input Sanitization
# ============================================================================


def sanitize_string(
    value: str,
    max_length: int = 1000,
    strip_html: bool = True,
) -> str:
    """
    Sanitize a string input.

    Args:
        value: Input string
        max_length: Maximum allowed length
        strip_html: Remove HTML tags

    Returns:
        str: Sanitized string
    """
    if not value:
        return value

    # Truncate to max length
    result = value[:max_length]

    # Strip HTML tags if requested
    if strip_html:
        result = re.sub(r"<[^>]+>", "", result)

    # Remove null bytes
    result = result.replace("\x00", "")

    return result


def sanitize_path(path: str) -> str:
    """
    Sanitize a file path to prevent directory traversal.

    Args:
        path: Input path

    Returns:
        str: Sanitized path

    Raises:
        HTTPException: If path contains dangerous patterns
    """
    if not path:
        return path

    # Check for directory traversal
    if ".." in path or path.startswith("/") or path.startswith("\\"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid path: directory traversal not allowed",
        )

    # Remove null bytes
    path = path.replace("\x00", "")

    # Normalize separators
    path = path.replace("\\", "/")

    return path


# ============================================================================
# Template Variable Validation
# ============================================================================


def validate_template_variables(
    variables: dict,
    max_key_length: int = 100,
    max_value_length: int = 10000,
) -> dict:
    """
    Validate and sanitize template variables.

    Args:
        variables: Dictionary of template variables
        max_key_length: Maximum key length
        max_value_length: Maximum value length

    Returns:
        dict: Sanitized variables

    Raises:
        HTTPException: If validation fails
    """
    if not variables:
        return {}

    sanitized = {}

    for key, value in variables.items():
        # Validate key
        if not isinstance(key, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Template variable keys must be strings",
            )

        if len(key) > max_key_length:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Template variable key too long: {key[:50]}... "
                f"(max {max_key_length} chars)",
            )

        # Validate and sanitize value
        if isinstance(value, str):
            if len(value) > max_value_length:
                value = value[:max_value_length]
            # Remove potential template injection patterns
            value = value.replace("{{", "{ {").replace("}}", "} }")

        sanitized[key] = value

    return sanitized
