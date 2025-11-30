"""
Defensive Toolkit REST API

Main FastAPI application with all routers and middleware.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from prometheus_fastapi_instrumentator import Instrumentator

from api.config import get_settings
from api.models import (
    Token, RefreshTokenRequest, HealthCheckResponse,
    APIResponse, StatusEnum, ErrorResponse
)
from api.auth import (
    authenticate_user, create_token_pair, verify_token,
    get_current_active_user, generate_api_key
)
from api.middleware import (
    setup_middleware, http_exception_handler, general_exception_handler
)

# Import all routers
from api.routers import (
    detection, incident_response, threat_hunting, hardening,
    monitoring, forensics, vulnerability, automation,
    compliance, log_analysis, webhooks, threat_intel, websocket, siem, scheduler,
    notifications
)

settings = get_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info("Starting Defensive Toolkit API...")
    logger.info(f"Version: {settings.app_version}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"Rate limiting: {settings.rate_limit_enabled}")
    logger.info(f"Authentication required: {settings.require_authentication}")

    yield

    # Shutdown
    logger.info("Shutting down Defensive Toolkit API...")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description=settings.app_description,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs" if settings.enable_swagger_ui else None,
    redoc_url="/redoc" if settings.enable_redoc else None,
    openapi_url=f"{settings.api_prefix}/openapi.json",
)

# Setup middleware (CORS, rate limiting, logging, security headers)
setup_middleware(app)

# Exception handlers
app.add_exception_handler(Exception, general_exception_handler)

# ============================================================================
# Prometheus Metrics Instrumentation
# ============================================================================

# Instrument the API with Prometheus metrics
Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)


# ============================================================================
# Root and Health Endpoints
# ============================================================================

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "description": settings.app_description,
        "docs": "/docs" if settings.enable_swagger_ui else None,
        "health": "/health",
    }


@app.get("/health", response_model=HealthCheckResponse, tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring."""
    return HealthCheckResponse(
        version=settings.app_version,
        services={
            "api": "healthy",
            "authentication": "healthy",
            "rate_limiting": "healthy" if settings.rate_limit_enabled else "disabled",
        }
    )


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.post(f"{settings.api_prefix}/auth/token", response_model=Token, tags=["Authentication"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token login endpoint.

    Use username and password to get access and refresh tokens.
    """
    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Incorrect username or password"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create token pair
    token = create_token_pair(
        username=user["username"],
        scopes=user.get("scopes", [])
    )

    logger.info(f"User {user['username']} logged in successfully")
    return token


@app.post(f"{settings.api_prefix}/auth/refresh", response_model=Token, tags=["Authentication"])
async def refresh_token(request: RefreshTokenRequest):
    """
    Refresh access token using refresh token.

    Implements token rotation for security.
    """
    # Verify refresh token
    token_data = verify_token(request.refresh_token, token_type="refresh")

    # Create new token pair
    token = create_token_pair(username=token_data.username)

    logger.info(f"Token refreshed for user {token_data.username}")
    return token


@app.post(f"{settings.api_prefix}/auth/logout", response_model=APIResponse, tags=["Authentication"])
async def logout(current_user: str = Depends(get_current_active_user)):
    """
    Logout endpoint (token invalidation).

    Note: For full token blacklisting, implement Redis-backed blacklist in production.
    """
    logger.info(f"User {current_user} logged out")
    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Logged out successfully"
    )


@app.get(f"{settings.api_prefix}/auth/me", tags=["Authentication"])
async def get_current_user_info(current_user: str = Depends(get_current_active_user)):
    """Get current authenticated user information."""
    return {
        "username": current_user,
        "authenticated": True
    }


@app.post(f"{settings.api_prefix}/auth/api-key", tags=["Authentication"])
async def create_api_key(current_user: str = Depends(get_current_active_user)):
    """
    Generate a new API key.

    API keys can be used as alternative to JWT tokens for service-to-service auth.
    """
    if current_user not in ["admin", "api_key_user"]:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Admin privileges required to create API keys"}
        )

    api_key = generate_api_key()

    return {
        "api_key": api_key,
        "usage": "Add header: X-API-Key: <your-api-key>",
        "warning": "Store this key securely. It will not be shown again."
    }


# ============================================================================
# Include All Category Routers
# ============================================================================

app.include_router(detection.router, prefix=settings.api_prefix)
app.include_router(incident_response.router, prefix=settings.api_prefix)
app.include_router(threat_hunting.router, prefix=settings.api_prefix)
app.include_router(hardening.router, prefix=settings.api_prefix)
app.include_router(monitoring.router, prefix=settings.api_prefix)
app.include_router(forensics.router, prefix=settings.api_prefix)
app.include_router(vulnerability.router, prefix=settings.api_prefix)
app.include_router(automation.router, prefix=settings.api_prefix)
app.include_router(compliance.router, prefix=settings.api_prefix)
app.include_router(log_analysis.router, prefix=settings.api_prefix)
app.include_router(webhooks.router, prefix=settings.api_prefix)
app.include_router(threat_intel.router, prefix=settings.api_prefix)
app.include_router(websocket.router, prefix=settings.api_prefix)
app.include_router(siem.router, prefix=settings.api_prefix)
app.include_router(scheduler.router, prefix=settings.api_prefix)
app.include_router(notifications.router, prefix=settings.api_prefix)

logger.info("All routers registered successfully")


# ============================================================================
# Run with uvicorn (development)
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
