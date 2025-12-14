# Multi-stage Dockerfile for Defensive Toolkit API
# Based on 2025 best practices for FastAPI production deployment

# ============================================================================
# Stage 1: Builder - Install dependencies and build wheels
# ============================================================================
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files
COPY pyproject.toml ./
COPY uv.lock* ./

# Create virtual environment and install dependencies
RUN uv venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies (excluding Windows-only extras)
RUN uv sync --no-dev --extra threat-intel --extra advanced

# Install gunicorn for production server
RUN uv pip install gunicorn

# ============================================================================
# Stage 2: Runtime - Minimal production image
# ============================================================================
FROM python:3.11-slim AS runtime

# Set metadata
LABEL maintainer="david.at.dashti@outlook.com"
LABEL description="Defensive Toolkit REST API - 100% Open Source Blue Team Security Platform"
LABEL version="1.3.0"

# Create non-root user for security
RUN groupadd -r toolkit && useradd -r -g toolkit toolkit

# Set working directory
WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code (src layout)
COPY --chown=toolkit:toolkit src/defensive_toolkit/ ./defensive_toolkit/
COPY --chown=toolkit:toolkit rules/ ./rules/
COPY --chown=toolkit:toolkit pyproject.toml ./

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    # API Configuration
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    # Security settings
    SECRET_KEY=CHANGEME_GENERATE_SECURE_KEY \
    # CORS
    CORS_ORIGINS=http://localhost:3000,http://localhost:8080 \
    # Rate limiting
    RATE_LIMIT_ENABLED=true \
    # Logging
    LOG_LEVEL=INFO

# Create directories for runtime
RUN mkdir -p /app/logs /app/data && \
    chown -R toolkit:toolkit /app/logs /app/data

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Switch to non-root user
USER toolkit

# Expose API port
EXPOSE 8000

# Use Gunicorn with Uvicorn workers for production (2025 best practice)
CMD ["gunicorn", "defensive_toolkit.api.main:app", \
     "--workers", "4", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--keep-alive", "5"]
