#!/bin/bash
# Production Deployment Script for Defensive Toolkit
# Automates Docker deployment with health checks and rollback capability
# Version: 1.3.0

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"
ENV_FILE="$PROJECT_ROOT/.env"
BACKUP_DIR="$PROJECT_ROOT/backups"
DEPLOYMENT_MODE="${1:-production}"  # production or dev

# Deployment settings
HEALTH_CHECK_TIMEOUT=60
HEALTH_CHECK_INTERVAL=5
MAX_RETRIES=3

# Logging
LOG_FILE="$PROJECT_ROOT/logs/deployment-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[X]${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG_FILE"
}

# Banner
echo -e "${BLUE}"
echo "=============================================="
echo "Defensive Toolkit - Production Deployment"
echo "100% Open Source Security Platform"
echo "=============================================="
echo -e "${NC}"

# Pre-flight checks
log_info "Running pre-flight checks..."

# Check if Docker is installed and running
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed"
    exit 1
fi

if ! docker info &> /dev/null; then
    log_error "Docker daemon is not running"
    exit 1
fi
log_success "Docker is installed and running"

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    log_error "Docker Compose is not installed"
    exit 1
fi
log_success "Docker Compose is available"

# Check if compose file exists
if [ ! -f "$COMPOSE_FILE" ]; then
    log_error "docker-compose.yml not found at $COMPOSE_FILE"
    exit 1
fi
log_success "Docker Compose file found"

# Check for .env file
if [ ! -f "$ENV_FILE" ]; then
    log_warning ".env file not found. Using defaults (NOT recommended for production)"

    if [ "$DEPLOYMENT_MODE" == "production" ]; then
        read -p "Continue without .env file? (y/N): " CONTINUE
        if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
            log_info "Deployment cancelled"
            exit 0
        fi
    fi
else
    log_success ".env file found"

    # Check for critical environment variables
    if grep -q "SECRET_KEY=CHANGE" "$ENV_FILE"; then
        log_error "SECRET_KEY not configured in .env file"
        log_info "Generate a secure key with: python -c 'import secrets; print(secrets.token_hex(32))'"
        exit 1
    fi
    log_success "Environment variables configured"
fi

# SSL Certificate check
if [ ! -f "$PROJECT_ROOT/nginx/ssl/cert.pem" ] || [ ! -f "$PROJECT_ROOT/nginx/ssl/key.pem" ]; then
    log_warning "SSL certificates not found. Generating self-signed certificates..."

    if [ -f "$PROJECT_ROOT/nginx/ssl/generate-certs.sh" ]; then
        bash "$PROJECT_ROOT/nginx/ssl/generate-certs.sh"
    else
        log_error "Certificate generation script not found"
        exit 1
    fi
fi
log_success "SSL certificates are present"

# Create backup of current deployment
log_info "Creating backup..."
mkdir -p "$BACKUP_DIR"

if docker-compose -f "$COMPOSE_FILE" ps | grep -q "Up"; then
    BACKUP_FILE="$BACKUP_DIR/backup-$(date +%Y%m%d-%H%M%S).tar.gz"

    # Backup data volumes
    docker-compose -f "$COMPOSE_FILE" exec -T api tar czf - /app/data 2>/dev/null | cat > "$BACKUP_FILE" || true

    if [ -f "$BACKUP_FILE" ]; then
        log_success "Backup created: $BACKUP_FILE"
    else
        log_warning "Backup creation failed or no data to backup"
    fi
fi

# Pull latest images
log_info "Pulling latest images..."
if docker-compose -f "$COMPOSE_FILE" pull; then
    log_success "Images pulled successfully"
else
    log_error "Failed to pull images"
    exit 1
fi

# Build custom images
log_info "Building custom images..."
if docker-compose -f "$COMPOSE_FILE" build --no-cache; then
    log_success "Images built successfully"
else
    log_error "Failed to build images"
    exit 1
fi

# Stop existing containers (graceful shutdown)
if docker-compose -f "$COMPOSE_FILE" ps | grep -q "Up"; then
    log_info "Stopping existing containers..."
    if docker-compose -f "$COMPOSE_FILE" down --timeout 30; then
        log_success "Containers stopped gracefully"
    else
        log_warning "Graceful shutdown failed, forcing stop..."
        docker-compose -f "$COMPOSE_FILE" down --timeout 5
    fi
fi

# Start new containers
log_info "Starting containers..."
if docker-compose -f "$COMPOSE_FILE" up -d; then
    log_success "Containers started"
else
    log_error "Failed to start containers"
    exit 1
fi

# Health check with retry
log_info "Performing health checks..."
ELAPSED=0
RETRY_COUNT=0

while [ $ELAPSED -lt $HEALTH_CHECK_TIMEOUT ]; do
    if curl -f http://localhost:8000/health &>/dev/null; then
        log_success "API health check passed"
        break
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))

    if [ $RETRY_COUNT -ge $MAX_RETRIES ] && [ $ELAPSED -ge 30 ]; then
        log_error "Health check failed after $MAX_RETRIES retries"
        log_info "Checking container logs..."
        docker-compose -f "$COMPOSE_FILE" logs --tail=50 api
        log_info "Rolling back deployment..."
        docker-compose -f "$COMPOSE_FILE" down
        exit 1
    fi

    sleep $HEALTH_CHECK_INTERVAL
    ELAPSED=$((ELAPSED + HEALTH_CHECK_INTERVAL))
    log_info "Waiting for API to become healthy... ($ELAPSED/${HEALTH_CHECK_TIMEOUT}s)"
done

# Check all services
log_info "Checking all services..."
SERVICES=$(docker-compose -f "$COMPOSE_FILE" ps --services)

for SERVICE in $SERVICES; do
    if docker-compose -f "$COMPOSE_FILE" ps "$SERVICE" | grep -q "Up"; then
        log_success "$SERVICE is running"
    else
        log_warning "$SERVICE is not running"
    fi
done

# Display deployment information
echo ""
log_info "=============================================="
log_success "Deployment completed successfully!"
log_info "=============================================="
echo ""
log_info "Service URLs:"
log_info "  API:        https://localhost (via Nginx)"
log_info "  API Direct: http://localhost:8000"
log_info "  Docs:       https://localhost/docs"
log_info "  Prometheus: http://localhost:9090"
log_info "  Grafana:    http://localhost:3000"
echo ""
log_info "Default Credentials (CHANGE THESE!):"
log_info "  API Admin:  admin / changeme123"
log_info "  Grafana:    admin / changeme"
echo ""
log_info "Next Steps:"
log_info "  1. Change default passwords immediately"
log_info "  2. Configure SSL certificates for production"
log_info "  3. Set up proper backup schedule"
log_info "  4. Configure monitoring alerts"
log_info "  5. Review security settings in .env"
echo ""
log_info "Logs: $LOG_FILE"
log_info "Backups: $BACKUP_DIR"
echo ""
log_info "To view logs: docker-compose -f $COMPOSE_FILE logs -f"
log_info "To stop services: docker-compose -f $COMPOSE_FILE down"
echo ""

# Save deployment metadata
cat > "$PROJECT_ROOT/.deployment-info" <<EOF
DEPLOYMENT_DATE=$(date '+%Y-%m-%d %H:%M:%S')
DEPLOYMENT_MODE=$DEPLOYMENT_MODE
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
EOF

log_success "Deployment complete!"
