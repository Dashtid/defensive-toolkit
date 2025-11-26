#!/bin/bash
# Local Docker Testing Script
# Run all Docker tests locally before pushing to CI/CD
# Version: 1.4.1

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_TIMEOUT=120

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[X]${NC} $1"
}

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Banner
echo -e "${BLUE}"
echo "=============================================="
echo "Defensive Toolkit - Local Docker Tests"
echo "=============================================="
echo -e "${NC}"

cd "$PROJECT_ROOT"

# Step 1: Check prerequisites
log_info "Step 1/7: Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed"
    exit 1
fi
log_success "Docker installed"

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    log_error "Docker Compose is not installed"
    exit 1
fi
log_success "Docker Compose installed"

# Step 2: Lint Dockerfiles
log_info "Step 2/7: Linting Dockerfiles..."

if command -v hadolint &> /dev/null; then
    hadolint Dockerfile && log_success "API Dockerfile passed linting"
    hadolint nginx/Dockerfile && log_success "Nginx Dockerfile passed linting"
else
    log_warning "Hadolint not installed, skipping Dockerfile linting"
    log_info "Install with: brew install hadolint (macOS) or download from https://github.com/hadolint/hadolint"
fi

# Step 3: Build images
log_info "Step 3/7: Building Docker images..."

docker-compose build --no-cache && log_success "Images built successfully"

# Step 4: Start services
log_info "Step 4/7: Starting Docker Compose stack..."

# Create test .env if it doesn't exist
if [ ! -f .env ]; then
    log_warning ".env not found, creating test configuration"
    cat > .env <<EOF
SECRET_KEY=test-secret-key-for-local-testing
API_HOST=0.0.0.0
API_PORT=8000
CORS_ORIGINS=http://localhost:3000
RATE_LIMIT_ENABLED=false
LOG_LEVEL=DEBUG
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=test-password
EOF
fi

# Generate SSL certificates if needed
if [ ! -f nginx/ssl/cert.pem ] || [ ! -f nginx/ssl/key.pem ]; then
    log_info "Generating SSL certificates..."
    mkdir -p nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/key.pem \
        -out nginx/ssl/cert.pem \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost"
fi

docker-compose up -d
log_success "Services started"

# Wait for services to be healthy
log_info "Waiting for services to become healthy..."
ELAPSED=0
while [ $ELAPSED -lt $TEST_TIMEOUT ]; do
    if curl -sf http://localhost:8000/health &>/dev/null; then
        log_success "API is healthy"
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    if [ $((ELAPSED % 20)) -eq 0 ]; then
        log_info "Still waiting... ($ELAPSED/${TEST_TIMEOUT}s)"
    fi
done

if [ $ELAPSED -ge $TEST_TIMEOUT ]; then
    log_error "Services failed to become healthy within ${TEST_TIMEOUT}s"
    log_info "Showing logs..."
    docker-compose logs --tail=50
    docker-compose down -v
    exit 1
fi

# Step 5: Run health checks
log_info "Step 5/7: Running health checks..."

# API health
if curl -sf http://localhost:8000/health | grep -q "healthy"; then
    log_success "API health check passed"
else
    log_error "API health check failed"
    docker-compose logs api
    docker-compose down -v
    exit 1
fi

# API via Nginx
if curl -k -sf https://localhost/health | grep -q "healthy"; then
    log_success "Nginx reverse proxy health check passed"
else
    log_error "Nginx health check failed"
    docker-compose logs nginx
    docker-compose down -v
    exit 1
fi

# Prometheus
if curl -sf http://localhost:9090/-/healthy &>/dev/null; then
    log_success "Prometheus health check passed"
else
    log_warning "Prometheus health check failed (non-critical)"
fi

# Grafana
if curl -sf http://localhost:3000/api/health &>/dev/null; then
    log_success "Grafana health check passed"
else
    log_warning "Grafana health check failed (non-critical)"
fi

# Step 6: Run integration tests
log_info "Step 6/7: Running integration tests..."

# Test metrics endpoint
if curl -sf http://localhost:8000/metrics | grep -q "http_requests_total"; then
    log_success "Prometheus metrics endpoint working"
else
    log_error "Metrics endpoint failed"
    docker-compose down -v
    exit 1
fi

# Test API documentation
if curl -sf http://localhost:8000/docs | grep -q "Defensive Toolkit"; then
    log_success "API documentation accessible"
else
    log_error "API documentation failed"
    docker-compose down -v
    exit 1
fi

# Test root endpoint
if curl -sf http://localhost:8000/ | grep -q "Defensive Toolkit"; then
    log_success "Root endpoint working"
else
    log_error "Root endpoint failed"
    docker-compose down -v
    exit 1
fi

# Step 7: Cleanup
log_info "Step 7/7: Cleaning up..."

docker-compose down -v
log_success "Services stopped and cleaned up"

# Summary
echo ""
log_info "=============================================="
log_success "All Docker tests passed!"
log_info "=============================================="
echo ""
log_info "Your Docker setup is ready for CI/CD"
log_info "To deploy: bash scripts/deploy.sh"
echo ""
