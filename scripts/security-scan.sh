#!/bin/bash
# Local Security Scanning Script
# Run comprehensive security scans on Docker images locally
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
REPORT_DIR="$PROJECT_ROOT/security-reports"

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
echo "Defensive Toolkit - Security Scanning"
echo "=============================================="
echo -e "${NC}"

cd "$PROJECT_ROOT"

# Create reports directory
mkdir -p "$REPORT_DIR"
log_info "Security reports will be saved to: $REPORT_DIR"
echo ""

# Step 1: Check prerequisites
log_info "Step 1/5: Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed"
    exit 1
fi
log_success "Docker installed"

# Check for Trivy
if ! command -v trivy &> /dev/null; then
    log_warning "Trivy not installed"
    log_info "Install with:"
    log_info "  macOS: brew install trivy"
    log_info "  Linux: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    log_info ""
    log_info "Continuing with Docker-based Trivy..."
    TRIVY_CMD="docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/work aquasec/trivy"
else
    TRIVY_CMD="trivy"
    log_success "Trivy installed"
fi

# Check for Hadolint
if ! command -v hadolint &> /dev/null; then
    log_warning "Hadolint not installed"
    log_info "Install with: brew install hadolint (macOS)"
    log_info "Or download from: https://github.com/hadolint/hadolint"
    HADOLINT_AVAILABLE=false
else
    HADOLINT_AVAILABLE=true
    log_success "Hadolint installed"
fi

# Step 2: Lint Dockerfiles
log_info "Step 2/5: Linting Dockerfiles with Hadolint..."

if [ "$HADOLINT_AVAILABLE" = true ]; then
    echo "Scanning: Dockerfile"
    hadolint Dockerfile | tee "$REPORT_DIR/hadolint-api.txt" || log_warning "Hadolint found issues in API Dockerfile"

    echo "Scanning: nginx/Dockerfile"
    hadolint nginx/Dockerfile | tee "$REPORT_DIR/hadolint-nginx.txt" || log_warning "Hadolint found issues in Nginx Dockerfile"

    log_success "Dockerfile linting complete"
else
    log_warning "Skipping Hadolint scan (not installed)"
fi

# Step 3: Build images if they don't exist
log_info "Step 3/5: Checking Docker images..."

if ! docker images | grep -q "defensive-toolkit-api"; then
    log_info "Building API image..."
    docker build -t defensive-toolkit-api:latest -f Dockerfile .
    log_success "API image built"
else
    log_success "API image exists"
fi

if ! docker images | grep -q "defensive-toolkit-nginx"; then
    log_info "Building Nginx image..."
    docker build -t defensive-toolkit-nginx:latest -f nginx/Dockerfile nginx/
    log_success "Nginx image built"
else
    log_success "Nginx image exists"
fi

# Step 4: Run Trivy scans
log_info "Step 4/5: Running Trivy vulnerability scans..."

echo ""
log_info "Scanning API image (HIGH/CRITICAL vulnerabilities)..."
$TRIVY_CMD image \
    --severity HIGH,CRITICAL \
    --format table \
    --output "$REPORT_DIR/trivy-api-critical.txt" \
    defensive-toolkit-api:latest

log_info "Scanning API image (full report)..."
$TRIVY_CMD image \
    --severity LOW,MEDIUM,HIGH,CRITICAL \
    --format json \
    --output "$REPORT_DIR/trivy-api-full.json" \
    defensive-toolkit-api:latest

echo ""
log_info "Scanning Nginx image (HIGH/CRITICAL vulnerabilities)..."
$TRIVY_CMD image \
    --severity HIGH,CRITICAL \
    --format table \
    --output "$REPORT_DIR/trivy-nginx-critical.txt" \
    defensive-toolkit-nginx:latest

log_info "Scanning Nginx image (full report)..."
$TRIVY_CMD image \
    --severity LOW,MEDIUM,HIGH,CRITICAL \
    --format json \
    --output "$REPORT_DIR/trivy-nginx-full.json" \
    defensive-toolkit-nginx:latest

log_success "Trivy scans complete"

# Step 5: Scan for secrets
log_info "Step 5/5: Scanning for secrets and misconfigurations..."

echo ""
log_info "Scanning API image for secrets..."
$TRIVY_CMD image \
    --scanners secret \
    --format table \
    --output "$REPORT_DIR/trivy-api-secrets.txt" \
    defensive-toolkit-api:latest || log_warning "Potential secrets found"

log_info "Scanning for IaC misconfigurations in docker-compose.yml..."
$TRIVY_CMD config \
    --severity HIGH,CRITICAL \
    --format table \
    --output "$REPORT_DIR/trivy-iac-scan.txt" \
    docker-compose.yml || log_warning "Misconfigurations found"

log_success "Secret scanning complete"

# Summary
echo ""
log_info "=============================================="
log_info "Security Scan Summary"
log_info "=============================================="
echo ""

# Count HIGH/CRITICAL vulnerabilities
API_CRITICAL=$(grep -c "CRITICAL\|HIGH" "$REPORT_DIR/trivy-api-critical.txt" 2>/dev/null || echo "0")
NGINX_CRITICAL=$(grep -c "CRITICAL\|HIGH" "$REPORT_DIR/trivy-nginx-critical.txt" 2>/dev/null || echo "0")

echo "API Image:"
log_info "  HIGH/CRITICAL vulnerabilities: $API_CRITICAL"
log_info "  Full report: $REPORT_DIR/trivy-api-full.json"

echo ""
echo "Nginx Image:"
log_info "  HIGH/CRITICAL vulnerabilities: $NGINX_CRITICAL"
log_info "  Full report: $REPORT_DIR/trivy-nginx-full.json"

echo ""
log_info "All reports saved to: $REPORT_DIR"
echo ""

# Detailed reports
log_info "View detailed reports:"
log_info "  cat $REPORT_DIR/trivy-api-critical.txt"
log_info "  cat $REPORT_DIR/trivy-nginx-critical.txt"
echo ""

# Check for critical issues
if [ "$API_CRITICAL" -gt 0 ] || [ "$NGINX_CRITICAL" -gt 0 ]; then
    log_warning "Found HIGH/CRITICAL vulnerabilities - review reports before deploying"
    log_info "To fix: Update base images and dependencies in Dockerfile"
    exit 1
else
    log_success "No HIGH/CRITICAL vulnerabilities found!"
    log_success "Images are ready for deployment"
fi
