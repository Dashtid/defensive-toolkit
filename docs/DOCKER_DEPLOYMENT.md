# Defensive Toolkit - Docker Deployment Guide

**100% Open Source** production deployment guide for Docker containerization.

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/Dashtid/defensive-toolkit.git
cd defensive-toolkit
cp .env.example .env
# Edit .env and set SECRET_KEY

# 2. Generate SSL certificates
bash nginx/ssl/generate-certs.sh

# 3. Deploy with automation script
bash scripts/deploy.sh

# 4. Access services
# API: https://localhost
# Grafana: http://localhost:3000 (admin/changeme)
# Prometheus: http://localhost:9090
```

## Prerequisites

- Docker 24.0+ and Docker Compose 2.20+
- 8GB RAM minimum (16GB recommended)
- 20GB disk space
- Linux/macOS (Windows via WSL2)

## Services

| Service | Port | URL | Description |
|---------|------|-----|-------------|
| API | 8000 | http://localhost:8000 | FastAPI REST API |
| Nginx | 80, 443 | https://localhost | Reverse proxy + SSL |
| Prometheus | 9090 | http://localhost:9090 | Metrics collection |
| Grafana | 3000 | http://localhost:3000 | Dashboards |

## Production Deployment

### Automated

```bash
bash scripts/deploy.sh production
```

### Manual

```bash
docker-compose build
docker-compose up -d
curl http://localhost:8000/health
```

## Development

```bash
docker-compose -f docker-compose.dev.yml up
# Hot reload, debug logging, extra services
```

## Monitoring

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/changeme)
- **Metrics**: http://localhost:8000/metrics

## Security

- Change all default passwords immediately
- Generate strong SECRET_KEY
- Use Let's Encrypt for production SSL
- Configure firewall (allow 80, 443 only)
- Enable rate limiting

## Troubleshooting

```bash
# View logs
docker-compose logs -f

# Restart services
docker-compose restart

# Check health
curl http://localhost:8000/health
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for comprehensive guide.

---

**Version**: 1.3.0
