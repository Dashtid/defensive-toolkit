# Kubernetes Deployment

Production-ready Kubernetes manifests for Defensive Toolkit API.

## Prerequisites

- Kubernetes 1.25+
- kubectl configured
- Nginx Ingress Controller (optional, for ingress)
- cert-manager (optional, for TLS)

## Quick Start

```bash
# Create namespace and deploy all resources
kubectl apply -k .

# Or apply individually
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f hpa.yaml
kubectl apply -f ingress.yaml
```

## Configuration

### Secrets (REQUIRED)

**Do not use the template values in production!**

```bash
# Generate secure secrets
kubectl create secret generic defensive-toolkit-secrets \
  --from-literal=SECRET_KEY=$(openssl rand -hex 32) \
  --from-literal=JWT_SECRET=$(openssl rand -hex 32) \
  -n defensive-toolkit
```

Or use external secrets management:
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- Sealed Secrets

### ConfigMap

Edit `configmap.yaml` to customize:
- `CORS_ORIGINS`: Allowed origins for CORS
- `LOG_LEVEL`: DEBUG, INFO, WARNING, ERROR
- `RATE_LIMIT_*`: Rate limiting configuration

### Ingress

Edit `ingress.yaml`:
1. Replace `defensive-toolkit.example.com` with your domain
2. Configure TLS certificate (cert-manager or manual)
3. Adjust rate limiting annotations as needed

## Manifests

| File | Description |
|------|-------------|
| `namespace.yaml` | Dedicated namespace |
| `configmap.yaml` | Non-sensitive configuration |
| `secret.yaml` | Sensitive configuration (TEMPLATE) |
| `deployment.yaml` | API deployment with security context |
| `service.yaml` | ClusterIP service |
| `hpa.yaml` | Horizontal Pod Autoscaler (2-10 replicas) |
| `ingress.yaml` | Nginx ingress with TLS |
| `kustomization.yaml` | Kustomize configuration |

## Security Features

- Non-root container (UID 1000)
- Read-only root filesystem
- Dropped capabilities
- Resource limits
- Pod anti-affinity (spread across nodes)
- Security headers via ingress

## Monitoring

Prometheus metrics available at `/metrics`:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8000"
  prometheus.io/path: "/metrics"
```

## Scaling

HPA configured for:
- Min replicas: 2
- Max replicas: 10
- CPU target: 70%
- Memory target: 80%

Manual scaling:
```bash
kubectl scale deployment defensive-toolkit-api --replicas=5 -n defensive-toolkit
```

## Troubleshooting

```bash
# Check pod status
kubectl get pods -n defensive-toolkit

# View logs
kubectl logs -l app.kubernetes.io/name=defensive-toolkit -n defensive-toolkit

# Describe deployment
kubectl describe deployment defensive-toolkit-api -n defensive-toolkit

# Check HPA status
kubectl get hpa -n defensive-toolkit
```
