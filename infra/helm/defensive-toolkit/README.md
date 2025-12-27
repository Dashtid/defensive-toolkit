# Defensive Toolkit Helm Chart

Helm chart for deploying the Defensive Toolkit API to Kubernetes.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.0+
- PV provisioner support (if persistence is enabled)

## Installation

### Quick Start

```bash
# Add the chart repository (if published)
helm repo add defensive-toolkit https://dashtid.github.io/defensive-toolkit

# Install with default values
helm install my-release defensive-toolkit/defensive-toolkit

# Or install from local chart
helm install my-release ./infra/helm/defensive-toolkit
```

### Production Installation

```bash
# Create namespace
kubectl create namespace defensive-toolkit

# Create secret with production values
kubectl create secret generic defensive-toolkit-secrets \
  --namespace defensive-toolkit \
  --from-literal=SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=VALID_API_KEYS="key1,key2,key3"

# Install with production values
helm install defensive-toolkit ./infra/helm/defensive-toolkit \
  --namespace defensive-toolkit \
  --set secrets.create=false \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=api.example.com \
  --set redis.enabled=true
```

## Configuration

See [values.yaml](values.yaml) for full configuration options.

### Key Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Image repository | `ghcr.io/dashtid/defensive-toolkit-api` |
| `image.tag` | Image tag | Chart appVersion |
| `ingress.enabled` | Enable ingress | `false` |
| `autoscaling.enabled` | Enable HPA | `true` |
| `redis.enabled` | Enable Redis for rate limiting | `false` |
| `secrets.secretKey` | JWT secret key | Must override! |

### Security Configuration

```yaml
# values-production.yaml
secrets:
  create: false  # Use external secret management

config:
  requireAuthentication: true
  rateLimitEnabled: true

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000

networkPolicy:
  enabled: true
```

### High Availability

```yaml
# values-ha.yaml
replicaCount: 3

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10

podDisruptionBudget:
  enabled: true
  minAvailable: 2

redis:
  enabled: true
```

### With Ingress and TLS

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: api.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: api-tls
      hosts:
        - api.example.com
```

## Upgrading

```bash
helm upgrade my-release ./infra/helm/defensive-toolkit \
  --namespace defensive-toolkit \
  -f values-production.yaml
```

## Uninstallation

```bash
helm uninstall my-release --namespace defensive-toolkit
kubectl delete namespace defensive-toolkit
```

## Troubleshooting

### Check pod status
```bash
kubectl get pods -n defensive-toolkit
kubectl describe pod <pod-name> -n defensive-toolkit
```

### View logs
```bash
kubectl logs -f deployment/defensive-toolkit -n defensive-toolkit
```

### Test connectivity
```bash
kubectl port-forward svc/defensive-toolkit 8000:8000 -n defensive-toolkit
curl http://localhost:8000/health
```
