# API Authentication Guide

This guide covers authentication and authorization for the Defensive Toolkit API, including JWT setup, API keys, and role-based access control (RBAC).

## Table of Contents

- [Overview](#overview)
- [Authentication Methods](#authentication-methods)
  - [JWT Authentication](#jwt-authentication)
  - [API Key Authentication](#api-key-authentication)
- [Token Management](#token-management)
- [Role-Based Access Control](#role-based-access-control)
- [Configuration](#configuration)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

---

## Overview

The Defensive Toolkit API implements a dual-authentication system supporting both:

1. **JWT (JSON Web Tokens)** - For interactive user sessions
2. **API Keys** - For service-to-service communication and automation

Both methods provide secure access with configurable permission scopes.

### Authentication Flow

```
Client Request
      │
      ▼
┌─────────────────────┐
│ Check Authorization │
│     Header          │
└─────────────────────┘
      │
      ▼
┌─────────────────────┐     ┌─────────────────────┐
│  JWT Token Present? │─Yes─▶│   Validate JWT     │
└─────────────────────┘     └─────────────────────┘
      │ No                           │
      ▼                              ▼
┌─────────────────────┐     ┌─────────────────────┐
│ X-API-Key Present?  │─Yes─▶│  Validate API Key  │
└─────────────────────┘     └─────────────────────┘
      │ No                           │
      ▼                              ▼
┌─────────────────────┐     ┌─────────────────────┐
│  401 Unauthorized   │     │   Access Granted    │
└─────────────────────┘     └─────────────────────┘
```

---

## Authentication Methods

### JWT Authentication

JWT provides session-based authentication with short-lived access tokens and long-lived refresh tokens.

#### Token Types

| Token Type | Lifetime | Purpose |
|------------|----------|---------|
| Access Token | 15 minutes | API request authorization |
| Refresh Token | 30 days | Obtaining new access tokens |

#### Obtaining Tokens

**Step 1: Login**

```bash
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=changeme123"
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 900
}
```

**Step 2: Use Access Token**

Include the access token in the `Authorization` header:

```bash
curl -X GET "http://localhost:8000/api/v1/detection/rules" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Refreshing Tokens

When the access token expires, use the refresh token to get a new one:

```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

#### Logout (Token Revocation)

Revoke tokens to end a session:

```bash
curl -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'
```

#### JWT Token Structure

Access tokens contain the following claims:

```json
{
  "sub": "admin",           // Username
  "scopes": ["admin", "read", "write"],  // Permission scopes
  "exp": 1703678400,        // Expiration timestamp
  "iat": 1703677500,        // Issued at timestamp
  "type": "access"          // Token type
}
```

---

### API Key Authentication

API keys are designed for:
- Automated scripts and CI/CD pipelines
- Service-to-service communication
- Long-running integrations (SIEM, SOAR platforms)

#### Using API Keys

Include the API key in the `X-API-Key` header:

```bash
curl -X GET "http://localhost:8000/api/v1/detection/rules" \
  -H "X-API-Key: your-api-key-here"
```

#### Generating API Keys

API keys are configured through environment variables. Generate a secure key:

```bash
# Generate a secure random key (64 hex characters)
python -c "import secrets; print(secrets.token_hex(32))"
```

Then add to your `.env` file:

```bash
VALID_API_KEYS=abc123def456,xyz789ghi012
```

Multiple keys can be comma-separated for different services.

#### API Key Best Practices

1. **Rotate regularly** - Change keys every 90 days
2. **Unique per service** - Each integration gets its own key
3. **Monitor usage** - Track which keys are used
4. **Never commit** - Store in environment variables or secrets manager

---

## Token Management

### Token Blacklisting

Revoked tokens are added to a blacklist until they expire. In production, use Redis for distributed blacklist storage.

```python
# Tokens are blacklisted on logout
POST /api/v1/auth/logout
```

### Token Introspection

Check token validity without making an API request:

```bash
curl -X GET "http://localhost:8000/api/v1/auth/verify" \
  -H "Authorization: Bearer <token>"
```

Response:
```json
{
  "valid": true,
  "username": "admin",
  "scopes": ["admin", "read", "write"],
  "expires_at": "2024-12-27T15:00:00Z"
}
```

---

## Role-Based Access Control

### Permission Scopes

| Scope | Description | Example Endpoints |
|-------|-------------|-------------------|
| `read` | View resources | GET /detection/rules |
| `write` | Create/modify resources | POST /detection/rules |
| `admin` | Administrative operations | DELETE /users, config changes |

### Built-in Users

| Username | Default Password | Scopes |
|----------|-----------------|--------|
| `admin` | `changeme123` | admin, read, write |
| `analyst` | `analyst123` | read |

**[!] IMPORTANT:** Change default passwords immediately in production!

### Scope Enforcement

Endpoints enforce scopes through FastAPI dependencies:

```python
from defensive_toolkit.api.dependencies import require_write_scope

@router.post("/rules")
async def create_rule(
    current_user: str = Depends(require_write_scope),
):
    # Only users with write scope can access
    ...
```

### Endpoint Authorization Matrix

| Endpoint Category | Required Scope |
|-------------------|----------------|
| View rules/alerts | `read` |
| Create/modify rules | `write` |
| Execute runbooks | `write` |
| Delete resources | `admin` |
| User management | `admin` |
| System configuration | `admin` |

---

## Configuration

### Environment Variables

```bash
# JWT Configuration
SECRET_KEY=your-super-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# API Keys (comma-separated)
VALID_API_KEYS=key1,key2,key3

# Authentication Settings
REQUIRE_AUTHENTICATION=true
```

### Generating a Secure Secret Key

```bash
# Option 1: Python
python -c "import secrets; print(secrets.token_hex(32))"

# Option 2: OpenSSL
openssl rand -hex 32

# Option 3: /dev/urandom (Linux/macOS)
head -c 32 /dev/urandom | xxd -p
```

### Configuration File (config.py)

Key settings in `src/defensive_toolkit/api/config.py`:

```python
class Settings(BaseSettings):
    # JWT Settings
    secret_key: str = "CHANGE_THIS_TO_A_SECURE_RANDOM_KEY"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30

    # Authentication
    require_authentication: bool = True

    # API Keys
    valid_api_keys: str = ""  # Comma-separated
```

---

## Security Best Practices

### 1. Secret Key Management

```bash
# WRONG - Never do this
SECRET_KEY=my-secret-key

# CORRECT - Use environment variable
SECRET_KEY=${SECRET_KEY}  # Injected at runtime

# BEST - Use secrets manager
# AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, etc.
```

### 2. Token Lifetime

- **Access tokens:** 15-30 minutes (shorter is more secure)
- **Refresh tokens:** 7-30 days (balance security vs. user experience)

```python
ACCESS_TOKEN_EXPIRE_MINUTES=15  # Recommended
REFRESH_TOKEN_EXPIRE_DAYS=30    # Maximum recommended
```

### 3. HTTPS Only

Always use HTTPS in production:

```nginx
server {
    listen 443 ssl;

    # Redirect token endpoint to HTTPS
    location /api/v1/auth/ {
        proxy_pass http://api:8000;
    }
}
```

### 4. Rate Limiting

Auth endpoints have stricter rate limits:

```python
RATE_LIMIT_AUTH=5/minute  # 5 login attempts per minute
```

### 5. Password Requirements

For production user management:

```python
# Minimum requirements
- Length: 12+ characters
- Must include: uppercase, lowercase, number, special character
- No common passwords
- No password reuse (last 10)
```

### 6. Audit Logging

All authentication events are logged:

```json
{
  "event": "login_success",
  "user": "admin",
  "ip": "192.168.1.100",
  "timestamp": "2024-12-27T10:30:00Z",
  "user_agent": "curl/8.0"
}
```

---

## Troubleshooting

### Common Issues

#### 401 Unauthorized - "Could not validate credentials"

**Cause:** Invalid or expired token

**Solution:**
1. Check token expiration
2. Refresh the access token
3. Re-authenticate if refresh token expired

```bash
# Check token expiration
python -c "import jwt; print(jwt.decode('TOKEN', options={'verify_signature': False}))"
```

#### 401 Unauthorized - "Token has been revoked"

**Cause:** Token was blacklisted (logout)

**Solution:** Obtain new tokens by logging in again

#### 403 Forbidden - "Admin privileges required"

**Cause:** User lacks required scope

**Solution:**
1. Check user's assigned scopes
2. Use a user with appropriate permissions
3. Contact administrator for scope upgrade

#### API Key Not Working

**Cause:** Key not in VALID_API_KEYS

**Solution:**
1. Verify key is in environment variable
2. Check for whitespace or formatting issues
3. Restart API after adding new keys

```bash
# Verify environment variable
echo $VALID_API_KEYS

# Check for whitespace
python -c "import os; print(repr(os.getenv('VALID_API_KEYS')))"
```

### Debug Mode

Enable debug logging for authentication issues:

```bash
LOG_LEVEL=DEBUG
DEBUG=true
```

Logs will show:
- Token validation attempts
- Scope verification
- Blacklist checks

---

## Integration Examples

### Python (requests)

```python
import requests

# JWT Authentication
def get_token(username, password):
    response = requests.post(
        "http://localhost:8000/api/v1/auth/token",
        data={"username": username, "password": password}
    )
    return response.json()

# Using the token
token = get_token("admin", "changeme123")
headers = {"Authorization": f"Bearer {token['access_token']}"}
response = requests.get(
    "http://localhost:8000/api/v1/detection/rules",
    headers=headers
)
```

### Python (httpx async)

```python
import httpx

async def fetch_rules():
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "http://localhost:8000/api/v1/detection/rules",
            headers={"X-API-Key": "your-api-key"}
        )
        return response.json()
```

### curl with Token Refresh

```bash
#!/bin/bash
# auto_refresh.sh - Automatic token refresh

ACCESS_TOKEN=""
REFRESH_TOKEN=""

refresh_token() {
    response=$(curl -s -X POST "http://localhost:8000/api/v1/auth/refresh" \
        -H "Content-Type: application/json" \
        -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")

    ACCESS_TOKEN=$(echo $response | jq -r '.access_token')
    REFRESH_TOKEN=$(echo $response | jq -r '.refresh_token')
}

# Make authenticated request with auto-refresh
api_request() {
    response=$(curl -s -w "\n%{http_code}" "$1" \
        -H "Authorization: Bearer $ACCESS_TOKEN")

    status=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$status" == "401" ]; then
        refresh_token
        api_request "$1"
    else
        echo "$body"
    fi
}
```

---

## Kubernetes Integration

### Mounting Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: defensive-toolkit-secrets
type: Opaque
stringData:
  SECRET_KEY: "your-64-character-secret-key"
  VALID_API_KEYS: "key1,key2,key3"
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: api
          envFrom:
            - secretRef:
                name: defensive-toolkit-secrets
```

### Using External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: defensive-toolkit-secrets
spec:
  secretStoreRef:
    kind: ClusterSecretStore
    name: vault
  target:
    name: defensive-toolkit-secrets
  data:
    - secretKey: SECRET_KEY
      remoteRef:
        key: defensive-toolkit
        property: jwt-secret
    - secretKey: VALID_API_KEYS
      remoteRef:
        key: defensive-toolkit
        property: api-keys
```

---

## Version History

| Version | Changes |
|---------|---------|
| 1.2.0 | Added Redis rate limiting, per-user limits |
| 1.1.0 | Added refresh token support |
| 1.0.0 | Initial JWT and API key authentication |
