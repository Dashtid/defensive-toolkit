# Defensive Toolkit REST API Documentation

**100% Open Source** REST API for security automation, detection, and response.

## Overview

The Defensive Toolkit REST API provides comprehensive endpoints for all 10 security categories, enabling programmatic access to detection rules, incident response, threat hunting, and more. All integrations are with open-source platforms only (Wazuh, Elastic, OpenSearch, Graylog, TheHive, MISP).

**Version:** 1.3.0
**Base URL:** `http://localhost:8000`
**API Prefix:** `/api/v1`

## Features

- [+] **JWT Authentication** with OAuth2 support
- [+] **API Key Authentication** for service-to-service integration
- [+] **Rate Limiting** to prevent abuse
- [+] **CORS Support** for web applications
- [+] **OpenAPI/Swagger Documentation** at `/docs`
- [+] **ReDoc Documentation** at `/redoc`
- [+] **Comprehensive Error Handling**
- [+] **Security Headers** (HSTS, CSP, X-Frame-Options)

## Quick Start

### 1. Installation

```bash
# Install dependencies
uv pip install -e ".[all]"

# Or with pip
pip install -e ".[all]"
```

### 2. Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env and set:
# - SECRET_KEY (generate with: python -c "import secrets; print(secrets.token_hex(32))")
# - VALID_API_KEYS (optional)
# - Other settings as needed
```

### 3. Start the API Server

```bash
# Start with uvicorn directly
uvicorn api.main:app --reload

# Or use the CLI
python -m api.main

# Or with installed CLI
toolkit-api
```

### 4. Access Documentation

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI JSON:** http://localhost:8000/api/v1/openapi.json

## Authentication

### JWT Authentication (Recommended)

#### Login to Get Tokens

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=changeme123"
```

**Response:**
```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "token_type": "bearer",
  "expires_in": 900
}
```

#### Use Access Token

```bash
curl -X GET http://localhost:8000/api/v1/detection/rules \
  -H "Authorization: Bearer <access_token>"
```

#### Refresh Access Token

```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'
```

### API Key Authentication (Alternative)

```bash
curl -X GET http://localhost:8000/api/v1/detection/rules \
  -H "X-API-Key: <your-api-key>"
```

**Generate API Key:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/api-key \
  -H "Authorization: Bearer <admin_token>"
```

### Default Users

| Username | Password | Scopes |
|----------|----------|--------|
| admin | changeme123 | admin, read, write |
| analyst | analyst123 | read |

**IMPORTANT:** Change default passwords in production!

## Rate Limiting

The API implements rate limiting to prevent abuse:

| Endpoint Type | Default Limit |
|---------------|---------------|
| General | 100 requests/minute |
| Authentication | 5 requests/minute |
| Heavy Operations | 10 requests/minute |

**Rate Limit Headers:**
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Timestamp when limit resets

**Response on Limit Exceeded (HTTP 429):**
```json
{
  "error": "Rate limit exceeded",
  "detail": "Maximum 100 requests per 60s",
  "retry_after": 45
}
```

## API Endpoints

### Health & Status

#### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.2.0",
  "timestamp": "2025-10-22T12:00:00Z",
  "services": {
    "api": "healthy",
    "authentication": "healthy"
  }
}
```

---

### Detection Rules

#### GET /api/v1/detection/rules
List all detection rules.

**Query Parameters:**
- `rule_type` (optional): Filter by type (sigma, yara, snort, custom)
- `severity` (optional): Filter by severity (low, medium, high, critical)

**Response:**
```json
{
  "rules": [
    {
      "id": "uuid",
      "name": "Suspicious PowerShell",
      "rule_type": "sigma",
      "severity": "high",
      "enabled": true
    }
  ],
  "total": 1
}
```

#### POST /api/v1/detection/rules
Create a new detection rule.

**Request Body:**
```json
{
  "name": "New Rule",
  "description": "Rule description",
  "rule_type": "sigma",
  "content": "detection:\n  selection:\n    test: value",
  "severity": "medium",
  "mitre_attack": ["T1059"],
  "tags": ["powershell"]
}
```

#### POST /api/v1/detection/rules/{rule_id}/deploy
Deploy rule to open-source SIEM platform.

**Request Body:**
```json
{
  "rule_id": "uuid",
  "siem_platform": "wazuh",
  "manager_host": "wazuh.example.com"
}
```

**Supported Platforms:** `wazuh`, `elastic`, `opensearch`, `graylog`

---

### Incident Response

#### GET /api/v1/incident-response/incidents
List all security incidents.

**Query Parameters:**
- `status_filter` (optional): Filter by status
- `severity_filter` (optional): Filter by severity

#### POST /api/v1/incident-response/incidents
Create a new incident.

**Request Body:**
```json
{
  "title": "Ransomware Detection",
  "description": "Suspicious file encryption activity detected",
  "severity": "critical",
  "mitre_tactics": ["TA0040"],
  "mitre_techniques": ["T1486"]
}
```

#### POST /api/v1/incident-response/playbooks/execute
Execute an IR playbook.

**Request Body:**
```json
{
  "playbook_name": "ransomware-response",
  "incident_id": "uuid",
  "parameters": {
    "isolate_host": true,
    "notify_security_team": true
  }
}
```

---

### Threat Hunting

#### POST /api/v1/threat-hunting/query
Execute a threat hunting query on open-source SIEM.

**Request Body (Wazuh):**
```json
{
  "name": "Lateral Movement Detection",
  "platform": "wazuh",
  "query": "rule.id:60122 AND data.win.eventdata.logonType:3",
  "time_range": "24h",
  "mitre_tactics": ["TA0008"]
}
```

**Request Body (Elastic/OpenSearch):**
```json
{
  "name": "Lateral Movement Detection",
  "platform": "elastic",
  "query": "event.code:4624 AND winlog.event_data.LogonType:3",
  "time_range": "24h",
  "mitre_tactics": ["TA0008"]
}
```

**Supported Platforms:** `wazuh`, `elastic`, `opensearch`, `graylog`

#### GET /api/v1/threat-hunting/queries
List available threat hunting queries.

---

### Hardening

#### POST /api/v1/hardening/scan
Scan system for hardening compliance.

**Request Body:**
```json
{
  "target": "localhost",
  "os_type": "linux",
  "cis_level": "level_2"
}
```

**Response:**
```json
{
  "target": "localhost",
  "total_checks": 100,
  "passed": 85,
  "failed": 15,
  "compliance_percentage": 85.0,
  "findings": []
}
```

#### POST /api/v1/hardening/apply
Apply hardening configurations.

---

### Forensics

#### POST /api/v1/forensics/analyze
Perform forensics analysis on artifact.

**Request Body:**
```json
{
  "artifact_type": "memory",
  "artifact_path": "/path/to/memory.dump",
  "analysis_modules": ["pslist", "netscan", "malfind"]
}
```

**Response:**
```json
{
  "analysis_id": "uuid",
  "artifact_type": "memory",
  "findings": [],
  "timeline": [],
  "chain_of_custody": []
}
```

---

### Vulnerability Management

#### POST /api/v1/vulnerability/scan
Scan target for vulnerabilities.

**Request Body:**
```json
{
  "target": "192.168.1.0/24",
  "scan_type": "comprehensive",
  "ports": "1-65535"
}
```

**Response:**
```json
{
  "scan_id": "uuid",
  "target": "192.168.1.0/24",
  "vulnerabilities": [],
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 3
  }
}
```

---

### Automation (SOAR)

#### POST /api/v1/automation/playbooks/execute
Execute a SOAR automation playbook.

**Request Body:**
```json
{
  "name": "Phishing Response",
  "description": "Automated phishing email response",
  "trigger_conditions": {},
  "actions": [
    {
      "action_name": "quarantine_email",
      "parameters": {"email_id": "123"}
    }
  ]
}
```

---

### Compliance

#### POST /api/v1/compliance/check
Check compliance against a framework.

**Request Body:**
```json
{
  "framework": "cis",
  "target": "localhost",
  "custom_controls": []
}
```

**Response:**
```json
{
  "framework": "cis",
  "total_controls": 100,
  "passed": 85,
  "failed": 10,
  "not_applicable": 5,
  "compliance_percentage": 85.0,
  "controls": []
}
```

#### GET /api/v1/compliance/frameworks
List supported compliance frameworks.

**Response:**
```json
["cis", "nist_800_53", "iso_27001", "pci_dss", "soc2", "hipaa"]
```

---

### Log Analysis

#### POST /api/v1/log-analysis/analyze
Analyze logs for anomalies.

**Request Body:**
```json
{
  "log_source": "syslog",
  "log_data": "Oct 22 12:00:00 server sshd[1234]: Failed password",
  "analysis_type": "anomaly"
}
```

---

### Monitoring

#### GET /api/v1/monitoring/metrics
Get current system monitoring metrics.

**Response:**
```json
{
  "cpu_usage_percent": 45.2,
  "memory_usage_percent": 67.8,
  "disk_usage_percent": 55.3,
  "network_connections": 127,
  "api_requests_count": 1543,
  "api_errors_count": 12,
  "timestamp": "2025-10-22T12:00:00Z"
}
```

#### POST /api/v1/monitoring/alerts
Create a new monitoring alert.

**Request Body:**
```json
{
  "alert_name": "High CPU Usage",
  "metric": "cpu_usage_percent",
  "threshold": 80.0,
  "condition": "gte",
  "notification_channel": "email",
  "enabled": true
}
```

---

## Error Handling

All errors follow a consistent format:

```json
{
  "status": "error",
  "error": "Error message",
  "detail": "Detailed error information",
  "path": "/api/v1/endpoint",
  "timestamp": "2025-10-22T12:00:00Z"
}
```

### Common HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request (validation error) |
| 401 | Unauthorized (missing/invalid credentials) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not Found |
| 429 | Too Many Requests (rate limit exceeded) |
| 500 | Internal Server Error |

---

## Security Best Practices

### For Production Deployment

1. **Change Default Credentials**
   - Update default user passwords immediately
   - Use strong, randomly generated passwords

2. **Secure SECRET_KEY**
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
   - Store in environment variable or secrets manager
   - Never commit to version control

3. **Enable HTTPS**
   - Use reverse proxy (nginx, Apache) with TLS certificates
   - Enforce HTTPS with HSTS headers (already enabled)

4. **Configure CORS Properly**
   - Set `CORS_ORIGINS` to specific allowed domains
   - Never use `*` in production

5. **Enable Redis for Rate Limiting**
   - For multi-instance deployments
   - Provides distributed rate limiting

6. **Use Strong API Keys**
   - 64+ character random strings
   - Rotate regularly
   - Store securely

7. **Monitor and Log**
   - Enable structured JSON logging
   - Send logs to SIEM
   - Set up alerts for anomalous API usage

8. **Database Integration**
   - Replace in-memory user store with database
   - Implement proper user management
   - Add user roles and permissions

---

## Development

### Running Tests

```bash
# Run all tests
pytest tests/api/

# Run with coverage
pytest tests/api/ --cov=api --cov-report=html

# Run specific test file
pytest tests/api/test_auth.py -v
```

### Code Quality

```bash
# Format code
black api/

# Lint code
ruff check api/

# Type checking
mypy api/

# Security scan
bandit -r api/
```

---

## Postman Collection

A comprehensive Postman collection is available for exploring and testing the API.

### Quick Start

1. **Import Collection**
   ```
   File: postman/Defensive-Toolkit-API.postman_collection.json
   ```

2. **Import Environment**
   - Local Development: `postman/Local-Development.postman_environment.json`
   - Docker: `postman/Docker.postman_environment.json`
   - Production: `postman/Production.postman_environment.json`

3. **Authenticate**
   - Run `Authentication > Login` request
   - Tokens automatically stored and used for all requests

### Collection Features

- **50+ Pre-configured Requests** across 10 API categories
- **Automatic Token Management** - No manual header setup needed
- **Test Scripts** - Validate responses automatically
- **Example Bodies** - All POST requests include example data
- **Environment Variables** - Easy switching between local/docker/production

### Newman CLI Support

Run the collection from command line for CI/CD:

```bash
# Install Newman
npm install -g newman

# Run entire collection
newman run postman/Defensive-Toolkit-API.postman_collection.json \
    --environment postman/Local-Development.postman_environment.json

# Run specific folder
newman run postman/Defensive-Toolkit-API.postman_collection.json \
    --folder "Detection Rules" \
    --environment postman/Docker.postman_environment.json

# Generate HTML report
newman run postman/Defensive-Toolkit-API.postman_collection.json \
    --environment postman/Production.postman_environment.json \
    --reporters cli,html \
    --reporter-html-export newman-report.html
```

**Full Postman Documentation:** [postman/README.md](../postman/README.md)

---

## Code Examples

### Python (requests library)

```python
import requests

base_url = "http://localhost:8000/api/v1"

# Authenticate
def get_access_token(username: str, password: str) -> str:
    response = requests.post(
        f"{base_url}/auth/token",
        data={"username": username, "password": password}
    )
    response.raise_for_status()
    return response.json()["access_token"]

# Create detection rule
def create_detection_rule(token: str, rule_data: dict) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(
        f"{base_url}/detection/rules",
        headers=headers,
        json=rule_data
    )
    response.raise_for_status()
    return response.json()

# Example usage
token = get_access_token("admin", "changeme123")

rule = {
    "name": "Suspicious PowerShell Execution",
    "description": "Detects encoded PowerShell commands",
    "rule_type": "sigma",
    "content": "detection:\n  selection:\n    EventID: 4688\n    CommandLine|contains: '-enc'",
    "severity": "high",
    "mitre_attack": ["T1059.001"],
    "tags": ["powershell", "execution"]
}

result = create_detection_rule(token, rule)
print(f"Created rule: {result['id']}")
```

### JavaScript/TypeScript (fetch)

```javascript
const baseUrl = "http://localhost:8000/api/v1";

// Authenticate
async function getAccessToken(username, password) {
  const response = await fetch(`${baseUrl}/auth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username, password })
  });

  if (!response.ok) throw new Error("Authentication failed");

  const data = await response.json();
  return data.access_token;
}

// List incidents
async function listIncidents(token, severityFilter = null) {
  const params = new URLSearchParams();
  if (severityFilter) params.append("severity_filter", severityFilter);

  const response = await fetch(
    `${baseUrl}/incident-response/incidents?${params}`,
    {
      headers: { "Authorization": `Bearer ${token}` }
    }
  );

  if (!response.ok) throw new Error("Failed to list incidents");

  return await response.json();
}

// Example usage
(async () => {
  const token = await getAccessToken("admin", "changeme123");
  const highSeverityIncidents = await listIncidents(token, "high");
  console.log(`Found ${highSeverityIncidents.length} high-severity incidents`);
})();
```

### Python (httpx async)

```python
import httpx
import asyncio

base_url = "http://localhost:8000/api/v1"

async def main():
    async with httpx.AsyncClient() as client:
        # Authenticate
        auth_response = await client.post(
            f"{base_url}/auth/token",
            data={"username": "admin", "password": "changeme123"}
        )
        token = auth_response.json()["access_token"]

        # Set headers for all requests
        headers = {"Authorization": f"Bearer {token}"}

        # Run vulnerability scan
        scan_response = await client.post(
            f"{base_url}/vulnerability/scan",
            headers=headers,
            json={
                "targets": ["192.168.1.0/24"],
                "scan_type": "full",
                "scanner": "openvas"
            }
        )
        scan_id = scan_response.json()["scan_id"]
        print(f"Started scan: {scan_id}")

        # List vulnerabilities
        vulns_response = await client.get(
            f"{base_url}/vulnerability/list",
            headers=headers,
            params={"severity": "high", "status": "open"}
        )
        vulns = vulns_response.json()
        print(f"Found {len(vulns)} high-severity vulnerabilities")

asyncio.run(main())
```

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
)

const baseURL = "http://localhost:8000/api/v1"

type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
}

type HuntQuery struct {
    Name         string   `json:"name"`
    Platform     string   `json:"platform"`
    Query        string   `json:"query"`
    TimeRange    string   `json:"time_range"`
    MitreTactics []string `json:"mitre_tactics"`
}

func getAccessToken(username, password string) (string, error) {
    data := url.Values{}
    data.Set("username", username)
    data.Set("password", password)

    resp, err := http.PostForm(baseURL+"/auth/token", data)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var tokenResp TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return "", err
    }

    return tokenResp.AccessToken, nil
}

func executeHuntQuery(token string, query HuntQuery) error {
    jsonData, err := json.Marshal(query)
    if err != nil {
        return err
    }

    req, err := http.NewRequest("POST", baseURL+"/threat-hunting/query", bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }

    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    fmt.Printf("Hunt query executed: %s\n", resp.Status)
    return nil
}

func main() {
    token, err := getAccessToken("admin", "changeme123")
    if err != nil {
        panic(err)
    }

    query := HuntQuery{
        Name:         "Lateral Movement Detection",
        Platform:     "wazuh",
        Query:        "rule.id:60122 AND data.win.eventdata.logonType:3",
        TimeRange:    "24h",
        MitreTactics: []string{"TA0008"},
    }

    if err := executeHuntQuery(token, query); err != nil {
        panic(err)
    }
}
```

### cURL (Bash)

```bash
#!/bin/bash
BASE_URL="http://localhost:8000/api/v1"

# Authenticate and save token
TOKEN=$(curl -s -X POST "$BASE_URL/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=changeme123" \
  | jq -r '.access_token')

echo "[+] Authenticated, token: ${TOKEN:0:20}..."

# Create incident
INCIDENT_ID=$(curl -s -X POST "$BASE_URL/incident-response/incidents" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Ransomware Detection",
    "description": "Suspicious file encryption activity",
    "severity": "critical",
    "mitre_tactics": ["TA0040"],
    "mitre_techniques": ["T1486"],
    "affected_hosts": ["WS-001"],
    "iocs": ["sha256:abc123...", "192.168.1.100"]
  }' | jq -r '.id')

echo "[+] Created incident: $INCIDENT_ID"

# Execute playbook
curl -s -X POST "$BASE_URL/incident-response/playbooks/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"playbook_name\": \"ransomware-response\",
    \"incident_id\": \"$INCIDENT_ID\",
    \"parameters\": {
      \"isolate_host\": true,
      \"notify_security_team\": true
    }
  }" | jq '.'

echo "[+] Playbook executed"
```

### PowerShell

```powershell
$BaseUrl = "http://localhost:8000/api/v1"

# Authenticate
$authBody = @{
    username = "admin"
    password = "changeme123"
}

$tokenResponse = Invoke-RestMethod -Method Post `
    -Uri "$BaseUrl/auth/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $authBody

$token = $tokenResponse.access_token
Write-Host "[+] Authenticated successfully"

# Create headers for authenticated requests
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# Run hardening scan
$scanBody = @{
    target = "192.168.1.100"
    scan_type = "full"
    os_type = "windows"
    compliance_frameworks = @("cis", "stig")
} | ConvertTo-Json

$scanResult = Invoke-RestMethod -Method Post `
    -Uri "$BaseUrl/hardening/scan" `
    -Headers $headers `
    -Body $scanBody

Write-Host "[+] Hardening scan started: $($scanResult.scan_id)"

# Check compliance
$complianceBody = @{
    framework = "cis"
    version = "8.0"
    targets = @("192.168.1.100")
    controls = @("1.1", "1.2", "2.1")
} | ConvertTo-Json

$complianceResult = Invoke-RestMethod -Method Post `
    -Uri "$BaseUrl/compliance/check" `
    -Headers $headers `
    -Body $complianceBody

Write-Host "[+] Compliance check complete: $($complianceResult.passed)/$($complianceResult.total) controls passed"
```

---

## Troubleshooting

### Issue: Import Errors

**Solution:** Install all dependencies
```bash
uv pip install -e ".[all]"
```

### Issue: Authentication Fails

**Solution:** Check SECRET_KEY is set
```bash
echo $SECRET_KEY
```

### Issue: Rate Limiting Too Aggressive

**Solution:** Adjust limits in .env
```bash
RATE_LIMIT_DEFAULT=1000/minute
```

### Issue: CORS Errors

**Solution:** Add your origin to CORS_ORIGINS
```bash
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
```

---

## Support

- **Documentation:** https://github.com/Dashtid/defensive-toolkit/tree/main/docs
- **Issues:** https://github.com/Dashtid/defensive-toolkit/issues
- **License:** MIT

---

**Last Updated:** October 22, 2025
**API Version:** 1.4.1
