# Defensive Toolkit - Postman Collection

Complete Postman collection for testing and exploring the Defensive Toolkit REST API.

## Quick Start

### 1. Import Collection

**Option A: Import from File**
```bash
# Open Postman
# Click Import button
# Select file: Defensive-Toolkit-API.postman_collection.json
```

**Option B: Import via URL** (if published)
```
https://github.com/Dashtid/defensive-toolkit/postman/Defensive-Toolkit-API.postman_collection.json
```

### 2. Import Environment

Choose the appropriate environment for your setup:

- **Local-Development.postman_environment.json** - Python development server (http://localhost:8000)
- **Docker.postman_environment.json** - Docker deployment via Nginx (https://localhost)
- **Production.postman_environment.json** - Production deployment (customize baseUrl)

```bash
# In Postman:
# Click "Environments" (top left)
# Click "Import"
# Select environment JSON file
# Select the imported environment from dropdown
```

### 3. Authenticate

```bash
# 1. Open collection folder: Authentication
# 2. Run the "Login" request
# 3. Access and refresh tokens are automatically saved
# 4. All subsequent requests will use these tokens automatically
```

That's it! You can now explore all API endpoints.

## Collection Structure

The collection is organized into 10 functional categories:

| Folder | Description | Example Endpoints |
|--------|-------------|-------------------|
| **Authentication** | JWT token management | Login, Refresh, Logout |
| **Health & Status** | API health monitoring | Health check, Metrics, Version |
| **Detection Rules** | Sigma/YARA/Suricata rules | Create, List, Deploy to SIEM |
| **Incident Response** | Security incident management | Create incident, Execute playbook |
| **Threat Hunting** | Proactive threat queries | Execute hunt, List queries |
| **Hardening** | System security hardening | Scan system, Apply hardening, Check compliance |
| **Monitoring** | Security monitoring & alerts | Get metrics, Create alert rules |
| **Forensics** | Digital forensics analysis | Analyze artifacts, Generate timeline |
| **Vulnerability Management** | Vuln scanning & SBOM | Run scan, List vulns, Generate SBOM |
| **Automation & SOAR** | Security orchestration | Execute workflows, List playbooks |
| **Compliance** | Framework compliance checks | Run compliance check, Generate reports |
| **Log Analysis** | Log parsing & correlation | Parse logs, Detect anomalies, Correlate events |

## Authentication Flow

The collection handles JWT authentication automatically:

1. **Login** - POST to `/auth/token` with username/password
   - Receives `access_token` (valid 15 minutes) and `refresh_token` (valid 30 days)
   - Tokens stored in environment variables automatically

2. **Auto-Refresh** - Pre-request script checks token expiry
   - If access token expired, automatically refreshes using refresh token
   - New tokens stored in environment variables
   - Request continues with fresh token

3. **All Requests** - Inherit bearer token authentication
   - `Authorization: Bearer {{accessToken}}` added automatically
   - No manual token management required

### Manual Token Management

If you need to manually set tokens:

```javascript
// In Postman Environment, set these variables:
accessToken: "your-jwt-access-token"
refreshToken: "your-jwt-refresh-token"
tokenExpiry: 1640000000000  // Unix timestamp in milliseconds
```

## Environment Variables

All environments use these variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `baseUrl` | API base URL | `http://localhost:8000` |
| `apiPrefix` | API version prefix | `/api/v1` |
| `username` | Login username | `admin` |
| `password` | Login password | `changeme123` |
| `accessToken` | JWT access token (auto-set) | Auto-populated after login |
| `refreshToken` | JWT refresh token (auto-set) | Auto-populated after login |
| `tokenExpiry` | Token expiry timestamp (auto-set) | Auto-populated after login |

### Environment-Specific Settings

**Local Development:**
- baseUrl: `http://localhost:8000`
- No SSL certificate required
- Default credentials work out of the box

**Docker:**
- baseUrl: `https://localhost`
- Uses Nginx reverse proxy with SSL
- May need to disable SSL verification in Postman settings (Settings > SSL certificate verification > OFF)

**Production:**
- baseUrl: `https://api.example.com` (customize to your domain)
- username/password: Leave empty, fill in with your credentials
- Enable SSL certificate verification

## Testing Features

### Pre-Request Scripts

The collection includes pre-request scripts for:
- Automatic token refresh on expiry
- Environment variable validation

### Test Scripts

Many requests include test scripts that:
- Validate response status codes
- Verify response structure
- Store tokens automatically
- Check expected values

Example tests in the Login request:
```javascript
pm.test('Status code is 200', () => {
    pm.response.to.have.status(200);
});

pm.test('Response contains tokens', () => {
    const json = pm.response.json();
    pm.expect(json).to.have.property('access_token');
    pm.expect(json).to.have.property('refresh_token');
});
```

## Example Usage Workflows

### Workflow 1: Initial API Exploration

```bash
1. Import collection and Local-Development environment
2. Start local API server: uvicorn api.main:app --reload
3. Run Authentication > Login request
4. Explore Health & Status folder to verify API
5. Try Detection Rules > List Rules
```

### Workflow 2: Incident Response Scenario

```bash
1. Authenticate (Authentication > Login)
2. Create detection rule (Detection Rules > Create Rule)
3. Deploy rule to SIEM (Detection Rules > Deploy Rule to SIEM)
4. Create incident when rule triggers (Incident Response > Create Incident)
5. Execute response playbook (Incident Response > Execute Playbook)
6. Monitor incident status
```

### Workflow 3: Vulnerability Management

```bash
1. Authenticate
2. Run vulnerability scan (Vulnerability Management > Run Vulnerability Scan)
3. List discovered vulnerabilities (List Vulnerabilities)
4. Generate SBOM for affected assets (Generate SBOM)
5. Calculate risk scores (Get Risk Score)
6. Create remediation incident
```

### Workflow 4: Compliance Audit

```bash
1. Authenticate
2. List available frameworks (Compliance > List Frameworks)
3. Run compliance check (Run Compliance Check)
4. Review results
5. Generate compliance report (Get Compliance Report)
6. Apply hardening fixes (Hardening > Apply Hardening)
7. Re-run compliance check to verify
```

## Running Collection with Newman

For CI/CD automation, use Newman (Postman CLI):

```bash
# Install Newman
npm install -g newman

# Run entire collection
newman run Defensive-Toolkit-API.postman_collection.json \
    --environment Local-Development.postman_environment.json

# Run specific folder
newman run Defensive-Toolkit-API.postman_collection.json \
    --folder "Authentication" \
    --environment Local-Development.postman_environment.json

# Run with HTML report
newman run Defensive-Toolkit-API.postman_collection.json \
    --environment Docker.postman_environment.json \
    --reporters cli,html \
    --reporter-html-export newman-report.html

# Run with environment variables from command line
newman run Defensive-Toolkit-API.postman_collection.json \
    --env-var "baseUrl=http://localhost:8000" \
    --env-var "username=admin" \
    --env-var "password=changeme123"
```

### CI/CD Integration Example

**GitHub Actions:**
```yaml
name: API Tests

on: [push, pull_request]

jobs:
  api-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start API server
        run: |
          docker-compose up -d
          sleep 10

      - name: Install Newman
        run: npm install -g newman

      - name: Run API tests
        run: |
          newman run postman/Defensive-Toolkit-API.postman_collection.json \
            --environment postman/Docker.postman_environment.json \
            --reporters cli,junit \
            --reporter-junit-export results.xml

      - name: Publish test results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: results.xml
```

## Troubleshooting

### SSL Certificate Errors (Docker/Production)

**Issue:** "SSL certificate verification failed"

**Solution:**
```bash
# Option 1: Disable SSL verification (development only)
Postman > Settings > SSL certificate verification > OFF

# Option 2: Add CA certificate
Postman > Settings > Certificates > CA Certificates > Add Certificate
```

### Token Expired Errors

**Issue:** 401 Unauthorized responses

**Solution:**
```bash
# 1. Run Authentication > Login request again
# 2. Check token expiry: {{tokenExpiry}} should be future timestamp
# 3. Clear environment variables and re-authenticate
```

### Connection Refused

**Issue:** "Could not send request"

**Solution:**
```bash
# Check baseUrl in environment
# Verify API server is running:
curl http://localhost:8000/health

# For Docker:
docker-compose ps  # Ensure containers are running
```

### Request Timeout

**Issue:** Requests take too long or timeout

**Solution:**
```bash
# Increase timeout in Postman:
Postman > Settings > Request timeout in ms > 30000 (30 seconds)

# Check API server logs:
docker-compose logs -f api
```

### Invalid JSON in Request Body

**Issue:** 400 Bad Request with JSON parse errors

**Solution:**
```bash
# Validate JSON in request body
# Use JSONLint or similar tool
# Ensure Content-Type header is "application/json"
```

## Code Examples

### Python (requests)

```python
import requests

base_url = "http://localhost:8000/api/v1"

# Login
response = requests.post(
    f"{base_url}/auth/token",
    data={"username": "admin", "password": "changeme123"}
)
tokens = response.json()
access_token = tokens["access_token"]

# Make authenticated request
headers = {"Authorization": f"Bearer {access_token}"}
response = requests.get(f"{base_url}/detection/rules", headers=headers)
rules = response.json()
```

### JavaScript (fetch)

```javascript
const baseUrl = "http://localhost:8000/api/v1";

// Login
const loginResponse = await fetch(`${baseUrl}/auth/token`, {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    username: "admin",
    password: "changeme123"
  })
});
const tokens = await loginResponse.json();

// Make authenticated request
const response = await fetch(`${baseUrl}/detection/rules`, {
  headers: { "Authorization": `Bearer ${tokens.access_token}` }
});
const rules = await response.json();
```

### cURL

```bash
# Login
curl -X POST "http://localhost:8000/api/v1/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=changeme123" \
  | jq -r '.access_token' > token.txt

# Make authenticated request
curl -X GET "http://localhost:8000/api/v1/detection/rules" \
  -H "Authorization: Bearer $(cat token.txt)"
```

## API Documentation

For complete API documentation, visit:
- **Interactive Docs:** http://localhost:8000/docs (Swagger UI)
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI Spec:** http://localhost:8000/openapi.json

## Support

- **Issues:** https://github.com/Dashtid/defensive-toolkit/issues
- **Documentation:** [docs/](../docs/)
- **Docker Deployment:** [docs/DOCKER_DEPLOYMENT.md](../docs/DOCKER_DEPLOYMENT.md)
- **API Reference:** [docs/API.md](../docs/API.md)

---

**Version:** 1.4.1
**Last Updated:** 2025-10-22
**Collection Items:** 50+ requests across 10 categories
