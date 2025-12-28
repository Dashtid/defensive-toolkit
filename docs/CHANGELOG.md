# Changelog

All notable changes to the Defensive Toolkit project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.7.0] - 2025-12-28

### Added

#### Complete API Router Wiring (5 routers, ~65 new endpoints)

All stub API routers are now fully wired to their backend implementations:

- **Compliance Router** (`routers/compliance.py` - 32 → 400+ LOC)
  - `POST /compliance/cis/run` - Run CIS Controls v8 checks
  - `POST /compliance/nist/run` - Run NIST 800-53 Rev 5 checks
  - `GET /compliance/mapping/{control_id}` - Map control across frameworks
  - `GET /compliance/mapping/coverage` - Cross-framework coverage matrix
  - `POST /compliance/policy/validate` - Validate against YAML policies
  - `POST /compliance/drift/create-baseline` - Create config baseline
  - `POST /compliance/drift/detect` - Detect configuration drift
  - `POST /compliance/report/generate` - Generate HTML/JSON reports

- **Vulnerability Router** (`routers/vulnerability.py` - 45 → 450+ LOC)
  - `POST /vulnerability/scan/openvas` - Start OpenVAS/GVM scan
  - `GET /vulnerability/scan/{task_id}` - Get scan status/results
  - `POST /vulnerability/scan/container` - Scan Docker images (Trivy)
  - `POST /vulnerability/scan/network` - Run nmap NSE vuln scan
  - `POST /vulnerability/sbom/generate` - Generate CycloneDX/SPDX SBOM
  - `POST /vulnerability/score` - Multi-factor risk scoring
  - `POST /vulnerability/enrich` - CVE threat intel enrichment
  - `GET /vulnerability/kev/{cve_id}` - CISA KEV catalog lookup

- **Log Analysis Router** (`routers/log_analysis.py` - 33 → 250+ LOC)
  - `POST /logs/parse` - Parse log lines (syslog, JSON, Apache, nginx)
  - `POST /logs/parse-file` - Upload and parse log file
  - `GET /logs/parser-info` - Get parser backend status
  - `POST /logs/anomalies/detect` - Statistical anomaly detection
  - `POST /logs/anomalies/create-baseline` - Create baseline statistics
  - `GET /logs/anomalies/baseline/{id}` - Get saved baseline
  - `POST /logs/stats` - Log statistics (counts, patterns)
  - `POST /logs/filter` - Filter parsed logs

- **Forensics Router** (`routers/forensics.py` - 32 → 400+ LOC)
  - `POST /forensics/memory/analyze` - Volatility memory analysis
  - `POST /forensics/memory/hunt` - Malware hunting in memory
  - `GET /forensics/memory/plugins` - List Volatility plugins
  - `POST /forensics/disk/parse-mft` - Parse NTFS MFT file
  - `POST /forensics/disk/carve` - File carving from disk images
  - `POST /forensics/artifacts/browser` - Browser history extraction
  - `POST /forensics/timeline/generate` - Multi-source timeline
  - `POST /forensics/timeline/analyze` - Timeline pattern analysis

- **Automation Router** (`routers/automation.py` - 35 → 350+ LOC)
  - `GET /automation/playbooks` - List available playbooks
  - `POST /automation/playbooks` - Create new playbook
  - `POST /automation/execute` - Execute playbook
  - `GET /automation/execute/{id}/status` - Execution status
  - `GET /automation/execute/{id}/logs` - Execution logs
  - `POST /automation/actions/containment/isolate` - Host isolation
  - `POST /automation/actions/containment/block-ip` - IP blocking
  - `POST /automation/actions/enrichment/ioc` - IOC enrichment
  - `POST /automation/actions/notification/*` - Email, Slack, webhook

#### Linux Hardening Module (New)

Built complete CIS Benchmark scanner from scratch:

- **LinuxHardeningScanner** (`hardening/linux/cis_benchmarks.py` - 450 LOC)
  - 18 CIS Benchmark checks across 5 categories:
    - SSH (5 checks): Protocol version, root login, password auth, empty passwords, max auth tries
    - File Permissions (4 checks): /etc/passwd, /etc/shadow, /etc/gshadow, /etc/group
    - Services (3 checks): Telnet, RSH, TFTP disabled
    - Kernel (4 checks): IP forwarding, ICMP redirects, source routing, SYN cookies
    - Audit (2 checks): auditd installed and enabled
  - CIS Level 1 and Level 2 support
  - Remediation script generation
  - Category-based compliance reporting

- **Hardening Router** (`routers/hardening.py` - 42 → 300+ LOC)
  - `POST /hardening/scan/linux` - Run Linux CIS Benchmark scan
  - `POST /hardening/scan/windows` - Placeholder (not yet implemented)
  - `POST /hardening/scan` - Auto-route by OS type
  - `GET /hardening/scan/{scan_id}` - Get scan results
  - `GET /hardening/scan/{scan_id}/summary` - Compliance summary
  - `GET /hardening/scan/{scan_id}/failed` - Failed checks with severity filter
  - `POST /hardening/remediate/{scan_id}` - Generate remediation script
  - `GET /hardening/benchmarks` - List available benchmarks
  - `GET /hardening/benchmarks/{id}` - Get benchmark details
  - `GET /hardening/recommendations` - Prioritized security recommendations

### Changed

- All routers use lazy-loading pattern with graceful HTTP 503 degradation
- Pinned bcrypt to `>=4.0.0,<5.0.0` for passlib 1.7.4 compatibility
- Added `security` and `performance` pytest markers

### Technical Details

- **New Endpoints**: ~65 across 6 routers
- **Router Code**: ~2,150 new LOC
- **Backend Code**: ~450 new LOC (hardening module)
- **Unit Tests**: 1501 passing, 169 skipped (platform-specific)
- **All Routers Verified**: Load successfully with expected route counts

### Migration Notes

Run `uv sync` or `pip install -e .` to get the compatible bcrypt version.

---

## [1.6.0] - 2025-12-28

### Added

#### OpenTelemetry Integration

- **Telemetry Module** (`src/defensive_toolkit/api/telemetry.py`)
  - Distributed tracing with OTLP exporter support
  - FastAPI auto-instrumentation for HTTP requests
  - HTTPX instrumentation for outbound calls
  - Redis instrumentation (when enabled)
  - Custom tracer helper for manual span creation
  - NoOpTracer fallback when OTEL packages not installed
  - Graceful initialization and shutdown handling

- **Configuration Settings** (added to `config.py`)
  - `OTEL_ENABLED`: Enable/disable OpenTelemetry (default: False)
  - `OTEL_SERVICE_NAME`: Service name in traces (default: "defensive-toolkit")
  - `OTEL_EXPORTER_ENDPOINT`: OTLP endpoint (default: `http://localhost:4317`)
  - `OTEL_TRACE_SAMPLE_RATE`: Sampling rate 0.0-1.0 (default: 1.0)

- **Health Check Integration**
  - Telemetry status in `/health` component list
  - Telemetry status in `/health/ready` readiness check
  - Telemetry logging in startup banner

- **Optional Dependencies** (added to `pyproject.toml`)
  - `opentelemetry-api>=1.20.0`
  - `opentelemetry-sdk>=1.20.0`
  - `opentelemetry-instrumentation-fastapi>=0.41b0`
  - `opentelemetry-instrumentation-httpx>=0.41b0`
  - `opentelemetry-instrumentation-redis>=0.41b0`
  - `opentelemetry-exporter-otlp>=1.20.0`
  - Install with: `pip install defensive-toolkit[otel]`

#### Network Threat Hunting Queries (30 queries)

- **KQL Queries** (`queries/kql/network_threat_hunting.kql` - 10 queries)
  - DNS tunneling detection (high query length)
  - Unusual TXT record queries
  - DNS queries to newly registered domains
  - C2 beaconing detection (periodic communication)
  - Connections to rare external IPs
  - HTTP/HTTPS to non-standard ports
  - SMB enumeration patterns
  - RDP brute force attempts
  - Port scanning behavior
  - Large outbound data transfers

- **SPL Queries** (`queries/spl/network_threat_hunting.spl` - 10 queries)
  - DNS tunneling via query length analysis
  - TXT record abuse detection
  - Newly registered domain queries
  - Periodic beaconing pattern detection
  - Rare destination IP connections
  - Non-standard HTTP ports
  - SMB lateral movement patterns
  - RDP authentication attacks
  - Port scan detection
  - Data exfiltration via large transfers

- **EQL Queries** (`queries/eql/network_threat_hunting.eql` - 20 queries)
  - DNS tunneling (long query names, TXT records)
  - High volume DNS queries
  - Non-standard port connections
  - Periodic network beaconing
  - SMB multi-host connections
  - RDP brute force sequences
  - Port scanning activity
  - Large data transfers
  - Suspicious process network activity
  - DNS queries after process start
  - WMI lateral movement
  - ICMP tunnel detection
  - SSH to external hosts
  - Encrypted channel to rare destinations
  - RPC lateral movement
  - Cloud storage exfiltration
  - Dynamic DNS providers
  - Scheduled task network activity
  - Proxy/tunnel tool detection

#### Identity Threat Hunting Queries (35 queries)

- **KQL Queries** (`queries/kql/identity_threat_hunting.kql` - 15 queries)
  - Password spraying detection
  - Credential stuffing patterns
  - Brute force from single IP
  - Unusual admin group additions
  - Service account abuse
  - Token manipulation detection
  - Kerberoasting (TGS requests)
  - AS-REP roasting detection
  - Suspicious account creation
  - Password reset by non-admin
  - Delegation abuse detection
  - Unusual authentication patterns (time-based)
  - Failed login followed by success
  - MFA fatigue attack detection
  - Impossible travel detection

- **SPL Queries** (`queries/spl/identity_threat_hunting.spl` - 15 queries)
  - Password spraying detection
  - Credential stuffing with success rate analysis
  - Brute force detection
  - Admin group membership changes
  - Service account lateral movement
  - Kerberoasting (RC4 TGS requests)
  - AS-REP roasting detection
  - Golden/Silver ticket detection
  - Suspicious account creation patterns
  - Unauthorized password resets
  - Delegation configuration changes
  - Off-hours authentication
  - Compromise indicator (failed then success)
  - Group Policy privilege escalation
  - Pass-the-Hash detection

- **EQL Queries** (`queries/eql/identity_threat_hunting.eql` - 20 queries)
  - Password spraying sequences
  - Credential stuffing with success
  - Brute force on single account
  - Admin group membership changes
  - Service account interactive logon
  - Kerberoasting activity
  - AS-REP roasting detection
  - Account creation followed by privilege
  - Suspicious account creation
  - Password reset on another user
  - Delegation configuration changes
  - Off-hours authentication
  - Multiple failures then success
  - NTLM from non-DC (Pass-the-Hash)
  - Token manipulation tools
  - Unusual LogonType 9
  - DCSync attack indicators
  - User added to multiple privileged groups
  - Disabled account authentication
  - Security event tampering

#### MITRE ATT&CK Coverage

**Network Techniques:**

- T1071.004: Application Layer Protocol: DNS
- T1571: Non-Standard Port
- T1573: Encrypted Channel
- T1021.001: Remote Services: RDP
- T1021.002: Remote Services: SMB
- T1046: Network Service Discovery
- T1048: Exfiltration Over Alternative Protocol
- T1095: Non-Application Layer Protocol
- T1090: Proxy
- T1567: Exfiltration Over Web Service

**Identity Techniques:**

- T1110: Brute Force (Password Spraying, Credential Stuffing)
- T1078: Valid Accounts
- T1134: Access Token Manipulation
- T1558: Steal or Forge Kerberos Tickets (Kerberoasting, AS-REP, Golden/Silver)
- T1098: Account Manipulation
- T1136: Create Account
- T1550: Use Alternate Authentication Material
- T1621: Multi-Factor Authentication Request Generation
- T1484: Domain Policy Modification
- T1003.006: DCSync

#### Testing

- **Telemetry Tests** (`tests/unit/test_telemetry.py`)
  - Module import tests
  - NoOpTracer and NoOpSpan functionality
  - Setup/shutdown behavior
  - Health check integration
  - Configuration settings validation
  - Main.py integration tests

### Changed

- Added OpenTelemetry to the "all" optional dependencies group
- Startup logging now includes OpenTelemetry status
- Readiness check now includes telemetry component status

### Technical Details

- **New Query Files**: 6 (network + identity × 3 languages)
- **New Queries**: 65 total (30 network + 35 identity)
- **Total Queries After**: ~147 (82 existing + 65 new)
- **New MITRE Techniques**: 20+
- **OpenTelemetry**: Full distributed tracing with OTLP export

---

## [1.5.0] - 2025-12-28

### Added

#### Complete API Implementation

- **Threat Hunting Service** (`src/defensive_toolkit/api/services/threat_hunting.py`)
  - Multi-language query support (KQL, SPL, EQL, Wazuh, Lucene)
  - Query file parser with MITRE ATT&CK technique extraction
  - Automatic query caching with force reload capability
  - Category-based query organization
  - Query execution against SIEM backends
  - Search and filtering (by language, category, text search)
  - Query summary statistics

- **Monitoring Service** (`src/defensive_toolkit/api/services/monitoring.py`)
  - Real system metrics collection via psutil
    - CPU, memory, disk, network, swap usage
    - Process count, network connections
    - Boot time and uptime tracking
  - Alert rule management (CRUD operations)
    - Configurable thresholds and conditions (gt, lt, eq, gte, lte)
    - Severity levels (info, warning, error, critical)
    - Cooldown periods to prevent alert storms
  - Alert triggering and resolution
  - Alert acknowledgement workflow
  - Alert history with severity filtering
  - Notification handler registration
  - Metrics history for trend analysis

#### API Router Enhancements

- **Threat Hunting Router** (expanded from 33 to 200+ lines)
  - `GET /threat-hunting/queries` - List queries with filtering
  - `GET /threat-hunting/queries/{query_id}` - Get specific query
  - `POST /threat-hunting/queries/{query_id}/execute` - Execute against SIEM
  - `GET /threat-hunting/summary` - Query statistics
  - `POST /threat-hunting/reload` - Force reload queries from disk

- **Monitoring Router** (expanded from 44 to 317 lines)
  - `GET /monitoring/metrics` - Current system metrics
  - `GET /monitoring/metrics/detailed` - Extended metrics with memory/disk sizes
  - `GET /monitoring/metrics/history` - Historical metrics for graphing
  - `POST /monitoring/alerts` - Create alert rule
  - `GET /monitoring/alerts` - List all alert rules with status
  - `GET /monitoring/alerts/active` - Currently triggered alerts
  - `POST /monitoring/alerts/{rule_id}/acknowledge` - Acknowledge alert
  - `GET /monitoring/alerts/history` - Alert history with severity filter
  - `PATCH /monitoring/alerts/{rule_id}` - Update alert rule
  - `DELETE /monitoring/alerts/{rule_id}` - Delete alert rule
  - `GET /monitoring/summary` - Monitoring system overview

#### Testing

- **Threat Hunting Service Tests** (`tests/unit/test_services/test_threat_hunting_service.py`)
  - Service initialization tests
  - Query file parsing (KQL, SPL, EQL)
  - Query loading and caching
  - Query retrieval and filtering
  - Query summary functionality
  - Query execution tests

- **Monitoring Service Tests** (`tests/unit/test_services/test_monitoring_service.py`)
  - Service initialization and singleton pattern
  - SystemMetrics serialization
  - Metrics collection and history
  - Alert rule CRUD operations
  - Condition evaluation (all operators)
  - Alert triggering and resolution
  - Alert acknowledgement workflow
  - Alert history filtering
  - Notification handler registration
  - Monitoring summary functionality

### Changed

- Services layer refactored to use dependency injection pattern
- Routers now use real service implementations instead of stubs
- Added psutil as optional dependency for system metrics
- Query files parsed on-demand with caching

### Technical Details

- **MetricType Enum**: cpu_usage_percent, memory_usage_percent, disk_usage_percent, network_connections, network_bytes_sent, network_bytes_recv, process_count, swap_usage_percent, load_average
- **AlertCondition Enum**: gt, lt, eq, gte, lte
- **AlertSeverity Enum**: info, warning, error, critical
- **AlertStatus Enum**: active, acknowledged, resolved
- **QueryLanguage Enum**: KQL, SPL, EQL, WAZUH, LUCENE

---

## [1.4.0] - 2025-12-28

### Added

#### Kubernetes Threat Hunting Queries

- **KQL Queries** (10 queries in `src/defensive_toolkit/threat_hunting/queries/kql/`)
  - Secrets enumeration and mass access detection
  - Privileged pod creation with dangerous capabilities
  - RBAC ClusterRoleBinding escalation to cluster-admin
  - Pod exec/attach command abuse
  - Service account token theft
  - Suspicious container image deployment
  - Kubernetes API reconnaissance patterns
  - ConfigMap manipulation in kube-system
  - Node proxy/exec access attempts
  - Namespace creation with suspicious names

- **SPL Queries** (10 queries in `src/defensive_toolkit/threat_hunting/queries/spl/`)
  - Secrets access from non-system users
  - Privileged pod with host namespace access
  - RBAC modifications with wildcard permissions
  - Pod exec/attach interactive sessions
  - Service account token creation
  - Suspicious image sources (public registries)
  - API server reconnaissance activity
  - ConfigMap modifications in sensitive namespaces
  - Node-level operations (proxy, exec, log)
  - Falco runtime security alert integration

- **EQL Queries** (25 queries in `src/defensive_toolkit/threat_hunting/queries/eql/`)
  - Individual detection queries (17 queries)
  - Sequence correlation queries (3 queries):
    - Secret access followed by pod exec
    - RBAC change followed by privileged pod
    - Reconnaissance followed by sensitive access
  - Covers all major MITRE ATT&CK Container techniques

#### MITRE ATT&CK Container Coverage

- T1552.007: Container API Secrets Access
- T1611: Escape to Host (Privileged Pods, hostPath)
- T1609: Container Administration Command (exec/attach)
- T1078: Valid Accounts (Service Account Abuse)
- T1098: Account Manipulation (RBAC Changes)
- T1613: Container and Resource Discovery
- T1610: Deploy Container (Malicious Images)
- T1562: Impair Defenses (Audit Tampering)

#### Testing

- New `TestKubernetesQueryFilesExist` test class
- `TestKQLQueryContent` - 7 content validation tests
- `TestSPLQueryContent` - 7 content validation tests
- `TestEQLQueryContent` - 7 content validation tests
- `TestMITREATTACKCoverage` - technique reference tests
- `TestQueryCount` - minimum query count validation

### Changed

- Updated threat hunting README with Kubernetes section
- Added SPL to supported platform table
- Expanded directory structure documentation

### Documentation

- Kubernetes threat hunting examples (KQL, SPL, EQL)
- MITRE ATT&CK technique mapping table
- Data source requirements (audit logs, Falco, runtime)
- Platform deployment guides (Azure AKS, Splunk, Elastic)

---

## [1.3.0] - 2025-12-28

### Added

#### Cloud Platform Detection Rules

- **AWS Detection Rules** (5 rules in `rules/sigma/cloud/aws/`)
  - IAM privilege escalation (T1098)
  - CloudTrail logging tampering (T1562.008)
  - S3 bucket public access exposure (T1530)
  - Root account usage detection (T1078.004)
  - Security group opened to internet (T1562.007)

- **Azure Detection Rules** (5 rules in `rules/sigma/cloud/azure/`)
  - MFA disabled for users (T1556.006)
  - Conditional Access policy modifications (T1562.001)
  - Suspicious OAuth app consent grants (T1550.001)
  - Privileged role assignments (T1098.003)
  - Key Vault secret access patterns (T1552.001)

- **GCP Detection Rules** (5 rules in `rules/sigma/cloud/gcp/`)
  - Service account key creation (T1098.001)
  - IAM policy modifications (T1098)
  - VPC firewall rule changes (T1562.007)
  - Cloud Logging sink tampering (T1562.008)
  - Compute instance suspicious activity (T1578)

- **Kubernetes Detection Rules** (5 rules in `rules/sigma/cloud/kubernetes/`)
  - Privileged pod/container creation (T1611)
  - Secrets enumeration and mass access (T1552.007)
  - RBAC ClusterRole/Binding modifications (T1098)
  - Pod exec/attach commands (T1609)
  - Service account token creation (T1078)

#### SIEM Deployment Enhancements

- **Sigma Dry-Run Mode**: Preview rule conversions without deployment
  - SPL query generation with metadata display
  - Conversion statistics and success rate
  - Error reporting for failed conversions

- **OpenSearch Security Analytics API**: Full API implementation
  - Rule creation via `POST /_plugins/_security_analytics/rules`
  - Rule updates with forced overwrite
  - Category auto-detection from logsource
  - Cloud platform tag mapping (AWS -> cloudtrail, Azure -> azure, etc.)
  - Rule listing with category filters

#### Monitoring Improvements

- **Email Alerting for Health Checks**: SMTP-based notifications
  - HTML-formatted alert emails with styled tables
  - SMTP server configuration (host, port, SSL)
  - Credential-based authentication support
  - Fallback to Windows Event Log on send failure
  - Toast notification support (BurntToast)

### Changed

- Total Sigma rules increased from 39 to 59 (20 new cloud rules)
- Test suite updated with `TestCloudPlatformCoverage` class (5 new tests)
- COVERAGE_MATRIX.md updated with cloud platform section
- Minimum Sigma rules test threshold increased to 50

### Documentation

- Updated COVERAGE_MATRIX.md with cloud platform detection tables
- Added API reference links to OpenSearch deployer
- Enhanced PowerShell script documentation with SMTP examples

---

## [1.2.0] - 2025-12-27

### Added

#### CI/CD Security Pipeline

- **Dependency Scanning**: pip-audit integration for Python vulnerability detection
- **Secret Detection**: gitleaks pre-commit scanning to prevent credential leaks
- **SAST Analysis**: Semgrep with OWASP Top 10 and Python security rulesets
- **SBOM Generation**: Syft-based Software Bill of Materials (SPDX, CycloneDX formats)
- **Container Signing**: Cosign keyless signing with OIDC (Sigstore)
- **Release Automation**: Release Please for semantic versioning and changelog generation

#### Kubernetes Deployment

- **Kustomize Manifests**: Production-ready K8s configs (`infra/kubernetes/`)
  - Deployment with security contexts, probes, resource limits
  - ConfigMap and Secret templates
  - HorizontalPodAutoscaler and PodDisruptionBudget
  - NetworkPolicy for traffic control
  - Ingress with TLS support
- **Helm Chart**: Parameterized deployment (`infra/helm/defensive-toolkit/`)
  - 200+ configurable options
  - Templates for all K8s resources
  - Support for Redis, Prometheus metrics, and multi-replica deployments

#### API Enhancements

- **Redis Rate Limiting**: Distributed sliding window algorithm
  - Per-user rate limiting with JWT user extraction
  - Separate buckets for authenticated vs anonymous users
  - Burst multiplier support (configurable)
  - Fallback to in-memory when Redis unavailable
- **Webhook Retry Service**: Robust delivery with exponential backoff
  - Circuit breaker pattern per endpoint (failure threshold, recovery timeout)
  - Dead letter queue for failed deliveries
  - Configurable retry attempts and jitter
- **Custom Prometheus Metrics**: Business-level observability
  - Webhook triggers, delivery duration, signature verification
  - Notification delivery, retries, queue size
  - Circuit breaker state, failures, trips
  - Dead letter queue size, adds, replays
  - Rate limit hits
- **Input Validation**: Security-focused validation utilities
  - URL validation (http/https only, blocks internal networks)
  - Payload size limits (configurable, default 10MB)
  - Path sanitization (directory traversal prevention)
  - Template variable validation
- **Enhanced Health Checks**: Kubernetes-ready probes
  - Component health (API, Redis, webhooks, notifications, rate limiting)
  - System resource checks (memory, disk)
  - `/health/live` liveness probe
  - `/health/ready` readiness probe

#### Testing

- **Webhook Integration Tests**: 500+ lines of comprehensive tests
  - CRUD operations, signature verification
  - Rule matching, rate limiting
  - Error handling, edge cases
- **Webhook Delivery Tests**: Circuit breaker and DLQ coverage
  - Retry logic, backoff verification
  - Circuit breaker state transitions
  - Dead letter queue operations

#### Documentation

- **API Authentication Guide** (`docs/API_AUTHENTICATION.md`)
  - JWT authentication flow
  - API key management
  - RBAC and permissions
  - Integration examples (Python, curl, JavaScript)
- **Updated PROJECT_STATUS.md**: v1.2.0 enhancements section

### Changed

- CI/CD workflow now includes security scanning stages
- Rate limiting middleware supports Redis backend
- Health endpoints return detailed component status
- Webhook router includes metrics recording

### Infrastructure

- Python 3.10+ requirement (updated from 3.8+)
- Redis 5.0+ optional dependency for distributed deployments
- Prometheus client for metrics export
- psutil for system health monitoring

---

## [1.1.0] - 2025-10-18

### Added
- **Comprehensive Test Suite**: 400+ tests across all 10 security categories
  - Unit tests for automation, compliance, forensics, log analysis, vulnerability management
  - Integration tests for SOAR workflows
  - 80%+ code coverage achieved
- **Modern Dependency Management**: uv package manager integration (10-100x faster than pip)
- **CI/CD Pipeline**: GitHub Actions workflows for automated testing
  - Multi-OS testing (Ubuntu, Windows)
  - Multi-version testing (Python 3.10, 3.11, 3.12)
  - Security scanning with Bandit
  - Code quality checks (Ruff, Black, mypy)
- **Utility Scripts**:
  - `scripts/cleanup.py` - Deep project cleanup utility
  - `scripts/validate_project.py` - Project structure validation
  - `scripts/generate_docs.py` - API documentation generator
- **Comprehensive Documentation**:
  - `docs/TESTING.md` - Complete testing guide
  - `docs/ARCHITECTURE.md` - System architecture documentation
  - `docs/DEPLOYMENT.md` - Enterprise deployment guide
  - `docs/API_REFERENCE.md` - Auto-generated API documentation
  - `docs/TROUBLESHOOTING.md` - Troubleshooting guide
  - `docs/CHANGELOG.md` - This file
  - `scripts/README.md` - Utility scripts documentation
- **Test Infrastructure**:
  - 50+ shared fixtures in `conftest.py`
  - Test markers for categorization (unit, integration, slow, platform-specific)
  - Parametrized tests for data variations
  - Performance benchmarks
- **Code Quality Tools**:
  - Bandit for security linting (SAST)
  - Black for code formatting
  - Ruff for fast linting
  - mypy for type checking
  - pytest-cov for coverage reporting

### Changed
- Reorganized project structure with proper `__init__.py` files (31 total)
- Updated main README.md with testing section and uv installation instructions
- Updated CONTRIBUTING.md with test requirements
- Updated .gitignore for uv and testing artifacts
- Modernized pyproject.toml with PEP 621 compliance and tool configurations
- Improved error handling across all modules

### Fixed
- Import path inconsistencies (hyphens vs underscores)
- Module structure for proper Python packaging
- Cross-platform compatibility issues

---

## [1.0.0] - 2025-10-15

### Added
- **Initial Release**: Complete 10-category defensive security toolkit
- **Detection Rules** (6 Sigma rules, 3 YARA rulesets):
  - Execution (T1059): PowerShell, WMI execution
  - Persistence (T1547, T1053): Registry run keys, scheduled tasks
  - Credential Access (T1003): LSASS dumping
  - Defense Evasion (T1070): Event log clearing
  - Webshell detection (PHP, ASPX, JSP, China Chopper)
  - Ransomware detection (WannaCry, generic patterns)
  - Suspicious script detection (PowerShell, VBScript, obfuscation)
- **Incident Response**:
  - 2 comprehensive playbooks (ransomware, malware infection)
  - Windows triage script (PowerShell, 400+ lines)
  - Linux triage script (Bash, 350+ lines)
  - Chain of custody and manifest generation
- **Threat Hunting**:
  - 7 KQL queries (Azure Sentinel/Defender)
  - 10 SPL queries (Splunk lateral movement detection)
  - 20 EQL queries (Elastic Security credential access)
  - PowerShell obfuscation detection
  - Lateral movement hunting
- **Security Hardening**:
  - 9 PowerShell hardening scripts
  - 3 hardening levels (safe, balanced, maximum)
  - Audit, backup, and restore capabilities
  - Coverage: UAC, Defender, Firewall, BitLocker, SMB, policies
- **Monitoring**:
  - SIEM integration (Syslog forwarder, WEF configuration)
  - Log forwarding (Rsyslog, WinRM)
  - Dashboards (Grafana, Splunk templates)
  - Health checks (system, security, performance)
- **Forensics**:
  - Memory analysis with Volatility automation
  - MFT extraction and analysis
  - Artifact collection (browser, Windows, Linux)
  - Timeline generation
  - Master evidence collector
- **Vulnerability Management**:
  - OpenVAS/GVM integration
  - Nmap NSE scripting
  - Trivy container scanning
  - SBOM generation (Syft, CISA 2025 compliant)
  - Multi-factor risk scoring (CVSS, KEV, exploitability, asset criticality)
  - KEV catalog integration (CISA Known Exploited Vulnerabilities)
  - HTML/Markdown/JSON reporting
- **Automation & SOAR**:
  - YAML-based playbook engine (400+ lines)
  - Containment actions (host isolation, IP blocking, file quarantine)
  - Enrichment actions (IOC enrichment, threat intel, geolocation)
  - Notification actions (email, ticketing)
  - SIEM, ticketing, and email integrations
  - 4 example workflows (phishing, malware, vuln remediation, alert enrichment)
- **Compliance**:
  - CIS Controls v8 checker (7 controls, Windows/Linux)
  - NIST 800-53 Rev 5 checker (6 families, 3 impact levels)
  - Multi-framework mapper (CIS, NIST, ISO 27001, PCI-DSS, SOC2)
  - YAML-based policy validation
  - Configuration drift detection (SHA256-based)
  - HTML compliance dashboards
- **Log Analysis**:
  - Universal log parser (Syslog, JSON, Apache, Nginx, Windows Event Log)
  - Auto-format detection
  - Statistical anomaly detection (frequency, pattern, statistical, rate)
  - Baseline management (create from historical data)
  - Text/JSON anomaly reports with severity classification

### Documentation
- Comprehensive README.md with overview and quick start
- PROJECT_STATUS.md with implementation summary
- CONTRIBUTING.md with contribution guidelines
- SECURITY.md with security policy and reporting
- GETTING_STARTED.md with detailed setup instructions
- Category-specific README files (10 categories)
- Example configurations and workflows
- LICENSE (MIT)

### Infrastructure
- Python 3.8+ support
- Multi-platform (Windows, Linux)
- Git repository structure
- requirements.txt for dependencies
- .gitignore for common patterns
- GitHub repository ready for CI/CD

---

## Future Releases

### [1.5.0] - Planned

- Web dashboard for monitoring
- OpenTelemetry tracing integration
- Additional threat hunting query sets (network, identity)

### [2.0.0] - Future

- Full SOAR platform (not just integrations)
- Machine learning anomaly models
- Mobile device forensics
- SaaS offering
- AI-powered threat hunting

---

## Version History

| Version | Date       | Description                                                |
|---------|------------|------------------------------------------------------------|
| 1.7.0   | 2025-12-28 | Wire up all routers, build hardening module (~65 endpoints)|
| 1.6.0   | 2025-12-28 | OpenTelemetry integration, network/identity threat queries |
| 1.5.0   | 2025-12-28 | Complete API implementation (services, monitoring, alerts) |
| 1.4.0   | 2025-12-28 | Kubernetes threat hunting queries (KQL, SPL, EQL)          |
| 1.3.0   | 2025-12-28 | Cloud detection rules, SIEM enhancements, email alerts     |
| 1.2.0   | 2025-12-27 | CI/CD security, Kubernetes/Helm, API enhancements          |
| 1.1.0   | 2025-10-18 | Comprehensive testing, documentation, modernization        |
| 1.0.0   | 2025-10-15 | Initial release with 10 complete categories                |

---

## Contributors

Thank you to all contributors who have helped build the Defensive Toolkit!

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to contribute.

---

## Support

For questions, issues, or feature requests:
- GitHub Issues: https://github.com/yourusername/defensive-toolkit/issues
- Documentation: https://github.com/yourusername/defensive-toolkit/tree/main/docs
- Security Issues: See [SECURITY.md](../SECURITY.md)

---

**Defend Forward. Hunt Threats. Secure Systems.**
