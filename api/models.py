"""
Pydantic Models for Request/Response Validation

All API endpoints use these models for type safety and automatic validation.
Following FastAPI best practices for 2025.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, validator


# ============================================================================
# Authentication Models
# ============================================================================

class Token(BaseModel):
    """JWT token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class TokenData(BaseModel):
    """Data encoded in JWT token"""
    username: Optional[str] = None
    scopes: List[str] = []


class UserLogin(BaseModel):
    """User login credentials"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)


class RefreshTokenRequest(BaseModel):
    """Request to refresh access token"""
    refresh_token: str


# ============================================================================
# Common Response Models
# ============================================================================

class StatusEnum(str, Enum):
    """Operation status"""
    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    IN_PROGRESS = "in_progress"


class APIResponse(BaseModel):
    """Standard API response wrapper"""
    status: StatusEnum
    message: str
    data: Optional[Any] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ErrorResponse(BaseModel):
    """Error response model"""
    status: str = "error"
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str = "healthy"
    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    services: Dict[str, str] = {}


# ============================================================================
# Detection Rules Models
# ============================================================================

class RuleTypeEnum(str, Enum):
    """Detection rule types"""
    SIGMA = "sigma"
    YARA = "yara"
    SNORT = "snort"
    CUSTOM = "custom"


class DetectionRule(BaseModel):
    """Detection rule model"""
    id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    rule_type: RuleTypeEnum
    content: str
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    mitre_attack: List[str] = []
    tags: List[str] = []
    enabled: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class DetectionRuleList(BaseModel):
    """List of detection rules"""
    rules: List[DetectionRule]
    total: int


class DeployRuleRequest(BaseModel):
    """Request to deploy rule to open-source SIEM"""
    rule_id: str
    siem_platform: str = Field(..., pattern="^(wazuh|elastic|opensearch|graylog)$")
    workspace_id: Optional[str] = None


# ============================================================================
# Incident Response Models
# ============================================================================

class SeverityEnum(str, Enum):
    """Incident severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatusEnum(str, Enum):
    """Incident status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class Incident(BaseModel):
    """Incident model"""
    id: Optional[str] = None
    title: str = Field(..., min_length=1, max_length=200)
    description: str
    severity: SeverityEnum
    status: IncidentStatusEnum = IncidentStatusEnum.NEW
    assigned_to: Optional[str] = None
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None


class PlaybookExecutionRequest(BaseModel):
    """Request to execute IR playbook"""
    playbook_name: str
    incident_id: Optional[str] = None
    parameters: Dict[str, Any] = {}


class PlaybookExecutionResponse(BaseModel):
    """Playbook execution result"""
    execution_id: str
    playbook_name: str
    status: StatusEnum
    steps_completed: int
    steps_total: int
    start_time: datetime
    end_time: Optional[datetime] = None
    results: Dict[str, Any] = {}


# ============================================================================
# Threat Hunting Models
# ============================================================================

class SIEMPlatformEnum(str, Enum):
    """Supported open-source SIEM platforms"""
    WAZUH = "wazuh"
    ELASTIC = "elastic"
    OPENSEARCH = "opensearch"
    GRAYLOG = "graylog"


class ThreatHuntQuery(BaseModel):
    """Threat hunting query"""
    name: str
    description: Optional[str] = None
    platform: SIEMPlatformEnum
    query: str
    time_range: str = "24h"
    mitre_tactics: List[str] = []


class ThreatHuntResult(BaseModel):
    """Threat hunting query result"""
    query_name: str
    platform: str
    results_count: int
    results: List[Dict[str, Any]]
    execution_time_ms: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Hardening Models
# ============================================================================

class OSTypeEnum(str, Enum):
    """Operating system types"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class CISLevelEnum(str, Enum):
    """CIS Benchmark levels"""
    LEVEL_1 = "level_1"
    LEVEL_2 = "level_2"
    LEVEL_3 = "level_3"


class HardeningProfile(BaseModel):
    """Security hardening profile"""
    os_type: OSTypeEnum
    cis_level: CISLevelEnum
    custom_rules: List[str] = []


class HardeningScanRequest(BaseModel):
    """Request to scan system for hardening compliance"""
    target: str = "localhost"
    os_type: OSTypeEnum
    cis_level: CISLevelEnum


class HardeningResult(BaseModel):
    """Hardening scan result"""
    target: str
    os_type: str
    cis_level: str
    total_checks: int
    passed: int
    failed: int
    compliance_percentage: float
    findings: List[Dict[str, Any]]
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Vulnerability Management Models
# ============================================================================

class VulnerabilityScanRequest(BaseModel):
    """Request to scan for vulnerabilities"""
    target: str = Field(..., description="IP, hostname, or CIDR range")
    scan_type: str = Field(..., pattern="^(quick|full|comprehensive)$")
    ports: Optional[str] = None  # e.g., "80,443,8080" or "1-65535"


class VulnerabilitySeverityEnum(str, Enum):
    """Vulnerability severity levels (CVSS)"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Vulnerability(BaseModel):
    """Vulnerability finding"""
    cve_id: Optional[str] = None
    title: str
    description: str
    severity: VulnerabilitySeverityEnum
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    affected_component: str
    remediation: Optional[str] = None


class VulnerabilityScanResult(BaseModel):
    """Vulnerability scan results"""
    scan_id: str
    target: str
    scan_type: str
    start_time: datetime
    end_time: datetime
    vulnerabilities: List[Vulnerability]
    summary: Dict[str, int]  # {"critical": 2, "high": 5, ...}


# ============================================================================
# Forensics Models
# ============================================================================

class ForensicsArtifactTypeEnum(str, Enum):
    """Forensics artifact types"""
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    REGISTRY = "registry"
    FILE_SYSTEM = "file_system"
    BROWSER = "browser"
    EVENT_LOG = "event_log"


class ForensicsAnalysisRequest(BaseModel):
    """Request for forensics analysis"""
    artifact_type: ForensicsArtifactTypeEnum
    artifact_path: str
    analysis_modules: List[str] = []


class ForensicsAnalysisResult(BaseModel):
    """Forensics analysis result"""
    analysis_id: str
    artifact_type: str
    artifact_path: str
    findings: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    chain_of_custody: List[Dict[str, str]]
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Automation (SOAR) Models
# ============================================================================

class AutomationAction(BaseModel):
    """SOAR automation action"""
    action_name: str
    parameters: Dict[str, Any]
    timeout_seconds: int = 300


class AutomationPlaybook(BaseModel):
    """SOAR playbook definition"""
    name: str
    description: Optional[str] = None
    trigger_conditions: Dict[str, Any]
    actions: List[AutomationAction]
    notification_channels: List[str] = []


class AutomationExecutionStatus(BaseModel):
    """Automation execution status"""
    execution_id: str
    playbook_name: str
    status: StatusEnum
    started_at: datetime
    completed_at: Optional[datetime] = None
    actions_completed: int
    actions_total: int
    results: Dict[str, Any] = {}


# ============================================================================
# Compliance Models
# ============================================================================

class ComplianceFrameworkEnum(str, Enum):
    """Supported compliance frameworks"""
    CIS = "cis"
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    HIPAA = "hipaa"


class ComplianceCheckRequest(BaseModel):
    """Request for compliance check"""
    framework: ComplianceFrameworkEnum
    target: str = "localhost"
    custom_controls: List[str] = []


class ComplianceControl(BaseModel):
    """Individual compliance control"""
    control_id: str
    title: str
    description: str
    status: str  # "pass", "fail", "not_applicable"
    evidence: Optional[str] = None


class ComplianceReport(BaseModel):
    """Compliance assessment report"""
    framework: str
    target: str
    total_controls: int
    passed: int
    failed: int
    not_applicable: int
    compliance_percentage: float
    controls: List[ComplianceControl]
    assessment_date: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Log Analysis Models
# ============================================================================

class LogSourceEnum(str, Enum):
    """Log source types"""
    SYSLOG = "syslog"
    WINDOWS_EVENT = "windows_event"
    APACHE = "apache"
    NGINX = "nginx"
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    APPLICATION = "application"


class LogAnalysisRequest(BaseModel):
    """Request for log analysis"""
    log_source: LogSourceEnum
    log_data: str  # Raw log data or file path
    analysis_type: str = Field(..., pattern="^(parse|anomaly|baseline)$")


class LogEntry(BaseModel):
    """Parsed log entry"""
    timestamp: datetime
    source: str
    severity: str
    message: str
    fields: Dict[str, Any]


class LogAnalysisResult(BaseModel):
    """Log analysis result"""
    analysis_id: str
    log_source: str
    analysis_type: str
    entries_processed: int
    anomalies_detected: int
    parsed_entries: List[LogEntry]
    anomalies: List[Dict[str, Any]]
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Monitoring Models
# ============================================================================

class MonitoringMetrics(BaseModel):
    """System monitoring metrics"""
    cpu_usage_percent: float
    memory_usage_percent: float
    disk_usage_percent: float
    network_connections: int
    api_requests_count: int
    api_errors_count: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AlertConfiguration(BaseModel):
    """Monitoring alert configuration"""
    alert_name: str
    metric: str
    threshold: float
    condition: str = Field(..., pattern="^(gt|lt|eq|gte|lte)$")
    notification_channel: str
    enabled: bool = True


# ============================================================================
# Runbook Models (v1.7.1)
# ============================================================================

class RunbookExecutionModeEnum(str, Enum):
    """Runbook execution modes"""
    NORMAL = "normal"       # Interactive with approval prompts
    DRY_RUN = "dry_run"     # Simulate without executing
    AUTO_APPROVE = "auto"   # Auto-approve based on severity level


class RunbookStepStatusEnum(str, Enum):
    """Individual step execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    AWAITING_APPROVAL = "awaiting_approval"


class RunbookSummary(BaseModel):
    """Summary of available runbook"""
    id: str
    name: str
    description: str
    version: str
    author: Optional[str] = None
    severity: str
    estimated_duration: Optional[str] = None
    mitre_attack: List[str] = []
    steps_count: int
    file_path: str
    created: Optional[str] = None
    updated: Optional[str] = None


class RunbookDetail(BaseModel):
    """Detailed runbook information including steps"""
    id: str
    name: str
    description: str
    version: str
    author: Optional[str] = None
    metadata: Dict[str, Any] = {}
    variables: Dict[str, Any] = {}
    steps: List[Dict[str, Any]]
    file_path: str


class RunbookListResponse(BaseModel):
    """List of available runbooks"""
    runbooks: List[RunbookSummary]
    total: int


class RunbookExecuteRequest(BaseModel):
    """Request to execute a runbook"""
    runbook_id: str = Field(..., description="Runbook identifier (filename without extension)")
    incident_id: Optional[str] = Field(None, description="Link to existing incident")
    mode: RunbookExecutionModeEnum = RunbookExecutionModeEnum.DRY_RUN
    auto_approve_level: Optional[str] = Field(
        None,
        pattern="^(low|medium|high)$",
        description="Auto-approve actions up to this severity level"
    )
    variables: Dict[str, Any] = Field(
        default_factory=dict,
        description="Runtime variables to pass to the runbook"
    )
    target_host: str = Field("localhost", description="Target host for containment actions")


class RunbookStepResult(BaseModel):
    """Result of a single runbook step"""
    step_name: str
    action: str
    status: RunbookStepStatusEnum
    severity: str
    message: Optional[str] = None
    data: Dict[str, Any] = {}
    executed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None


class RunbookExecutionStatus(BaseModel):
    """Current status of runbook execution"""
    execution_id: str
    runbook_name: str
    runbook_version: str
    incident_id: str
    status: StatusEnum
    mode: RunbookExecutionModeEnum
    started_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    current_step: int
    total_steps: int
    steps_completed: int
    steps_failed: int
    steps_skipped: int
    steps_awaiting: int
    step_results: List[RunbookStepResult] = []
    variables: Dict[str, Any] = {}
    analyst: str
    target_host: str


class RunbookExecutionResponse(BaseModel):
    """Response after initiating runbook execution"""
    execution_id: str
    incident_id: str
    runbook_name: str
    status: StatusEnum
    message: str
    monitor_url: str


class PendingApproval(BaseModel):
    """Pending approval request for high-severity action"""
    approval_id: str
    execution_id: str
    step_name: str
    action: str
    severity: str
    description: str
    parameters: Dict[str, Any]
    requested_at: datetime
    expires_at: Optional[datetime] = None


class ApprovalDecision(BaseModel):
    """Analyst decision on pending approval"""
    approved: bool
    reason: Optional[str] = None


class EvidenceItem(BaseModel):
    """Evidence item in chain of custody"""
    evidence_id: str
    incident_id: str
    evidence_type: str
    source: str
    description: str
    collected_at: datetime
    collected_by: str
    hostname: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    sha256: Optional[str] = None


class EvidenceChainResponse(BaseModel):
    """Chain of custody for collected evidence"""
    incident_id: str
    created_at: datetime
    evidence_count: int
    evidence: List[EvidenceItem]


class RollbackRequest(BaseModel):
    """Request to rollback executed actions"""
    execution_id: str
    confirm: bool = Field(..., description="Must be true to confirm rollback")


# ============================================================================
# Webhook Models (v1.7.2)
# ============================================================================

class WebhookSourceEnum(str, Enum):
    """Supported webhook sources"""
    WAZUH = "wazuh"
    ELASTIC = "elastic"
    OPENSEARCH = "opensearch"
    GRAYLOG = "graylog"
    GENERIC = "generic"
    CUSTOM = "custom"


class WebhookStatusEnum(str, Enum):
    """Webhook configuration status"""
    ACTIVE = "active"
    DISABLED = "disabled"
    TESTING = "testing"


class AlertSeverityMapping(BaseModel):
    """Maps alert severity to runbook execution mode"""
    alert_severity: str = Field(..., description="Source alert severity (e.g., 'critical', 'high', '15')")
    runbook_mode: RunbookExecutionModeEnum = Field(
        default=RunbookExecutionModeEnum.DRY_RUN,
        description="Execution mode for this severity"
    )
    auto_approve_level: Optional[str] = Field(
        None,
        pattern="^(low|medium|high)$",
        description="Auto-approve level when mode is 'auto'"
    )


class WebhookTriggerRule(BaseModel):
    """Rule for mapping alerts to runbooks"""
    rule_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    enabled: bool = True

    # Matching conditions (all must match)
    match_field: str = Field(..., description="Alert field to match (e.g., 'rule.id', 'alert.signature')")
    match_pattern: str = Field(..., description="Regex pattern or exact value to match")
    match_type: str = Field("regex", pattern="^(regex|exact|contains)$")

    # Optional additional conditions
    severity_min: Optional[str] = Field(None, description="Minimum severity to trigger")
    severity_max: Optional[str] = Field(None, description="Maximum severity to trigger")

    # Action
    runbook_id: str = Field(..., description="Runbook to execute when matched")
    execution_mode: RunbookExecutionModeEnum = RunbookExecutionModeEnum.DRY_RUN
    auto_approve_level: Optional[str] = Field(None, pattern="^(low|medium|high)$")

    # Variable mapping from alert to runbook
    variable_mappings: Dict[str, str] = Field(
        default_factory=dict,
        description="Map alert fields to runbook variables (e.g., {'compromised_user': 'data.user'})"
    )

    # Rate limiting
    cooldown_seconds: int = Field(300, ge=0, description="Minimum seconds between triggers for same rule")
    max_triggers_per_hour: int = Field(10, ge=1, le=100, description="Maximum triggers per hour")


class WebhookConfig(BaseModel):
    """Webhook endpoint configuration"""
    webhook_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    source: WebhookSourceEnum
    status: WebhookStatusEnum = WebhookStatusEnum.ACTIVE

    # Security
    secret_key: Optional[str] = Field(None, description="HMAC secret for signature verification")
    allowed_ips: List[str] = Field(default_factory=list, description="Allowed source IPs (empty = all)")

    # Alert parsing
    alert_id_field: str = Field("id", description="JSON path to alert ID")
    alert_severity_field: str = Field("severity", description="JSON path to severity")
    alert_title_field: str = Field("title", description="JSON path to alert title")
    alert_description_field: str = Field("description", description="JSON path to description")
    alert_timestamp_field: str = Field("timestamp", description="JSON path to timestamp")

    # Trigger rules
    trigger_rules: List[WebhookTriggerRule] = Field(default_factory=list)

    # Default behavior when no rules match
    default_runbook_id: Optional[str] = Field(None, description="Default runbook if no rules match")
    default_execution_mode: RunbookExecutionModeEnum = RunbookExecutionModeEnum.DRY_RUN

    # Metadata
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None


class WebhookConfigList(BaseModel):
    """List of webhook configurations"""
    webhooks: List[WebhookConfig]
    total: int


class IncomingAlert(BaseModel):
    """Parsed incoming alert from webhook"""
    alert_id: str
    source: WebhookSourceEnum
    severity: str
    title: str
    description: Optional[str] = None
    timestamp: datetime
    raw_payload: Dict[str, Any]
    matched_rule: Optional[str] = None
    source_ip: Optional[str] = None


class WebhookTriggerResult(BaseModel):
    """Result of webhook trigger processing"""
    webhook_id: str
    alert_id: str
    received_at: datetime
    processed: bool
    matched_rule: Optional[str] = None
    execution_id: Optional[str] = None
    incident_id: Optional[str] = None
    runbook_triggered: Optional[str] = None
    execution_mode: Optional[str] = None
    message: str
    skipped_reason: Optional[str] = None


class WebhookTestRequest(BaseModel):
    """Request to test webhook configuration"""
    webhook_id: str
    test_payload: Dict[str, Any] = Field(..., description="Sample alert payload to test")


class WebhookTestResult(BaseModel):
    """Result of webhook configuration test"""
    webhook_id: str
    test_passed: bool
    parsed_alert: Optional[IncomingAlert] = None
    matched_rules: List[str] = []
    would_trigger_runbook: Optional[str] = None
    would_use_mode: Optional[str] = None
    errors: List[str] = []
    warnings: List[str] = []


class WebhookStats(BaseModel):
    """Statistics for a webhook endpoint"""
    webhook_id: str
    webhook_name: str
    total_received: int
    total_processed: int
    total_triggered: int
    total_skipped: int
    total_errors: int
    last_received_at: Optional[datetime] = None
    last_triggered_at: Optional[datetime] = None
    triggers_last_hour: int
    triggers_last_24h: int
    top_triggered_rules: List[Dict[str, Any]] = []


# ============================================================================
# Threat Intelligence Models (v1.7.3)
# ============================================================================

class IOCTypeEnum(str, Enum):
    """Types of Indicators of Compromise"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"


class ThreatIntelSourceEnum(str, Enum):
    """Supported threat intelligence sources"""
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    ALIENVAULT_OTX = "alienvault_otx"
    MISP = "misp"
    GREYNOISE = "greynoise"
    SHODAN = "shodan"
    URLSCAN = "urlscan"
    HYBRID_ANALYSIS = "hybrid_analysis"
    INTERNAL = "internal"


class ThreatCategoryEnum(str, Enum):
    """Threat categories for IOCs"""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    C2 = "command_and_control"
    RANSOMWARE = "ransomware"
    SPAM = "spam"
    SCANNER = "scanner"
    BRUTE_FORCE = "brute_force"
    EXPLOIT = "exploit"
    APT = "apt"
    CRYPTOCURRENCY = "cryptocurrency"
    UNKNOWN = "unknown"
    CLEAN = "clean"


class ReputationScoreEnum(str, Enum):
    """IOC reputation classification"""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NEUTRAL = "neutral"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class IOCEnrichmentRequest(BaseModel):
    """Request to enrich one or more IOCs"""
    iocs: List[str] = Field(..., min_items=1, max_items=100, description="List of IOCs to enrich")
    ioc_type: Optional[IOCTypeEnum] = Field(None, description="IOC type (auto-detected if not specified)")
    sources: List[ThreatIntelSourceEnum] = Field(
        default_factory=lambda: [ThreatIntelSourceEnum.VIRUSTOTAL, ThreatIntelSourceEnum.ABUSEIPDB],
        description="Intelligence sources to query"
    )
    include_whois: bool = Field(False, description="Include WHOIS data for domains/IPs")
    include_passive_dns: bool = Field(False, description="Include passive DNS records")
    include_related_samples: bool = Field(False, description="Include related malware samples")


class SourceResult(BaseModel):
    """Result from a single intelligence source"""
    source: ThreatIntelSourceEnum
    queried_at: datetime
    success: bool
    error_message: Optional[str] = None

    # Reputation data
    reputation: Optional[ReputationScoreEnum] = None
    confidence: Optional[int] = Field(None, ge=0, le=100, description="Confidence score 0-100")
    risk_score: Optional[int] = Field(None, ge=0, le=100, description="Risk score 0-100")

    # Detection counts (for VT-style sources)
    malicious_count: Optional[int] = None
    suspicious_count: Optional[int] = None
    clean_count: Optional[int] = None
    total_engines: Optional[int] = None

    # Categorization
    categories: List[ThreatCategoryEnum] = []
    tags: List[str] = []

    # Additional context
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    report_count: Optional[int] = None

    # Raw response (truncated for large responses)
    raw_data: Optional[Dict[str, Any]] = None


class WhoisData(BaseModel):
    """WHOIS registration data"""
    registrar: Optional[str] = None
    registrant: Optional[str] = None
    registrant_country: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    name_servers: List[str] = []
    status: List[str] = []
    raw_text: Optional[str] = None


class PassiveDNSRecord(BaseModel):
    """Passive DNS record"""
    record_type: str = Field(..., description="A, AAAA, CNAME, MX, etc.")
    value: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source: Optional[str] = None


class RelatedSample(BaseModel):
    """Related malware sample"""
    sha256: str
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    detection_ratio: Optional[str] = None
    first_seen: Optional[datetime] = None
    relationship_type: str = Field(..., description="communicates_with, downloaded_from, etc.")


class GeoIPData(BaseModel):
    """Geographic IP data"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None


class IOCEnrichmentResult(BaseModel):
    """Enrichment result for a single IOC"""
    ioc: str
    ioc_type: IOCTypeEnum
    enriched_at: datetime

    # Aggregated verdict
    overall_reputation: ReputationScoreEnum
    overall_risk_score: int = Field(..., ge=0, le=100)
    confidence: int = Field(..., ge=0, le=100)

    # Aggregated categories
    threat_categories: List[ThreatCategoryEnum] = []
    tags: List[str] = []

    # Source-specific results
    source_results: List[SourceResult] = []

    # Optional enrichments
    whois: Optional[WhoisData] = None
    geoip: Optional[GeoIPData] = None
    passive_dns: List[PassiveDNSRecord] = []
    related_samples: List[RelatedSample] = []

    # Associated threat intel
    mitre_techniques: List[str] = []
    threat_actors: List[str] = []
    campaigns: List[str] = []

    # Recommendations
    recommended_actions: List[str] = []
    block_recommended: bool = False


class BulkEnrichmentResponse(BaseModel):
    """Response for bulk IOC enrichment"""
    request_id: str
    total_iocs: int
    enriched_count: int
    failed_count: int
    results: List[IOCEnrichmentResult]
    processing_time_ms: int
    sources_queried: List[ThreatIntelSourceEnum]


class ThreatIntelSourceConfig(BaseModel):
    """Configuration for a threat intelligence source"""
    source: ThreatIntelSourceEnum
    enabled: bool = True
    api_key_configured: bool = False
    base_url: Optional[str] = None
    rate_limit_per_minute: int = 4
    rate_limit_per_day: int = 500
    priority: int = Field(1, ge=1, le=10, description="Query priority (lower = higher priority)")
    timeout_seconds: int = 30


class ThreatIntelSourceStatus(BaseModel):
    """Status of a threat intelligence source"""
    source: ThreatIntelSourceEnum
    enabled: bool
    api_key_configured: bool
    last_query_at: Optional[datetime] = None
    queries_today: int = 0
    queries_remaining: int = 0
    rate_limited: bool = False
    last_error: Optional[str] = None
    average_response_ms: Optional[int] = None


class ThreatIntelFeed(BaseModel):
    """Threat intelligence feed configuration"""
    feed_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    source: ThreatIntelSourceEnum
    feed_url: Optional[str] = None

    # Feed type and format
    feed_type: str = Field("iocs", pattern="^(iocs|stix|misp|csv|json)$")
    ioc_types: List[IOCTypeEnum] = []

    # Sync settings
    enabled: bool = True
    sync_interval_minutes: int = Field(60, ge=5, le=1440)
    last_sync_at: Optional[datetime] = None
    next_sync_at: Optional[datetime] = None

    # Statistics
    total_indicators: int = 0
    new_indicators_last_sync: int = 0

    # Metadata
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ThreatIntelFeedList(BaseModel):
    """List of threat intelligence feeds"""
    feeds: List[ThreatIntelFeed]
    total: int


class IOCSearchRequest(BaseModel):
    """Search for IOCs in local threat intel database"""
    query: str = Field(..., min_length=1, description="Search query (IOC value or partial match)")
    ioc_types: List[IOCTypeEnum] = Field(default_factory=list, description="Filter by IOC types")
    categories: List[ThreatCategoryEnum] = Field(default_factory=list, description="Filter by categories")
    min_risk_score: Optional[int] = Field(None, ge=0, le=100)
    max_age_days: Optional[int] = Field(None, ge=1, description="Maximum age of IOC data")
    sources: List[ThreatIntelSourceEnum] = Field(default_factory=list, description="Filter by sources")
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


class IOCSearchResult(BaseModel):
    """Local IOC search result"""
    ioc: str
    ioc_type: IOCTypeEnum
    reputation: ReputationScoreEnum
    risk_score: int
    categories: List[ThreatCategoryEnum]
    sources: List[ThreatIntelSourceEnum]
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = []


class IOCSearchResponse(BaseModel):
    """Response for IOC search"""
    query: str
    total_matches: int
    results: List[IOCSearchResult]
    search_time_ms: int


class ThreatIntelStats(BaseModel):
    """Threat intelligence system statistics"""
    total_iocs_cached: int
    iocs_by_type: Dict[str, int]
    iocs_by_category: Dict[str, int]
    iocs_by_reputation: Dict[str, int]
    sources_status: List[ThreatIntelSourceStatus]
    cache_hit_rate: float = Field(..., ge=0, le=1)
    queries_last_hour: int
    queries_last_24h: int
    average_enrichment_time_ms: int


# ============================================================================
# WebSocket Real-Time Updates Models (v1.7.4)
# ============================================================================

class WebSocketEventTypeEnum(str, Enum):
    """Types of real-time events"""
    # Connection events
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    AUTHENTICATED = "authenticated"
    AUTHENTICATION_FAILED = "authentication_failed"
    HEARTBEAT = "heartbeat"

    # Runbook execution events
    RUNBOOK_STARTED = "runbook_started"
    RUNBOOK_STEP_STARTED = "runbook_step_started"
    RUNBOOK_STEP_COMPLETED = "runbook_step_completed"
    RUNBOOK_STEP_FAILED = "runbook_step_failed"
    RUNBOOK_STEP_SKIPPED = "runbook_step_skipped"
    RUNBOOK_AWAITING_APPROVAL = "runbook_awaiting_approval"
    RUNBOOK_COMPLETED = "runbook_completed"
    RUNBOOK_FAILED = "runbook_failed"
    RUNBOOK_PROGRESS = "runbook_progress"

    # Incident events
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_ESCALATED = "incident_escalated"
    INCIDENT_CLOSED = "incident_closed"
    INCIDENT_COMMENT = "incident_comment"

    # Webhook/Alert events
    ALERT_RECEIVED = "alert_received"
    ALERT_PROCESSED = "alert_processed"
    ALERT_TRIGGERED_RUNBOOK = "alert_triggered_runbook"

    # Threat intel events
    IOC_ENRICHMENT_STARTED = "ioc_enrichment_started"
    IOC_ENRICHMENT_COMPLETED = "ioc_enrichment_completed"
    IOC_HIGH_RISK_DETECTED = "ioc_high_risk_detected"

    # System events
    SYSTEM_ALERT = "system_alert"
    ERROR = "error"


class WebSocketChannelEnum(str, Enum):
    """Subscription channels for events"""
    ALL = "all"                          # All events
    RUNBOOKS = "runbooks"                # Runbook execution events
    INCIDENTS = "incidents"              # Incident updates
    ALERTS = "alerts"                    # Webhook/alert events
    THREAT_INTEL = "threat_intel"        # IOC enrichment events
    SYSTEM = "system"                    # System alerts and errors
    EXECUTION = "execution"              # Specific execution ID (requires param)


class WebSocketMessage(BaseModel):
    """Base WebSocket message format"""
    event_type: WebSocketEventTypeEnum
    channel: WebSocketChannelEnum
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    data: Dict[str, Any] = {}


class WebSocketAuthRequest(BaseModel):
    """Authentication request for WebSocket connection"""
    token: str = Field(..., description="JWT access token or API key")
    subscribe_channels: List[WebSocketChannelEnum] = Field(
        default_factory=lambda: [WebSocketChannelEnum.ALL],
        description="Channels to subscribe to"
    )
    subscribe_executions: List[str] = Field(
        default_factory=list,
        description="Specific execution IDs to monitor"
    )
    subscribe_incidents: List[str] = Field(
        default_factory=list,
        description="Specific incident IDs to monitor"
    )


class WebSocketAuthResponse(BaseModel):
    """Authentication response"""
    success: bool
    message: str
    user: Optional[str] = None
    subscribed_channels: List[WebSocketChannelEnum] = []
    connection_id: Optional[str] = None
    expires_at: Optional[datetime] = None


class WebSocketSubscribeRequest(BaseModel):
    """Request to modify subscriptions"""
    action: str = Field(..., pattern="^(subscribe|unsubscribe)$")
    channels: List[WebSocketChannelEnum] = []
    execution_ids: List[str] = []
    incident_ids: List[str] = []


class WebSocketSubscribeResponse(BaseModel):
    """Subscription modification response"""
    success: bool
    message: str
    current_subscriptions: Dict[str, List[str]] = {}


class WebSocketHeartbeat(BaseModel):
    """Heartbeat message for connection keep-alive"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    sequence: int
    connection_uptime_seconds: int


class WebSocketConnectionInfo(BaseModel):
    """Information about a WebSocket connection"""
    connection_id: str
    user: str
    connected_at: datetime
    last_activity: datetime
    subscribed_channels: List[WebSocketChannelEnum]
    subscribed_executions: List[str]
    subscribed_incidents: List[str]
    messages_sent: int
    messages_received: int
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None


class WebSocketConnectionStats(BaseModel):
    """Statistics for WebSocket connections"""
    active_connections: int
    total_connections_today: int
    total_messages_sent: int
    total_messages_received: int
    connections_by_channel: Dict[str, int] = {}
    average_connection_duration_seconds: float
    peak_connections_today: int
    last_activity_at: Optional[datetime] = None


class RunbookProgressEvent(BaseModel):
    """Real-time progress update for runbook execution"""
    execution_id: str
    runbook_name: str
    incident_id: str
    current_step: int
    total_steps: int
    steps_completed: int
    steps_failed: int
    steps_skipped: int
    steps_awaiting: int
    percentage_complete: float = Field(..., ge=0, le=100)
    current_step_name: Optional[str] = None
    current_step_action: Optional[str] = None
    status: StatusEnum
    estimated_remaining_seconds: Optional[int] = None


class RunbookStepEvent(BaseModel):
    """Event for individual runbook step status change"""
    execution_id: str
    runbook_name: str
    incident_id: str
    step_index: int
    step_name: str
    action: str
    severity: str
    status: RunbookStepStatusEnum
    message: Optional[str] = None
    data: Dict[str, Any] = {}
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None


class ApprovalRequestEvent(BaseModel):
    """Event when a runbook step requires approval"""
    execution_id: str
    runbook_name: str
    incident_id: str
    approval_id: str
    step_name: str
    action: str
    severity: str
    description: str
    parameters: Dict[str, Any] = {}
    requested_by: str
    requested_at: datetime
    expires_at: Optional[datetime] = None


class IncidentEvent(BaseModel):
    """Event for incident status changes"""
    incident_id: str
    title: str
    previous_status: Optional[IncidentStatusEnum] = None
    current_status: IncidentStatusEnum
    severity: SeverityEnum
    assigned_to: Optional[str] = None
    updated_by: str
    update_type: str  # created, status_change, assigned, escalated, comment, closed
    comment: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AlertEvent(BaseModel):
    """Event for incoming alerts from webhooks"""
    webhook_id: str
    webhook_name: str
    alert_id: str
    source: WebhookSourceEnum
    severity: str
    title: str
    received_at: datetime
    processed: bool
    triggered_runbook: Optional[str] = None
    execution_id: Optional[str] = None
    incident_id: Optional[str] = None


class IOCEnrichmentEvent(BaseModel):
    """Event for IOC enrichment progress"""
    request_id: str
    ioc: str
    ioc_type: IOCTypeEnum
    status: str  # started, source_completed, completed, failed
    sources_queried: List[ThreatIntelSourceEnum] = []
    sources_completed: int = 0
    total_sources: int = 0
    overall_reputation: Optional[ReputationScoreEnum] = None
    risk_score: Optional[int] = None
    high_risk_detected: bool = False
    completed_at: Optional[datetime] = None
    processing_time_ms: Optional[int] = None


class SystemAlertEvent(BaseModel):
    """System-level alert event"""
    alert_type: str  # rate_limit_warning, api_error, connection_limit, etc.
    severity: str  # info, warning, error, critical
    title: str
    description: str
    affected_component: Optional[str] = None
    metadata: Dict[str, Any] = {}


# ============================================================================
# SIEM Integration Models (v1.7.5)
# ============================================================================

class SIEMPlatformTypeEnum(str, Enum):
    """Supported SIEM platform types"""
    WAZUH = "wazuh"
    ELASTIC = "elastic"
    OPENSEARCH = "opensearch"
    GRAYLOG = "graylog"
    SPLUNK = "splunk"


class SIEMConnectionStatusEnum(str, Enum):
    """SIEM connection status"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"
    UNAUTHORIZED = "unauthorized"


class SIEMAuthTypeEnum(str, Enum):
    """SIEM authentication types"""
    BASIC = "basic"
    API_KEY = "api_key"
    TOKEN = "token"
    CERTIFICATE = "certificate"


class SIEMConnectionConfig(BaseModel):
    """Configuration for connecting to a SIEM platform"""
    connection_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    platform: SIEMPlatformTypeEnum
    enabled: bool = True

    # Connection settings
    host: str = Field(..., description="SIEM host URL (e.g., https://wazuh.example.com)")
    port: int = Field(443, ge=1, le=65535)
    use_ssl: bool = True
    verify_ssl: bool = True

    # Authentication
    auth_type: SIEMAuthTypeEnum = SIEMAuthTypeEnum.BASIC
    username: Optional[str] = None
    password: Optional[str] = None  # Will be stored encrypted in production
    api_key: Optional[str] = None
    token: Optional[str] = None
    certificate_path: Optional[str] = None

    # Platform-specific settings
    index_pattern: str = Field("wazuh-alerts-*", description="Index pattern for alerts")
    api_version: Optional[str] = None

    # Connection pool settings
    timeout_seconds: int = Field(30, ge=5, le=300)
    max_retries: int = Field(3, ge=0, le=10)
    pool_connections: int = Field(10, ge=1, le=100)

    # Metadata
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_connected_at: Optional[datetime] = None
    created_by: Optional[str] = None


class SIEMConnectionConfigList(BaseModel):
    """List of SIEM connections"""
    connections: List[SIEMConnectionConfig]
    total: int


class SIEMConnectionStatus(BaseModel):
    """Current status of a SIEM connection"""
    connection_id: str
    name: str
    platform: SIEMPlatformTypeEnum
    status: SIEMConnectionStatusEnum
    last_check: datetime
    latency_ms: Optional[int] = None
    version: Optional[str] = None
    cluster_name: Optional[str] = None
    node_count: Optional[int] = None
    index_count: Optional[int] = None
    document_count: Optional[int] = None
    error_message: Optional[str] = None


class SIEMQueryRequest(BaseModel):
    """Request to query SIEM for alerts/events"""
    connection_id: str = Field(..., description="SIEM connection to query")
    query: Optional[str] = Field(None, description="Query string (Lucene/KQL syntax)")
    query_dsl: Optional[Dict[str, Any]] = Field(None, description="Full DSL query object")

    # Time range
    time_from: datetime = Field(..., description="Start time for query")
    time_to: Optional[datetime] = Field(None, description="End time (defaults to now)")
    time_field: str = Field("timestamp", description="Field name for time filtering")

    # Filters
    severity_min: Optional[str] = None
    rule_ids: List[str] = Field(default_factory=list)
    agent_ids: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)

    # Pagination
    size: int = Field(100, ge=1, le=10000)
    from_offset: int = Field(0, ge=0)

    # Sorting
    sort_field: str = Field("timestamp", description="Field to sort by")
    sort_order: str = Field("desc", pattern="^(asc|desc)$")

    # Response options
    include_raw: bool = Field(False, description="Include raw SIEM response")
    fields: List[str] = Field(default_factory=list, description="Specific fields to return")


class SIEMAlert(BaseModel):
    """Normalized alert from SIEM"""
    alert_id: str
    timestamp: datetime
    platform: SIEMPlatformTypeEnum

    # Alert details
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    rule_description: Optional[str] = None
    rule_level: Optional[int] = None
    rule_groups: List[str] = []

    # Severity mapping
    severity: str  # low, medium, high, critical
    severity_score: Optional[float] = None

    # Source information
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    agent_ip: Optional[str] = None
    manager_name: Optional[str] = None

    # Event details
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None

    # User context
    user: Optional[str] = None
    src_user: Optional[str] = None
    dst_user: Optional[str] = None

    # File/process context
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None

    # MITRE ATT&CK
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    mitre_ids: List[str] = []

    # Additional data
    full_log: Optional[str] = None
    decoder_name: Optional[str] = None
    location: Optional[str] = None
    data: Dict[str, Any] = {}

    # Raw response
    raw: Optional[Dict[str, Any]] = None


class SIEMQueryResponse(BaseModel):
    """Response from SIEM query"""
    connection_id: str
    platform: SIEMPlatformTypeEnum
    query_time_ms: int
    total_hits: int
    returned_count: int
    alerts: List[SIEMAlert]
    aggregations: Optional[Dict[str, Any]] = None
    raw_response: Optional[Dict[str, Any]] = None


class SIEMAggregationRequest(BaseModel):
    """Request for SIEM aggregation query"""
    connection_id: str
    time_from: datetime
    time_to: Optional[datetime] = None
    time_field: str = "timestamp"

    # Aggregation type
    aggregation_type: str = Field(
        ...,
        pattern="^(terms|date_histogram|histogram|stats|cardinality|top_hits)$"
    )
    field: str = Field(..., description="Field to aggregate on")

    # Options
    size: int = Field(10, ge=1, le=1000, description="Number of buckets")
    interval: Optional[str] = Field(None, description="Interval for date_histogram (1h, 1d, etc.)")
    min_doc_count: int = Field(1, ge=0)

    # Filters
    query: Optional[str] = None
    filters: Dict[str, Any] = {}


class SIEMAggregationBucket(BaseModel):
    """Single aggregation bucket"""
    key: Any
    key_as_string: Optional[str] = None
    doc_count: int
    sub_aggregations: Optional[Dict[str, Any]] = None


class SIEMAggregationResponse(BaseModel):
    """Response from SIEM aggregation"""
    connection_id: str
    platform: SIEMPlatformTypeEnum
    query_time_ms: int
    aggregation_type: str
    field: str
    total_docs: int
    buckets: List[SIEMAggregationBucket]


class SIEMAgentInfo(BaseModel):
    """Information about a SIEM agent"""
    agent_id: str
    name: str
    ip: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_platform: Optional[str] = None
    version: Optional[str] = None
    status: str  # active, disconnected, never_connected, pending
    last_keep_alive: Optional[datetime] = None
    date_add: Optional[datetime] = None
    group: List[str] = []
    manager: Optional[str] = None
    node_name: Optional[str] = None


class SIEMAgentListResponse(BaseModel):
    """List of SIEM agents"""
    connection_id: str
    platform: SIEMPlatformTypeEnum
    total_agents: int
    agents: List[SIEMAgentInfo]
    affected_items: int
    failed_items: int


class SIEMRuleInfo(BaseModel):
    """Information about a SIEM detection rule"""
    rule_id: str
    level: int
    description: str
    groups: List[str] = []
    pci_dss: List[str] = []
    gpg13: List[str] = []
    gdpr: List[str] = []
    hipaa: List[str] = []
    nist_800_53: List[str] = []
    tsc: List[str] = []
    mitre: Dict[str, List[str]] = {}
    file: Optional[str] = None
    path: Optional[str] = None
    relative_dirname: Optional[str] = None
    status: str = "enabled"


class SIEMRuleListResponse(BaseModel):
    """List of SIEM rules"""
    connection_id: str
    platform: SIEMPlatformTypeEnum
    total_rules: int
    rules: List[SIEMRuleInfo]


class SIEMIndexInfo(BaseModel):
    """Information about a SIEM index"""
    index_name: str
    status: str  # open, closed
    health: str  # green, yellow, red
    doc_count: int
    store_size_bytes: int
    store_size_human: str
    primary_shards: int
    replica_shards: int
    creation_date: Optional[datetime] = None


class SIEMIndexListResponse(BaseModel):
    """List of SIEM indices"""
    connection_id: str
    platform: SIEMPlatformTypeEnum
    total_indices: int
    indices: List[SIEMIndexInfo]
    total_docs: int
    total_size_bytes: int
    total_size_human: str


class SIEMDashboardStats(BaseModel):
    """Dashboard statistics from SIEM"""
    connection_id: str
    platform: SIEMPlatformTypeEnum
    time_range_hours: int
    generated_at: datetime

    # Alert statistics
    total_alerts: int
    alerts_by_severity: Dict[str, int]
    alerts_by_hour: List[Dict[str, Any]]

    # Top items
    top_rules: List[Dict[str, Any]]
    top_agents: List[Dict[str, Any]]
    top_source_ips: List[Dict[str, Any]]
    top_mitre_tactics: List[Dict[str, Any]]
    top_mitre_techniques: List[Dict[str, Any]]

    # Agent statistics
    total_agents: int
    active_agents: int
    disconnected_agents: int

    # System health
    cluster_status: Optional[str] = None
    index_health: Optional[str] = None


class SIEMHealthCheck(BaseModel):
    """SIEM platform health check result"""
    connection_id: str
    name: str
    platform: SIEMPlatformTypeEnum
    healthy: bool
    checks: Dict[str, bool] = {}  # connectivity, authentication, indices, etc.
    latency_ms: int
    version: Optional[str] = None
    cluster_health: Optional[str] = None
    error_message: Optional[str] = None
    checked_at: datetime


class SIEMBulkHealthCheck(BaseModel):
    """Bulk health check for all SIEM connections"""
    total_connections: int
    healthy_count: int
    unhealthy_count: int
    results: List[SIEMHealthCheck]
    checked_at: datetime


class SIEMAlertAcknowledge(BaseModel):
    """Request to acknowledge alerts in SIEM"""
    connection_id: str
    alert_ids: List[str] = Field(..., min_items=1, max_items=100)
    acknowledged_by: str
    comment: Optional[str] = None


class SIEMAlertAcknowledgeResponse(BaseModel):
    """Response from alert acknowledgment"""
    connection_id: str
    acknowledged_count: int
    failed_count: int
    failed_ids: List[str] = []
    error_message: Optional[str] = None


# ============================================================================
# Scheduled Tasks/Jobs Models (v1.7.6)
# ============================================================================

class ScheduledJobTypeEnum(str, Enum):
    """Types of scheduled jobs"""
    # Security scans
    VULNERABILITY_SCAN = "vulnerability_scan"
    COMPLIANCE_CHECK = "compliance_check"
    HARDENING_AUDIT = "hardening_audit"

    # SIEM operations
    SIEM_HEALTH_CHECK = "siem_health_check"
    SIEM_ALERT_DIGEST = "siem_alert_digest"
    SIEM_AGENT_STATUS = "siem_agent_status"

    # Threat intelligence
    IOC_ENRICHMENT = "ioc_enrichment"
    THREAT_FEED_UPDATE = "threat_feed_update"

    # Reporting
    SECURITY_REPORT = "security_report"
    INCIDENT_SUMMARY = "incident_summary"
    METRICS_EXPORT = "metrics_export"

    # Maintenance
    LOG_CLEANUP = "log_cleanup"
    CACHE_CLEANUP = "cache_cleanup"
    BACKUP = "backup"

    # Runbooks
    RUNBOOK_EXECUTION = "runbook_execution"

    # Custom
    WEBHOOK_CALL = "webhook_call"
    CUSTOM_SCRIPT = "custom_script"


class ScheduledJobStatusEnum(str, Enum):
    """Status of a scheduled job"""
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"
    EXPIRED = "expired"


class JobExecutionStatusEnum(str, Enum):
    """Status of a job execution"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class ScheduleTypeEnum(str, Enum):
    """Type of schedule"""
    CRON = "cron"
    INTERVAL = "interval"
    ONCE = "once"
    MANUAL = "manual"


class JobPriorityEnum(str, Enum):
    """Job execution priority"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class ScheduledJobConfig(BaseModel):
    """Configuration for a scheduled job"""
    job_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    job_type: ScheduledJobTypeEnum
    status: ScheduledJobStatusEnum = ScheduledJobStatusEnum.ACTIVE
    priority: JobPriorityEnum = JobPriorityEnum.NORMAL

    # Schedule configuration
    schedule_type: ScheduleTypeEnum = ScheduleTypeEnum.CRON
    cron_expression: Optional[str] = Field(
        None,
        description="Cron expression (e.g., '0 */6 * * *' for every 6 hours)"
    )
    interval_seconds: Optional[int] = Field(
        None,
        ge=60,
        description="Interval in seconds (minimum 60)"
    )
    run_at: Optional[datetime] = Field(
        None,
        description="Specific datetime for one-time execution"
    )
    timezone: str = Field("UTC", description="Timezone for schedule")

    # Execution settings
    timeout_seconds: int = Field(3600, ge=60, le=86400)
    max_retries: int = Field(3, ge=0, le=10)
    retry_delay_seconds: int = Field(300, ge=60, le=3600)
    concurrent_allowed: bool = Field(
        False,
        description="Allow concurrent executions of this job"
    )

    # Job-specific parameters
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Job-type specific parameters"
    )

    # Notification settings
    notify_on_success: bool = False
    notify_on_failure: bool = True
    notification_channels: List[str] = Field(
        default_factory=list,
        description="Notification channels (email, slack, webhook)"
    )
    notification_emails: List[str] = Field(default_factory=list)

    # Validity period
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None

    # Metadata
    tags: List[str] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None


class ScheduledJobCreateRequest(BaseModel):
    """Request to create a scheduled job"""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    job_type: ScheduledJobTypeEnum
    priority: JobPriorityEnum = JobPriorityEnum.NORMAL

    # Schedule
    schedule_type: ScheduleTypeEnum = ScheduleTypeEnum.CRON
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    run_at: Optional[datetime] = None
    timezone: str = "UTC"

    # Execution settings
    timeout_seconds: int = 3600
    max_retries: int = 3
    retry_delay_seconds: int = 300
    concurrent_allowed: bool = False

    # Parameters
    parameters: Dict[str, Any] = {}

    # Notifications
    notify_on_success: bool = False
    notify_on_failure: bool = True
    notification_channels: List[str] = []
    notification_emails: List[str] = []

    # Validity
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    tags: List[str] = []


class ScheduledJobUpdateRequest(BaseModel):
    """Request to update a scheduled job"""
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[ScheduledJobStatusEnum] = None
    priority: Optional[JobPriorityEnum] = None

    # Schedule updates
    cron_expression: Optional[str] = None
    interval_seconds: Optional[int] = None
    run_at: Optional[datetime] = None
    timezone: Optional[str] = None

    # Execution settings
    timeout_seconds: Optional[int] = None
    max_retries: Optional[int] = None
    retry_delay_seconds: Optional[int] = None
    concurrent_allowed: Optional[bool] = None

    # Parameters
    parameters: Optional[Dict[str, Any]] = None

    # Notifications
    notify_on_success: Optional[bool] = None
    notify_on_failure: Optional[bool] = None
    notification_channels: Optional[List[str]] = None
    notification_emails: Optional[List[str]] = None

    # Validity
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    tags: Optional[List[str]] = None


class ScheduledJobResponse(BaseModel):
    """Response for a scheduled job"""
    job_id: str
    name: str
    description: Optional[str]
    job_type: ScheduledJobTypeEnum
    status: ScheduledJobStatusEnum
    priority: JobPriorityEnum
    schedule_type: ScheduleTypeEnum
    cron_expression: Optional[str]
    interval_seconds: Optional[int]
    timezone: str
    next_run_at: Optional[datetime]
    last_run_at: Optional[datetime]
    last_run_status: Optional[JobExecutionStatusEnum]
    total_runs: int
    successful_runs: int
    failed_runs: int
    created_at: datetime
    updated_at: Optional[datetime]
    created_by: Optional[str]


class ScheduledJobListResponse(BaseModel):
    """List of scheduled jobs"""
    jobs: List[ScheduledJobResponse]
    total: int
    active_count: int
    paused_count: int
    disabled_count: int


class JobExecution(BaseModel):
    """Record of a job execution"""
    execution_id: str
    job_id: str
    job_name: str
    job_type: ScheduledJobTypeEnum
    status: JobExecutionStatusEnum
    priority: JobPriorityEnum

    # Timing
    scheduled_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Execution details
    attempt_number: int = 1
    triggered_by: str = "scheduler"  # scheduler, manual, api, webhook
    parameters: Dict[str, Any] = {}

    # Results
    result: Optional[Dict[str, Any]] = None
    output: Optional[str] = None
    error_message: Optional[str] = None
    error_traceback: Optional[str] = None

    # Metrics
    items_processed: Optional[int] = None
    items_succeeded: Optional[int] = None
    items_failed: Optional[int] = None


class JobExecutionListResponse(BaseModel):
    """List of job executions"""
    executions: List[JobExecution]
    total: int
    running_count: int
    pending_count: int


class JobExecutionRequest(BaseModel):
    """Request to manually trigger a job"""
    job_id: str
    parameters: Optional[Dict[str, Any]] = None
    priority: Optional[JobPriorityEnum] = None
    skip_queue: bool = Field(
        False,
        description="Execute immediately, bypassing the queue"
    )


class JobExecutionResponse(BaseModel):
    """Response from triggering a job"""
    execution_id: str
    job_id: str
    job_name: str
    status: JobExecutionStatusEnum
    scheduled_at: datetime
    message: str


class JobCancelRequest(BaseModel):
    """Request to cancel a running job"""
    execution_id: str
    reason: Optional[str] = None


class JobCancelResponse(BaseModel):
    """Response from cancelling a job"""
    execution_id: str
    cancelled: bool
    message: str
    previous_status: JobExecutionStatusEnum


class SchedulerStats(BaseModel):
    """Scheduler system statistics"""
    scheduler_status: str  # running, paused, stopped
    uptime_seconds: int
    jobs_total: int
    jobs_active: int
    jobs_paused: int
    jobs_disabled: int

    # Execution stats
    executions_today: int
    executions_this_hour: int
    successful_today: int
    failed_today: int
    cancelled_today: int

    # Queue stats
    queue_length: int
    running_jobs: int
    pending_jobs: int

    # Performance
    average_execution_time_seconds: float
    average_wait_time_seconds: float
    jobs_per_hour: float

    # By job type
    executions_by_type: Dict[str, int]
    failures_by_type: Dict[str, int]

    # Recent activity
    last_execution_at: Optional[datetime] = None
    next_scheduled_job: Optional[str] = None
    next_scheduled_at: Optional[datetime] = None


class SchedulerHealthCheck(BaseModel):
    """Health check for scheduler"""
    healthy: bool
    status: str
    checks: Dict[str, bool]
    message: Optional[str] = None
    last_heartbeat: datetime
    worker_count: int
    queue_healthy: bool
    storage_healthy: bool


class CronValidationRequest(BaseModel):
    """Request to validate a cron expression"""
    cron_expression: str
    timezone: str = "UTC"
    count: int = Field(5, ge=1, le=20, description="Number of next runs to show")


class CronValidationResponse(BaseModel):
    """Response from cron validation"""
    valid: bool
    expression: str
    description: str
    timezone: str
    next_runs: List[datetime]
    error: Optional[str] = None


class JobTypeInfo(BaseModel):
    """Information about a job type"""
    job_type: ScheduledJobTypeEnum
    name: str
    description: str
    category: str
    required_parameters: List[str]
    optional_parameters: List[str]
    parameter_schema: Dict[str, Any]
    default_timeout_seconds: int
    supports_concurrent: bool
    example_parameters: Dict[str, Any]


class JobTypeListResponse(BaseModel):
    """List of available job types"""
    job_types: List[JobTypeInfo]
    categories: List[str]


class BulkJobActionRequest(BaseModel):
    """Request for bulk job actions"""
    job_ids: List[str] = Field(..., min_items=1, max_items=100)
    action: str = Field(..., pattern="^(pause|resume|disable|delete)$")


class BulkJobActionResponse(BaseModel):
    """Response from bulk job action"""
    action: str
    total_requested: int
    succeeded: int
    failed: int
    results: List[Dict[str, Any]]


class JobNotificationConfig(BaseModel):
    """Notification configuration for jobs"""
    job_id: str
    notify_on_success: bool = False
    notify_on_failure: bool = True
    notify_on_timeout: bool = True
    notification_channels: List[str] = []
    email_recipients: List[str] = []
    slack_channels: List[str] = []
    webhook_urls: List[str] = []
    include_output: bool = False
    include_error_details: bool = True


class JobDependency(BaseModel):
    """Dependency between jobs"""
    job_id: str
    depends_on_job_id: str
    dependency_type: str = Field(
        "completion",
        pattern="^(completion|success|failure)$"
    )
    wait_timeout_seconds: int = Field(3600, ge=60)


class JobDependencyResponse(BaseModel):
    """Response for job dependencies"""
    job_id: str
    dependencies: List[JobDependency]
    dependents: List[str]  # Jobs that depend on this job


# ============================================================================
# Notification Hub Models (v1.7.7)
# ============================================================================

class NotificationChannelTypeEnum(str, Enum):
    """Types of notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    SMS = "sms"
    DISCORD = "discord"
    OPSGENIE = "opsgenie"
    VICTOROPS = "victorops"
    CUSTOM = "custom"


class NotificationPriorityEnum(str, Enum):
    """Priority levels for notifications"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"


class NotificationStatusEnum(str, Enum):
    """Status of notification delivery"""
    PENDING = "pending"
    QUEUED = "queued"
    SENDING = "sending"
    DELIVERED = "delivered"
    FAILED = "failed"
    PARTIAL = "partial"  # Some channels succeeded, others failed
    RETRYING = "retrying"
    EXPIRED = "expired"


class NotificationCategoryEnum(str, Enum):
    """Categories of notifications for routing and filtering"""
    SECURITY_ALERT = "security_alert"
    INCIDENT = "incident"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    SYSTEM_HEALTH = "system_health"
    JOB_STATUS = "job_status"
    THREAT_INTEL = "threat_intel"
    AUDIT = "audit"
    MAINTENANCE = "maintenance"
    CUSTOM = "custom"


class ChannelStatusEnum(str, Enum):
    """Status of notification channels"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    MAINTENANCE = "maintenance"


# --- Channel Configuration Models ---

class EmailChannelConfig(BaseModel):
    """Configuration for email notification channel"""
    smtp_host: str
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_username: str
    smtp_password: str = Field(..., min_length=1)
    use_tls: bool = True
    use_ssl: bool = False
    from_address: str
    from_name: Optional[str] = "Defensive Toolkit"
    reply_to: Optional[str] = None
    default_recipients: List[str] = []


class SlackChannelConfig(BaseModel):
    """Configuration for Slack notification channel"""
    webhook_url: Optional[str] = None
    bot_token: Optional[str] = None
    app_token: Optional[str] = None
    default_channel: Optional[str] = None
    username: str = "Defensive Toolkit"
    icon_emoji: Optional[str] = ":shield:"
    icon_url: Optional[str] = None


class TeamsChannelConfig(BaseModel):
    """Configuration for Microsoft Teams notification channel"""
    webhook_url: str
    default_title: str = "Defensive Toolkit Notification"
    theme_color: str = "0076D7"


class PagerDutyChannelConfig(BaseModel):
    """Configuration for PagerDuty notification channel"""
    api_key: str
    routing_key: str
    service_id: Optional[str] = None
    default_severity: str = Field("warning", pattern="^(critical|error|warning|info)$")
    include_details: bool = True


class WebhookChannelConfig(BaseModel):
    """Configuration for generic webhook notification channel"""
    url: str
    method: str = Field("POST", pattern="^(GET|POST|PUT|PATCH)$")
    headers: Dict[str, str] = {}
    auth_type: Optional[str] = Field(None, pattern="^(none|basic|bearer|api_key)$")
    auth_credentials: Optional[Dict[str, str]] = None
    timeout_seconds: int = Field(30, ge=5, le=120)
    retry_count: int = Field(3, ge=0, le=10)
    verify_ssl: bool = True


class SMSChannelConfig(BaseModel):
    """Configuration for SMS notification channel"""
    provider: str = Field(..., pattern="^(twilio|nexmo|aws_sns|custom)$")
    api_key: str
    api_secret: Optional[str] = None
    from_number: str
    default_recipients: List[str] = []


class DiscordChannelConfig(BaseModel):
    """Configuration for Discord notification channel"""
    webhook_url: str
    username: str = "Defensive Toolkit"
    avatar_url: Optional[str] = None


class OpsGenieChannelConfig(BaseModel):
    """Configuration for OpsGenie notification channel"""
    api_key: str
    team_id: Optional[str] = None
    responders: List[Dict[str, str]] = []
    priority: str = Field("P3", pattern="^(P1|P2|P3|P4|P5)$")


class VictorOpsChannelConfig(BaseModel):
    """Configuration for VictorOps/Splunk On-Call notification channel"""
    api_key: str
    routing_key: str
    entity_id_prefix: str = "defensive-toolkit"


# --- Notification Channel Models ---

class NotificationChannelBase(BaseModel):
    """Base model for notification channels"""
    name: str = Field(..., min_length=1, max_length=100)
    channel_type: NotificationChannelTypeEnum
    description: Optional[str] = None
    enabled: bool = True
    categories: List[NotificationCategoryEnum] = []
    priority_threshold: NotificationPriorityEnum = NotificationPriorityEnum.LOW
    rate_limit_per_minute: int = Field(60, ge=1, le=1000)
    rate_limit_per_hour: int = Field(500, ge=1, le=10000)
    config: Dict[str, Any] = {}


class NotificationChannelCreate(NotificationChannelBase):
    """Request to create a notification channel"""
    pass


class NotificationChannelUpdate(BaseModel):
    """Request to update a notification channel"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    enabled: Optional[bool] = None
    categories: Optional[List[NotificationCategoryEnum]] = None
    priority_threshold: Optional[NotificationPriorityEnum] = None
    rate_limit_per_minute: Optional[int] = Field(None, ge=1, le=1000)
    rate_limit_per_hour: Optional[int] = Field(None, ge=1, le=10000)
    config: Optional[Dict[str, Any]] = None


class NotificationChannel(NotificationChannelBase):
    """Full notification channel model"""
    id: str
    status: ChannelStatusEnum = ChannelStatusEnum.ACTIVE
    created_at: datetime
    updated_at: datetime
    last_used: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    last_error: Optional[str] = None
    last_error_at: Optional[datetime] = None


class NotificationChannelResponse(BaseModel):
    """Response for notification channel operations"""
    status: StatusEnum
    message: str
    channel: Optional[NotificationChannel] = None


class NotificationChannelListResponse(BaseModel):
    """Response for listing notification channels"""
    channels: List[NotificationChannel]
    total: int
    by_type: Dict[str, int]
    by_status: Dict[str, int]


# --- Message Template Models ---

class TemplateVariableInfo(BaseModel):
    """Information about a template variable"""
    name: str
    description: str
    type: str = "string"
    required: bool = False
    default: Optional[Any] = None
    example: Optional[Any] = None


class NotificationTemplateBase(BaseModel):
    """Base model for notification templates"""
    name: str = Field(..., min_length=1, max_length=100)
    category: NotificationCategoryEnum
    description: Optional[str] = None
    subject_template: Optional[str] = None  # For email, used as title for others
    body_template: str = Field(..., min_length=1)
    html_template: Optional[str] = None  # HTML version for email
    variables: List[TemplateVariableInfo] = []
    default_priority: NotificationPriorityEnum = NotificationPriorityEnum.NORMAL
    channel_overrides: Dict[str, Dict[str, str]] = {}  # Channel-specific templates


class NotificationTemplateCreate(NotificationTemplateBase):
    """Request to create a notification template"""
    pass


class NotificationTemplateUpdate(BaseModel):
    """Request to update a notification template"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    category: Optional[NotificationCategoryEnum] = None
    description: Optional[str] = None
    subject_template: Optional[str] = None
    body_template: Optional[str] = None
    html_template: Optional[str] = None
    variables: Optional[List[TemplateVariableInfo]] = None
    default_priority: Optional[NotificationPriorityEnum] = None
    channel_overrides: Optional[Dict[str, Dict[str, str]]] = None


class NotificationTemplate(NotificationTemplateBase):
    """Full notification template model"""
    id: str
    created_at: datetime
    updated_at: datetime
    usage_count: int = 0
    last_used: Optional[datetime] = None


class NotificationTemplateResponse(BaseModel):
    """Response for notification template operations"""
    status: StatusEnum
    message: str
    template: Optional[NotificationTemplate] = None


class NotificationTemplateListResponse(BaseModel):
    """Response for listing notification templates"""
    templates: List[NotificationTemplate]
    total: int
    by_category: Dict[str, int]


class TemplateRenderRequest(BaseModel):
    """Request to render a template preview"""
    template_id: str
    variables: Dict[str, Any] = {}
    target_channel: Optional[NotificationChannelTypeEnum] = None


class TemplateRenderResponse(BaseModel):
    """Response for template rendering"""
    status: StatusEnum
    subject: Optional[str] = None
    body: str
    html: Optional[str] = None
    variables_used: List[str]
    missing_variables: List[str]


# --- Routing Rule Models ---

class RoutingCondition(BaseModel):
    """Condition for notification routing"""
    field: str = Field(..., pattern="^(category|priority|source|tag|custom)$")
    operator: str = Field(..., pattern="^(equals|not_equals|contains|regex|in|not_in|gt|lt|gte|lte)$")
    value: Any


class RoutingAction(BaseModel):
    """Action to take when routing rule matches"""
    action_type: str = Field(..., pattern="^(route|suppress|delay|transform|escalate)$")
    channel_ids: List[str] = []
    delay_seconds: int = Field(0, ge=0)
    transform_template: Optional[str] = None
    escalation_policy: Optional[str] = None
    override_priority: Optional[NotificationPriorityEnum] = None


class RoutingRuleBase(BaseModel):
    """Base model for routing rules"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    enabled: bool = True
    priority: int = Field(100, ge=1, le=1000)  # Lower = higher priority
    conditions: List[RoutingCondition] = []
    condition_logic: str = Field("all", pattern="^(all|any)$")  # all = AND, any = OR
    actions: List[RoutingAction]
    schedule: Optional[Dict[str, Any]] = None  # Time-based activation


class RoutingRuleCreate(RoutingRuleBase):
    """Request to create a routing rule"""
    pass


class RoutingRuleUpdate(BaseModel):
    """Request to update a routing rule"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = Field(None, ge=1, le=1000)
    conditions: Optional[List[RoutingCondition]] = None
    condition_logic: Optional[str] = Field(None, pattern="^(all|any)$")
    actions: Optional[List[RoutingAction]] = None
    schedule: Optional[Dict[str, Any]] = None


class RoutingRule(RoutingRuleBase):
    """Full routing rule model"""
    id: str
    created_at: datetime
    updated_at: datetime
    match_count: int = 0
    last_matched: Optional[datetime] = None


class RoutingRuleResponse(BaseModel):
    """Response for routing rule operations"""
    status: StatusEnum
    message: str
    rule: Optional[RoutingRule] = None


class RoutingRuleListResponse(BaseModel):
    """Response for listing routing rules"""
    rules: List[RoutingRule]
    total: int


# --- Notification Models ---

class NotificationRecipient(BaseModel):
    """Recipient for a notification"""
    channel_id: str
    address: Optional[str] = None  # Override default channel address
    metadata: Dict[str, Any] = {}


class NotificationBase(BaseModel):
    """Base model for notifications"""
    category: NotificationCategoryEnum
    priority: NotificationPriorityEnum = NotificationPriorityEnum.NORMAL
    subject: str = Field(..., min_length=1, max_length=500)
    body: str = Field(..., min_length=1)
    html_body: Optional[str] = None
    source: str = "api"
    source_id: Optional[str] = None  # ID from source system (incident ID, etc.)
    tags: List[str] = []
    metadata: Dict[str, Any] = {}
    recipients: List[NotificationRecipient] = []
    template_id: Optional[str] = None
    template_variables: Dict[str, Any] = {}


class NotificationCreate(NotificationBase):
    """Request to create/send a notification"""
    defer_until: Optional[datetime] = None
    expire_at: Optional[datetime] = None
    dedupe_key: Optional[str] = None  # For deduplication
    dedupe_window_seconds: int = Field(300, ge=0)


class Notification(NotificationBase):
    """Full notification model"""
    id: str
    status: NotificationStatusEnum
    created_at: datetime
    updated_at: datetime
    queued_at: Optional[datetime] = None
    sent_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3
    next_retry_at: Optional[datetime] = None
    channel_statuses: Dict[str, Dict[str, Any]] = {}  # Status per channel
    error_message: Optional[str] = None
    routing_rules_matched: List[str] = []


class NotificationResponse(BaseModel):
    """Response for notification operations"""
    status: StatusEnum
    message: str
    notification: Optional[Notification] = None


class NotificationListResponse(BaseModel):
    """Response for listing notifications"""
    notifications: List[Notification]
    total: int
    page: int
    page_size: int
    by_status: Dict[str, int]
    by_category: Dict[str, int]


class NotificationRetryRequest(BaseModel):
    """Request to retry a failed notification"""
    notification_id: str
    channels: Optional[List[str]] = None  # Specific channels to retry, or all failed


# --- Escalation Policy Models ---

class EscalationStep(BaseModel):
    """Step in an escalation policy"""
    step_number: int = Field(..., ge=1)
    delay_minutes: int = Field(0, ge=0)
    channel_ids: List[str]
    notify_previous: bool = True  # Also notify channels from previous steps
    repeat_count: int = Field(1, ge=1, le=10)
    repeat_interval_minutes: int = Field(5, ge=1)


class EscalationPolicyBase(BaseModel):
    """Base model for escalation policies"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    enabled: bool = True
    categories: List[NotificationCategoryEnum] = []
    min_priority: NotificationPriorityEnum = NotificationPriorityEnum.HIGH
    steps: List[EscalationStep]
    acknowledgment_timeout_minutes: int = Field(30, ge=5)
    total_timeout_minutes: int = Field(120, ge=10)


class EscalationPolicyCreate(EscalationPolicyBase):
    """Request to create an escalation policy"""
    pass


class EscalationPolicyUpdate(BaseModel):
    """Request to update an escalation policy"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    enabled: Optional[bool] = None
    categories: Optional[List[NotificationCategoryEnum]] = None
    min_priority: Optional[NotificationPriorityEnum] = None
    steps: Optional[List[EscalationStep]] = None
    acknowledgment_timeout_minutes: Optional[int] = Field(None, ge=5)
    total_timeout_minutes: Optional[int] = Field(None, ge=10)


class EscalationPolicy(EscalationPolicyBase):
    """Full escalation policy model"""
    id: str
    created_at: datetime
    updated_at: datetime
    trigger_count: int = 0
    last_triggered: Optional[datetime] = None


class EscalationPolicyResponse(BaseModel):
    """Response for escalation policy operations"""
    status: StatusEnum
    message: str
    policy: Optional[EscalationPolicy] = None


class EscalationPolicyListResponse(BaseModel):
    """Response for listing escalation policies"""
    policies: List[EscalationPolicy]
    total: int


# --- Active Escalation Models ---

class ActiveEscalation(BaseModel):
    """Active escalation in progress"""
    id: str
    policy_id: str
    notification_id: str
    current_step: int
    started_at: datetime
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    status: str  # active, acknowledged, resolved, timeout
    step_history: List[Dict[str, Any]] = []


class EscalationAcknowledgeRequest(BaseModel):
    """Request to acknowledge an escalation"""
    escalation_id: str
    acknowledged_by: str
    note: Optional[str] = None


class EscalationResolveRequest(BaseModel):
    """Request to resolve an escalation"""
    escalation_id: str
    resolved_by: str
    resolution_note: Optional[str] = None


# --- Statistics and Health Models ---

class NotificationStats(BaseModel):
    """Notification system statistics"""
    total_notifications: int
    notifications_today: int
    notifications_this_hour: int
    by_status: Dict[str, int]
    by_category: Dict[str, int]
    by_priority: Dict[str, int]
    by_channel: Dict[str, int]
    avg_delivery_time_seconds: float
    success_rate_percent: float
    active_escalations: int
    channels_active: int
    channels_error: int
    rate_limited_channels: int
    queue_depth: int


class NotificationHealthCheck(BaseModel):
    """Health check for notification system"""
    status: str  # healthy, degraded, unhealthy
    timestamp: datetime
    channels_status: Dict[str, Dict[str, Any]]
    queue_status: Dict[str, Any]
    recent_failures: List[Dict[str, Any]]
    recommendations: List[str]


class ChannelTestRequest(BaseModel):
    """Request to test a notification channel"""
    channel_id: str
    test_message: Optional[str] = "This is a test notification from Defensive Toolkit"


class ChannelTestResponse(BaseModel):
    """Response for channel test"""
    status: StatusEnum
    message: str
    channel_id: str
    response_time_ms: int
    details: Dict[str, Any] = {}


# --- Bulk Operations ---

class BulkNotificationRequest(BaseModel):
    """Request to send bulk notifications"""
    notifications: List[NotificationCreate] = Field(..., min_items=1, max_items=100)
    fail_on_first_error: bool = False


class BulkNotificationResponse(BaseModel):
    """Response for bulk notification operation"""
    status: StatusEnum
    total_requested: int
    succeeded: int
    failed: int
    results: List[Dict[str, Any]]


# --- Subscription Models ---

class NotificationSubscription(BaseModel):
    """Subscription for notification preferences"""
    id: str
    subscriber_id: str  # User ID or system identifier
    subscriber_type: str = Field(..., pattern="^(user|system|team)$")
    categories: List[NotificationCategoryEnum] = []
    min_priority: NotificationPriorityEnum = NotificationPriorityEnum.LOW
    channels: List[str] = []  # Channel IDs
    schedule: Optional[Dict[str, Any]] = None  # Quiet hours, etc.
    enabled: bool = True
    created_at: datetime
    updated_at: datetime


class SubscriptionCreateRequest(BaseModel):
    """Request to create a notification subscription"""
    subscriber_id: str
    subscriber_type: str = Field("user", pattern="^(user|system|team)$")
    categories: List[NotificationCategoryEnum] = []
    min_priority: NotificationPriorityEnum = NotificationPriorityEnum.LOW
    channels: List[str] = []
    schedule: Optional[Dict[str, Any]] = None


class SubscriptionUpdateRequest(BaseModel):
    """Request to update a notification subscription"""
    categories: Optional[List[NotificationCategoryEnum]] = None
    min_priority: Optional[NotificationPriorityEnum] = None
    channels: Optional[List[str]] = None
    schedule: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class SubscriptionListResponse(BaseModel):
    """Response for listing subscriptions"""
    subscriptions: List[NotificationSubscription]
    total: int
