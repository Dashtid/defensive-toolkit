"""
Pydantic Models for Request/Response Validation

All API endpoints use these models for type safety and automatic validation.
Following FastAPI best practices for 2025.
"""

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
