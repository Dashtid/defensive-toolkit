"""
Pydantic Models for Request/Response Validation

All API endpoints use these models for type safety and automatic validation.
Following FastAPI best practices for 2025.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

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


# =============================================================================
# Alert Correlation Engine Models (v1.7.8)
# =============================================================================
# Provides alert correlation, MITRE ATT&CK mapping, kill chain tracking,
# alert clustering, and multi-stage attack detection.

# --- Enums ---

class CorrelationRuleTypeEnum(str, Enum):
    """Types of correlation rules"""
    SEQUENCE = "sequence"  # Events must occur in specific order
    THRESHOLD = "threshold"  # Count of events exceeds threshold
    TEMPORAL = "temporal"  # Events within time window
    PATTERN = "pattern"  # Regex or pattern matching
    AGGREGATION = "aggregation"  # Group by field values
    STATISTICAL = "statistical"  # Anomaly detection
    CHAIN = "chain"  # Multi-stage attack chain


class CorrelationRuleStatusEnum(str, Enum):
    """Status of correlation rules"""
    ACTIVE = "active"
    DISABLED = "disabled"
    TESTING = "testing"
    ARCHIVED = "archived"


class KillChainPhaseEnum(str, Enum):
    """Cyber Kill Chain phases (Lockheed Martin model)"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class CorrelatedAlertStatusEnum(str, Enum):
    """Status of correlated alert groups"""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class ClusteringAlgorithmEnum(str, Enum):
    """Supported clustering algorithms"""
    KMEANS = "kmeans"
    DBSCAN = "dbscan"
    HIERARCHICAL = "hierarchical"
    SIMILARITY = "similarity"  # Custom similarity scoring


class AttackPatternStatusEnum(str, Enum):
    """Status of detected attack patterns"""
    DETECTED = "detected"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"


# --- MITRE ATT&CK Models ---

class MitreTactic(BaseModel):
    """MITRE ATT&CK Tactic"""
    id: str = Field(..., description="Tactic ID (e.g., TA0001)")
    name: str = Field(..., description="Tactic name (e.g., Initial Access)")
    description: Optional[str] = None
    url: Optional[str] = None


class MitreTechnique(BaseModel):
    """MITRE ATT&CK Technique"""
    id: str = Field(..., description="Technique ID (e.g., T1566)")
    name: str = Field(..., description="Technique name (e.g., Phishing)")
    tactic_ids: List[str] = Field(default_factory=list, description="Associated tactic IDs")
    description: Optional[str] = None
    url: Optional[str] = None
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    detection: Optional[str] = None
    mitigations: List[str] = Field(default_factory=list)


class MitreMapping(BaseModel):
    """Mapping of an alert or rule to MITRE ATT&CK"""
    technique_ids: List[str] = Field(default_factory=list)
    tactic_ids: List[str] = Field(default_factory=list)
    kill_chain_phases: List[KillChainPhaseEnum] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence in mapping")
    notes: Optional[str] = None


# --- Correlation Rule Models ---

class CorrelationCondition(BaseModel):
    """Single condition in a correlation rule"""
    field: str = Field(..., description="Field to match (e.g., source_ip, event_type)")
    operator: str = Field(..., description="Comparison operator (eq, ne, gt, lt, contains, regex, in)")
    value: Any = Field(..., description="Value to compare against")
    case_sensitive: bool = True


class CorrelationRuleCreate(BaseModel):
    """Request to create a correlation rule"""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    rule_type: CorrelationRuleTypeEnum
    conditions: List[CorrelationCondition] = Field(..., min_items=1)
    time_window_seconds: int = Field(300, ge=1, le=86400, description="Time window for correlation")
    threshold: int = Field(1, ge=1, description="Minimum events to trigger")
    group_by: List[str] = Field(default_factory=list, description="Fields to group by")
    severity: SeverityEnum = SeverityEnum.MEDIUM
    mitre_mapping: Optional[MitreMapping] = None
    tags: List[str] = Field(default_factory=list)
    enabled: bool = True
    actions: List[Dict[str, Any]] = Field(default_factory=list, description="Actions on trigger")


class CorrelationRule(BaseModel):
    """Correlation rule definition"""
    id: str
    name: str
    description: Optional[str] = None
    rule_type: CorrelationRuleTypeEnum
    conditions: List[CorrelationCondition]
    time_window_seconds: int
    threshold: int
    group_by: List[str] = Field(default_factory=list)
    severity: SeverityEnum
    mitre_mapping: Optional[MitreMapping] = None
    tags: List[str] = Field(default_factory=list)
    status: CorrelationRuleStatusEnum = CorrelationRuleStatusEnum.ACTIVE
    enabled: bool = True
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    trigger_count: int = 0
    last_triggered: Optional[datetime] = None


class CorrelationRuleUpdate(BaseModel):
    """Request to update a correlation rule"""
    name: Optional[str] = None
    description: Optional[str] = None
    rule_type: Optional[CorrelationRuleTypeEnum] = None
    conditions: Optional[List[CorrelationCondition]] = None
    time_window_seconds: Optional[int] = Field(None, ge=1, le=86400)
    threshold: Optional[int] = Field(None, ge=1)
    group_by: Optional[List[str]] = None
    severity: Optional[SeverityEnum] = None
    mitre_mapping: Optional[MitreMapping] = None
    tags: Optional[List[str]] = None
    status: Optional[CorrelationRuleStatusEnum] = None
    enabled: Optional[bool] = None
    actions: Optional[List[Dict[str, Any]]] = None


class CorrelationRuleListResponse(BaseModel):
    """Response for listing correlation rules"""
    rules: List[CorrelationRule]
    total: int
    active_count: int
    disabled_count: int


# --- Correlated Alert Models ---

class CorrelatedAlertMember(BaseModel):
    """Individual alert that is part of a correlated group"""
    alert_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: SeverityEnum
    summary: str
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    matched_conditions: List[str] = Field(default_factory=list)


class CorrelatedAlertCreate(BaseModel):
    """Request to create a correlated alert group"""
    rule_id: str
    alerts: List[CorrelatedAlertMember] = Field(..., min_items=1)
    summary: Optional[str] = None
    notes: Optional[str] = None


class CorrelatedAlert(BaseModel):
    """Correlated alert group - multiple alerts linked together"""
    id: str
    rule_id: str
    rule_name: str
    alerts: List[CorrelatedAlertMember]
    alert_count: int
    first_seen: datetime
    last_seen: datetime
    time_span_seconds: int
    severity: SeverityEnum
    status: CorrelatedAlertStatusEnum = CorrelatedAlertStatusEnum.OPEN
    mitre_mapping: Optional[MitreMapping] = None
    kill_chain_phase: Optional[KillChainPhaseEnum] = None
    summary: str
    group_key: str = Field(..., description="Key identifying the correlation group")
    source_ips: List[str] = Field(default_factory=list)
    destination_ips: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None


class CorrelatedAlertUpdate(BaseModel):
    """Request to update a correlated alert"""
    status: Optional[CorrelatedAlertStatusEnum] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None
    resolution_notes: Optional[str] = None


class CorrelatedAlertListResponse(BaseModel):
    """Response for listing correlated alerts"""
    correlated_alerts: List[CorrelatedAlert]
    total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]


# --- Alert Clustering Models ---

class ClusterConfig(BaseModel):
    """Configuration for alert clustering"""
    algorithm: ClusteringAlgorithmEnum = ClusteringAlgorithmEnum.SIMILARITY
    similarity_threshold: float = Field(0.7, ge=0.0, le=1.0)
    min_cluster_size: int = Field(2, ge=2)
    max_cluster_size: int = Field(100, ge=2)
    features: List[str] = Field(
        default_factory=lambda: ["source_ip", "destination_ip", "event_type", "severity"],
        description="Fields to use for clustering"
    )
    time_window_hours: int = Field(24, ge=1, le=168)


class AlertCluster(BaseModel):
    """Cluster of similar alerts"""
    id: str
    cluster_name: str
    alerts: List[CorrelatedAlertMember]
    alert_count: int
    centroid: Dict[str, Any] = Field(default_factory=dict, description="Cluster centroid features")
    similarity_score: float = Field(..., ge=0.0, le=1.0)
    common_features: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime
    last_seen: datetime
    severity: SeverityEnum
    is_deduplicated: bool = False
    representative_alert_id: str = Field(..., description="Most representative alert")
    created_at: datetime


class ClusteringRequest(BaseModel):
    """Request to run clustering on alerts"""
    alert_ids: Optional[List[str]] = None  # If None, cluster recent alerts
    config: Optional[ClusterConfig] = None
    time_range_hours: int = Field(24, ge=1, le=168)


class ClusteringResponse(BaseModel):
    """Response from clustering operation"""
    status: StatusEnum
    clusters_found: int
    total_alerts_processed: int
    alerts_clustered: int
    alerts_deduplicated: int
    deduplication_rate_percent: float
    clusters: List[AlertCluster]
    processing_time_ms: int


# --- Deduplication Models ---

class DeduplicationConfig(BaseModel):
    """Configuration for alert deduplication"""
    enabled: bool = True
    similarity_threshold: float = Field(0.85, ge=0.0, le=1.0)
    time_window_minutes: int = Field(60, ge=1, le=1440)
    fields_to_compare: List[str] = Field(
        default_factory=lambda: ["source_ip", "destination_ip", "event_type", "alert_name"]
    )
    keep_strategy: str = Field("first", pattern="^(first|last|highest_severity)$")


class DeduplicationResult(BaseModel):
    """Result of deduplication operation"""
    original_count: int
    deduplicated_count: int
    duplicates_removed: int
    deduplication_rate_percent: float
    duplicate_groups: List[Dict[str, Any]]


# --- Attack Pattern Models ---

class AttackStage(BaseModel):
    """Single stage in a multi-stage attack"""
    stage_number: int
    name: str
    description: Optional[str] = None
    kill_chain_phase: KillChainPhaseEnum
    mitre_techniques: List[str] = Field(default_factory=list)
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    alerts: List[str] = Field(default_factory=list, description="Alert IDs in this stage")
    timestamp_start: Optional[datetime] = None
    timestamp_end: Optional[datetime] = None
    completed: bool = False


class AttackPatternCreate(BaseModel):
    """Request to create an attack pattern definition"""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    stages: List[AttackStage] = Field(..., min_items=1)
    mitre_mapping: Optional[MitreMapping] = None
    severity: SeverityEnum = SeverityEnum.CRITICAL
    tags: List[str] = Field(default_factory=list)


class AttackPattern(BaseModel):
    """Detected multi-stage attack pattern"""
    id: str
    name: str
    description: Optional[str] = None
    stages: List[AttackStage]
    stages_completed: int
    stages_total: int
    progress_percent: float
    status: AttackPatternStatusEnum
    severity: SeverityEnum
    mitre_mapping: Optional[MitreMapping] = None
    kill_chain_coverage: List[KillChainPhaseEnum] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    target_hosts: List[str] = Field(default_factory=list)
    target_users: List[str] = Field(default_factory=list)
    first_seen: datetime
    last_activity: datetime
    time_span_hours: float
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    related_correlated_alerts: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AttackPatternUpdate(BaseModel):
    """Request to update an attack pattern"""
    status: Optional[AttackPatternStatusEnum] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None


class AttackPatternListResponse(BaseModel):
    """Response for listing attack patterns"""
    patterns: List[AttackPattern]
    total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    active_attacks: int


# --- Alert Ingestion Models ---

class AlertIngest(BaseModel):
    """Alert to be ingested for correlation"""
    source: str = Field(..., description="Source system (e.g., siem, edr, firewall)")
    event_type: str = Field(..., description="Type of event")
    timestamp: datetime
    severity: SeverityEnum
    summary: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class AlertIngestBatch(BaseModel):
    """Batch of alerts for correlation processing"""
    alerts: List[AlertIngest] = Field(..., min_items=1, max_items=1000)
    process_immediately: bool = True


class AlertIngestResponse(BaseModel):
    """Response from alert ingestion"""
    status: StatusEnum
    alerts_received: int
    alerts_processed: int
    correlations_triggered: int
    new_correlated_alerts: int
    patterns_detected: int
    processing_time_ms: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)


# --- Correlation Statistics Models ---

class CorrelationStats(BaseModel):
    """Statistics for the correlation engine"""
    total_rules: int
    active_rules: int
    disabled_rules: int
    total_correlated_alerts: int
    open_correlated_alerts: int
    alerts_processed_24h: int
    correlations_triggered_24h: int
    alerts_deduplicated_24h: int
    deduplication_rate_percent: float
    avg_correlation_time_ms: float
    active_attack_patterns: int
    kill_chain_coverage: Dict[str, int]
    top_triggered_rules: List[Dict[str, Any]]
    mitre_technique_frequency: Dict[str, int]


class CorrelationHealthCheck(BaseModel):
    """Health check for correlation engine"""
    status: str = Field(..., pattern="^(healthy|degraded|unhealthy)$")
    timestamp: datetime
    rules_status: Dict[str, Any]
    processing_status: Dict[str, Any]
    queue_depth: int
    avg_latency_ms: float
    error_rate_percent: float
    last_correlation_at: Optional[datetime] = None
    recommendations: List[str] = Field(default_factory=list)


# --- Rule Testing Models ---

class RuleTestRequest(BaseModel):
    """Request to test a correlation rule"""
    rule_id: Optional[str] = None  # Test existing rule
    rule: Optional[CorrelationRuleCreate] = None  # Test new rule definition
    test_alerts: List[AlertIngest] = Field(..., min_items=1)


class RuleTestResponse(BaseModel):
    """Response from rule testing"""
    status: StatusEnum
    rule_matched: bool
    matching_alerts: List[Dict[str, Any]]
    alerts_tested: int
    alerts_matched: int
    match_details: Dict[str, Any]
    would_trigger: bool
    execution_time_ms: int


# --- Kill Chain Analysis Models ---

class KillChainAnalysis(BaseModel):
    """Analysis of kill chain progression"""
    analysis_id: str
    time_range_start: datetime
    time_range_end: datetime
    phases_detected: List[KillChainPhaseEnum]
    phases_missing: List[KillChainPhaseEnum]
    coverage_percent: float
    phase_details: Dict[str, Dict[str, Any]]
    potential_attack_progression: bool
    high_risk_indicators: List[str]
    recommendations: List[str]
    related_alerts: List[str]
    created_at: datetime


class KillChainAnalysisRequest(BaseModel):
    """Request for kill chain analysis"""
    source_ip: Optional[str] = None
    target_host: Optional[str] = None
    time_range_hours: int = Field(24, ge=1, le=168)
    include_all_severities: bool = False


# --- Suppression Models ---

class CorrelationSuppression(BaseModel):
    """Suppression rule for correlation"""
    id: str
    name: str
    description: Optional[str] = None
    conditions: List[CorrelationCondition]
    suppress_duration_minutes: int = Field(60, ge=1, le=10080)
    suppress_count: int = Field(0, description="Number of alerts suppressed")
    enabled: bool = True
    expires_at: Optional[datetime] = None
    created_at: datetime
    created_by: Optional[str] = None


class SuppressionCreateRequest(BaseModel):
    """Request to create a suppression rule"""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    conditions: List[CorrelationCondition] = Field(..., min_items=1)
    suppress_duration_minutes: int = Field(60, ge=1, le=10080)
    expires_at: Optional[datetime] = None


class SuppressionListResponse(BaseModel):
    """Response for listing suppression rules"""
    suppressions: List[CorrelationSuppression]
    total: int
    active_count: int


# =============================================================================
# Dashboard Widgets API Models (v1.7.9)
# =============================================================================
# Configurable dashboard system with security-focused widgets, real-time
# metrics visualization, user-customizable layouts, and data aggregation.

# --- Dashboard Enums ---

class WidgetTypeEnum(str, Enum):
    """Types of dashboard widgets"""
    COUNTER = "counter"  # Single metric value with trend
    CHART_LINE = "chart_line"  # Time-series line chart
    CHART_BAR = "chart_bar"  # Bar chart
    CHART_PIE = "chart_pie"  # Pie/donut chart
    CHART_AREA = "chart_area"  # Area chart
    HEATMAP = "heatmap"  # Heat map visualization
    TABLE = "table"  # Data table
    LIST = "list"  # Simple list
    MAP = "map"  # Geographic map
    GAUGE = "gauge"  # Gauge/speedometer
    SPARKLINE = "sparkline"  # Mini inline chart
    STATUS = "status"  # Status indicator
    TIMELINE = "timeline"  # Event timeline
    TREEMAP = "treemap"  # Hierarchical treemap
    CUSTOM = "custom"  # Custom widget type


class WidgetCategoryEnum(str, Enum):
    """Categories of security widgets"""
    THREAT_OVERVIEW = "threat_overview"
    INCIDENT_METRICS = "incident_metrics"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    USER_ACTIVITY = "user_activity"
    SIEM = "siem"
    CORRELATION = "correlation"
    SYSTEM_HEALTH = "system_health"
    CUSTOM = "custom"


class DashboardLayoutTypeEnum(str, Enum):
    """Dashboard layout types"""
    GRID = "grid"  # Fixed grid layout
    FREEFORM = "freeform"  # Free positioning
    RESPONSIVE = "responsive"  # Auto-responsive


class RefreshIntervalEnum(str, Enum):
    """Widget refresh intervals"""
    REALTIME = "realtime"  # SSE/WebSocket
    SECONDS_10 = "10s"
    SECONDS_30 = "30s"
    MINUTE_1 = "1m"
    MINUTES_5 = "5m"
    MINUTES_15 = "15m"
    MINUTES_30 = "30m"
    HOUR_1 = "1h"
    MANUAL = "manual"


class TimeRangePresetEnum(str, Enum):
    """Preset time ranges for widgets"""
    LAST_15_MINUTES = "15m"
    LAST_HOUR = "1h"
    LAST_4_HOURS = "4h"
    LAST_24_HOURS = "24h"
    LAST_7_DAYS = "7d"
    LAST_30_DAYS = "30d"
    LAST_90_DAYS = "90d"
    CUSTOM = "custom"


class AggregationTypeEnum(str, Enum):
    """Data aggregation types"""
    COUNT = "count"
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
    PERCENTILE_95 = "p95"
    PERCENTILE_99 = "p99"
    RATE = "rate"
    DELTA = "delta"


class ThresholdOperatorEnum(str, Enum):
    """Threshold comparison operators"""
    GT = "gt"  # Greater than
    GTE = "gte"  # Greater than or equal
    LT = "lt"  # Less than
    LTE = "lte"  # Less than or equal
    EQ = "eq"  # Equal
    BETWEEN = "between"  # Between two values


# --- Widget Configuration Models ---

class WidgetThreshold(BaseModel):
    """Threshold configuration for visual indicators"""
    operator: ThresholdOperatorEnum
    value: float
    value_max: Optional[float] = None  # For BETWEEN operator
    color: str = Field(..., pattern="^#[0-9A-Fa-f]{6}$")
    label: Optional[str] = None


class WidgetDataSource(BaseModel):
    """Data source configuration for a widget"""
    endpoint: str = Field(..., description="API endpoint to fetch data from")
    method: str = Field("GET", pattern="^(GET|POST)$")
    params: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    transform: Optional[str] = Field(None, description="JSONPath or JMESPath expression")
    cache_ttl_seconds: int = Field(60, ge=0, le=3600)


class WidgetPosition(BaseModel):
    """Widget position in grid layout"""
    x: int = Field(0, ge=0, le=23)
    y: int = Field(0, ge=0)
    width: int = Field(4, ge=1, le=24)
    height: int = Field(3, ge=1, le=12)


class ChartSeriesConfig(BaseModel):
    """Configuration for a chart series"""
    name: str
    field: str
    color: Optional[str] = None
    type: Optional[str] = None  # Override chart type per series
    aggregation: AggregationTypeEnum = AggregationTypeEnum.COUNT
    stack_group: Optional[str] = None


class ChartAxisConfig(BaseModel):
    """Axis configuration for charts"""
    label: Optional[str] = None
    min: Optional[float] = None
    max: Optional[float] = None
    format: Optional[str] = None  # Number format string
    logarithmic: bool = False


class ChartConfig(BaseModel):
    """Configuration for chart widgets"""
    series: List[ChartSeriesConfig] = Field(default_factory=list)
    x_axis: Optional[ChartAxisConfig] = None
    y_axis: Optional[ChartAxisConfig] = None
    show_legend: bool = True
    legend_position: str = Field("bottom", pattern="^(top|bottom|left|right)$")
    stacked: bool = False
    fill: bool = False
    smooth: bool = True


class TableColumnConfig(BaseModel):
    """Configuration for table columns"""
    field: str
    header: str
    width: Optional[int] = None
    sortable: bool = True
    filterable: bool = False
    format: Optional[str] = None
    link_template: Optional[str] = None


class TableConfig(BaseModel):
    """Configuration for table widgets"""
    columns: List[TableColumnConfig] = Field(default_factory=list)
    page_size: int = Field(10, ge=5, le=100)
    show_pagination: bool = True
    show_search: bool = True
    row_click_action: Optional[str] = None
    highlight_rules: List[Dict[str, Any]] = Field(default_factory=list)


class CounterConfig(BaseModel):
    """Configuration for counter widgets"""
    value_field: str
    label: str
    unit: Optional[str] = None
    format: Optional[str] = None
    show_trend: bool = True
    trend_field: Optional[str] = None
    trend_comparison: str = Field("previous_period", pattern="^(previous_period|baseline|target)$")
    thresholds: List[WidgetThreshold] = Field(default_factory=list)
    icon: Optional[str] = None


class GaugeConfig(BaseModel):
    """Configuration for gauge widgets"""
    value_field: str
    min_value: float = 0
    max_value: float = 100
    unit: Optional[str] = None
    thresholds: List[WidgetThreshold] = Field(default_factory=list)
    show_value: bool = True
    arc_width: int = Field(20, ge=5, le=50)


class MapConfig(BaseModel):
    """Configuration for map widgets"""
    lat_field: str
    lon_field: str
    value_field: Optional[str] = None
    label_field: Optional[str] = None
    cluster: bool = True
    initial_zoom: int = Field(2, ge=1, le=18)
    initial_center: Optional[List[float]] = None
    tile_layer: str = "openstreetmap"


class HeatmapConfig(BaseModel):
    """Configuration for heatmap widgets"""
    x_field: str
    y_field: str
    value_field: str
    x_labels: Optional[List[str]] = None
    y_labels: Optional[List[str]] = None
    color_scale: str = Field("viridis", pattern="^(viridis|plasma|inferno|magma|cividis|blues|reds|greens)$")
    show_values: bool = True


class TimelineConfig(BaseModel):
    """Configuration for timeline widgets"""
    timestamp_field: str
    title_field: str
    description_field: Optional[str] = None
    category_field: Optional[str] = None
    severity_field: Optional[str] = None
    max_items: int = Field(50, ge=10, le=200)


# --- Widget Models ---

class WidgetConfigUnion(BaseModel):
    """Union of all widget configuration types"""
    chart: Optional[ChartConfig] = None
    table: Optional[TableConfig] = None
    counter: Optional[CounterConfig] = None
    gauge: Optional[GaugeConfig] = None
    map: Optional[MapConfig] = None
    heatmap: Optional[HeatmapConfig] = None
    timeline: Optional[TimelineConfig] = None
    custom: Optional[Dict[str, Any]] = None


class WidgetCreate(BaseModel):
    """Request to create a widget"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    widget_type: WidgetTypeEnum
    category: WidgetCategoryEnum
    data_source: WidgetDataSource
    config: WidgetConfigUnion = Field(default_factory=WidgetConfigUnion)
    position: WidgetPosition = Field(default_factory=WidgetPosition)
    refresh_interval: RefreshIntervalEnum = RefreshIntervalEnum.MINUTES_5
    time_range: TimeRangePresetEnum = TimeRangePresetEnum.LAST_24_HOURS
    custom_time_start: Optional[datetime] = None
    custom_time_end: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    visible: bool = True


class Widget(BaseModel):
    """Dashboard widget"""
    id: str
    name: str
    description: Optional[str] = None
    widget_type: WidgetTypeEnum
    category: WidgetCategoryEnum
    data_source: WidgetDataSource
    config: WidgetConfigUnion
    position: WidgetPosition
    refresh_interval: RefreshIntervalEnum
    time_range: TimeRangePresetEnum
    custom_time_start: Optional[datetime] = None
    custom_time_end: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    visible: bool = True
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    last_data_fetch: Optional[datetime] = None
    error_count: int = 0
    last_error: Optional[str] = None


class WidgetUpdate(BaseModel):
    """Request to update a widget"""
    name: Optional[str] = None
    description: Optional[str] = None
    widget_type: Optional[WidgetTypeEnum] = None
    category: Optional[WidgetCategoryEnum] = None
    data_source: Optional[WidgetDataSource] = None
    config: Optional[WidgetConfigUnion] = None
    position: Optional[WidgetPosition] = None
    refresh_interval: Optional[RefreshIntervalEnum] = None
    time_range: Optional[TimeRangePresetEnum] = None
    custom_time_start: Optional[datetime] = None
    custom_time_end: Optional[datetime] = None
    tags: Optional[List[str]] = None
    visible: Optional[bool] = None


class WidgetDataResponse(BaseModel):
    """Response containing widget data"""
    widget_id: str
    data: Any
    timestamp: datetime
    cached: bool = False
    cache_expires_at: Optional[datetime] = None
    query_time_ms: int
    row_count: Optional[int] = None
    truncated: bool = False


class WidgetListResponse(BaseModel):
    """Response for listing widgets"""
    widgets: List[Widget]
    total: int
    by_type: Dict[str, int]
    by_category: Dict[str, int]


# --- Dashboard Models ---

class DashboardVariable(BaseModel):
    """Dashboard variable for dynamic filtering"""
    name: str = Field(..., pattern="^[a-zA-Z_][a-zA-Z0-9_]*$")
    label: str
    type: str = Field(..., pattern="^(text|select|multiselect|date|daterange)$")
    default_value: Any = None
    options: Optional[List[Dict[str, Any]]] = None  # For select types
    data_source: Optional[WidgetDataSource] = None  # Dynamic options


class DashboardCreate(BaseModel):
    """Request to create a dashboard"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    layout_type: DashboardLayoutTypeEnum = DashboardLayoutTypeEnum.GRID
    columns: int = Field(24, ge=12, le=48)
    row_height: int = Field(50, ge=30, le=100)
    variables: List[DashboardVariable] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    is_default: bool = False
    is_public: bool = False


class Dashboard(BaseModel):
    """Dashboard definition"""
    id: str
    name: str
    description: Optional[str] = None
    layout_type: DashboardLayoutTypeEnum
    columns: int
    row_height: int
    widgets: List[Widget] = Field(default_factory=list)
    widget_ids: List[str] = Field(default_factory=list)
    variables: List[DashboardVariable] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    is_default: bool = False
    is_public: bool = False
    owner: str
    shared_with: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    last_viewed_at: Optional[datetime] = None
    view_count: int = 0


class DashboardUpdate(BaseModel):
    """Request to update a dashboard"""
    name: Optional[str] = None
    description: Optional[str] = None
    layout_type: Optional[DashboardLayoutTypeEnum] = None
    columns: Optional[int] = Field(None, ge=12, le=48)
    row_height: Optional[int] = Field(None, ge=30, le=100)
    variables: Optional[List[DashboardVariable]] = None
    tags: Optional[List[str]] = None
    is_default: Optional[bool] = None
    is_public: Optional[bool] = None
    shared_with: Optional[List[str]] = None


class DashboardListResponse(BaseModel):
    """Response for listing dashboards"""
    dashboards: List[Dashboard]
    total: int
    owned: int
    shared: int
    public: int


# --- Widget Template Models ---

class WidgetTemplate(BaseModel):
    """Pre-configured widget template"""
    id: str
    name: str
    description: Optional[str] = None
    category: WidgetCategoryEnum
    widget_type: WidgetTypeEnum
    preview_image: Optional[str] = None
    default_config: WidgetConfigUnion
    default_data_source: WidgetDataSource
    default_position: WidgetPosition
    tags: List[str] = Field(default_factory=list)
    is_builtin: bool = True
    usage_count: int = 0
    created_at: datetime


class WidgetTemplateListResponse(BaseModel):
    """Response for listing widget templates"""
    templates: List[WidgetTemplate]
    total: int
    by_category: Dict[str, int]


# --- Dashboard Export/Import Models ---

class DashboardExport(BaseModel):
    """Exported dashboard configuration"""
    version: str = "1.0"
    exported_at: datetime
    dashboard: Dashboard
    widgets: List[Widget]


class DashboardImportRequest(BaseModel):
    """Request to import a dashboard"""
    dashboard_export: DashboardExport
    rename_to: Optional[str] = None
    overwrite_existing: bool = False


class DashboardImportResponse(BaseModel):
    """Response from dashboard import"""
    status: StatusEnum
    dashboard_id: str
    widgets_imported: int
    warnings: List[str] = Field(default_factory=list)


# --- Real-time Data Models ---

class WidgetDataSubscription(BaseModel):
    """Subscription for real-time widget data"""
    widget_id: str
    dashboard_id: str
    subscriber_id: str
    subscribed_at: datetime


class WidgetDataEvent(BaseModel):
    """Real-time widget data event (for SSE/WebSocket)"""
    event_type: str = Field(..., pattern="^(data|error|heartbeat)$")
    widget_id: str
    timestamp: datetime
    data: Optional[Any] = None
    error: Optional[str] = None


# --- Dashboard Statistics Models ---

class DashboardStats(BaseModel):
    """Dashboard system statistics"""
    total_dashboards: int
    total_widgets: int
    active_users_24h: int
    total_views_24h: int
    avg_widgets_per_dashboard: float
    widgets_by_type: Dict[str, int]
    widgets_by_category: Dict[str, int]
    most_viewed_dashboards: List[Dict[str, Any]]
    most_used_templates: List[Dict[str, Any]]
    data_fetch_errors_24h: int
    avg_data_fetch_time_ms: float


class DashboardHealthCheck(BaseModel):
    """Health check for dashboard system"""
    status: str = Field(..., pattern="^(healthy|degraded|unhealthy)$")
    timestamp: datetime
    widgets_status: Dict[str, Any]
    data_sources_status: Dict[str, Any]
    cache_status: Dict[str, Any]
    realtime_connections: int
    recommendations: List[str] = Field(default_factory=list)


# --- Layout Snapshot Models ---

class LayoutSnapshot(BaseModel):
    """Saved layout snapshot for undo/redo"""
    id: str
    dashboard_id: str
    widgets_positions: Dict[str, WidgetPosition]
    created_at: datetime
    created_by: Optional[str] = None
    description: Optional[str] = None


class LayoutSnapshotListResponse(BaseModel):
    """Response for listing layout snapshots"""
    snapshots: List[LayoutSnapshot]
    total: int


# --- Bulk Operations ---

class BulkWidgetPositionUpdate(BaseModel):
    """Bulk update widget positions"""
    updates: List[Dict[str, Any]] = Field(
        ...,
        min_items=1,
        description="List of {widget_id, position} objects"
    )


class BulkWidgetPositionResponse(BaseModel):
    """Response from bulk position update"""
    status: StatusEnum
    updated: int
    failed: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)


# =============================================================================
# ASSET INVENTORY & MANAGEMENT MODELS (v1.7.10)
# =============================================================================
# Comprehensive asset inventory system with CMDB integration, criticality
# scoring, network topology, and lifecycle management following CIS Controls
# v8.1 asset classification (devices, software, data, users, networks).
# =============================================================================


# --- Asset Enums ---

class AssetTypeEnum(str, Enum):
    """Asset type classification based on CIS Controls v8.1"""
    # Hardware Devices
    SERVER = "server"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    MOBILE_DEVICE = "mobile_device"
    NETWORK_DEVICE = "network_device"  # Router, switch, firewall, etc.
    IOT_DEVICE = "iot_device"
    PRINTER = "printer"
    STORAGE_DEVICE = "storage_device"
    VIRTUAL_MACHINE = "virtual_machine"

    # Cloud Resources
    CLOUD_INSTANCE = "cloud_instance"
    CLOUD_CONTAINER = "cloud_container"
    CLOUD_FUNCTION = "cloud_function"
    CLOUD_DATABASE = "cloud_database"
    CLOUD_STORAGE = "cloud_storage"

    # Network
    NETWORK_SEGMENT = "network_segment"
    VLAN = "vlan"
    SUBNET = "subnet"
    VPN_GATEWAY = "vpn_gateway"
    LOAD_BALANCER = "load_balancer"

    # Software/Services
    APPLICATION = "application"
    SERVICE = "service"
    DATABASE = "database"
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"

    # Identity
    USER_ACCOUNT = "user_account"
    SERVICE_ACCOUNT = "service_account"
    GROUP = "group"

    # Data
    DATA_REPOSITORY = "data_repository"
    FILE_SHARE = "file_share"

    # Other
    UNKNOWN = "unknown"
    OTHER = "other"


class AssetStatusEnum(str, Enum):
    """Asset lifecycle status"""
    DISCOVERED = "discovered"
    PENDING_REVIEW = "pending_review"
    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    DECOMMISSIONING = "decommissioning"
    DECOMMISSIONED = "decommissioned"
    MISSING = "missing"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


class AssetCriticalityEnum(str, Enum):
    """Asset criticality levels (qualitative)"""
    CRITICAL = "critical"  # Business-critical, contains sensitive data
    HIGH = "high"  # Important for operations
    MEDIUM = "medium"  # Standard business asset
    LOW = "low"  # Non-essential
    MINIMAL = "minimal"  # No business impact if unavailable


class AssetEnvironmentEnum(str, Enum):
    """Deployment environment"""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    QA = "qa"
    DR = "dr"  # Disaster recovery
    DMZ = "dmz"
    ISOLATED = "isolated"
    UNKNOWN = "unknown"


class AssetOwnershipEnum(str, Enum):
    """Asset ownership type"""
    OWNED = "owned"
    LEASED = "leased"
    RENTED = "rented"
    BYOD = "byod"
    MANAGED = "managed"
    THIRD_PARTY = "third_party"
    SHARED = "shared"
    UNKNOWN = "unknown"


class DiscoveryMethodEnum(str, Enum):
    """How the asset was discovered"""
    MANUAL = "manual"
    AGENT = "agent"
    NETWORK_SCAN = "network_scan"
    CLOUD_API = "cloud_api"
    CMDB_IMPORT = "cmdb_import"
    AD_SYNC = "ad_sync"  # Active Directory
    SCCM = "sccm"  # System Center Configuration Manager
    SIEM = "siem"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    EDR = "edr"  # Endpoint Detection and Response
    DHCP = "dhcp"
    DNS = "dns"
    SNMP = "snmp"
    API = "api"
    OTHER = "other"


class ComplianceStatusEnum(str, Enum):
    """Asset compliance status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    PENDING_ASSESSMENT = "pending_assessment"


class RelationshipTypeEnum(str, Enum):
    """Types of relationships between assets"""
    HOSTS = "hosts"  # Server hosts VM/container
    HOSTED_BY = "hosted_by"
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    DEPENDENCY_OF = "dependency_of"
    CONTAINS = "contains"
    CONTAINED_BY = "contained_by"
    MANAGES = "manages"
    MANAGED_BY = "managed_by"
    AUTHENTICATES_TO = "authenticates_to"
    MEMBER_OF = "member_of"
    BACKUP_OF = "backup_of"
    REPLICATED_TO = "replicated_to"
    ROUTES_TO = "routes_to"
    PROTECTED_BY = "protected_by"


class ScanTypeEnum(str, Enum):
    """Types of asset discovery scans"""
    FULL = "full"
    INCREMENTAL = "incremental"
    TARGETED = "targeted"
    QUICK = "quick"
    DEEP = "deep"
    NETWORK_ONLY = "network_only"
    AGENT_ONLY = "agent_only"


# --- Asset Configuration Models ---

class NetworkInterface(BaseModel):
    """Network interface details"""
    name: str
    mac_address: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    ipv6_addresses: List[str] = Field(default_factory=list)
    netmask: Optional[str] = None
    gateway: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    is_primary: bool = False
    speed_mbps: Optional[int] = None
    duplex: Optional[str] = None
    vlan_id: Optional[int] = None
    status: str = "up"


class HardwareInfo(BaseModel):
    """Hardware specifications"""
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    cpu_threads: Optional[int] = None
    ram_gb: Optional[float] = None
    storage_gb: Optional[float] = None
    storage_type: Optional[str] = None  # SSD, HDD, NVMe, etc.
    gpu_model: Optional[str] = None
    bios_version: Optional[str] = None
    firmware_version: Optional[str] = None
    purchase_date: Optional[datetime] = None
    warranty_expiry: Optional[datetime] = None


class OperatingSystem(BaseModel):
    """Operating system information"""
    name: str
    version: Optional[str] = None
    build: Optional[str] = None
    architecture: Optional[str] = None  # x64, x86, arm64
    kernel_version: Optional[str] = None
    install_date: Optional[datetime] = None
    last_boot: Optional[datetime] = None
    patch_level: Optional[str] = None
    end_of_life: Optional[datetime] = None
    is_supported: bool = True


class InstalledSoftware(BaseModel):
    """Installed software details"""
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    install_date: Optional[datetime] = None
    install_path: Optional[str] = None
    is_security_tool: bool = False
    is_authorized: bool = True
    license_type: Optional[str] = None
    cpe: Optional[str] = None  # Common Platform Enumeration


class CloudMetadata(BaseModel):
    """Cloud-specific asset metadata"""
    provider: str  # aws, azure, gcp, etc.
    account_id: Optional[str] = None
    region: Optional[str] = None
    availability_zone: Optional[str] = None
    instance_type: Optional[str] = None
    instance_id: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    security_groups: List[str] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    launch_time: Optional[datetime] = None
    state: Optional[str] = None
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    ami_id: Optional[str] = None  # For AWS
    resource_group: Optional[str] = None  # For Azure


class AssetLocation(BaseModel):
    """Physical or logical location"""
    site: Optional[str] = None
    building: Optional[str] = None
    floor: Optional[str] = None
    room: Optional[str] = None
    rack: Optional[str] = None
    rack_position: Optional[int] = None
    datacenter: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    address: Optional[str] = None
    geo_coordinates: Optional[Dict[str, float]] = None  # lat, lon


class AssetOwner(BaseModel):
    """Asset ownership information"""
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    owner_department: Optional[str] = None
    technical_contact_id: Optional[str] = None
    technical_contact_name: Optional[str] = None
    technical_contact_email: Optional[str] = None
    business_unit: Optional[str] = None
    cost_center: Optional[str] = None


class AssetRiskScore(BaseModel):
    """Comprehensive risk scoring (inspired by Tenable ACR/VPR)"""
    # Overall score (1-10 scale, 10 being most critical)
    overall_score: float = Field(..., ge=1.0, le=10.0)

    # Component scores
    criticality_score: float = Field(default=5.0, ge=1.0, le=10.0)
    vulnerability_score: float = Field(default=5.0, ge=1.0, le=10.0)
    exposure_score: float = Field(default=5.0, ge=1.0, le=10.0)
    threat_score: float = Field(default=5.0, ge=1.0, le=10.0)

    # Factors
    has_sensitive_data: bool = False
    is_internet_facing: bool = False
    has_critical_vulnerabilities: bool = False
    days_since_last_scan: Optional[int] = None
    patch_compliance_percentage: Optional[float] = None
    active_threats_count: int = 0

    # Metadata
    calculated_at: datetime = Field(default_factory=datetime.utcnow)
    calculation_method: str = "weighted_average"
    factors_considered: List[str] = Field(default_factory=list)


class VulnerabilitySummary(BaseModel):
    """Summary of vulnerabilities on an asset"""
    total_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    exploitable_count: int = 0
    patch_available_count: int = 0
    last_scan_date: Optional[datetime] = None
    scanner_source: Optional[str] = None


class SecurityControls(BaseModel):
    """Security controls status on the asset"""
    antivirus_installed: bool = False
    antivirus_updated: bool = False
    antivirus_product: Optional[str] = None

    edr_installed: bool = False
    edr_product: Optional[str] = None
    edr_status: Optional[str] = None

    firewall_enabled: bool = False
    firewall_product: Optional[str] = None

    encryption_enabled: bool = False
    encryption_type: Optional[str] = None

    mfa_enabled: bool = False
    backup_enabled: bool = False
    backup_last_run: Optional[datetime] = None

    dlp_enabled: bool = False
    siem_agent_installed: bool = False
    vulnerability_agent_installed: bool = False

    compliance_frameworks: List[str] = Field(default_factory=list)


# --- Asset CRUD Models ---

class AssetCreate(BaseModel):
    """Create a new asset"""
    # Required fields
    name: str = Field(..., min_length=1, max_length=255)
    asset_type: AssetTypeEnum

    # Classification
    status: AssetStatusEnum = AssetStatusEnum.DISCOVERED
    criticality: AssetCriticalityEnum = AssetCriticalityEnum.MEDIUM
    criticality_score: float = Field(default=5.0, ge=1.0, le=10.0)
    environment: AssetEnvironmentEnum = AssetEnvironmentEnum.UNKNOWN
    ownership_type: AssetOwnershipEnum = AssetOwnershipEnum.UNKNOWN

    # Identifiers
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    primary_ip: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    asset_tag: Optional[str] = None
    external_id: Optional[str] = None  # ID from external system (CMDB, etc.)

    # Details
    description: Optional[str] = None
    notes: Optional[str] = None

    # Network
    network_interfaces: List[NetworkInterface] = Field(default_factory=list)

    # Hardware/OS
    hardware: Optional[HardwareInfo] = None
    operating_system: Optional[OperatingSystem] = None
    installed_software: List[InstalledSoftware] = Field(default_factory=list)

    # Cloud
    cloud_metadata: Optional[CloudMetadata] = None
    is_cloud_asset: bool = False

    # Location/Ownership
    location: Optional[AssetLocation] = None
    owner: Optional[AssetOwner] = None

    # Discovery
    discovery_method: DiscoveryMethodEnum = DiscoveryMethodEnum.MANUAL
    discovery_source: Optional[str] = None

    # Security
    security_controls: Optional[SecurityControls] = None
    data_classification: Optional[str] = None  # Public, Internal, Confidential, etc.

    # Compliance
    compliance_status: ComplianceStatusEnum = ComplianceStatusEnum.UNKNOWN
    compliance_frameworks: List[str] = Field(default_factory=list)

    # Metadata
    tags: List[str] = Field(default_factory=list)
    custom_attributes: Dict[str, Any] = Field(default_factory=dict)


class Asset(BaseModel):
    """Complete asset model"""
    id: str

    # Required fields
    name: str
    asset_type: AssetTypeEnum

    # Classification
    status: AssetStatusEnum
    criticality: AssetCriticalityEnum
    criticality_score: float
    environment: AssetEnvironmentEnum
    ownership_type: AssetOwnershipEnum

    # Identifiers
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    primary_ip: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    asset_tag: Optional[str] = None
    external_id: Optional[str] = None

    # Details
    description: Optional[str] = None
    notes: Optional[str] = None

    # Network
    network_interfaces: List[NetworkInterface] = Field(default_factory=list)

    # Hardware/OS
    hardware: Optional[HardwareInfo] = None
    operating_system: Optional[OperatingSystem] = None
    installed_software: List[InstalledSoftware] = Field(default_factory=list)

    # Cloud
    cloud_metadata: Optional[CloudMetadata] = None
    is_cloud_asset: bool = False

    # Location/Ownership
    location: Optional[AssetLocation] = None
    owner: Optional[AssetOwner] = None

    # Discovery
    discovery_method: DiscoveryMethodEnum
    discovery_source: Optional[str] = None
    first_seen: datetime
    last_seen: datetime

    # Security
    security_controls: Optional[SecurityControls] = None
    vulnerability_summary: Optional[VulnerabilitySummary] = None
    risk_score: Optional[AssetRiskScore] = None
    data_classification: Optional[str] = None

    # Compliance
    compliance_status: ComplianceStatusEnum
    compliance_frameworks: List[str] = Field(default_factory=list)

    # Metadata
    tags: List[str] = Field(default_factory=list)
    custom_attributes: Dict[str, Any] = Field(default_factory=dict)

    # Audit
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    updated_by: Optional[str] = None


class AssetUpdate(BaseModel):
    """Update an existing asset"""
    name: Optional[str] = None
    asset_type: Optional[AssetTypeEnum] = None
    status: Optional[AssetStatusEnum] = None
    criticality: Optional[AssetCriticalityEnum] = None
    criticality_score: Optional[float] = Field(default=None, ge=1.0, le=10.0)
    environment: Optional[AssetEnvironmentEnum] = None
    ownership_type: Optional[AssetOwnershipEnum] = None
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    primary_ip: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    asset_tag: Optional[str] = None
    external_id: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    network_interfaces: Optional[List[NetworkInterface]] = None
    hardware: Optional[HardwareInfo] = None
    operating_system: Optional[OperatingSystem] = None
    installed_software: Optional[List[InstalledSoftware]] = None
    cloud_metadata: Optional[CloudMetadata] = None
    is_cloud_asset: Optional[bool] = None
    location: Optional[AssetLocation] = None
    owner: Optional[AssetOwner] = None
    security_controls: Optional[SecurityControls] = None
    data_classification: Optional[str] = None
    compliance_status: Optional[ComplianceStatusEnum] = None
    compliance_frameworks: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    custom_attributes: Optional[Dict[str, Any]] = None


class AssetListResponse(BaseModel):
    """Paginated list of assets"""
    assets: List[Asset]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool


class AssetSearchQuery(BaseModel):
    """Advanced asset search query"""
    query: Optional[str] = None  # Full-text search
    asset_types: Optional[List[AssetTypeEnum]] = None
    statuses: Optional[List[AssetStatusEnum]] = None
    criticalities: Optional[List[AssetCriticalityEnum]] = None
    environments: Optional[List[AssetEnvironmentEnum]] = None
    discovery_methods: Optional[List[DiscoveryMethodEnum]] = None
    compliance_statuses: Optional[List[ComplianceStatusEnum]] = None

    # IP/Network filters
    ip_range: Optional[str] = None
    subnet: Optional[str] = None
    vlan_id: Optional[int] = None

    # Location filters
    site: Optional[str] = None
    datacenter: Optional[str] = None

    # Owner filters
    owner_id: Optional[str] = None
    department: Optional[str] = None
    business_unit: Optional[str] = None

    # Risk/Vulnerability filters
    min_risk_score: Optional[float] = None
    max_risk_score: Optional[float] = None
    has_critical_vulnerabilities: Optional[bool] = None
    has_exploitable_vulnerabilities: Optional[bool] = None

    # Time filters
    first_seen_after: Optional[datetime] = None
    first_seen_before: Optional[datetime] = None
    last_seen_after: Optional[datetime] = None
    last_seen_before: Optional[datetime] = None
    not_seen_since: Optional[datetime] = None

    # Cloud filters
    is_cloud_asset: Optional[bool] = None
    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None

    # Security filters
    has_edr: Optional[bool] = None
    has_antivirus: Optional[bool] = None
    is_encrypted: Optional[bool] = None

    # Tag/Attribute filters
    tags: Optional[List[str]] = None
    tags_match_all: bool = False
    custom_attributes: Optional[Dict[str, Any]] = None

    # OS/Software filters
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    software_name: Optional[str] = None
    software_version: Optional[str] = None

    # Pagination
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)

    # Sorting
    sort_by: str = "last_seen"
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")


# --- Asset Relationship Models ---

class AssetRelationshipCreate(BaseModel):
    """Create a relationship between assets"""
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipTypeEnum
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_bidirectional: bool = False
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class AssetRelationship(BaseModel):
    """Relationship between two assets"""
    id: str
    source_asset_id: str
    source_asset_name: str
    target_asset_id: str
    target_asset_name: str
    relationship_type: RelationshipTypeEnum
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_bidirectional: bool
    confidence: float
    discovered_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AssetRelationshipListResponse(BaseModel):
    """List of asset relationships"""
    relationships: List[AssetRelationship]
    total: int


# --- Asset Group Models ---

class AssetGroupCreate(BaseModel):
    """Create an asset group"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    group_type: str = "static"  # static, dynamic

    # For static groups
    asset_ids: List[str] = Field(default_factory=list)

    # For dynamic groups
    filter_query: Optional[AssetSearchQuery] = None

    # Metadata
    tags: List[str] = Field(default_factory=list)
    owner_id: Optional[str] = None
    color: Optional[str] = None  # For UI display


class AssetGroup(BaseModel):
    """Asset group"""
    id: str
    name: str
    description: Optional[str] = None
    group_type: str
    asset_ids: List[str] = Field(default_factory=list)
    asset_count: int
    filter_query: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list)
    owner_id: Optional[str] = None
    color: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None


class AssetGroupUpdate(BaseModel):
    """Update an asset group"""
    name: Optional[str] = None
    description: Optional[str] = None
    asset_ids: Optional[List[str]] = None
    filter_query: Optional[AssetSearchQuery] = None
    tags: Optional[List[str]] = None
    owner_id: Optional[str] = None
    color: Optional[str] = None


class AssetGroupListResponse(BaseModel):
    """List of asset groups"""
    groups: List[AssetGroup]
    total: int


# --- Discovery Scan Models ---

class DiscoveryScanConfig(BaseModel):
    """Configuration for asset discovery scan"""
    name: str = Field(..., min_length=1, max_length=255)
    scan_type: ScanTypeEnum = ScanTypeEnum.FULL
    description: Optional[str] = None

    # Target specification
    target_networks: List[str] = Field(default_factory=list)  # CIDR notation
    target_domains: List[str] = Field(default_factory=list)
    target_cloud_accounts: List[str] = Field(default_factory=list)
    exclude_ranges: List[str] = Field(default_factory=list)

    # Discovery methods to use
    use_network_scan: bool = True
    use_agent_data: bool = True
    use_cloud_api: bool = True
    use_ad_sync: bool = False
    use_dns_enumeration: bool = False
    use_snmp: bool = False

    # Scan settings
    ports_to_scan: List[int] = Field(default_factory=lambda: [22, 80, 443, 445, 3389])
    scan_timeout_seconds: int = 300
    max_concurrent_hosts: int = 100
    retry_count: int = 2

    # Scheduling
    schedule_enabled: bool = False
    schedule_cron: Optional[str] = None

    # Actions
    auto_import: bool = True
    auto_tag: bool = True
    default_tags: List[str] = Field(default_factory=list)

    # Notifications
    notify_on_completion: bool = False
    notification_emails: List[str] = Field(default_factory=list)


class DiscoveryScan(BaseModel):
    """Discovery scan execution"""
    id: str
    name: str
    config: DiscoveryScanConfig
    status: str  # pending, running, completed, failed, cancelled

    # Execution details
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None

    # Results
    total_hosts_scanned: int = 0
    new_assets_found: int = 0
    updated_assets: int = 0
    failed_hosts: int = 0

    # Errors
    errors: List[Dict[str, Any]] = Field(default_factory=list)

    # Metadata
    created_at: datetime
    created_by: Optional[str] = None
    last_run_at: Optional[datetime] = None


class DiscoveryScanCreate(BaseModel):
    """Create a new discovery scan"""
    config: DiscoveryScanConfig
    run_immediately: bool = False


class DiscoveryScanListResponse(BaseModel):
    """List of discovery scans"""
    scans: List[DiscoveryScan]
    total: int


class DiscoveryScanResult(BaseModel):
    """Results from a discovery scan"""
    scan_id: str
    scan_name: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Statistics
    total_hosts_scanned: int
    new_assets: List[Dict[str, Any]] = Field(default_factory=list)
    updated_assets: List[Dict[str, Any]] = Field(default_factory=list)
    failed_hosts: List[Dict[str, Any]] = Field(default_factory=list)

    # Summary
    by_asset_type: Dict[str, int] = Field(default_factory=dict)
    by_os: Dict[str, int] = Field(default_factory=dict)
    by_network: Dict[str, int] = Field(default_factory=dict)


# --- Network Topology Models ---

class TopologyNode(BaseModel):
    """Node in network topology"""
    id: str
    asset_id: str
    asset_name: str
    asset_type: AssetTypeEnum
    ip_address: Optional[str] = None
    status: AssetStatusEnum
    criticality: AssetCriticalityEnum
    risk_score: Optional[float] = None

    # Visualization
    x: Optional[float] = None
    y: Optional[float] = None
    size: int = 1
    color: Optional[str] = None
    icon: Optional[str] = None
    group: Optional[str] = None


class TopologyEdge(BaseModel):
    """Edge in network topology"""
    id: str
    source: str
    target: str
    relationship_type: RelationshipTypeEnum
    label: Optional[str] = None
    weight: float = 1.0
    color: Optional[str] = None
    style: str = "solid"  # solid, dashed, dotted


class NetworkTopology(BaseModel):
    """Network topology graph"""
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]
    total_nodes: int
    total_edges: int
    generated_at: datetime

    # Metadata
    filters_applied: Dict[str, Any] = Field(default_factory=dict)
    layout_algorithm: str = "force-directed"


class TopologyQuery(BaseModel):
    """Query parameters for topology generation"""
    # Scope
    asset_ids: Optional[List[str]] = None
    asset_group_id: Optional[str] = None
    network_segment: Optional[str] = None
    datacenter: Optional[str] = None

    # Filters
    asset_types: Optional[List[AssetTypeEnum]] = None
    min_criticality: Optional[AssetCriticalityEnum] = None
    include_relationships: Optional[List[RelationshipTypeEnum]] = None

    # Depth
    max_depth: int = Field(default=3, ge=1, le=10)

    # Layout
    layout_algorithm: str = "force-directed"  # force-directed, hierarchical, circular


# --- CMDB Integration Models ---

class CMDBSyncConfig(BaseModel):
    """Configuration for CMDB synchronization"""
    name: str = Field(..., min_length=1, max_length=255)
    cmdb_type: str  # servicenow, jira, cmdb, custom

    # Connection
    endpoint_url: str
    auth_type: str = "api_key"  # api_key, oauth, basic
    # Note: Credentials stored separately in secrets

    # Mapping
    field_mapping: Dict[str, str] = Field(default_factory=dict)
    type_mapping: Dict[str, str] = Field(default_factory=dict)
    status_mapping: Dict[str, str] = Field(default_factory=dict)

    # Sync settings
    sync_direction: str = "bidirectional"  # import, export, bidirectional
    sync_frequency_minutes: int = 60
    batch_size: int = 100

    # Filters
    import_filter: Optional[str] = None  # Query to filter what to import
    export_filter: Optional[AssetSearchQuery] = None

    # Behavior
    create_missing: bool = True
    update_existing: bool = True
    delete_removed: bool = False

    # Metadata
    enabled: bool = True
    last_sync_at: Optional[datetime] = None


class CMDBSyncResult(BaseModel):
    """Result of CMDB synchronization"""
    config_id: str
    sync_type: str  # scheduled, manual
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str  # running, completed, failed

    # Statistics
    records_processed: int = 0
    imported: int = 0
    exported: int = 0
    updated: int = 0
    deleted: int = 0
    failed: int = 0

    # Errors
    errors: List[Dict[str, Any]] = Field(default_factory=list)


# --- Asset Import/Export Models ---

class AssetImportConfig(BaseModel):
    """Configuration for asset import"""
    format: str = "csv"  # csv, json, xlsx
    column_mapping: Dict[str, str] = Field(default_factory=dict)
    default_values: Dict[str, Any] = Field(default_factory=dict)

    # Behavior
    update_existing: bool = True
    match_on: List[str] = Field(default_factory=lambda: ["hostname", "primary_ip"])
    skip_invalid: bool = False
    dry_run: bool = False


class AssetImportResult(BaseModel):
    """Result of asset import"""
    import_id: str
    filename: str
    format: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str

    # Statistics
    total_records: int
    imported: int
    updated: int
    skipped: int
    failed: int

    # Details
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[Dict[str, Any]] = Field(default_factory=list)
    imported_asset_ids: List[str] = Field(default_factory=list)


class AssetExportConfig(BaseModel):
    """Configuration for asset export"""
    format: str = "csv"  # csv, json, xlsx
    columns: List[str] = Field(default_factory=list)  # Empty = all columns
    include_software: bool = False
    include_vulnerabilities: bool = False
    include_relationships: bool = False
    filter_query: Optional[AssetSearchQuery] = None


class AssetExportResult(BaseModel):
    """Result of asset export"""
    export_id: str
    format: str
    total_assets: int
    file_size_bytes: int
    download_url: str
    expires_at: datetime
    created_at: datetime


# --- Asset Statistics Models ---

class AssetStatistics(BaseModel):
    """Overall asset inventory statistics"""
    total_assets: int

    # By status
    by_status: Dict[str, int] = Field(default_factory=dict)

    # By type
    by_type: Dict[str, int] = Field(default_factory=dict)

    # By criticality
    by_criticality: Dict[str, int] = Field(default_factory=dict)

    # By environment
    by_environment: Dict[str, int] = Field(default_factory=dict)

    # By compliance
    by_compliance_status: Dict[str, int] = Field(default_factory=dict)

    # Risk distribution
    risk_distribution: Dict[str, int] = Field(default_factory=dict)  # low, medium, high, critical
    average_risk_score: float = 0.0

    # Discovery
    new_assets_7d: int = 0
    updated_assets_7d: int = 0
    missing_assets: int = 0

    # Cloud
    cloud_assets: int = 0
    by_cloud_provider: Dict[str, int] = Field(default_factory=dict)

    # Security
    assets_without_edr: int = 0
    assets_without_antivirus: int = 0
    assets_with_critical_vulns: int = 0

    # Time
    generated_at: datetime


class AssetTrendData(BaseModel):
    """Asset inventory trends over time"""
    period: str  # daily, weekly, monthly
    data_points: List[Dict[str, Any]] = Field(default_factory=list)
    # Each point: {date, total, new, decommissioned, by_type, by_criticality, avg_risk}


# --- Asset Activity/Audit Models ---

class AssetActivity(BaseModel):
    """Activity log entry for an asset"""
    id: str
    asset_id: str
    activity_type: str  # created, updated, deleted, scanned, status_changed, etc.
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)
    performed_by: Optional[str] = None
    timestamp: datetime


class AssetActivityListResponse(BaseModel):
    """List of asset activities"""
    activities: List[AssetActivity]
    total: int
    page: int
    page_size: int


# --- Bulk Operations ---

class BulkAssetUpdate(BaseModel):
    """Bulk update multiple assets"""
    asset_ids: List[str] = Field(..., min_items=1, max_items=1000)
    updates: AssetUpdate


class BulkAssetUpdateResult(BaseModel):
    """Result of bulk asset update"""
    status: StatusEnum
    total: int
    updated: int
    failed: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)


class BulkAssetTag(BaseModel):
    """Bulk tag/untag assets"""
    asset_ids: List[str] = Field(..., min_items=1, max_items=1000)
    tags_to_add: List[str] = Field(default_factory=list)
    tags_to_remove: List[str] = Field(default_factory=list)


class BulkAssetDelete(BaseModel):
    """Bulk delete assets"""
    asset_ids: List[str] = Field(..., min_items=1, max_items=1000)
    soft_delete: bool = True
    reason: Optional[str] = None


class BulkOperationResult(BaseModel):
    """Generic bulk operation result"""
    operation: str
    status: StatusEnum
    total: int
    succeeded: int
    failed: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)


# --- Asset Health Check ---

class AssetHealthCheck(BaseModel):
    """Health check for asset inventory system"""
    status: str = Field(..., pattern="^(healthy|degraded|unhealthy)$")
    timestamp: datetime

    # Component status
    database_status: str
    discovery_engine_status: str
    cmdb_sync_status: str

    # Statistics
    total_assets: int
    assets_synced_today: int
    pending_discoveries: int
    failed_syncs_24h: int

    # Issues
    issues: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
