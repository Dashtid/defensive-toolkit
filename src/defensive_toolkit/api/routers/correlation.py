"""
Alert Correlation Engine Router (v1.7.8)

Provides endpoints for:
- Correlation rules management (CRUD)
- Correlated alert groups
- MITRE ATT&CK technique mapping
- Kill chain phase tracking
- Alert clustering and deduplication
- Multi-stage attack pattern detection
- Alert ingestion for correlation processing
- Statistics and health monitoring
"""

import logging
import re
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from api.auth import get_current_active_user
from api.models import (
    AlertCluster,
    # Alert Ingestion Models
    AlertIngestBatch,
    AlertIngestResponse,
    # Common Models
    APIResponse,
    AttackPattern,
    AttackPatternCreate,
    AttackPatternListResponse,
    AttackPatternStatusEnum,
    AttackPatternUpdate,
    # Attack Pattern Models
    ClusterConfig,
    ClusteringRequest,
    ClusteringResponse,
    CorrelatedAlert,
    CorrelatedAlertCreate,
    CorrelatedAlertListResponse,
    # Correlated Alert Models
    CorrelatedAlertMember,
    CorrelatedAlertStatusEnum,
    CorrelatedAlertUpdate,
    # Correlation Rule Models
    CorrelationCondition,
    CorrelationHealthCheck,
    CorrelationRule,
    CorrelationRuleCreate,
    CorrelationRuleListResponse,
    CorrelationRuleStatusEnum,
    CorrelationRuleTypeEnum,
    CorrelationRuleUpdate,
    # Statistics Models
    CorrelationStats,
    # Suppression Models
    CorrelationSuppression,
    # Deduplication Models
    KillChainAnalysis,
    KillChainAnalysisRequest,
    KillChainPhaseEnum,
    MitreTactic,
    MitreTechnique,
    # Rule Testing Models
    RuleTestRequest,
    RuleTestResponse,
    SeverityEnum,
    # Enums
    StatusEnum,
    SuppressionCreateRequest,
    SuppressionListResponse,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/correlation",
    tags=["Alert Correlation Engine"],
    responses={404: {"description": "Not found"}},
)

# =============================================================================
# In-Memory Storage (Replace with database in production)
# =============================================================================

correlation_rules_db: Dict[str, CorrelationRule] = {}
correlated_alerts_db: Dict[str, CorrelatedAlert] = {}
attack_patterns_db: Dict[str, AttackPattern] = {}
suppressions_db: Dict[str, CorrelationSuppression] = {}
alert_clusters_db: Dict[str, AlertCluster] = {}
ingested_alerts_db: List[Dict[str, Any]] = []

# MITRE ATT&CK reference data (subset for demonstration)
mitre_tactics_db: Dict[str, MitreTactic] = {
    "TA0001": MitreTactic(id="TA0001", name="Initial Access", description="Techniques for gaining initial entry to a network"),
    "TA0002": MitreTactic(id="TA0002", name="Execution", description="Techniques for running malicious code"),
    "TA0003": MitreTactic(id="TA0003", name="Persistence", description="Techniques for maintaining foothold"),
    "TA0004": MitreTactic(id="TA0004", name="Privilege Escalation", description="Techniques for gaining higher-level permissions"),
    "TA0005": MitreTactic(id="TA0005", name="Defense Evasion", description="Techniques for avoiding detection"),
    "TA0006": MitreTactic(id="TA0006", name="Credential Access", description="Techniques for stealing credentials"),
    "TA0007": MitreTactic(id="TA0007", name="Discovery", description="Techniques for exploring the environment"),
    "TA0008": MitreTactic(id="TA0008", name="Lateral Movement", description="Techniques for moving through the environment"),
    "TA0009": MitreTactic(id="TA0009", name="Collection", description="Techniques for gathering data"),
    "TA0010": MitreTactic(id="TA0010", name="Exfiltration", description="Techniques for stealing data"),
    "TA0011": MitreTactic(id="TA0011", name="Command and Control", description="Techniques for communicating with compromised systems"),
    "TA0040": MitreTactic(id="TA0040", name="Impact", description="Techniques for disrupting availability or integrity"),
}

mitre_techniques_db: Dict[str, MitreTechnique] = {
    "T1566": MitreTechnique(id="T1566", name="Phishing", tactic_ids=["TA0001"], platforms=["Windows", "macOS", "Linux"]),
    "T1566.001": MitreTechnique(id="T1566.001", name="Spearphishing Attachment", tactic_ids=["TA0001"], is_subtechnique=True, parent_technique_id="T1566"),
    "T1059": MitreTechnique(id="T1059", name="Command and Scripting Interpreter", tactic_ids=["TA0002"]),
    "T1059.001": MitreTechnique(id="T1059.001", name="PowerShell", tactic_ids=["TA0002"], is_subtechnique=True, parent_technique_id="T1059"),
    "T1053": MitreTechnique(id="T1053", name="Scheduled Task/Job", tactic_ids=["TA0002", "TA0003", "TA0004"]),
    "T1547": MitreTechnique(id="T1547", name="Boot or Logon Autostart Execution", tactic_ids=["TA0003", "TA0004"]),
    "T1078": MitreTechnique(id="T1078", name="Valid Accounts", tactic_ids=["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1110": MitreTechnique(id="T1110", name="Brute Force", tactic_ids=["TA0006"]),
    "T1021": MitreTechnique(id="T1021", name="Remote Services", tactic_ids=["TA0008"]),
    "T1071": MitreTechnique(id="T1071", name="Application Layer Protocol", tactic_ids=["TA0011"]),
    "T1486": MitreTechnique(id="T1486", name="Data Encrypted for Impact", tactic_ids=["TA0040"]),
}

# Statistics tracking
correlation_stats = {
    "alerts_processed": 0,
    "correlations_triggered": 0,
    "alerts_deduplicated": 0,
    "processing_times_ms": [],
}


# =============================================================================
# Helper Functions
# =============================================================================

def generate_id() -> str:
    """Generate a unique ID"""
    return str(uuid.uuid4())


def evaluate_condition(condition: CorrelationCondition, alert_data: Dict[str, Any]) -> bool:
    """Evaluate a single condition against alert data"""
    field_value = alert_data.get(condition.field)
    if field_value is None:
        return False

    compare_value = condition.value
    if not condition.case_sensitive and isinstance(field_value, str) and isinstance(compare_value, str):
        field_value = field_value.lower()
        compare_value = compare_value.lower()

    operator = condition.operator.lower()

    if operator == "eq":
        return field_value == compare_value
    elif operator == "ne":
        return field_value != compare_value
    elif operator == "gt":
        return field_value > compare_value
    elif operator == "lt":
        return field_value < compare_value
    elif operator == "gte":
        return field_value >= compare_value
    elif operator == "lte":
        return field_value <= compare_value
    elif operator == "contains":
        return str(compare_value) in str(field_value)
    elif operator == "regex":
        try:
            return bool(re.search(str(compare_value), str(field_value)))
        except re.error:
            return False
    elif operator == "in":
        if isinstance(compare_value, list):
            return field_value in compare_value
        return False
    elif operator == "startswith":
        return str(field_value).startswith(str(compare_value))
    elif operator == "endswith":
        return str(field_value).endswith(str(compare_value))

    return False


def calculate_similarity(alert1: Dict[str, Any], alert2: Dict[str, Any], features: List[str]) -> float:
    """Calculate similarity score between two alerts based on specified features"""
    if not features:
        return 0.0

    matches = 0
    for feature in features:
        val1 = alert1.get(feature)
        val2 = alert2.get(feature)
        if val1 is not None and val2 is not None and val1 == val2:
            matches += 1

    return matches / len(features)


def map_to_kill_chain(mitre_techniques: List[str]) -> List[KillChainPhaseEnum]:
    """Map MITRE techniques to kill chain phases"""
    phase_mapping = {
        "TA0001": KillChainPhaseEnum.DELIVERY,
        "TA0002": KillChainPhaseEnum.EXPLOITATION,
        "TA0003": KillChainPhaseEnum.INSTALLATION,
        "TA0004": KillChainPhaseEnum.EXPLOITATION,
        "TA0005": KillChainPhaseEnum.INSTALLATION,
        "TA0006": KillChainPhaseEnum.EXPLOITATION,
        "TA0007": KillChainPhaseEnum.RECONNAISSANCE,
        "TA0008": KillChainPhaseEnum.COMMAND_AND_CONTROL,
        "TA0009": KillChainPhaseEnum.ACTIONS_ON_OBJECTIVES,
        "TA0010": KillChainPhaseEnum.ACTIONS_ON_OBJECTIVES,
        "TA0011": KillChainPhaseEnum.COMMAND_AND_CONTROL,
        "TA0040": KillChainPhaseEnum.ACTIONS_ON_OBJECTIVES,
    }

    phases = set()
    for technique_id in mitre_techniques:
        technique = mitre_techniques_db.get(technique_id)
        if technique:
            for tactic_id in technique.tactic_ids:
                if tactic_id in phase_mapping:
                    phases.add(phase_mapping[tactic_id])

    return list(phases)


# =============================================================================
# Correlation Rules Endpoints
# =============================================================================

@router.post("/rules", response_model=CorrelationRule, status_code=status.HTTP_201_CREATED)
async def create_correlation_rule(
    rule: CorrelationRuleCreate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Create a new correlation rule.

    Correlation rules define patterns to detect related security events.
    """
    rule_id = generate_id()
    now = datetime.utcnow()

    new_rule = CorrelationRule(
        id=rule_id,
        name=rule.name,
        description=rule.description,
        rule_type=rule.rule_type,
        conditions=rule.conditions,
        time_window_seconds=rule.time_window_seconds,
        threshold=rule.threshold,
        group_by=rule.group_by,
        severity=rule.severity,
        mitre_mapping=rule.mitre_mapping,
        tags=rule.tags,
        status=CorrelationRuleStatusEnum.ACTIVE if rule.enabled else CorrelationRuleStatusEnum.DISABLED,
        enabled=rule.enabled,
        actions=rule.actions,
        created_at=now,
        updated_at=now,
        created_by=current_user,
        trigger_count=0,
        last_triggered=None,
    )

    correlation_rules_db[rule_id] = new_rule
    logger.info(f"Created correlation rule: {rule.name} (ID: {rule_id})")

    return new_rule


@router.get("/rules", response_model=CorrelationRuleListResponse)
async def list_correlation_rules(
    rule_type: Optional[CorrelationRuleTypeEnum] = None,
    status: Optional[CorrelationRuleStatusEnum] = None,
    enabled: Optional[bool] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    List all correlation rules with optional filtering.
    """
    rules = list(correlation_rules_db.values())

    # Apply filters
    if rule_type:
        rules = [r for r in rules if r.rule_type == rule_type]
    if status:
        rules = [r for r in rules if r.status == status]
    if enabled is not None:
        rules = [r for r in rules if r.enabled == enabled]
    if tag:
        rules = [r for r in rules if tag in r.tags]
    if search:
        search_lower = search.lower()
        rules = [r for r in rules if search_lower in r.name.lower() or
                 (r.description and search_lower in r.description.lower())]

    # Calculate counts
    active_count = len([r for r in rules if r.status == CorrelationRuleStatusEnum.ACTIVE])
    disabled_count = len([r for r in rules if r.status == CorrelationRuleStatusEnum.DISABLED])

    # Pagination
    total = len(rules)
    rules = rules[skip:skip + limit]

    return CorrelationRuleListResponse(
        rules=rules,
        total=total,
        active_count=active_count,
        disabled_count=disabled_count,
    )


@router.get("/rules/{rule_id}", response_model=CorrelationRule)
async def get_correlation_rule(rule_id: str):
    """
    Get a specific correlation rule by ID.
    """
    rule = correlation_rules_db.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Correlation rule {rule_id} not found")
    return rule


@router.patch("/rules/{rule_id}", response_model=CorrelationRule)
async def update_correlation_rule(
    rule_id: str,
    update: CorrelationRuleUpdate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Update a correlation rule.
    """
    rule = correlation_rules_db.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Correlation rule {rule_id} not found")

    update_data = update.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(rule, field, value)

    rule.updated_at = datetime.utcnow()
    correlation_rules_db[rule_id] = rule

    logger.info(f"Updated correlation rule: {rule_id}")
    return rule


@router.delete("/rules/{rule_id}", response_model=APIResponse)
async def delete_correlation_rule(
    rule_id: str,
    current_user: str = Depends(get_current_active_user)
):
    """
    Delete a correlation rule.
    """
    if rule_id not in correlation_rules_db:
        raise HTTPException(status_code=404, detail=f"Correlation rule {rule_id} not found")

    del correlation_rules_db[rule_id]
    logger.info(f"Deleted correlation rule: {rule_id}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Correlation rule {rule_id} deleted successfully"
    )


@router.post("/rules/{rule_id}/enable", response_model=CorrelationRule)
async def enable_correlation_rule(
    rule_id: str,
    current_user: str = Depends(get_current_active_user)
):
    """
    Enable a correlation rule.
    """
    rule = correlation_rules_db.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Correlation rule {rule_id} not found")

    rule.enabled = True
    rule.status = CorrelationRuleStatusEnum.ACTIVE
    rule.updated_at = datetime.utcnow()
    correlation_rules_db[rule_id] = rule

    return rule


@router.post("/rules/{rule_id}/disable", response_model=CorrelationRule)
async def disable_correlation_rule(
    rule_id: str,
    current_user: str = Depends(get_current_active_user)
):
    """
    Disable a correlation rule.
    """
    rule = correlation_rules_db.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Correlation rule {rule_id} not found")

    rule.enabled = False
    rule.status = CorrelationRuleStatusEnum.DISABLED
    rule.updated_at = datetime.utcnow()
    correlation_rules_db[rule_id] = rule

    return rule


@router.post("/rules/test", response_model=RuleTestResponse)
async def test_correlation_rule(request: RuleTestRequest):
    """
    Test a correlation rule against sample alerts.

    Can test either an existing rule by ID or a new rule definition.
    """
    import time
    start_time = time.time()

    # Get the rule to test
    if request.rule_id:
        rule = correlation_rules_db.get(request.rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail=f"Correlation rule {request.rule_id} not found")
        conditions = rule.conditions
        threshold = rule.threshold
    elif request.rule:
        conditions = request.rule.conditions
        threshold = request.rule.threshold
    else:
        raise HTTPException(status_code=400, detail="Either rule_id or rule must be provided")

    # Test alerts against conditions
    matching_alerts = []
    for alert in request.test_alerts:
        alert_data = {
            "source": alert.source,
            "event_type": alert.event_type,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity.value,
            "summary": alert.summary,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "user": alert.user,
            "host": alert.host,
            **alert.raw_data,
        }

        # Check all conditions
        all_match = True
        matched_conditions = []
        for condition in conditions:
            if evaluate_condition(condition, alert_data):
                matched_conditions.append(f"{condition.field} {condition.operator} {condition.value}")
            else:
                all_match = False

        if all_match:
            matching_alerts.append({
                "alert": alert_data,
                "matched_conditions": matched_conditions,
            })

    execution_time_ms = int((time.time() - start_time) * 1000)
    would_trigger = len(matching_alerts) >= threshold

    return RuleTestResponse(
        status=StatusEnum.SUCCESS,
        rule_matched=len(matching_alerts) > 0,
        matching_alerts=matching_alerts,
        alerts_tested=len(request.test_alerts),
        alerts_matched=len(matching_alerts),
        match_details={
            "threshold": threshold,
            "matches_needed": threshold,
            "matches_found": len(matching_alerts),
        },
        would_trigger=would_trigger,
        execution_time_ms=execution_time_ms,
    )


# =============================================================================
# Correlated Alerts Endpoints
# =============================================================================

@router.post("/alerts", response_model=CorrelatedAlert, status_code=status.HTTP_201_CREATED)
async def create_correlated_alert(
    alert: CorrelatedAlertCreate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Manually create a correlated alert group.
    """
    rule = correlation_rules_db.get(alert.rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Correlation rule {alert.rule_id} not found")

    alert_id = generate_id()
    now = datetime.utcnow()

    # Extract metadata from alerts
    timestamps = [a.timestamp for a in alert.alerts]
    first_seen = min(timestamps)
    last_seen = max(timestamps)
    time_span = int((last_seen - first_seen).total_seconds())

    source_ips = list(set(
        a.raw_data.get("source_ip") for a in alert.alerts
        if a.raw_data.get("source_ip")
    ))
    dest_ips = list(set(
        a.raw_data.get("destination_ip") for a in alert.alerts
        if a.raw_data.get("destination_ip")
    ))
    users = list(set(
        a.raw_data.get("user") for a in alert.alerts
        if a.raw_data.get("user")
    ))
    hosts = list(set(
        a.raw_data.get("host") for a in alert.alerts
        if a.raw_data.get("host")
    ))

    # Generate group key
    group_key = f"{alert.rule_id}:{':'.join(sorted(source_ips))}:{first_seen.isoformat()}"

    correlated = CorrelatedAlert(
        id=alert_id,
        rule_id=alert.rule_id,
        rule_name=rule.name,
        alerts=alert.alerts,
        alert_count=len(alert.alerts),
        first_seen=first_seen,
        last_seen=last_seen,
        time_span_seconds=time_span,
        severity=rule.severity,
        status=CorrelatedAlertStatusEnum.OPEN,
        mitre_mapping=rule.mitre_mapping,
        kill_chain_phase=rule.mitre_mapping.kill_chain_phases[0] if rule.mitre_mapping and rule.mitre_mapping.kill_chain_phases else None,
        summary=alert.summary or f"Correlated alert group from rule: {rule.name}",
        group_key=group_key,
        source_ips=source_ips,
        destination_ips=dest_ips,
        users=users,
        hosts=hosts,
        tags=rule.tags,
        notes=alert.notes,
        created_at=now,
        updated_at=now,
    )

    correlated_alerts_db[alert_id] = correlated
    logger.info(f"Created correlated alert: {alert_id} (Rule: {rule.name})")

    return correlated


@router.get("/alerts", response_model=CorrelatedAlertListResponse)
async def list_correlated_alerts(
    status: Optional[CorrelatedAlertStatusEnum] = None,
    severity: Optional[SeverityEnum] = None,
    rule_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    assigned_to: Optional[str] = None,
    hours: int = Query(24, ge=1, le=168),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    List correlated alerts with filtering options.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    alerts = [a for a in correlated_alerts_db.values() if a.created_at >= cutoff]

    # Apply filters
    if status:
        alerts = [a for a in alerts if a.status == status]
    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    if rule_id:
        alerts = [a for a in alerts if a.rule_id == rule_id]
    if source_ip:
        alerts = [a for a in alerts if source_ip in a.source_ips]
    if assigned_to:
        alerts = [a for a in alerts if a.assigned_to == assigned_to]

    # Sort by last_seen descending
    alerts.sort(key=lambda x: x.last_seen, reverse=True)

    # Calculate statistics
    by_status = defaultdict(int)
    by_severity = defaultdict(int)
    for alert in alerts:
        by_status[alert.status.value] += 1
        by_severity[alert.severity.value] += 1

    # Pagination
    total = len(alerts)
    alerts = alerts[skip:skip + limit]

    return CorrelatedAlertListResponse(
        correlated_alerts=alerts,
        total=total,
        by_status=dict(by_status),
        by_severity=dict(by_severity),
    )


@router.get("/alerts/{alert_id}", response_model=CorrelatedAlert)
async def get_correlated_alert(alert_id: str):
    """
    Get a specific correlated alert by ID.
    """
    alert = correlated_alerts_db.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Correlated alert {alert_id} not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=CorrelatedAlert)
async def update_correlated_alert(
    alert_id: str,
    update: CorrelatedAlertUpdate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Update a correlated alert (status, assignment, notes).
    """
    alert = correlated_alerts_db.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Correlated alert {alert_id} not found")

    update_data = update.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(alert, field, value)

    alert.updated_at = datetime.utcnow()

    if update.status == CorrelatedAlertStatusEnum.RESOLVED:
        alert.resolved_at = datetime.utcnow()

    correlated_alerts_db[alert_id] = alert
    logger.info(f"Updated correlated alert: {alert_id}")

    return alert


@router.post("/alerts/{alert_id}/resolve", response_model=CorrelatedAlert)
async def resolve_correlated_alert(
    alert_id: str,
    resolution_notes: Optional[str] = None,
    current_user: str = Depends(get_current_active_user)
):
    """
    Resolve a correlated alert.
    """
    alert = correlated_alerts_db.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Correlated alert {alert_id} not found")

    alert.status = CorrelatedAlertStatusEnum.RESOLVED
    alert.resolved_at = datetime.utcnow()
    alert.updated_at = datetime.utcnow()
    if resolution_notes:
        alert.resolution_notes = resolution_notes

    correlated_alerts_db[alert_id] = alert
    return alert


# =============================================================================
# Alert Ingestion Endpoints
# =============================================================================

@router.post("/ingest", response_model=AlertIngestResponse)
async def ingest_alerts(
    batch: AlertIngestBatch,
    current_user: str = Depends(get_current_active_user)
):
    """
    Ingest alerts for correlation processing.

    This endpoint receives alerts from various sources and processes them
    through active correlation rules to detect patterns.
    """
    import time
    start_time = time.time()

    alerts_processed = 0
    correlations_triggered = 0
    new_correlated_alerts = 0
    patterns_detected = 0
    errors = []

    # Get active rules
    active_rules = [r for r in correlation_rules_db.values() if r.enabled]

    # Process each alert
    for alert in batch.alerts:
        try:
            alert_data = {
                "id": generate_id(),
                "source": alert.source,
                "event_type": alert.event_type,
                "timestamp": alert.timestamp,
                "severity": alert.severity.value,
                "summary": alert.summary,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "user": alert.user,
                "host": alert.host,
                **alert.raw_data,
            }

            # Store alert for correlation window
            ingested_alerts_db.append(alert_data)
            alerts_processed += 1

            # Check against each active rule
            for rule in active_rules:
                # Evaluate conditions
                all_match = True
                for condition in rule.conditions:
                    if not evaluate_condition(condition, alert_data):
                        all_match = False
                        break

                if all_match:
                    correlations_triggered += 1

                    # Check if we have enough alerts in time window for threshold
                    window_start = alert.timestamp - timedelta(seconds=rule.time_window_seconds)
                    matching_in_window = [
                        a for a in ingested_alerts_db
                        if a["timestamp"] >= window_start and
                        all(evaluate_condition(c, a) for c in rule.conditions)
                    ]

                    if len(matching_in_window) >= rule.threshold:
                        # Create correlated alert
                        alert_members = [
                            CorrelatedAlertMember(
                                alert_id=a["id"],
                                timestamp=a["timestamp"],
                                source=a["source"],
                                event_type=a["event_type"],
                                severity=SeverityEnum(a["severity"]),
                                summary=a["summary"],
                                raw_data=a,
                            )
                            for a in matching_in_window
                        ]

                        correlated_id = generate_id()
                        now = datetime.utcnow()

                        timestamps = [a.timestamp for a in alert_members]
                        source_ips = list(set(a["source_ip"] for a in matching_in_window if a.get("source_ip")))

                        correlated = CorrelatedAlert(
                            id=correlated_id,
                            rule_id=rule.id,
                            rule_name=rule.name,
                            alerts=alert_members,
                            alert_count=len(alert_members),
                            first_seen=min(timestamps),
                            last_seen=max(timestamps),
                            time_span_seconds=int((max(timestamps) - min(timestamps)).total_seconds()),
                            severity=rule.severity,
                            status=CorrelatedAlertStatusEnum.OPEN,
                            mitre_mapping=rule.mitre_mapping,
                            summary=f"Auto-correlated: {rule.name}",
                            group_key=f"{rule.id}:{':'.join(sorted(source_ips))}",
                            source_ips=source_ips,
                            created_at=now,
                            updated_at=now,
                        )

                        correlated_alerts_db[correlated_id] = correlated
                        new_correlated_alerts += 1

                        # Update rule trigger count
                        rule.trigger_count += 1
                        rule.last_triggered = now
                        correlation_rules_db[rule.id] = rule

        except Exception as e:
            errors.append({"alert": alert.summary, "error": str(e)})
            logger.error(f"Error processing alert: {e}")

    # Cleanup old alerts outside correlation windows
    max_window = max((r.time_window_seconds for r in active_rules), default=3600)
    cutoff = datetime.utcnow() - timedelta(seconds=max_window * 2)
    ingested_alerts_db[:] = [a for a in ingested_alerts_db if a["timestamp"] >= cutoff]

    processing_time_ms = int((time.time() - start_time) * 1000)

    # Update stats
    correlation_stats["alerts_processed"] += alerts_processed
    correlation_stats["correlations_triggered"] += correlations_triggered
    correlation_stats["processing_times_ms"].append(processing_time_ms)

    return AlertIngestResponse(
        status=StatusEnum.SUCCESS,
        alerts_received=len(batch.alerts),
        alerts_processed=alerts_processed,
        correlations_triggered=correlations_triggered,
        new_correlated_alerts=new_correlated_alerts,
        patterns_detected=patterns_detected,
        processing_time_ms=processing_time_ms,
        errors=errors,
    )


# =============================================================================
# Alert Clustering Endpoints
# =============================================================================

@router.post("/cluster", response_model=ClusteringResponse)
async def cluster_alerts(
    request: ClusteringRequest,
    current_user: str = Depends(get_current_active_user)
):
    """
    Cluster alerts based on similarity.

    Groups similar alerts together to reduce alert fatigue and identify patterns.
    """
    import time
    start_time = time.time()

    config = request.config or ClusterConfig()

    # Get alerts to cluster
    cutoff = datetime.utcnow() - timedelta(hours=request.time_range_hours)
    if request.alert_ids:
        alerts_to_cluster = [
            a for a in ingested_alerts_db
            if a["id"] in request.alert_ids
        ]
    else:
        alerts_to_cluster = [
            a for a in ingested_alerts_db
            if a["timestamp"] >= cutoff
        ]

    if not alerts_to_cluster:
        return ClusteringResponse(
            status=StatusEnum.SUCCESS,
            clusters_found=0,
            total_alerts_processed=0,
            alerts_clustered=0,
            alerts_deduplicated=0,
            deduplication_rate_percent=0.0,
            clusters=[],
            processing_time_ms=0,
        )

    # Simple similarity-based clustering
    clusters: List[List[Dict[str, Any]]] = []
    clustered_ids = set()

    for alert in alerts_to_cluster:
        if alert["id"] in clustered_ids:
            continue

        # Start a new cluster with this alert
        cluster = [alert]
        clustered_ids.add(alert["id"])

        # Find similar alerts
        for other in alerts_to_cluster:
            if other["id"] in clustered_ids:
                continue

            similarity = calculate_similarity(alert, other, config.features)
            if similarity >= config.similarity_threshold:
                cluster.append(other)
                clustered_ids.add(other["id"])

                if len(cluster) >= config.max_cluster_size:
                    break

        if len(cluster) >= config.min_cluster_size:
            clusters.append(cluster)

    # Create AlertCluster objects
    result_clusters = []
    alerts_deduplicated = 0

    for i, cluster_alerts in enumerate(clusters):
        cluster_id = generate_id()
        now = datetime.utcnow()

        timestamps = [a["timestamp"] for a in cluster_alerts]
        severities = [a["severity"] for a in cluster_alerts]

        # Find most common features
        common_features = {}
        for feature in config.features:
            values = [a.get(feature) for a in cluster_alerts if a.get(feature)]
            if values:
                most_common = max(set(values), key=values.count)
                common_features[feature] = most_common

        # Determine highest severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        highest_severity = min(severities, key=lambda s: severity_order.index(s) if s in severity_order else 999)

        alert_members = [
            CorrelatedAlertMember(
                alert_id=a["id"],
                timestamp=a["timestamp"],
                source=a["source"],
                event_type=a["event_type"],
                severity=SeverityEnum(a["severity"]),
                summary=a["summary"],
                raw_data=a,
            )
            for a in cluster_alerts
        ]

        cluster = AlertCluster(
            id=cluster_id,
            cluster_name=f"Cluster {i + 1}: {common_features.get('event_type', 'Unknown')}",
            alerts=alert_members,
            alert_count=len(alert_members),
            centroid=common_features,
            similarity_score=config.similarity_threshold,
            common_features=common_features,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            severity=SeverityEnum(highest_severity),
            is_deduplicated=True,
            representative_alert_id=cluster_alerts[0]["id"],
            created_at=now,
        )

        result_clusters.append(cluster)
        alert_clusters_db[cluster_id] = cluster
        alerts_deduplicated += len(cluster_alerts) - 1  # All but representative

    processing_time_ms = int((time.time() - start_time) * 1000)
    total_clustered = sum(c.alert_count for c in result_clusters)
    dedup_rate = (alerts_deduplicated / len(alerts_to_cluster) * 100) if alerts_to_cluster else 0.0

    correlation_stats["alerts_deduplicated"] += alerts_deduplicated

    return ClusteringResponse(
        status=StatusEnum.SUCCESS,
        clusters_found=len(result_clusters),
        total_alerts_processed=len(alerts_to_cluster),
        alerts_clustered=total_clustered,
        alerts_deduplicated=alerts_deduplicated,
        deduplication_rate_percent=round(dedup_rate, 2),
        clusters=result_clusters,
        processing_time_ms=processing_time_ms,
    )


@router.get("/clusters", response_model=List[AlertCluster])
async def list_clusters(
    hours: int = Query(24, ge=1, le=168),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    List alert clusters.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    clusters = [c for c in alert_clusters_db.values() if c.created_at >= cutoff]
    clusters.sort(key=lambda x: x.created_at, reverse=True)

    return clusters[skip:skip + limit]


# =============================================================================
# Attack Pattern Endpoints
# =============================================================================

@router.post("/patterns", response_model=AttackPattern, status_code=status.HTTP_201_CREATED)
async def create_attack_pattern(
    pattern: AttackPatternCreate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Create an attack pattern definition for multi-stage attack detection.
    """
    pattern_id = generate_id()
    now = datetime.utcnow()

    kill_chain_phases = list(set(stage.kill_chain_phase for stage in pattern.stages))

    new_pattern = AttackPattern(
        id=pattern_id,
        name=pattern.name,
        description=pattern.description,
        stages=pattern.stages,
        stages_completed=0,
        stages_total=len(pattern.stages),
        progress_percent=0.0,
        status=AttackPatternStatusEnum.DETECTED,
        severity=pattern.severity,
        mitre_mapping=pattern.mitre_mapping,
        kill_chain_coverage=kill_chain_phases,
        first_seen=now,
        last_activity=now,
        time_span_hours=0.0,
        confidence=0.0,
        tags=pattern.tags,
        created_at=now,
        updated_at=now,
    )

    attack_patterns_db[pattern_id] = new_pattern
    logger.info(f"Created attack pattern: {pattern.name} (ID: {pattern_id})")

    return new_pattern


@router.get("/patterns", response_model=AttackPatternListResponse)
async def list_attack_patterns(
    status: Optional[AttackPatternStatusEnum] = None,
    severity: Optional[SeverityEnum] = None,
    active_only: bool = False,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    List detected attack patterns.
    """
    patterns = list(attack_patterns_db.values())

    if status:
        patterns = [p for p in patterns if p.status == status]
    if severity:
        patterns = [p for p in patterns if p.severity == severity]
    if active_only:
        patterns = [p for p in patterns if p.status in [
            AttackPatternStatusEnum.DETECTED,
            AttackPatternStatusEnum.CONFIRMED,
            AttackPatternStatusEnum.IN_PROGRESS,
        ]]

    patterns.sort(key=lambda x: x.last_activity, reverse=True)

    by_status = defaultdict(int)
    by_severity = defaultdict(int)
    for p in patterns:
        by_status[p.status.value] += 1
        by_severity[p.severity.value] += 1

    active_attacks = len([p for p in patterns if p.status in [
        AttackPatternStatusEnum.DETECTED,
        AttackPatternStatusEnum.CONFIRMED,
        AttackPatternStatusEnum.IN_PROGRESS,
    ]])

    total = len(patterns)
    patterns = patterns[skip:skip + limit]

    return AttackPatternListResponse(
        patterns=patterns,
        total=total,
        by_status=dict(by_status),
        by_severity=dict(by_severity),
        active_attacks=active_attacks,
    )


@router.get("/patterns/{pattern_id}", response_model=AttackPattern)
async def get_attack_pattern(pattern_id: str):
    """
    Get a specific attack pattern by ID.
    """
    pattern = attack_patterns_db.get(pattern_id)
    if not pattern:
        raise HTTPException(status_code=404, detail=f"Attack pattern {pattern_id} not found")
    return pattern


@router.patch("/patterns/{pattern_id}", response_model=AttackPattern)
async def update_attack_pattern(
    pattern_id: str,
    update: AttackPatternUpdate,
    current_user: str = Depends(get_current_active_user)
):
    """
    Update an attack pattern.
    """
    pattern = attack_patterns_db.get(pattern_id)
    if not pattern:
        raise HTTPException(status_code=404, detail=f"Attack pattern {pattern_id} not found")

    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(pattern, field, value)

    pattern.updated_at = datetime.utcnow()
    attack_patterns_db[pattern_id] = pattern

    return pattern


# =============================================================================
# MITRE ATT&CK Endpoints
# =============================================================================

@router.get("/mitre/tactics", response_model=List[MitreTactic])
async def list_mitre_tactics():
    """
    List all MITRE ATT&CK tactics.
    """
    return list(mitre_tactics_db.values())


@router.get("/mitre/tactics/{tactic_id}", response_model=MitreTactic)
async def get_mitre_tactic(tactic_id: str):
    """
    Get a specific MITRE ATT&CK tactic.
    """
    tactic = mitre_tactics_db.get(tactic_id)
    if not tactic:
        raise HTTPException(status_code=404, detail=f"Tactic {tactic_id} not found")
    return tactic


@router.get("/mitre/techniques", response_model=List[MitreTechnique])
async def list_mitre_techniques(
    tactic_id: Optional[str] = None,
    subtechniques: bool = True,
):
    """
    List MITRE ATT&CK techniques.
    """
    techniques = list(mitre_techniques_db.values())

    if tactic_id:
        techniques = [t for t in techniques if tactic_id in t.tactic_ids]
    if not subtechniques:
        techniques = [t for t in techniques if not t.is_subtechnique]

    return techniques


@router.get("/mitre/techniques/{technique_id}", response_model=MitreTechnique)
async def get_mitre_technique(technique_id: str):
    """
    Get a specific MITRE ATT&CK technique.
    """
    technique = mitre_techniques_db.get(technique_id)
    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return technique


# =============================================================================
# Kill Chain Analysis Endpoints
# =============================================================================

@router.post("/killchain/analyze", response_model=KillChainAnalysis)
async def analyze_kill_chain(
    request: KillChainAnalysisRequest,
    current_user: str = Depends(get_current_active_user)
):
    """
    Analyze kill chain progression for a source IP or target host.
    """
    analysis_id = generate_id()
    now = datetime.utcnow()
    start_time = now - timedelta(hours=request.time_range_hours)

    # Get relevant correlated alerts
    alerts = list(correlated_alerts_db.values())
    if request.source_ip:
        alerts = [a for a in alerts if request.source_ip in a.source_ips]
    if request.target_host:
        alerts = [a for a in alerts if request.target_host in a.hosts]

    alerts = [a for a in alerts if a.created_at >= start_time]

    if not request.include_all_severities:
        alerts = [a for a in alerts if a.severity in [SeverityEnum.HIGH, SeverityEnum.CRITICAL]]

    # Analyze kill chain phases
    all_phases = list(KillChainPhaseEnum)
    detected_phases = set()
    phase_details = {}

    for alert in alerts:
        if alert.kill_chain_phase:
            detected_phases.add(alert.kill_chain_phase)
            phase_name = alert.kill_chain_phase.value
            if phase_name not in phase_details:
                phase_details[phase_name] = {
                    "alert_count": 0,
                    "first_seen": alert.first_seen,
                    "last_seen": alert.last_seen,
                    "alert_ids": [],
                }
            phase_details[phase_name]["alert_count"] += 1
            phase_details[phase_name]["alert_ids"].append(alert.id)
            if alert.first_seen < phase_details[phase_name]["first_seen"]:
                phase_details[phase_name]["first_seen"] = alert.first_seen
            if alert.last_seen > phase_details[phase_name]["last_seen"]:
                phase_details[phase_name]["last_seen"] = alert.last_seen

    missing_phases = [p for p in all_phases if p not in detected_phases]
    coverage = len(detected_phases) / len(all_phases) * 100

    # Determine if there's potential attack progression
    phase_order = {p: i for i, p in enumerate(all_phases)}
    detected_ordered = sorted(detected_phases, key=lambda p: phase_order[p])
    potential_progression = len(detected_ordered) >= 3

    # Generate recommendations
    recommendations = []
    if KillChainPhaseEnum.RECONNAISSANCE in detected_phases:
        recommendations.append("Monitor for follow-up delivery attempts")
    if KillChainPhaseEnum.EXPLOITATION in detected_phases:
        recommendations.append("Check for lateral movement indicators")
    if KillChainPhaseEnum.COMMAND_AND_CONTROL in detected_phases:
        recommendations.append("Block identified C2 infrastructure immediately")
    if potential_progression:
        recommendations.append("URGENT: Multi-stage attack in progress - initiate incident response")

    # High risk indicators
    high_risk = []
    if KillChainPhaseEnum.COMMAND_AND_CONTROL in detected_phases:
        high_risk.append("Active C2 communication detected")
    if KillChainPhaseEnum.ACTIONS_ON_OBJECTIVES in detected_phases:
        high_risk.append("Adversary achieving objectives")

    return KillChainAnalysis(
        analysis_id=analysis_id,
        time_range_start=start_time,
        time_range_end=now,
        phases_detected=list(detected_phases),
        phases_missing=missing_phases,
        coverage_percent=round(coverage, 2),
        phase_details={k: {**v, "first_seen": v["first_seen"].isoformat(), "last_seen": v["last_seen"].isoformat()} for k, v in phase_details.items()},
        potential_attack_progression=potential_progression,
        high_risk_indicators=high_risk,
        recommendations=recommendations,
        related_alerts=[a.id for a in alerts],
        created_at=now,
    )


@router.get("/killchain/phases", response_model=List[Dict[str, str]])
async def list_kill_chain_phases():
    """
    List all kill chain phases with descriptions.
    """
    phases = [
        {"phase": KillChainPhaseEnum.RECONNAISSANCE.value, "description": "Attacker gathers information about the target"},
        {"phase": KillChainPhaseEnum.WEAPONIZATION.value, "description": "Attacker creates malicious payload"},
        {"phase": KillChainPhaseEnum.DELIVERY.value, "description": "Attacker transmits the weapon to the target"},
        {"phase": KillChainPhaseEnum.EXPLOITATION.value, "description": "Attacker exploits a vulnerability"},
        {"phase": KillChainPhaseEnum.INSTALLATION.value, "description": "Attacker installs malware on the target"},
        {"phase": KillChainPhaseEnum.COMMAND_AND_CONTROL.value, "description": "Attacker establishes command channel"},
        {"phase": KillChainPhaseEnum.ACTIONS_ON_OBJECTIVES.value, "description": "Attacker achieves their goals"},
    ]
    return phases


# =============================================================================
# Suppression Endpoints
# =============================================================================

@router.post("/suppressions", response_model=CorrelationSuppression, status_code=status.HTTP_201_CREATED)
async def create_suppression(
    suppression: SuppressionCreateRequest,
    current_user: str = Depends(get_current_active_user)
):
    """
    Create a suppression rule to temporarily suppress correlation alerts.
    """
    suppression_id = generate_id()
    now = datetime.utcnow()

    new_suppression = CorrelationSuppression(
        id=suppression_id,
        name=suppression.name,
        description=suppression.description,
        conditions=suppression.conditions,
        suppress_duration_minutes=suppression.suppress_duration_minutes,
        suppress_count=0,
        enabled=True,
        expires_at=suppression.expires_at,
        created_at=now,
        created_by=current_user,
    )

    suppressions_db[suppression_id] = new_suppression
    logger.info(f"Created suppression rule: {suppression.name}")

    return new_suppression


@router.get("/suppressions", response_model=SuppressionListResponse)
async def list_suppressions(
    enabled_only: bool = False,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """
    List suppression rules.
    """
    suppressions = list(suppressions_db.values())

    if enabled_only:
        now = datetime.utcnow()
        suppressions = [
            s for s in suppressions
            if s.enabled and (s.expires_at is None or s.expires_at > now)
        ]

    total = len(suppressions)
    active_count = len([s for s in suppressions if s.enabled])
    suppressions = suppressions[skip:skip + limit]

    return SuppressionListResponse(
        suppressions=suppressions,
        total=total,
        active_count=active_count,
    )


@router.delete("/suppressions/{suppression_id}", response_model=APIResponse)
async def delete_suppression(
    suppression_id: str,
    current_user: str = Depends(get_current_active_user)
):
    """
    Delete a suppression rule.
    """
    if suppression_id not in suppressions_db:
        raise HTTPException(status_code=404, detail=f"Suppression {suppression_id} not found")

    del suppressions_db[suppression_id]
    return APIResponse(
        status=StatusEnum.SUCCESS,
        message=f"Suppression {suppression_id} deleted successfully"
    )


# =============================================================================
# Statistics and Health Endpoints
# =============================================================================

@router.get("/stats", response_model=CorrelationStats)
async def get_correlation_stats():
    """
    Get correlation engine statistics.
    """
    rules = list(correlation_rules_db.values())
    alerts = list(correlated_alerts_db.values())
    patterns = list(attack_patterns_db.values())

    # Calculate 24h stats
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    alerts_24h = [a for a in alerts if a.created_at >= cutoff_24h]

    # Kill chain coverage
    kill_chain_coverage = defaultdict(int)
    for alert in alerts:
        if alert.kill_chain_phase:
            kill_chain_coverage[alert.kill_chain_phase.value] += 1

    # Top triggered rules
    top_rules = sorted(rules, key=lambda r: r.trigger_count, reverse=True)[:5]
    top_triggered = [{"rule_id": r.id, "name": r.name, "trigger_count": r.trigger_count} for r in top_rules]

    # MITRE technique frequency
    mitre_freq = defaultdict(int)
    for alert in alerts:
        if alert.mitre_mapping:
            for technique in alert.mitre_mapping.technique_ids:
                mitre_freq[technique] += 1

    # Average processing time
    avg_time = sum(correlation_stats["processing_times_ms"][-100:]) / max(len(correlation_stats["processing_times_ms"][-100:]), 1)

    # Deduplication rate
    total_processed = correlation_stats["alerts_processed"] or 1
    dedup_rate = (correlation_stats["alerts_deduplicated"] / total_processed) * 100

    return CorrelationStats(
        total_rules=len(rules),
        active_rules=len([r for r in rules if r.enabled]),
        disabled_rules=len([r for r in rules if not r.enabled]),
        total_correlated_alerts=len(alerts),
        open_correlated_alerts=len([a for a in alerts if a.status == CorrelatedAlertStatusEnum.OPEN]),
        alerts_processed_24h=correlation_stats["alerts_processed"],
        correlations_triggered_24h=correlation_stats["correlations_triggered"],
        alerts_deduplicated_24h=correlation_stats["alerts_deduplicated"],
        deduplication_rate_percent=round(dedup_rate, 2),
        avg_correlation_time_ms=round(avg_time, 2),
        active_attack_patterns=len([p for p in patterns if p.status in [
            AttackPatternStatusEnum.DETECTED,
            AttackPatternStatusEnum.IN_PROGRESS,
        ]]),
        kill_chain_coverage=dict(kill_chain_coverage),
        top_triggered_rules=top_triggered,
        mitre_technique_frequency=dict(mitre_freq),
    )


@router.get("/health", response_model=CorrelationHealthCheck)
async def get_correlation_health():
    """
    Health check for the correlation engine.
    """
    now = datetime.utcnow()
    rules = list(correlation_rules_db.values())
    alerts = list(correlated_alerts_db.values())

    # Check rules status
    active_rules = len([r for r in rules if r.enabled])
    rules_status = {
        "total": len(rules),
        "active": active_rules,
        "healthy": active_rules > 0,
    }

    # Check processing status
    recent_times = correlation_stats["processing_times_ms"][-10:]
    avg_latency = sum(recent_times) / max(len(recent_times), 1)
    processing_status = {
        "alerts_in_buffer": len(ingested_alerts_db),
        "last_10_latencies_ms": recent_times,
        "avg_latency_ms": round(avg_latency, 2),
    }

    # Determine overall health
    queue_depth = len(ingested_alerts_db)
    error_rate = 0.0  # Would track actual errors in production

    if queue_depth > 10000 or error_rate > 5.0:
        status = "unhealthy"
    elif queue_depth > 5000 or error_rate > 1.0 or active_rules == 0:
        status = "degraded"
    else:
        status = "healthy"

    # Recommendations
    recommendations = []
    if active_rules == 0:
        recommendations.append("No active correlation rules - create rules to enable correlation")
    if queue_depth > 5000:
        recommendations.append("High queue depth - consider scaling or reducing alert volume")
    if avg_latency > 100:
        recommendations.append("High latency - review rule complexity")

    # Find last correlation
    last_correlation = None
    if alerts:
        last_correlation = max(a.created_at for a in alerts)

    return CorrelationHealthCheck(
        status=status,
        timestamp=now,
        rules_status=rules_status,
        processing_status=processing_status,
        queue_depth=queue_depth,
        avg_latency_ms=round(avg_latency, 2),
        error_rate_percent=error_rate,
        last_correlation_at=last_correlation,
        recommendations=recommendations,
    )
