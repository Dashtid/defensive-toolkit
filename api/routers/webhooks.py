"""
Webhook API Router

Event-driven runbook triggers from SIEM alerts.
Supports Wazuh, Elastic, OpenSearch, Graylog, and custom sources.

Version: 1.7.2
Author: Defensive Toolkit
"""

import hashlib
import hmac
import json
import logging
import re
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    status,
)

from api.models import (
    APIResponse,
    IncomingAlert,
    RunbookExecuteRequest,
    RunbookExecutionModeEnum,
    StatusEnum,
    WebhookConfig,
    WebhookConfigList,
    WebhookSourceEnum,
    WebhookStats,
    WebhookStatusEnum,
    WebhookTestRequest,
    WebhookTestResult,
    WebhookTriggerResult,
    WebhookTriggerRule,
)
from api.dependencies import get_current_active_user, require_write_scope

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

# In-memory storage (replace with database in production)
webhooks_db: Dict[str, WebhookConfig] = {}
webhook_stats: Dict[str, Dict[str, Any]] = {}
trigger_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
rate_limit_tracker: Dict[str, Dict[str, datetime]] = defaultdict(dict)

# Import runbook execution function (lazy import to avoid circular)
_execute_runbook = None


def _get_runbook_executor():
    """Lazy import of runbook execution to avoid circular imports."""
    global _execute_runbook
    if _execute_runbook is None:
        from api.routers.incident_response import execute_runbook
        _execute_runbook = execute_runbook
    return _execute_runbook


# ============================================================================
# Helper Functions
# ============================================================================

def _generate_webhook_id() -> str:
    """Generate unique webhook ID."""
    return f"WH-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"


def _generate_rule_id() -> str:
    """Generate unique rule ID."""
    return f"RULE-{str(uuid.uuid4())[:8].upper()}"


def _verify_signature(
    payload: bytes,
    signature: str,
    secret: str,
    algorithm: str = "sha256"
) -> bool:
    """
    Verify HMAC signature of webhook payload.

    Supports formats:
    - sha256=<hex>
    - <hex> (assumes sha256)
    """
    if not secret:
        return True  # No secret configured, skip verification

    # Parse signature format
    if "=" in signature:
        algo, sig_hex = signature.split("=", 1)
    else:
        algo = algorithm
        sig_hex = signature

    # Calculate expected signature
    if algo == "sha256":
        expected = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
    elif algo == "sha1":
        expected = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha1
        ).hexdigest()
    else:
        logger.warning(f"[!] Unsupported signature algorithm: {algo}")
        return False

    # Constant-time comparison
    return hmac.compare_digest(expected.lower(), sig_hex.lower())


def _check_ip_allowed(client_ip: str, allowed_ips: List[str]) -> bool:
    """Check if client IP is in allowed list."""
    if not allowed_ips:
        return True  # No restrictions

    try:
        client = ip_address(client_ip)
        for allowed in allowed_ips:
            if "/" in allowed:
                # CIDR notation
                if client in ip_network(allowed, strict=False):
                    return True
            else:
                # Single IP
                if client == ip_address(allowed):
                    return True
        return False
    except ValueError as e:
        logger.warning(f"[!] Invalid IP check: {e}")
        return False


def _get_nested_value(data: Dict[str, Any], path: str) -> Any:
    """
    Get value from nested dict using dot notation.

    Example: _get_nested_value({"data": {"user": "john"}}, "data.user") -> "john"
    """
    keys = path.split(".")
    value = data

    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and key.isdigit():
            idx = int(key)
            value = value[idx] if 0 <= idx < len(value) else None
        else:
            return None

        if value is None:
            return None

    return value


def _parse_alert(
    payload: Dict[str, Any],
    config: WebhookConfig
) -> IncomingAlert:
    """Parse incoming alert payload using webhook configuration."""

    # Extract fields using configured paths
    alert_id = str(_get_nested_value(payload, config.alert_id_field) or uuid.uuid4())
    severity = str(_get_nested_value(payload, config.alert_severity_field) or "unknown")
    title = str(_get_nested_value(payload, config.alert_title_field) or "Unknown Alert")
    description = _get_nested_value(payload, config.alert_description_field)

    # Parse timestamp
    ts_value = _get_nested_value(payload, config.alert_timestamp_field)
    if ts_value:
        if isinstance(ts_value, (int, float)):
            timestamp = datetime.fromtimestamp(ts_value)
        elif isinstance(ts_value, str):
            try:
                timestamp = datetime.fromisoformat(ts_value.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()
    else:
        timestamp = datetime.utcnow()

    return IncomingAlert(
        alert_id=alert_id,
        source=config.source,
        severity=severity,
        title=title,
        description=str(description) if description else None,
        timestamp=timestamp,
        raw_payload=payload,
    )


def _match_rule(
    alert: IncomingAlert,
    rule: WebhookTriggerRule,
    payload: Dict[str, Any]
) -> bool:
    """Check if alert matches a trigger rule."""

    if not rule.enabled:
        return False

    # Get the field value to match
    field_value = _get_nested_value(payload, rule.match_field)
    if field_value is None:
        return False

    field_value = str(field_value)

    # Check match type
    if rule.match_type == "exact":
        if field_value != rule.match_pattern:
            return False
    elif rule.match_type == "contains":
        if rule.match_pattern not in field_value:
            return False
    elif rule.match_type == "regex":
        try:
            if not re.search(rule.match_pattern, field_value):
                return False
        except re.error as e:
            logger.warning(f"[!] Invalid regex in rule {rule.rule_id}: {e}")
            return False

    # Check severity constraints if specified
    # (simplified - in production, use proper severity ordering)

    return True


def _check_rate_limit(webhook_id: str, rule_id: str, rule: WebhookTriggerRule) -> bool:
    """Check if rule is within rate limits."""
    now = datetime.utcnow()
    key = f"{webhook_id}:{rule_id}"

    # Check cooldown
    last_trigger = rate_limit_tracker[key].get("last_trigger")
    if last_trigger:
        elapsed = (now - last_trigger).total_seconds()
        if elapsed < rule.cooldown_seconds:
            logger.info(f"[i] Rule {rule_id} in cooldown ({elapsed:.0f}s < {rule.cooldown_seconds}s)")
            return False

    # Check hourly limit
    hour_ago = now - timedelta(hours=1)
    triggers = trigger_history[key]
    recent_triggers = [t for t in triggers if t.get("timestamp", datetime.min) > hour_ago]

    if len(recent_triggers) >= rule.max_triggers_per_hour:
        logger.info(f"[i] Rule {rule_id} hit hourly limit ({len(recent_triggers)} >= {rule.max_triggers_per_hour})")
        return False

    return True


def _record_trigger(webhook_id: str, rule_id: str, alert_id: str):
    """Record trigger for rate limiting."""
    now = datetime.utcnow()
    key = f"{webhook_id}:{rule_id}"

    rate_limit_tracker[key]["last_trigger"] = now
    trigger_history[key].append({
        "timestamp": now,
        "alert_id": alert_id,
    })

    # Cleanup old entries (keep last 24h)
    day_ago = now - timedelta(hours=24)
    trigger_history[key] = [
        t for t in trigger_history[key]
        if t.get("timestamp", datetime.min) > day_ago
    ]


def _update_stats(
    webhook_id: str,
    received: bool = False,
    processed: bool = False,
    triggered: bool = False,
    skipped: bool = False,
    error: bool = False
):
    """Update webhook statistics."""
    if webhook_id not in webhook_stats:
        webhook_stats[webhook_id] = {
            "total_received": 0,
            "total_processed": 0,
            "total_triggered": 0,
            "total_skipped": 0,
            "total_errors": 0,
            "last_received_at": None,
            "last_triggered_at": None,
            "rule_triggers": defaultdict(int),
        }

    stats = webhook_stats[webhook_id]
    now = datetime.utcnow()

    if received:
        stats["total_received"] += 1
        stats["last_received_at"] = now
    if processed:
        stats["total_processed"] += 1
    if triggered:
        stats["total_triggered"] += 1
        stats["last_triggered_at"] = now
    if skipped:
        stats["total_skipped"] += 1
    if error:
        stats["total_errors"] += 1


def _extract_variables(
    payload: Dict[str, Any],
    mappings: Dict[str, str]
) -> Dict[str, Any]:
    """Extract variables from payload using mappings."""
    variables = {}

    for var_name, json_path in mappings.items():
        value = _get_nested_value(payload, json_path)
        if value is not None:
            variables[var_name] = value

    return variables


# ============================================================================
# Webhook Configuration Endpoints
# ============================================================================

@router.get("", response_model=WebhookConfigList)
async def list_webhooks(
    source: Optional[str] = Query(None, description="Filter by source"),
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    current_user: str = Depends(get_current_active_user),
):
    """
    List all webhook configurations.

    Returns webhook endpoints configured for receiving SIEM alerts.
    """
    webhooks = list(webhooks_db.values())

    if source:
        webhooks = [w for w in webhooks if w.source.value == source]
    if status_filter:
        webhooks = [w for w in webhooks if w.status.value == status_filter]

    # Sort by name
    webhooks.sort(key=lambda x: x.name)

    return WebhookConfigList(webhooks=webhooks, total=len(webhooks))


@router.get("/{webhook_id}", response_model=WebhookConfig)
async def get_webhook(
    webhook_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get webhook configuration details.

    Note: Secret key is masked in response.
    """
    if webhook_id not in webhooks_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found"
        )

    webhook = webhooks_db[webhook_id].model_copy()

    # Mask secret key
    if webhook.secret_key:
        webhook.secret_key = "***" + webhook.secret_key[-4:] if len(webhook.secret_key) > 4 else "****"

    return webhook


@router.post("", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    config: WebhookConfig,
    current_user: str = Depends(require_write_scope),
):
    """
    Create a new webhook configuration.

    Configure endpoint to receive alerts from SIEM and trigger runbooks.
    """
    # Generate ID
    config.webhook_id = _generate_webhook_id()
    config.created_at = datetime.utcnow()
    config.updated_at = datetime.utcnow()
    config.created_by = current_user

    # Generate rule IDs
    for rule in config.trigger_rules:
        if not rule.rule_id:
            rule.rule_id = _generate_rule_id()

    webhooks_db[config.webhook_id] = config

    logger.info(f"[+] Webhook created: {config.webhook_id} ({config.name})")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Webhook configuration created",
        data={
            "webhook_id": config.webhook_id,
            "endpoint": f"/api/v1/webhooks/{config.webhook_id}/trigger",
            "rules_count": len(config.trigger_rules),
        }
    )


@router.put("/{webhook_id}", response_model=APIResponse)
async def update_webhook(
    webhook_id: str,
    config: WebhookConfig,
    current_user: str = Depends(require_write_scope),
):
    """
    Update webhook configuration.

    Note: Secret key is only updated if a new non-empty value is provided.
    """
    if webhook_id not in webhooks_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found"
        )

    existing = webhooks_db[webhook_id]

    # Preserve certain fields
    config.webhook_id = webhook_id
    config.created_at = existing.created_at
    config.created_by = existing.created_by
    config.updated_at = datetime.utcnow()

    # Don't overwrite secret if masked value provided
    if config.secret_key and config.secret_key.startswith("***"):
        config.secret_key = existing.secret_key

    # Generate IDs for new rules
    for rule in config.trigger_rules:
        if not rule.rule_id:
            rule.rule_id = _generate_rule_id()

    webhooks_db[webhook_id] = config

    logger.info(f"[+] Webhook updated: {webhook_id}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Webhook configuration updated"
    )


@router.delete("/{webhook_id}", response_model=APIResponse)
async def delete_webhook(
    webhook_id: str,
    current_user: str = Depends(require_write_scope),
):
    """Delete a webhook configuration."""
    if webhook_id not in webhooks_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found"
        )

    del webhooks_db[webhook_id]

    # Cleanup stats
    if webhook_id in webhook_stats:
        del webhook_stats[webhook_id]

    logger.info(f"[+] Webhook deleted: {webhook_id}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Webhook configuration deleted"
    )


# ============================================================================
# Webhook Trigger Endpoint (receives alerts)
# ============================================================================

@router.post("/{webhook_id}/trigger", response_model=WebhookTriggerResult)
async def trigger_webhook(
    webhook_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_hub_signature: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_wazuh_signature: Optional[str] = Header(None, alias="X-Wazuh-Signature"),
):
    """
    Receive alert from SIEM and trigger appropriate runbook.

    This endpoint is called by SIEM systems when alerts fire.
    No authentication required - uses signature verification instead.

    Supports signature headers:
    - X-Signature: Generic HMAC signature
    - X-Hub-Signature-256: GitHub-style sha256=<hex>
    - X-Wazuh-Signature: Wazuh webhook signature
    """
    received_at = datetime.utcnow()

    # Get webhook config
    if webhook_id not in webhooks_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found"
        )

    config = webhooks_db[webhook_id]

    # Check if webhook is active
    if config.status == WebhookStatusEnum.DISABLED:
        return WebhookTriggerResult(
            webhook_id=webhook_id,
            alert_id="",
            received_at=received_at,
            processed=False,
            message="Webhook is disabled",
            skipped_reason="webhook_disabled",
        )

    # Get client IP
    client_ip = request.client.host if request.client else "unknown"

    # Check IP whitelist
    if not _check_ip_allowed(client_ip, config.allowed_ips):
        _update_stats(webhook_id, received=True, error=True)
        logger.warning(f"[!] Webhook {webhook_id}: IP {client_ip} not allowed")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Source IP not allowed"
        )

    # Get raw body for signature verification
    body = await request.body()

    # Verify signature if configured
    signature = x_signature or x_hub_signature or x_wazuh_signature
    if config.secret_key:
        if not signature:
            _update_stats(webhook_id, received=True, error=True)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Signature required"
            )

        if not _verify_signature(body, signature, config.secret_key):
            _update_stats(webhook_id, received=True, error=True)
            logger.warning(f"[!] Webhook {webhook_id}: Invalid signature")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid signature"
            )

    # Parse JSON payload
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        _update_stats(webhook_id, received=True, error=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON: {e}"
        )

    _update_stats(webhook_id, received=True)

    # Parse alert
    try:
        alert = _parse_alert(payload, config)
        alert.source_ip = client_ip
    except Exception as e:
        _update_stats(webhook_id, error=True)
        logger.error(f"[-] Webhook {webhook_id}: Failed to parse alert: {e}")
        return WebhookTriggerResult(
            webhook_id=webhook_id,
            alert_id="parse_error",
            received_at=received_at,
            processed=False,
            message=f"Failed to parse alert: {e}",
            skipped_reason="parse_error",
        )

    logger.info(f"[+] Webhook {webhook_id}: Received alert {alert.alert_id} - {alert.title}")

    # Find matching rule
    matched_rule: Optional[WebhookTriggerRule] = None

    for rule in config.trigger_rules:
        if _match_rule(alert, rule, payload):
            # Check rate limit
            if _check_rate_limit(webhook_id, rule.rule_id, rule):
                matched_rule = rule
                break
            else:
                _update_stats(webhook_id, skipped=True)
                return WebhookTriggerResult(
                    webhook_id=webhook_id,
                    alert_id=alert.alert_id,
                    received_at=received_at,
                    processed=True,
                    matched_rule=rule.rule_id,
                    message=f"Rule {rule.name} matched but rate limited",
                    skipped_reason="rate_limited",
                )

    # Use default if no rule matched
    runbook_id = None
    execution_mode = config.default_execution_mode
    auto_approve = None
    variable_mappings = {}

    if matched_rule:
        runbook_id = matched_rule.runbook_id
        execution_mode = matched_rule.execution_mode
        auto_approve = matched_rule.auto_approve_level
        variable_mappings = matched_rule.variable_mappings
        alert.matched_rule = matched_rule.rule_id
    elif config.default_runbook_id:
        runbook_id = config.default_runbook_id

    if not runbook_id:
        _update_stats(webhook_id, processed=True, skipped=True)
        return WebhookTriggerResult(
            webhook_id=webhook_id,
            alert_id=alert.alert_id,
            received_at=received_at,
            processed=True,
            message="No matching rule and no default runbook configured",
            skipped_reason="no_rule_match",
        )

    # Extract variables from alert
    variables = _extract_variables(payload, variable_mappings)
    variables["alert_id"] = alert.alert_id
    variables["alert_title"] = alert.title
    variables["alert_severity"] = alert.severity
    variables["alert_source"] = config.source.value
    variables["webhook_id"] = webhook_id

    # Record trigger for rate limiting
    if matched_rule:
        _record_trigger(webhook_id, matched_rule.rule_id, alert.alert_id)
        webhook_stats[webhook_id]["rule_triggers"][matched_rule.rule_id] += 1

    # Create execution request
    exec_request = RunbookExecuteRequest(
        runbook_id=runbook_id,
        mode=execution_mode,
        auto_approve_level=auto_approve,
        variables=variables,
    )

    # Execute runbook (import here to avoid circular)
    try:
        from api.routers.incident_response import (
            execute_runbook,
            executions_db,
            RUNBOOKS_DIR,
        )

        # Check if runbook exists
        yaml_file = RUNBOOKS_DIR / f"{runbook_id}.yaml"
        if not yaml_file.exists():
            yaml_file = RUNBOOKS_DIR / f"{runbook_id}.yml"

        if not yaml_file.exists():
            _update_stats(webhook_id, processed=True, error=True)
            return WebhookTriggerResult(
                webhook_id=webhook_id,
                alert_id=alert.alert_id,
                received_at=received_at,
                processed=True,
                matched_rule=matched_rule.rule_id if matched_rule else None,
                message=f"Runbook '{runbook_id}' not found",
                skipped_reason="runbook_not_found",
            )

        # Call execute_runbook (simulate the API call)
        # In production, this would use internal execution
        exec_response = await execute_runbook(
            request=exec_request,
            background_tasks=background_tasks,
            current_user=f"webhook:{webhook_id}",
        )

        _update_stats(webhook_id, processed=True, triggered=True)

        logger.info(
            f"[+] Webhook {webhook_id}: Triggered runbook {runbook_id} "
            f"(execution: {exec_response.execution_id})"
        )

        return WebhookTriggerResult(
            webhook_id=webhook_id,
            alert_id=alert.alert_id,
            received_at=received_at,
            processed=True,
            matched_rule=matched_rule.rule_id if matched_rule else None,
            execution_id=exec_response.execution_id,
            incident_id=exec_response.incident_id,
            runbook_triggered=runbook_id,
            execution_mode=execution_mode.value,
            message=f"Runbook '{runbook_id}' triggered successfully",
        )

    except Exception as e:
        _update_stats(webhook_id, processed=True, error=True)
        logger.error(f"[-] Webhook {webhook_id}: Runbook execution failed: {e}")
        return WebhookTriggerResult(
            webhook_id=webhook_id,
            alert_id=alert.alert_id,
            received_at=received_at,
            processed=True,
            matched_rule=matched_rule.rule_id if matched_rule else None,
            message=f"Runbook execution failed: {e}",
            skipped_reason="execution_error",
        )


# ============================================================================
# Testing and Statistics Endpoints
# ============================================================================

@router.post("/{webhook_id}/test", response_model=WebhookTestResult)
async def test_webhook(
    webhook_id: str,
    test_request: WebhookTestRequest,
    current_user: str = Depends(get_current_active_user),
):
    """
    Test webhook configuration with a sample payload.

    Tests parsing and rule matching without triggering execution.
    """
    if webhook_id not in webhooks_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found"
        )

    config = webhooks_db[webhook_id]
    errors = []
    warnings = []
    matched_rules = []

    # Test parsing
    try:
        alert = _parse_alert(test_request.test_payload, config)
    except Exception as e:
        return WebhookTestResult(
            webhook_id=webhook_id,
            test_passed=False,
            errors=[f"Failed to parse alert: {e}"],
            warnings=warnings,
        )

    # Check for missing fields
    if alert.alert_id == str(uuid.uuid4()):
        warnings.append(f"Alert ID field '{config.alert_id_field}' not found in payload")
    if alert.severity == "unknown":
        warnings.append(f"Severity field '{config.alert_severity_field}' not found in payload")
    if alert.title == "Unknown Alert":
        warnings.append(f"Title field '{config.alert_title_field}' not found in payload")

    # Test rule matching
    for rule in config.trigger_rules:
        if _match_rule(alert, rule, test_request.test_payload):
            matched_rules.append(rule.rule_id)

    # Determine what would be triggered
    would_trigger = None
    would_mode = None

    if matched_rules:
        # First matching rule
        for rule in config.trigger_rules:
            if rule.rule_id == matched_rules[0]:
                would_trigger = rule.runbook_id
                would_mode = rule.execution_mode.value
                break
    elif config.default_runbook_id:
        would_trigger = config.default_runbook_id
        would_mode = config.default_execution_mode.value
        warnings.append("No rules matched - would use default runbook")
    else:
        warnings.append("No rules matched and no default runbook configured")

    return WebhookTestResult(
        webhook_id=webhook_id,
        test_passed=len(errors) == 0,
        parsed_alert=alert,
        matched_rules=matched_rules,
        would_trigger_runbook=would_trigger,
        would_use_mode=would_mode,
        errors=errors,
        warnings=warnings,
    )


@router.get("/{webhook_id}/stats", response_model=WebhookStats)
async def get_webhook_stats(
    webhook_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get statistics for a webhook endpoint."""
    if webhook_id not in webhooks_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found"
        )

    config = webhooks_db[webhook_id]
    stats = webhook_stats.get(webhook_id, {})

    # Calculate recent triggers
    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(hours=24)

    triggers_last_hour = 0
    triggers_last_24h = 0

    for key, history in trigger_history.items():
        if key.startswith(f"{webhook_id}:"):
            for trigger in history:
                ts = trigger.get("timestamp", datetime.min)
                if ts > hour_ago:
                    triggers_last_hour += 1
                if ts > day_ago:
                    triggers_last_24h += 1

    # Get top triggered rules
    rule_triggers = stats.get("rule_triggers", {})
    top_rules = sorted(
        [{"rule_id": k, "count": v} for k, v in rule_triggers.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:5]

    return WebhookStats(
        webhook_id=webhook_id,
        webhook_name=config.name,
        total_received=stats.get("total_received", 0),
        total_processed=stats.get("total_processed", 0),
        total_triggered=stats.get("total_triggered", 0),
        total_skipped=stats.get("total_skipped", 0),
        total_errors=stats.get("total_errors", 0),
        last_received_at=stats.get("last_received_at"),
        last_triggered_at=stats.get("last_triggered_at"),
        triggers_last_hour=triggers_last_hour,
        triggers_last_24h=triggers_last_24h,
        top_triggered_rules=top_rules,
    )


# ============================================================================
# Trigger Rule Management
# ============================================================================

@router.post("/{webhook_id}/rules", response_model=APIResponse)
async def add_trigger_rule(
    webhook_id: str,
    rule: WebhookTriggerRule,
    current_user: str = Depends(require_write_scope),
):
    """Add a new trigger rule to webhook."""
    if webhook_id not in webhooks_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found"
        )

    config = webhooks_db[webhook_id]

    # Generate rule ID
    rule.rule_id = _generate_rule_id()

    # Validate regex if used
    if rule.match_type == "regex":
        try:
            re.compile(rule.match_pattern)
        except re.error as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid regex pattern: {e}"
            )

    config.trigger_rules.append(rule)
    config.updated_at = datetime.utcnow()

    logger.info(f"[+] Rule added to webhook {webhook_id}: {rule.rule_id}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Trigger rule added",
        data={"rule_id": rule.rule_id}
    )


@router.delete("/{webhook_id}/rules/{rule_id}", response_model=APIResponse)
async def delete_trigger_rule(
    webhook_id: str,
    rule_id: str,
    current_user: str = Depends(require_write_scope),
):
    """Remove a trigger rule from webhook."""
    if webhook_id not in webhooks_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook '{webhook_id}' not found"
        )

    config = webhooks_db[webhook_id]

    # Find and remove rule
    original_count = len(config.trigger_rules)
    config.trigger_rules = [r for r in config.trigger_rules if r.rule_id != rule_id]

    if len(config.trigger_rules) == original_count:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found"
        )

    config.updated_at = datetime.utcnow()

    logger.info(f"[+] Rule removed from webhook {webhook_id}: {rule_id}")

    return APIResponse(
        status=StatusEnum.SUCCESS,
        message="Trigger rule deleted"
    )


# ============================================================================
# Preset Configurations
# ============================================================================

@router.get("/presets/{source}", response_model=WebhookConfig)
async def get_webhook_preset(
    source: WebhookSourceEnum,
    current_user: str = Depends(get_current_active_user),
):
    """
    Get preset webhook configuration for a SIEM source.

    Returns pre-configured field mappings for common SIEM platforms.
    """
    presets = {
        WebhookSourceEnum.WAZUH: WebhookConfig(
            name="Wazuh Alerts",
            description="Preset for Wazuh SIEM alerts",
            source=WebhookSourceEnum.WAZUH,
            alert_id_field="id",
            alert_severity_field="rule.level",
            alert_title_field="rule.description",
            alert_description_field="full_log",
            alert_timestamp_field="timestamp",
            trigger_rules=[
                WebhookTriggerRule(
                    rule_id="PRESET-WAZUH-CRED",
                    name="Credential Compromise Detection",
                    description="Triggers on Wazuh credential access alerts",
                    match_field="rule.groups",
                    match_pattern="authentication_failed|credential_access",
                    match_type="regex",
                    runbook_id="credential_compromise",
                    execution_mode=RunbookExecutionModeEnum.DRY_RUN,
                    variable_mappings={
                        "compromised_user": "data.srcuser",
                        "source_ip": "data.srcip",
                    },
                ),
                WebhookTriggerRule(
                    rule_id="PRESET-WAZUH-MALWARE",
                    name="Malware Detection",
                    description="Triggers on Wazuh malware alerts",
                    match_field="rule.groups",
                    match_pattern="malware|virus|trojan",
                    match_type="regex",
                    runbook_id="malware",
                    execution_mode=RunbookExecutionModeEnum.DRY_RUN,
                    variable_mappings={
                        "malware_file": "data.file",
                    },
                ),
            ],
        ),
        WebhookSourceEnum.ELASTIC: WebhookConfig(
            name="Elastic SIEM Alerts",
            description="Preset for Elastic Security alerts",
            source=WebhookSourceEnum.ELASTIC,
            alert_id_field="kibana.alert.uuid",
            alert_severity_field="kibana.alert.severity",
            alert_title_field="kibana.alert.rule.name",
            alert_description_field="kibana.alert.reason",
            alert_timestamp_field="@timestamp",
            trigger_rules=[
                WebhookTriggerRule(
                    rule_id="PRESET-ELASTIC-RANSOMWARE",
                    name="Ransomware Detection",
                    description="Triggers on Elastic ransomware alerts",
                    match_field="kibana.alert.rule.tags",
                    match_pattern="ransomware|encryption",
                    match_type="regex",
                    runbook_id="ransomware",
                    execution_mode=RunbookExecutionModeEnum.DRY_RUN,
                ),
            ],
        ),
        WebhookSourceEnum.OPENSEARCH: WebhookConfig(
            name="OpenSearch Security Analytics",
            description="Preset for OpenSearch Security Analytics alerts",
            source=WebhookSourceEnum.OPENSEARCH,
            alert_id_field="alert_id",
            alert_severity_field="severity",
            alert_title_field="trigger_name",
            alert_description_field="alert_body",
            alert_timestamp_field="start_time",
            trigger_rules=[],
        ),
        WebhookSourceEnum.GRAYLOG: WebhookConfig(
            name="Graylog Alerts",
            description="Preset for Graylog event notifications",
            source=WebhookSourceEnum.GRAYLOG,
            alert_id_field="event.id",
            alert_severity_field="event.priority",
            alert_title_field="event_definition_title",
            alert_description_field="event.message",
            alert_timestamp_field="event.timestamp",
            trigger_rules=[],
        ),
        WebhookSourceEnum.GENERIC: WebhookConfig(
            name="Generic Webhook",
            description="Generic webhook with common field mappings",
            source=WebhookSourceEnum.GENERIC,
            alert_id_field="id",
            alert_severity_field="severity",
            alert_title_field="title",
            alert_description_field="description",
            alert_timestamp_field="timestamp",
            trigger_rules=[],
        ),
    }

    if source not in presets:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No preset available for source '{source.value}'"
        )

    return presets[source]
