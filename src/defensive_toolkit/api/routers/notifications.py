"""
Notification Hub Router (v1.7.7)

Unified notification management supporting multiple channels:
- Email (SMTP)
- Slack (Webhook/Bot)
- Microsoft Teams (Webhook)
- PagerDuty (Events API)
- Generic Webhooks
- SMS (Twilio/Nexmo/AWS SNS)
- Discord (Webhook)
- OpsGenie
- VictorOps/Splunk On-Call

Features:
- Multi-channel notification routing
- Message templates with Jinja2
- Routing rules and conditions
- Escalation policies
- Rate limiting per channel
- Deduplication
- Delivery tracking and retries
"""

import logging
import re
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from fastapi.responses import JSONResponse

from api.auth import get_current_active_user
from api.models import (
    StatusEnum,
    # Channel Types and Enums
    NotificationChannelTypeEnum,
    NotificationPriorityEnum,
    NotificationStatusEnum,
    NotificationCategoryEnum,
    ChannelStatusEnum,
    # Channel Models
    NotificationChannelCreate,
    NotificationChannelUpdate,
    NotificationChannel,
    NotificationChannelResponse,
    NotificationChannelListResponse,
    # Template Models
    NotificationTemplateCreate,
    NotificationTemplateUpdate,
    NotificationTemplate,
    NotificationTemplateResponse,
    NotificationTemplateListResponse,
    TemplateRenderRequest,
    TemplateRenderResponse,
    TemplateVariableInfo,
    # Routing Rule Models
    RoutingRuleCreate,
    RoutingRuleUpdate,
    RoutingRule,
    RoutingRuleResponse,
    RoutingRuleListResponse,
    RoutingCondition,
    RoutingAction,
    # Notification Models
    NotificationCreate,
    Notification,
    NotificationResponse,
    NotificationListResponse,
    NotificationRetryRequest,
    NotificationRecipient,
    # Escalation Models
    EscalationPolicyCreate,
    EscalationPolicyUpdate,
    EscalationPolicy,
    EscalationPolicyResponse,
    EscalationPolicyListResponse,
    EscalationStep,
    ActiveEscalation,
    EscalationAcknowledgeRequest,
    EscalationResolveRequest,
    # Stats and Health
    NotificationStats,
    NotificationHealthCheck,
    ChannelTestRequest,
    ChannelTestResponse,
    # Bulk Operations
    BulkNotificationRequest,
    BulkNotificationResponse,
    # Subscriptions
    NotificationSubscription,
    SubscriptionCreateRequest,
    SubscriptionUpdateRequest,
    SubscriptionListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["Notifications"])

# ============================================================================
# In-Memory Storage (Production: Use database + Redis for queue)
# ============================================================================

channels_db: Dict[str, Dict[str, Any]] = {}
templates_db: Dict[str, Dict[str, Any]] = {}
routing_rules_db: Dict[str, Dict[str, Any]] = {}
notifications_db: Dict[str, Dict[str, Any]] = {}
escalation_policies_db: Dict[str, Dict[str, Any]] = {}
active_escalations_db: Dict[str, Dict[str, Any]] = {}
subscriptions_db: Dict[str, Dict[str, Any]] = {}

# Rate limiting tracking
rate_limits: Dict[str, Dict[str, List[datetime]]] = {}

# Deduplication cache
dedupe_cache: Dict[str, datetime] = {}

# Notification queue
notification_queue: List[Dict[str, Any]] = []


# ============================================================================
# Helper Functions
# ============================================================================

def generate_channel_id() -> str:
    """Generate unique channel ID"""
    return f"ch_{secrets.token_hex(8)}"


def generate_template_id() -> str:
    """Generate unique template ID"""
    return f"tpl_{secrets.token_hex(8)}"


def generate_rule_id() -> str:
    """Generate unique routing rule ID"""
    return f"rule_{secrets.token_hex(8)}"


def generate_notification_id() -> str:
    """Generate unique notification ID"""
    return f"notif_{secrets.token_hex(12)}"


def generate_policy_id() -> str:
    """Generate unique escalation policy ID"""
    return f"esc_{secrets.token_hex(8)}"


def generate_escalation_id() -> str:
    """Generate unique active escalation ID"""
    return f"active_{secrets.token_hex(8)}"


def generate_subscription_id() -> str:
    """Generate unique subscription ID"""
    return f"sub_{secrets.token_hex(8)}"


def check_rate_limit(channel_id: str, limits: Dict[str, int]) -> bool:
    """
    Check if channel is within rate limits.
    Returns True if allowed, False if rate limited.
    """
    now = datetime.utcnow()

    if channel_id not in rate_limits:
        rate_limits[channel_id] = {"minute": [], "hour": []}

    # Clean old entries
    minute_ago = now - timedelta(minutes=1)
    hour_ago = now - timedelta(hours=1)

    rate_limits[channel_id]["minute"] = [
        t for t in rate_limits[channel_id]["minute"] if t > minute_ago
    ]
    rate_limits[channel_id]["hour"] = [
        t for t in rate_limits[channel_id]["hour"] if t > hour_ago
    ]

    # Check limits
    per_minute = limits.get("rate_limit_per_minute", 60)
    per_hour = limits.get("rate_limit_per_hour", 500)

    if len(rate_limits[channel_id]["minute"]) >= per_minute:
        return False
    if len(rate_limits[channel_id]["hour"]) >= per_hour:
        return False

    # Record this request
    rate_limits[channel_id]["minute"].append(now)
    rate_limits[channel_id]["hour"].append(now)

    return True


def check_dedupe(key: str, window_seconds: int) -> bool:
    """
    Check if notification should be deduplicated.
    Returns True if duplicate (should skip), False if new.
    """
    if not key:
        return False

    now = datetime.utcnow()

    # Clean old entries
    expired_keys = [
        k for k, t in dedupe_cache.items()
        if (now - t).total_seconds() > 3600  # Clean after 1 hour
    ]
    for k in expired_keys:
        del dedupe_cache[k]

    # Check if exists within window
    if key in dedupe_cache:
        cached_time = dedupe_cache[key]
        if (now - cached_time).total_seconds() < window_seconds:
            return True  # Duplicate

    # Record new entry
    dedupe_cache[key] = now
    return False


def render_template(template_str: str, variables: Dict[str, Any]) -> str:
    """
    Simple template rendering using Python string formatting.
    For production, use Jinja2 with sandboxing for security.
    """
    try:
        # Simple {{variable}} replacement
        result = template_str
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", str(value))
        return result
    except Exception as e:
        logger.error(f"Template rendering error: {e}")
        return template_str


def evaluate_condition(condition: RoutingCondition, notification: Dict[str, Any]) -> bool:
    """Evaluate a single routing condition against a notification"""
    field = condition.field
    operator = condition.operator
    expected = condition.value

    # Get actual value from notification
    if field == "category":
        actual = notification.get("category")
    elif field == "priority":
        actual = notification.get("priority")
    elif field == "source":
        actual = notification.get("source")
    elif field == "tag":
        actual = notification.get("tags", [])
    elif field == "custom":
        actual = notification.get("metadata", {}).get(str(expected).split(".")[0])
    else:
        actual = None

    # Evaluate based on operator
    if operator == "equals":
        return actual == expected
    elif operator == "not_equals":
        return actual != expected
    elif operator == "contains":
        if isinstance(actual, list):
            return expected in actual
        return str(expected) in str(actual)
    elif operator == "regex":
        try:
            return bool(re.match(str(expected), str(actual)))
        except re.error:
            return False
    elif operator == "in":
        if isinstance(expected, list):
            return actual in expected
        return False
    elif operator == "not_in":
        if isinstance(expected, list):
            return actual not in expected
        return True
    elif operator in ("gt", "lt", "gte", "lte"):
        try:
            actual_num = float(actual)
            expected_num = float(expected)
            if operator == "gt":
                return actual_num > expected_num
            elif operator == "lt":
                return actual_num < expected_num
            elif operator == "gte":
                return actual_num >= expected_num
            elif operator == "lte":
                return actual_num <= expected_num
        except (ValueError, TypeError):
            return False

    return False


def match_routing_rules(notification: Dict[str, Any]) -> List[str]:
    """Find all matching routing rules for a notification"""
    matched_rules = []

    # Sort rules by priority (lower number = higher priority)
    sorted_rules = sorted(
        routing_rules_db.values(),
        key=lambda r: r.get("priority", 100)
    )

    for rule in sorted_rules:
        if not rule.get("enabled", True):
            continue

        conditions = rule.get("conditions", [])
        logic = rule.get("condition_logic", "all")

        if not conditions:
            # No conditions = always match
            matched_rules.append(rule["id"])
            continue

        # Evaluate conditions
        results = []
        for cond_data in conditions:
            cond = RoutingCondition(**cond_data)
            results.append(evaluate_condition(cond, notification))

        if logic == "all":
            if all(results):
                matched_rules.append(rule["id"])
        else:  # any
            if any(results):
                matched_rules.append(rule["id"])

    return matched_rules


async def send_to_channel(
    channel: Dict[str, Any],
    notification: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Send notification to a specific channel.
    This is a mock implementation - production would integrate with actual APIs.
    """
    channel_type = channel.get("channel_type")
    config = channel.get("config", {})

    result = {
        "channel_id": channel["id"],
        "channel_type": channel_type,
        "status": "delivered",
        "sent_at": datetime.utcnow().isoformat(),
        "response_time_ms": 150,  # Mock response time
    }

    # Simulate different channel behaviors
    if channel_type == NotificationChannelTypeEnum.EMAIL.value:
        result["details"] = {
            "recipients": config.get("default_recipients", []),
            "from": config.get("from_address"),
            "message_id": f"msg_{secrets.token_hex(8)}@defensivetoolkit.local"
        }

    elif channel_type == NotificationChannelTypeEnum.SLACK.value:
        result["details"] = {
            "channel": config.get("default_channel", "#alerts"),
            "ts": f"1234567890.{secrets.token_hex(4)}"
        }

    elif channel_type == NotificationChannelTypeEnum.TEAMS.value:
        result["details"] = {
            "message_id": secrets.token_hex(16),
            "activity_id": secrets.token_hex(8)
        }

    elif channel_type == NotificationChannelTypeEnum.PAGERDUTY.value:
        result["details"] = {
            "dedup_key": notification.get("dedupe_key") or secrets.token_hex(8),
            "incident_key": f"dt_{secrets.token_hex(8)}"
        }

    elif channel_type == NotificationChannelTypeEnum.WEBHOOK.value:
        result["details"] = {
            "url": config.get("url"),
            "response_code": 200,
            "response_body": '{"status": "received"}'
        }

    elif channel_type == NotificationChannelTypeEnum.SMS.value:
        result["details"] = {
            "provider": config.get("provider"),
            "message_sid": f"SM{secrets.token_hex(16)}"
        }

    elif channel_type == NotificationChannelTypeEnum.DISCORD.value:
        result["details"] = {
            "message_id": secrets.token_hex(18)
        }

    elif channel_type == NotificationChannelTypeEnum.OPSGENIE.value:
        result["details"] = {
            "request_id": secrets.token_hex(16),
            "alert_id": secrets.token_hex(12)
        }

    elif channel_type == NotificationChannelTypeEnum.VICTOROPS.value:
        result["details"] = {
            "entity_id": f"{config.get('entity_id_prefix', 'dt')}-{secrets.token_hex(8)}"
        }

    else:
        result["details"] = {"note": "Custom channel type"}

    logger.info(f"Notification sent to {channel_type} channel {channel['id']}")
    return result


async def process_notification(notification_id: str):
    """Background task to process and send a notification"""
    if notification_id not in notifications_db:
        logger.error(f"Notification {notification_id} not found for processing")
        return

    notification = notifications_db[notification_id]
    notification["status"] = NotificationStatusEnum.SENDING.value
    notification["updated_at"] = datetime.utcnow().isoformat()

    # Get recipients and channels
    recipients = notification.get("recipients", [])
    channel_statuses = {}

    success_count = 0
    failure_count = 0

    for recipient in recipients:
        channel_id = recipient.get("channel_id")
        if channel_id not in channels_db:
            channel_statuses[channel_id] = {
                "status": "failed",
                "error": "Channel not found"
            }
            failure_count += 1
            continue

        channel = channels_db[channel_id]

        # Check if channel is enabled
        if not channel.get("enabled", True):
            channel_statuses[channel_id] = {
                "status": "skipped",
                "reason": "Channel disabled"
            }
            continue

        # Check rate limits
        if not check_rate_limit(channel_id, channel):
            channel_statuses[channel_id] = {
                "status": "rate_limited",
                "retry_after_seconds": 60
            }
            channels_db[channel_id]["status"] = ChannelStatusEnum.RATE_LIMITED.value
            failure_count += 1
            continue

        try:
            result = await send_to_channel(channel, notification)
            channel_statuses[channel_id] = result
            success_count += 1

            # Update channel stats
            channels_db[channel_id]["success_count"] = channel.get("success_count", 0) + 1
            channels_db[channel_id]["last_used"] = datetime.utcnow().isoformat()

        except Exception as e:
            channel_statuses[channel_id] = {
                "status": "failed",
                "error": str(e)
            }
            failure_count += 1

            # Update channel error stats
            channels_db[channel_id]["failure_count"] = channel.get("failure_count", 0) + 1
            channels_db[channel_id]["last_error"] = str(e)
            channels_db[channel_id]["last_error_at"] = datetime.utcnow().isoformat()

    # Update notification status
    notification["channel_statuses"] = channel_statuses
    notification["updated_at"] = datetime.utcnow().isoformat()

    if failure_count == 0 and success_count > 0:
        notification["status"] = NotificationStatusEnum.DELIVERED.value
        notification["delivered_at"] = datetime.utcnow().isoformat()
    elif success_count > 0 and failure_count > 0:
        notification["status"] = NotificationStatusEnum.PARTIAL.value
    elif failure_count > 0:
        notification["status"] = NotificationStatusEnum.FAILED.value
        notification["failed_at"] = datetime.utcnow().isoformat()

    notifications_db[notification_id] = notification
    logger.info(f"Notification {notification_id} processed: {success_count} succeeded, {failure_count} failed")


# ============================================================================
# Channel Management Endpoints
# ============================================================================

@router.get("/channels", response_model=NotificationChannelListResponse)
async def list_channels(
    channel_type: Optional[NotificationChannelTypeEnum] = None,
    status: Optional[ChannelStatusEnum] = None,
    enabled: Optional[bool] = None,
    current_user: str = Depends(get_current_active_user),
):
    """List all notification channels with optional filtering."""
    channels = list(channels_db.values())

    if channel_type:
        channels = [c for c in channels if c.get("channel_type") == channel_type.value]
    if status:
        channels = [c for c in channels if c.get("status") == status.value]
    if enabled is not None:
        channels = [c for c in channels if c.get("enabled") == enabled]

    # Calculate statistics
    by_type = {}
    by_status = {}
    for c in channels_db.values():
        ct = c.get("channel_type", "unknown")
        cs = c.get("status", "unknown")
        by_type[ct] = by_type.get(ct, 0) + 1
        by_status[cs] = by_status.get(cs, 0) + 1

    return NotificationChannelListResponse(
        channels=[NotificationChannel(**c) for c in channels],
        total=len(channels),
        by_type=by_type,
        by_status=by_status,
    )


@router.get("/channels/{channel_id}", response_model=NotificationChannelResponse)
async def get_channel(
    channel_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get details of a specific notification channel."""
    if channel_id not in channels_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Channel {channel_id} not found"}
        )

    return NotificationChannelResponse(
        status=StatusEnum.SUCCESS,
        message="Channel retrieved successfully",
        channel=NotificationChannel(**channels_db[channel_id]),
    )


@router.post("/channels", response_model=NotificationChannelResponse)
async def create_channel(
    request: NotificationChannelCreate,
    current_user: str = Depends(get_current_active_user),
):
    """Create a new notification channel."""
    now = datetime.utcnow()
    channel_id = generate_channel_id()

    channel_data = {
        "id": channel_id,
        "name": request.name,
        "channel_type": request.channel_type.value,
        "description": request.description,
        "enabled": request.enabled,
        "categories": [c.value for c in request.categories],
        "priority_threshold": request.priority_threshold.value,
        "rate_limit_per_minute": request.rate_limit_per_minute,
        "rate_limit_per_hour": request.rate_limit_per_hour,
        "config": request.config,
        "status": ChannelStatusEnum.ACTIVE.value,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "last_used": None,
        "success_count": 0,
        "failure_count": 0,
        "last_error": None,
        "last_error_at": None,
    }

    channels_db[channel_id] = channel_data
    logger.info(f"Created notification channel: {channel_id} ({request.channel_type.value})")

    return NotificationChannelResponse(
        status=StatusEnum.SUCCESS,
        message=f"Channel '{request.name}' created successfully",
        channel=NotificationChannel(**channel_data),
    )


@router.put("/channels/{channel_id}", response_model=NotificationChannelResponse)
async def update_channel(
    channel_id: str,
    request: NotificationChannelUpdate,
    current_user: str = Depends(get_current_active_user),
):
    """Update an existing notification channel."""
    if channel_id not in channels_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Channel {channel_id} not found"}
        )

    channel = channels_db[channel_id]

    if request.name is not None:
        channel["name"] = request.name
    if request.description is not None:
        channel["description"] = request.description
    if request.enabled is not None:
        channel["enabled"] = request.enabled
    if request.categories is not None:
        channel["categories"] = [c.value for c in request.categories]
    if request.priority_threshold is not None:
        channel["priority_threshold"] = request.priority_threshold.value
    if request.rate_limit_per_minute is not None:
        channel["rate_limit_per_minute"] = request.rate_limit_per_minute
    if request.rate_limit_per_hour is not None:
        channel["rate_limit_per_hour"] = request.rate_limit_per_hour
    if request.config is not None:
        channel["config"] = request.config

    channel["updated_at"] = datetime.utcnow().isoformat()
    channels_db[channel_id] = channel

    logger.info(f"Updated notification channel: {channel_id}")

    return NotificationChannelResponse(
        status=StatusEnum.SUCCESS,
        message=f"Channel updated successfully",
        channel=NotificationChannel(**channel),
    )


@router.delete("/channels/{channel_id}", response_model=NotificationChannelResponse)
async def delete_channel(
    channel_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Delete a notification channel."""
    if channel_id not in channels_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Channel {channel_id} not found"}
        )

    channel = channels_db.pop(channel_id)
    logger.info(f"Deleted notification channel: {channel_id}")

    return NotificationChannelResponse(
        status=StatusEnum.SUCCESS,
        message=f"Channel '{channel['name']}' deleted successfully",
        channel=None,
    )


@router.post("/channels/{channel_id}/test", response_model=ChannelTestResponse)
async def test_channel(
    channel_id: str,
    request: ChannelTestRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Test a notification channel by sending a test message."""
    if channel_id not in channels_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Channel {channel_id} not found"}
        )

    channel = channels_db[channel_id]

    # Simulate test notification
    test_notification = {
        "subject": "Test Notification",
        "body": request.test_message,
        "category": NotificationCategoryEnum.SYSTEM_HEALTH.value,
        "priority": NotificationPriorityEnum.LOW.value,
    }

    try:
        start_time = datetime.utcnow()
        result = await send_to_channel(channel, test_notification)
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        return ChannelTestResponse(
            status=StatusEnum.SUCCESS,
            message="Test notification sent successfully",
            channel_id=channel_id,
            response_time_ms=response_time,
            details=result.get("details", {}),
        )
    except Exception as e:
        return ChannelTestResponse(
            status=StatusEnum.ERROR,
            message=f"Test failed: {str(e)}",
            channel_id=channel_id,
            response_time_ms=0,
            details={"error": str(e)},
        )


# ============================================================================
# Template Management Endpoints
# ============================================================================

@router.get("/templates", response_model=NotificationTemplateListResponse)
async def list_templates(
    category: Optional[NotificationCategoryEnum] = None,
    current_user: str = Depends(get_current_active_user),
):
    """List all notification templates."""
    templates = list(templates_db.values())

    if category:
        templates = [t for t in templates if t.get("category") == category.value]

    # Calculate statistics
    by_category = {}
    for t in templates_db.values():
        cat = t.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

    return NotificationTemplateListResponse(
        templates=[NotificationTemplate(**t) for t in templates],
        total=len(templates),
        by_category=by_category,
    )


@router.get("/templates/{template_id}", response_model=NotificationTemplateResponse)
async def get_template(
    template_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get details of a specific template."""
    if template_id not in templates_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Template {template_id} not found"}
        )

    return NotificationTemplateResponse(
        status=StatusEnum.SUCCESS,
        message="Template retrieved successfully",
        template=NotificationTemplate(**templates_db[template_id]),
    )


@router.post("/templates", response_model=NotificationTemplateResponse)
async def create_template(
    request: NotificationTemplateCreate,
    current_user: str = Depends(get_current_active_user),
):
    """Create a new notification template."""
    now = datetime.utcnow()
    template_id = generate_template_id()

    template_data = {
        "id": template_id,
        "name": request.name,
        "category": request.category.value,
        "description": request.description,
        "subject_template": request.subject_template,
        "body_template": request.body_template,
        "html_template": request.html_template,
        "variables": [v.model_dump() for v in request.variables],
        "default_priority": request.default_priority.value,
        "channel_overrides": request.channel_overrides,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "usage_count": 0,
        "last_used": None,
    }

    templates_db[template_id] = template_data
    logger.info(f"Created notification template: {template_id}")

    return NotificationTemplateResponse(
        status=StatusEnum.SUCCESS,
        message=f"Template '{request.name}' created successfully",
        template=NotificationTemplate(**template_data),
    )


@router.put("/templates/{template_id}", response_model=NotificationTemplateResponse)
async def update_template(
    template_id: str,
    request: NotificationTemplateUpdate,
    current_user: str = Depends(get_current_active_user),
):
    """Update an existing notification template."""
    if template_id not in templates_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Template {template_id} not found"}
        )

    template = templates_db[template_id]

    if request.name is not None:
        template["name"] = request.name
    if request.category is not None:
        template["category"] = request.category.value
    if request.description is not None:
        template["description"] = request.description
    if request.subject_template is not None:
        template["subject_template"] = request.subject_template
    if request.body_template is not None:
        template["body_template"] = request.body_template
    if request.html_template is not None:
        template["html_template"] = request.html_template
    if request.variables is not None:
        template["variables"] = [v.model_dump() for v in request.variables]
    if request.default_priority is not None:
        template["default_priority"] = request.default_priority.value
    if request.channel_overrides is not None:
        template["channel_overrides"] = request.channel_overrides

    template["updated_at"] = datetime.utcnow().isoformat()
    templates_db[template_id] = template

    logger.info(f"Updated notification template: {template_id}")

    return NotificationTemplateResponse(
        status=StatusEnum.SUCCESS,
        message="Template updated successfully",
        template=NotificationTemplate(**template),
    )


@router.delete("/templates/{template_id}", response_model=NotificationTemplateResponse)
async def delete_template(
    template_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Delete a notification template."""
    if template_id not in templates_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Template {template_id} not found"}
        )

    template = templates_db.pop(template_id)
    logger.info(f"Deleted notification template: {template_id}")

    return NotificationTemplateResponse(
        status=StatusEnum.SUCCESS,
        message=f"Template '{template['name']}' deleted successfully",
        template=None,
    )


@router.post("/templates/render", response_model=TemplateRenderResponse)
async def render_template_preview(
    request: TemplateRenderRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Render a template with provided variables for preview."""
    if request.template_id not in templates_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Template {request.template_id} not found"}
        )

    template = templates_db[request.template_id]

    # Get template content (with channel override if specified)
    body_template = template.get("body_template", "")
    subject_template = template.get("subject_template")
    html_template = template.get("html_template")

    if request.target_channel:
        overrides = template.get("channel_overrides", {}).get(request.target_channel.value, {})
        if "body" in overrides:
            body_template = overrides["body"]
        if "subject" in overrides:
            subject_template = overrides["subject"]

    # Render templates
    rendered_body = render_template(body_template, request.variables)
    rendered_subject = render_template(subject_template, request.variables) if subject_template else None
    rendered_html = render_template(html_template, request.variables) if html_template else None

    # Find used and missing variables
    template_vars = template.get("variables", [])
    required_vars = [v["name"] for v in template_vars if v.get("required")]
    all_vars = [v["name"] for v in template_vars]

    provided_vars = set(request.variables.keys())
    missing_vars = [v for v in required_vars if v not in provided_vars]

    # Update template usage
    templates_db[request.template_id]["usage_count"] = template.get("usage_count", 0) + 1
    templates_db[request.template_id]["last_used"] = datetime.utcnow().isoformat()

    return TemplateRenderResponse(
        status=StatusEnum.SUCCESS,
        subject=rendered_subject,
        body=rendered_body,
        html=rendered_html,
        variables_used=list(provided_vars & set(all_vars)),
        missing_variables=missing_vars,
    )


# ============================================================================
# Routing Rule Endpoints
# ============================================================================

@router.get("/routing-rules", response_model=RoutingRuleListResponse)
async def list_routing_rules(
    enabled: Optional[bool] = None,
    current_user: str = Depends(get_current_active_user),
):
    """List all routing rules sorted by priority."""
    rules = list(routing_rules_db.values())

    if enabled is not None:
        rules = [r for r in rules if r.get("enabled") == enabled]

    # Sort by priority (lower = higher priority)
    rules.sort(key=lambda r: r.get("priority", 100))

    return RoutingRuleListResponse(
        rules=[RoutingRule(**r) for r in rules],
        total=len(rules),
    )


@router.get("/routing-rules/{rule_id}", response_model=RoutingRuleResponse)
async def get_routing_rule(
    rule_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get details of a specific routing rule."""
    if rule_id not in routing_rules_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Rule {rule_id} not found"}
        )

    return RoutingRuleResponse(
        status=StatusEnum.SUCCESS,
        message="Rule retrieved successfully",
        rule=RoutingRule(**routing_rules_db[rule_id]),
    )


@router.post("/routing-rules", response_model=RoutingRuleResponse)
async def create_routing_rule(
    request: RoutingRuleCreate,
    current_user: str = Depends(get_current_active_user),
):
    """Create a new routing rule."""
    now = datetime.utcnow()
    rule_id = generate_rule_id()

    rule_data = {
        "id": rule_id,
        "name": request.name,
        "description": request.description,
        "enabled": request.enabled,
        "priority": request.priority,
        "conditions": [c.model_dump() for c in request.conditions],
        "condition_logic": request.condition_logic,
        "actions": [a.model_dump() for a in request.actions],
        "schedule": request.schedule,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "match_count": 0,
        "last_matched": None,
    }

    routing_rules_db[rule_id] = rule_data
    logger.info(f"Created routing rule: {rule_id}")

    return RoutingRuleResponse(
        status=StatusEnum.SUCCESS,
        message=f"Rule '{request.name}' created successfully",
        rule=RoutingRule(**rule_data),
    )


@router.put("/routing-rules/{rule_id}", response_model=RoutingRuleResponse)
async def update_routing_rule(
    rule_id: str,
    request: RoutingRuleUpdate,
    current_user: str = Depends(get_current_active_user),
):
    """Update an existing routing rule."""
    if rule_id not in routing_rules_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Rule {rule_id} not found"}
        )

    rule = routing_rules_db[rule_id]

    if request.name is not None:
        rule["name"] = request.name
    if request.description is not None:
        rule["description"] = request.description
    if request.enabled is not None:
        rule["enabled"] = request.enabled
    if request.priority is not None:
        rule["priority"] = request.priority
    if request.conditions is not None:
        rule["conditions"] = [c.model_dump() for c in request.conditions]
    if request.condition_logic is not None:
        rule["condition_logic"] = request.condition_logic
    if request.actions is not None:
        rule["actions"] = [a.model_dump() for a in request.actions]
    if request.schedule is not None:
        rule["schedule"] = request.schedule

    rule["updated_at"] = datetime.utcnow().isoformat()
    routing_rules_db[rule_id] = rule

    logger.info(f"Updated routing rule: {rule_id}")

    return RoutingRuleResponse(
        status=StatusEnum.SUCCESS,
        message="Rule updated successfully",
        rule=RoutingRule(**rule),
    )


@router.delete("/routing-rules/{rule_id}", response_model=RoutingRuleResponse)
async def delete_routing_rule(
    rule_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Delete a routing rule."""
    if rule_id not in routing_rules_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Rule {rule_id} not found"}
        )

    rule = routing_rules_db.pop(rule_id)
    logger.info(f"Deleted routing rule: {rule_id}")

    return RoutingRuleResponse(
        status=StatusEnum.SUCCESS,
        message=f"Rule '{rule['name']}' deleted successfully",
        rule=None,
    )


# ============================================================================
# Notification Endpoints
# ============================================================================

@router.get("/", response_model=NotificationListResponse)
async def list_notifications(
    status_filter: Optional[NotificationStatusEnum] = Query(None, alias="status"),
    category: Optional[NotificationCategoryEnum] = None,
    priority: Optional[NotificationPriorityEnum] = None,
    source: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    current_user: str = Depends(get_current_active_user),
):
    """List notifications with optional filtering and pagination."""
    notifications = list(notifications_db.values())

    if status_filter:
        notifications = [n for n in notifications if n.get("status") == status_filter.value]
    if category:
        notifications = [n for n in notifications if n.get("category") == category.value]
    if priority:
        notifications = [n for n in notifications if n.get("priority") == priority.value]
    if source:
        notifications = [n for n in notifications if n.get("source") == source]

    # Sort by created_at descending
    notifications.sort(key=lambda n: n.get("created_at", ""), reverse=True)

    # Paginate
    total = len(notifications)
    start = (page - 1) * page_size
    end = start + page_size
    notifications = notifications[start:end]

    # Calculate statistics
    by_status = {}
    by_category = {}
    for n in notifications_db.values():
        s = n.get("status", "unknown")
        c = n.get("category", "unknown")
        by_status[s] = by_status.get(s, 0) + 1
        by_category[c] = by_category.get(c, 0) + 1

    return NotificationListResponse(
        notifications=[Notification(**n) for n in notifications],
        total=total,
        page=page,
        page_size=page_size,
        by_status=by_status,
        by_category=by_category,
    )


@router.get("/{notification_id}", response_model=NotificationResponse)
async def get_notification(
    notification_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get details of a specific notification."""
    if notification_id not in notifications_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Notification {notification_id} not found"}
        )

    return NotificationResponse(
        status=StatusEnum.SUCCESS,
        message="Notification retrieved successfully",
        notification=Notification(**notifications_db[notification_id]),
    )


@router.post("/", response_model=NotificationResponse)
async def send_notification(
    request: NotificationCreate,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_active_user),
):
    """Send a notification through configured channels."""
    now = datetime.utcnow()

    # Check deduplication
    if request.dedupe_key:
        if check_dedupe(request.dedupe_key, request.dedupe_window_seconds):
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "status": "error",
                    "message": f"Duplicate notification (dedupe_key: {request.dedupe_key})"
                }
            )

    notification_id = generate_notification_id()

    # Process template if specified
    subject = request.subject
    body = request.body
    html_body = request.html_body

    if request.template_id:
        if request.template_id in templates_db:
            template = templates_db[request.template_id]
            if template.get("subject_template"):
                subject = render_template(template["subject_template"], request.template_variables)
            if template.get("body_template"):
                body = render_template(template["body_template"], request.template_variables)
            if template.get("html_template"):
                html_body = render_template(template["html_template"], request.template_variables)

    # Build notification data
    notification_data = {
        "id": notification_id,
        "category": request.category.value,
        "priority": request.priority.value,
        "subject": subject,
        "body": body,
        "html_body": html_body,
        "source": request.source,
        "source_id": request.source_id,
        "tags": request.tags,
        "metadata": request.metadata,
        "recipients": [r.model_dump() for r in request.recipients],
        "template_id": request.template_id,
        "template_variables": request.template_variables,
        "status": NotificationStatusEnum.PENDING.value,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "queued_at": None,
        "sent_at": None,
        "delivered_at": None,
        "failed_at": None,
        "retry_count": 0,
        "max_retries": 3,
        "next_retry_at": None,
        "channel_statuses": {},
        "error_message": None,
        "routing_rules_matched": [],
    }

    # Match routing rules and apply actions
    matched_rules = match_routing_rules(notification_data)
    notification_data["routing_rules_matched"] = matched_rules

    # Update rule match counts
    for rule_id in matched_rules:
        if rule_id in routing_rules_db:
            routing_rules_db[rule_id]["match_count"] = routing_rules_db[rule_id].get("match_count", 0) + 1
            routing_rules_db[rule_id]["last_matched"] = now.isoformat()

    # If no explicit recipients, use routing rules to determine channels
    if not notification_data["recipients"]:
        for rule_id in matched_rules:
            if rule_id in routing_rules_db:
                rule = routing_rules_db[rule_id]
                for action in rule.get("actions", []):
                    if action.get("action_type") == "route":
                        for channel_id in action.get("channel_ids", []):
                            notification_data["recipients"].append({
                                "channel_id": channel_id,
                                "address": None,
                                "metadata": {}
                            })

    # Check for deferred delivery
    if request.defer_until and request.defer_until > now:
        notification_data["status"] = NotificationStatusEnum.QUEUED.value
        notification_data["queued_at"] = now.isoformat()
        # In production, this would be added to a delayed queue
        notifications_db[notification_id] = notification_data

        return NotificationResponse(
            status=StatusEnum.SUCCESS,
            message=f"Notification queued for delivery at {request.defer_until.isoformat()}",
            notification=Notification(**notification_data),
        )

    notifications_db[notification_id] = notification_data

    # Process notification in background
    background_tasks.add_task(process_notification, notification_id)

    logger.info(f"Notification {notification_id} created and queued for delivery")

    return NotificationResponse(
        status=StatusEnum.SUCCESS,
        message="Notification sent successfully",
        notification=Notification(**notification_data),
    )


@router.post("/{notification_id}/retry", response_model=NotificationResponse)
async def retry_notification(
    notification_id: str,
    background_tasks: BackgroundTasks,
    request: Optional[NotificationRetryRequest] = None,
    current_user: str = Depends(get_current_active_user),
):
    """Retry a failed notification."""
    if notification_id not in notifications_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Notification {notification_id} not found"}
        )

    notification = notifications_db[notification_id]

    if notification["status"] not in [
        NotificationStatusEnum.FAILED.value,
        NotificationStatusEnum.PARTIAL.value
    ]:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"status": "error", "message": "Only failed or partial notifications can be retried"}
        )

    # Increment retry count
    notification["retry_count"] = notification.get("retry_count", 0) + 1
    notification["status"] = NotificationStatusEnum.RETRYING.value
    notification["updated_at"] = datetime.utcnow().isoformat()

    # If specific channels requested, filter recipients
    if request and request.channels:
        notification["recipients"] = [
            r for r in notification["recipients"]
            if r["channel_id"] in request.channels
        ]

    notifications_db[notification_id] = notification

    # Process retry in background
    background_tasks.add_task(process_notification, notification_id)

    logger.info(f"Retrying notification {notification_id} (attempt {notification['retry_count']})")

    return NotificationResponse(
        status=StatusEnum.SUCCESS,
        message=f"Notification retry initiated (attempt {notification['retry_count']})",
        notification=Notification(**notification),
    )


@router.post("/bulk", response_model=BulkNotificationResponse)
async def send_bulk_notifications(
    request: BulkNotificationRequest,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_active_user),
):
    """Send multiple notifications in bulk."""
    results = []
    succeeded = 0
    failed = 0

    for notif_request in request.notifications:
        try:
            # Create notification without background processing for now
            now = datetime.utcnow()
            notification_id = generate_notification_id()

            notification_data = {
                "id": notification_id,
                "category": notif_request.category.value,
                "priority": notif_request.priority.value,
                "subject": notif_request.subject,
                "body": notif_request.body,
                "html_body": notif_request.html_body,
                "source": notif_request.source,
                "source_id": notif_request.source_id,
                "tags": notif_request.tags,
                "metadata": notif_request.metadata,
                "recipients": [r.model_dump() for r in notif_request.recipients],
                "template_id": notif_request.template_id,
                "template_variables": notif_request.template_variables,
                "status": NotificationStatusEnum.PENDING.value,
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
                "queued_at": None,
                "sent_at": None,
                "delivered_at": None,
                "failed_at": None,
                "retry_count": 0,
                "max_retries": 3,
                "next_retry_at": None,
                "channel_statuses": {},
                "error_message": None,
                "routing_rules_matched": [],
            }

            notifications_db[notification_id] = notification_data
            background_tasks.add_task(process_notification, notification_id)

            results.append({
                "notification_id": notification_id,
                "status": "queued",
                "subject": notif_request.subject,
            })
            succeeded += 1

        except Exception as e:
            results.append({
                "subject": notif_request.subject,
                "status": "failed",
                "error": str(e),
            })
            failed += 1

            if request.fail_on_first_error:
                break

    return BulkNotificationResponse(
        status=StatusEnum.SUCCESS if failed == 0 else StatusEnum.ERROR,
        total_requested=len(request.notifications),
        succeeded=succeeded,
        failed=failed,
        results=results,
    )


# ============================================================================
# Escalation Policy Endpoints
# ============================================================================

@router.get("/escalation-policies", response_model=EscalationPolicyListResponse)
async def list_escalation_policies(
    enabled: Optional[bool] = None,
    current_user: str = Depends(get_current_active_user),
):
    """List all escalation policies."""
    policies = list(escalation_policies_db.values())

    if enabled is not None:
        policies = [p for p in policies if p.get("enabled") == enabled]

    return EscalationPolicyListResponse(
        policies=[EscalationPolicy(**p) for p in policies],
        total=len(policies),
    )


@router.get("/escalation-policies/{policy_id}", response_model=EscalationPolicyResponse)
async def get_escalation_policy(
    policy_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Get details of a specific escalation policy."""
    if policy_id not in escalation_policies_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Policy {policy_id} not found"}
        )

    return EscalationPolicyResponse(
        status=StatusEnum.SUCCESS,
        message="Policy retrieved successfully",
        policy=EscalationPolicy(**escalation_policies_db[policy_id]),
    )


@router.post("/escalation-policies", response_model=EscalationPolicyResponse)
async def create_escalation_policy(
    request: EscalationPolicyCreate,
    current_user: str = Depends(get_current_active_user),
):
    """Create a new escalation policy."""
    now = datetime.utcnow()
    policy_id = generate_policy_id()

    policy_data = {
        "id": policy_id,
        "name": request.name,
        "description": request.description,
        "enabled": request.enabled,
        "categories": [c.value for c in request.categories],
        "min_priority": request.min_priority.value,
        "steps": [s.model_dump() for s in request.steps],
        "acknowledgment_timeout_minutes": request.acknowledgment_timeout_minutes,
        "total_timeout_minutes": request.total_timeout_minutes,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "trigger_count": 0,
        "last_triggered": None,
    }

    escalation_policies_db[policy_id] = policy_data
    logger.info(f"Created escalation policy: {policy_id}")

    return EscalationPolicyResponse(
        status=StatusEnum.SUCCESS,
        message=f"Escalation policy '{request.name}' created successfully",
        policy=EscalationPolicy(**policy_data),
    )


@router.put("/escalation-policies/{policy_id}", response_model=EscalationPolicyResponse)
async def update_escalation_policy(
    policy_id: str,
    request: EscalationPolicyUpdate,
    current_user: str = Depends(get_current_active_user),
):
    """Update an existing escalation policy."""
    if policy_id not in escalation_policies_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Policy {policy_id} not found"}
        )

    policy = escalation_policies_db[policy_id]

    if request.name is not None:
        policy["name"] = request.name
    if request.description is not None:
        policy["description"] = request.description
    if request.enabled is not None:
        policy["enabled"] = request.enabled
    if request.categories is not None:
        policy["categories"] = [c.value for c in request.categories]
    if request.min_priority is not None:
        policy["min_priority"] = request.min_priority.value
    if request.steps is not None:
        policy["steps"] = [s.model_dump() for s in request.steps]
    if request.acknowledgment_timeout_minutes is not None:
        policy["acknowledgment_timeout_minutes"] = request.acknowledgment_timeout_minutes
    if request.total_timeout_minutes is not None:
        policy["total_timeout_minutes"] = request.total_timeout_minutes

    policy["updated_at"] = datetime.utcnow().isoformat()
    escalation_policies_db[policy_id] = policy

    logger.info(f"Updated escalation policy: {policy_id}")

    return EscalationPolicyResponse(
        status=StatusEnum.SUCCESS,
        message="Policy updated successfully",
        policy=EscalationPolicy(**policy),
    )


@router.delete("/escalation-policies/{policy_id}", response_model=EscalationPolicyResponse)
async def delete_escalation_policy(
    policy_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Delete an escalation policy."""
    if policy_id not in escalation_policies_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Policy {policy_id} not found"}
        )

    policy = escalation_policies_db.pop(policy_id)
    logger.info(f"Deleted escalation policy: {policy_id}")

    return EscalationPolicyResponse(
        status=StatusEnum.SUCCESS,
        message=f"Policy '{policy['name']}' deleted successfully",
        policy=None,
    )


# ============================================================================
# Active Escalation Endpoints
# ============================================================================

@router.get("/escalations/active")
async def list_active_escalations(
    current_user: str = Depends(get_current_active_user),
):
    """List all active escalations."""
    escalations = [
        e for e in active_escalations_db.values()
        if e.get("status") == "active"
    ]

    return {
        "escalations": [ActiveEscalation(**e) for e in escalations],
        "total": len(escalations),
    }


@router.post("/escalations/acknowledge")
async def acknowledge_escalation(
    request: EscalationAcknowledgeRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Acknowledge an active escalation."""
    if request.escalation_id not in active_escalations_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Escalation {request.escalation_id} not found"}
        )

    escalation = active_escalations_db[request.escalation_id]

    if escalation["status"] != "active":
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"status": "error", "message": "Escalation is not active"}
        )

    now = datetime.utcnow()
    escalation["status"] = "acknowledged"
    escalation["acknowledged_at"] = now.isoformat()
    escalation["acknowledged_by"] = request.acknowledged_by
    escalation["step_history"].append({
        "action": "acknowledged",
        "by": request.acknowledged_by,
        "at": now.isoformat(),
        "note": request.note,
    })

    active_escalations_db[request.escalation_id] = escalation
    logger.info(f"Escalation {request.escalation_id} acknowledged by {request.acknowledged_by}")

    return {
        "status": "success",
        "message": "Escalation acknowledged successfully",
        "escalation": ActiveEscalation(**escalation),
    }


@router.post("/escalations/resolve")
async def resolve_escalation(
    request: EscalationResolveRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Resolve an active escalation."""
    if request.escalation_id not in active_escalations_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Escalation {request.escalation_id} not found"}
        )

    escalation = active_escalations_db[request.escalation_id]

    if escalation["status"] not in ["active", "acknowledged"]:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"status": "error", "message": "Escalation cannot be resolved"}
        )

    now = datetime.utcnow()
    escalation["status"] = "resolved"
    escalation["resolved_at"] = now.isoformat()
    escalation["resolved_by"] = request.resolved_by
    escalation["step_history"].append({
        "action": "resolved",
        "by": request.resolved_by,
        "at": now.isoformat(),
        "note": request.resolution_note,
    })

    active_escalations_db[request.escalation_id] = escalation
    logger.info(f"Escalation {request.escalation_id} resolved by {request.resolved_by}")

    return {
        "status": "success",
        "message": "Escalation resolved successfully",
        "escalation": ActiveEscalation(**escalation),
    }


# ============================================================================
# Subscription Endpoints
# ============================================================================

@router.get("/subscriptions", response_model=SubscriptionListResponse)
async def list_subscriptions(
    subscriber_id: Optional[str] = None,
    subscriber_type: Optional[str] = None,
    enabled: Optional[bool] = None,
    current_user: str = Depends(get_current_active_user),
):
    """List notification subscriptions."""
    subs = list(subscriptions_db.values())

    if subscriber_id:
        subs = [s for s in subs if s.get("subscriber_id") == subscriber_id]
    if subscriber_type:
        subs = [s for s in subs if s.get("subscriber_type") == subscriber_type]
    if enabled is not None:
        subs = [s for s in subs if s.get("enabled") == enabled]

    return SubscriptionListResponse(
        subscriptions=[NotificationSubscription(**s) for s in subs],
        total=len(subs),
    )


@router.post("/subscriptions")
async def create_subscription(
    request: SubscriptionCreateRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Create a notification subscription."""
    now = datetime.utcnow()
    sub_id = generate_subscription_id()

    sub_data = {
        "id": sub_id,
        "subscriber_id": request.subscriber_id,
        "subscriber_type": request.subscriber_type,
        "categories": [c.value for c in request.categories],
        "min_priority": request.min_priority.value,
        "channels": request.channels,
        "schedule": request.schedule,
        "enabled": True,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    subscriptions_db[sub_id] = sub_data
    logger.info(f"Created subscription: {sub_id} for {request.subscriber_id}")

    return {
        "status": "success",
        "message": "Subscription created successfully",
        "subscription": NotificationSubscription(**sub_data),
    }


@router.put("/subscriptions/{subscription_id}")
async def update_subscription(
    subscription_id: str,
    request: SubscriptionUpdateRequest,
    current_user: str = Depends(get_current_active_user),
):
    """Update a notification subscription."""
    if subscription_id not in subscriptions_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Subscription {subscription_id} not found"}
        )

    sub = subscriptions_db[subscription_id]

    if request.categories is not None:
        sub["categories"] = [c.value for c in request.categories]
    if request.min_priority is not None:
        sub["min_priority"] = request.min_priority.value
    if request.channels is not None:
        sub["channels"] = request.channels
    if request.schedule is not None:
        sub["schedule"] = request.schedule
    if request.enabled is not None:
        sub["enabled"] = request.enabled

    sub["updated_at"] = datetime.utcnow().isoformat()
    subscriptions_db[subscription_id] = sub

    logger.info(f"Updated subscription: {subscription_id}")

    return {
        "status": "success",
        "message": "Subscription updated successfully",
        "subscription": NotificationSubscription(**sub),
    }


@router.delete("/subscriptions/{subscription_id}")
async def delete_subscription(
    subscription_id: str,
    current_user: str = Depends(get_current_active_user),
):
    """Delete a notification subscription."""
    if subscription_id not in subscriptions_db:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"status": "error", "message": f"Subscription {subscription_id} not found"}
        )

    sub = subscriptions_db.pop(subscription_id)
    logger.info(f"Deleted subscription: {subscription_id}")

    return {
        "status": "success",
        "message": "Subscription deleted successfully",
    }


# ============================================================================
# Statistics and Health Endpoints
# ============================================================================

@router.get("/stats", response_model=NotificationStats)
async def get_notification_stats(
    current_user: str = Depends(get_current_active_user),
):
    """Get notification system statistics."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    hour_start = now.replace(minute=0, second=0, microsecond=0)

    notifications = list(notifications_db.values())

    # Calculate statistics
    notifications_today = sum(
        1 for n in notifications
        if datetime.fromisoformat(n["created_at"]) >= today_start
    )
    notifications_this_hour = sum(
        1 for n in notifications
        if datetime.fromisoformat(n["created_at"]) >= hour_start
    )

    by_status = {}
    by_category = {}
    by_priority = {}
    by_channel = {}

    total_delivery_time = 0
    delivered_count = 0

    for n in notifications:
        s = n.get("status", "unknown")
        c = n.get("category", "unknown")
        p = n.get("priority", "unknown")

        by_status[s] = by_status.get(s, 0) + 1
        by_category[c] = by_category.get(c, 0) + 1
        by_priority[p] = by_priority.get(p, 0) + 1

        # Count by channel
        for ch_status in n.get("channel_statuses", {}).values():
            ch_type = ch_status.get("channel_type", "unknown")
            by_channel[ch_type] = by_channel.get(ch_type, 0) + 1

        # Calculate delivery time
        if n.get("delivered_at") and n.get("created_at"):
            created = datetime.fromisoformat(n["created_at"])
            delivered = datetime.fromisoformat(n["delivered_at"])
            total_delivery_time += (delivered - created).total_seconds()
            delivered_count += 1

    avg_delivery_time = total_delivery_time / delivered_count if delivered_count > 0 else 0
    success_rate = (by_status.get("delivered", 0) / len(notifications) * 100) if notifications else 0

    # Channel statistics
    channels = list(channels_db.values())
    channels_active = sum(1 for c in channels if c.get("status") == ChannelStatusEnum.ACTIVE.value)
    channels_error = sum(1 for c in channels if c.get("status") == ChannelStatusEnum.ERROR.value)
    rate_limited = sum(1 for c in channels if c.get("status") == ChannelStatusEnum.RATE_LIMITED.value)

    # Active escalations
    active_esc = sum(1 for e in active_escalations_db.values() if e.get("status") == "active")

    return NotificationStats(
        total_notifications=len(notifications),
        notifications_today=notifications_today,
        notifications_this_hour=notifications_this_hour,
        by_status=by_status,
        by_category=by_category,
        by_priority=by_priority,
        by_channel=by_channel,
        avg_delivery_time_seconds=avg_delivery_time,
        success_rate_percent=success_rate,
        active_escalations=active_esc,
        channels_active=channels_active,
        channels_error=channels_error,
        rate_limited_channels=rate_limited,
        queue_depth=len(notification_queue),
    )


@router.get("/health", response_model=NotificationHealthCheck)
async def get_notification_health(
    current_user: str = Depends(get_current_active_user),
):
    """Get notification system health status."""
    now = datetime.utcnow()

    # Check channel statuses
    channels_status = {}
    error_channels = 0

    for channel_id, channel in channels_db.items():
        ch_status = channel.get("status", "unknown")
        channels_status[channel_id] = {
            "name": channel.get("name"),
            "type": channel.get("channel_type"),
            "status": ch_status,
            "last_used": channel.get("last_used"),
            "success_count": channel.get("success_count", 0),
            "failure_count": channel.get("failure_count", 0),
        }

        if ch_status in [ChannelStatusEnum.ERROR.value, ChannelStatusEnum.RATE_LIMITED.value]:
            error_channels += 1

    # Get recent failures
    hour_ago = now - timedelta(hours=1)
    recent_failures = [
        {
            "notification_id": n["id"],
            "subject": n.get("subject"),
            "failed_at": n.get("failed_at"),
            "error": n.get("error_message"),
        }
        for n in notifications_db.values()
        if n.get("status") == NotificationStatusEnum.FAILED.value
        and n.get("failed_at")
        and datetime.fromisoformat(n["failed_at"]) >= hour_ago
    ][:10]  # Limit to 10 most recent

    # Determine overall health
    total_channels = len(channels_db)
    if error_channels == 0:
        health_status = "healthy"
    elif error_channels < total_channels / 2:
        health_status = "degraded"
    else:
        health_status = "unhealthy"

    # Generate recommendations
    recommendations = []

    if error_channels > 0:
        recommendations.append(f"Review and fix {error_channels} channel(s) with errors")

    if len(recent_failures) > 5:
        recommendations.append("High failure rate in the last hour - investigate notification delivery")

    if len(notification_queue) > 100:
        recommendations.append("Notification queue is building up - check processing capacity")

    # Check for channels with high failure rates
    for channel_id, channel in channels_db.items():
        success = channel.get("success_count", 0)
        failure = channel.get("failure_count", 0)
        total = success + failure
        if total > 10 and failure / total > 0.2:
            recommendations.append(f"Channel '{channel.get('name')}' has high failure rate ({failure}/{total})")

    return NotificationHealthCheck(
        status=health_status,
        timestamp=now,
        channels_status=channels_status,
        queue_status={
            "depth": len(notification_queue),
            "oldest_item_age_seconds": 0,  # Would track in production
        },
        recent_failures=recent_failures,
        recommendations=recommendations,
    )
