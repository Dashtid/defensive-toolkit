#!/usr/bin/env python3
"""
Escalation Actions for Incident Response

Provides alerting, ticket creation, severity updates, and on-call
notification capabilities for incident response automation.

Author: Defensive Toolkit
Version: 1.0.0
Date: 2025-11-30

Integrations supported:
- Email (SMTP)
- Slack (Webhook)
- Microsoft Teams (Webhook)
- Jira (REST API)
- ServiceNow (REST API)
- PagerDuty (Events API)
"""

import json
import logging
import os
import platform
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Import ActionResult from parent - handle both direct and module import
try:
    from ..runbook_engine import ActionResult
except ImportError:
    class ActionResult:
        def __init__(self, success: bool, message: str, data: Optional[Dict] = None,
                     rollback_info: Optional[Dict] = None):
            self.success = success
            self.message = message
            self.data = data or {}
            self.rollback_info = rollback_info
            self.timestamp = datetime.now().isoformat()

        def to_dict(self) -> Dict:
            return {
                "success": self.success,
                "message": self.message,
                "data": self.data,
                "rollback_info": self.rollback_info,
                "timestamp": self.timestamp
            }

logger = logging.getLogger(__name__)


def send_alert(
    method: str,
    recipients: List[str],
    subject: str,
    message: str,
    severity: str = "medium",
    incident_id: Optional[str] = None,
    config: Optional[Dict] = None
) -> ActionResult:
    """
    Send alert notification via specified method.

    Args:
        method: Alert method (email, slack, teams, pagerduty)
        recipients: List of recipients (emails, channels, etc.)
        subject: Alert subject
        message: Alert message body
        severity: Alert severity (low, medium, high, critical)
        incident_id: Incident identifier
        config: Configuration for the alert method

    Returns:
        ActionResult with delivery status
    """
    logger.info(f"[+] Sending {method} alert: {subject}")

    config = config or {}
    incident_id = incident_id or f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    alert_handlers = {
        "email": _send_email_alert,
        "slack": _send_slack_alert,
        "teams": _send_teams_alert,
        "pagerduty": _send_pagerduty_alert,
    }

    handler = alert_handlers.get(method.lower())
    if not handler:
        return ActionResult(
            success=False,
            message=f"Unknown alert method: {method}"
        )

    return handler(recipients, subject, message, severity, incident_id, config)


def _send_email_alert(
    recipients: List[str],
    subject: str,
    message: str,
    severity: str,
    incident_id: str,
    config: Dict
) -> ActionResult:
    """Send email alert via SMTP"""
    # Get SMTP config from environment or config dict
    smtp_server = config.get("smtp_server") or os.getenv("SMTP_SERVER")
    smtp_port = int(config.get("smtp_port") or os.getenv("SMTP_PORT", "587"))
    smtp_user = config.get("smtp_user") or os.getenv("SMTP_USER")
    smtp_password = config.get("smtp_password") or os.getenv("SMTP_PASSWORD")
    from_address = config.get("from_address") or os.getenv("ALERT_FROM_ADDRESS", smtp_user)
    use_tls = config.get("use_tls", True)

    if not smtp_server:
        return ActionResult(
            success=False,
            message="SMTP server not configured. Set SMTP_SERVER environment variable or provide in config."
        )

    try:
        # Build email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{severity.upper()}] {subject}"
        msg["From"] = from_address
        msg["To"] = ", ".join(recipients)

        # Plain text version
        text_body = f"""
Incident Response Alert
=======================
Incident ID: {incident_id}
Severity: {severity.upper()}
Time: {datetime.now().isoformat()}
Hostname: {platform.node()}

{message}

--
This is an automated alert from the Defensive Toolkit IR system.
        """

        # HTML version
        severity_colors = {
            "low": "#28a745",
            "medium": "#ffc107",
            "high": "#fd7e14",
            "critical": "#dc3545"
        }
        color = severity_colors.get(severity.lower(), "#6c757d")

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: {color}; color: white; padding: 15px; border-radius: 5px 5px 0 0; }}
        .content {{ border: 1px solid #ddd; border-top: none; padding: 20px; }}
        .metadata {{ background: #f8f9fa; padding: 10px; margin-bottom: 15px; font-size: 14px; }}
        .footer {{ font-size: 12px; color: #666; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h2 style="margin: 0;">[{severity.upper()}] Incident Response Alert</h2>
    </div>
    <div class="content">
        <div class="metadata">
            <strong>Incident ID:</strong> {incident_id}<br>
            <strong>Severity:</strong> {severity.upper()}<br>
            <strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Source:</strong> {platform.node()}
        </div>
        <h3>{subject}</h3>
        <p>{message.replace(chr(10), '<br>')}</p>
        <div class="footer">
            <p>This is an automated alert from the Defensive Toolkit IR system.</p>
        </div>
    </div>
</body>
</html>
        """

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        # Send email
        context = ssl.create_default_context()

        if use_tls:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls(context=context)
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.sendmail(from_address, recipients, msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.sendmail(from_address, recipients, msg.as_string())

        return ActionResult(
            success=True,
            message=f"Email alert sent to {len(recipients)} recipient(s)",
            data={"recipients": recipients, "subject": subject}
        )

    except Exception as e:
        return ActionResult(success=False, message=f"Failed to send email: {e}")


def _send_slack_alert(
    recipients: List[str],
    subject: str,
    message: str,
    severity: str,
    incident_id: str,
    config: Dict
) -> ActionResult:
    """Send Slack alert via webhook"""
    webhook_url = config.get("webhook_url") or os.getenv("SLACK_WEBHOOK_URL")

    if not webhook_url:
        return ActionResult(
            success=False,
            message="Slack webhook URL not configured. Set SLACK_WEBHOOK_URL environment variable."
        )

    severity_emojis = {
        "low": ":large_blue_circle:",
        "medium": ":large_yellow_circle:",
        "high": ":large_orange_circle:",
        "critical": ":red_circle:"
    }
    emoji = severity_emojis.get(severity.lower(), ":warning:")

    payload = {
        "text": f"{emoji} *[{severity.upper()}] {subject}*",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"[{severity.upper()}] Incident Response Alert"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n{incident_id}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"},
                    {"type": "mrkdwn", "text": f"*Source:*\n{platform.node()}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{subject}*\n{message}"}
            }
        ]
    }

    # Add channel mentions if specified
    if recipients:
        payload["channel"] = recipients[0]

    try:
        data = json.dumps(payload).encode("utf-8")
        req = Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
        response = urlopen(req, timeout=30)

        if response.status == 200:
            return ActionResult(
                success=True,
                message="Slack alert sent successfully",
                data={"channel": recipients[0] if recipients else "default"}
            )
        else:
            return ActionResult(
                success=False,
                message=f"Slack API returned status {response.status}"
            )

    except (HTTPError, URLError) as e:
        return ActionResult(success=False, message=f"Failed to send Slack alert: {e}")


def _send_teams_alert(
    recipients: List[str],
    subject: str,
    message: str,
    severity: str,
    incident_id: str,
    config: Dict
) -> ActionResult:
    """Send Microsoft Teams alert via webhook"""
    webhook_url = config.get("webhook_url") or os.getenv("TEAMS_WEBHOOK_URL")

    if not webhook_url:
        return ActionResult(
            success=False,
            message="Teams webhook URL not configured. Set TEAMS_WEBHOOK_URL environment variable."
        )

    severity_colors = {
        "low": "28a745",
        "medium": "ffc107",
        "high": "fd7e14",
        "critical": "dc3545"
    }
    color = severity_colors.get(severity.lower(), "6c757d")

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"[{severity.upper()}] {subject}",
        "sections": [{
            "activityTitle": f"[{severity.upper()}] Incident Response Alert",
            "facts": [
                {"name": "Incident ID", "value": incident_id},
                {"name": "Severity", "value": severity.upper()},
                {"name": "Time", "value": datetime.now().strftime('%Y-%m-%d %H:%M:%S')},
                {"name": "Source", "value": platform.node()}
            ],
            "text": f"**{subject}**\n\n{message}"
        }]
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
        response = urlopen(req, timeout=30)

        if response.status == 200:
            return ActionResult(
                success=True,
                message="Teams alert sent successfully"
            )
        else:
            return ActionResult(
                success=False,
                message=f"Teams API returned status {response.status}"
            )

    except (HTTPError, URLError) as e:
        return ActionResult(success=False, message=f"Failed to send Teams alert: {e}")


def _send_pagerduty_alert(
    recipients: List[str],
    subject: str,
    message: str,
    severity: str,
    incident_id: str,
    config: Dict
) -> ActionResult:
    """Send PagerDuty alert via Events API"""
    routing_key = config.get("routing_key") or os.getenv("PAGERDUTY_ROUTING_KEY")

    if not routing_key:
        return ActionResult(
            success=False,
            message="PagerDuty routing key not configured. Set PAGERDUTY_ROUTING_KEY environment variable."
        )

    severity_map = {
        "low": "info",
        "medium": "warning",
        "high": "error",
        "critical": "critical"
    }

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": incident_id,
        "payload": {
            "summary": f"[{severity.upper()}] {subject}",
            "severity": severity_map.get(severity.lower(), "warning"),
            "source": platform.node(),
            "timestamp": datetime.now().isoformat(),
            "custom_details": {
                "incident_id": incident_id,
                "message": message
            }
        }
    }

    try:
        url = "https://events.pagerduty.com/v2/enqueue"
        data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, headers={"Content-Type": "application/json"})
        response = urlopen(req, timeout=30)

        result = json.loads(response.read().decode("utf-8"))

        if result.get("status") == "success":
            return ActionResult(
                success=True,
                message="PagerDuty alert created",
                data={"dedup_key": result.get("dedup_key")}
            )
        else:
            return ActionResult(
                success=False,
                message=f"PagerDuty API error: {result.get('message')}"
            )

    except (HTTPError, URLError) as e:
        return ActionResult(success=False, message=f"Failed to send PagerDuty alert: {e}")


def create_ticket(
    system: str,
    title: str,
    description: str,
    priority: str = "medium",
    incident_id: Optional[str] = None,
    assignee: Optional[str] = None,
    config: Optional[Dict] = None
) -> ActionResult:
    """
    Create incident ticket in ticketing system.

    Args:
        system: Ticketing system (jira, servicenow)
        title: Ticket title
        description: Ticket description
        priority: Ticket priority
        incident_id: Incident identifier
        assignee: Ticket assignee
        config: System-specific configuration

    Returns:
        ActionResult with ticket details
    """
    logger.info(f"[+] Creating {system} ticket: {title}")

    config = config or {}
    incident_id = incident_id or f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    ticket_handlers = {
        "jira": _create_jira_ticket,
        "servicenow": _create_servicenow_ticket,
    }

    handler = ticket_handlers.get(system.lower())
    if not handler:
        return ActionResult(
            success=False,
            message=f"Unknown ticketing system: {system}"
        )

    return handler(title, description, priority, incident_id, assignee, config)


def _create_jira_ticket(
    title: str,
    description: str,
    priority: str,
    incident_id: str,
    assignee: Optional[str],
    config: Dict
) -> ActionResult:
    """Create Jira ticket"""
    jira_url = config.get("url") or os.getenv("JIRA_URL")
    jira_user = config.get("user") or os.getenv("JIRA_USER")
    jira_token = config.get("token") or os.getenv("JIRA_API_TOKEN")
    project_key = config.get("project_key") or os.getenv("JIRA_PROJECT_KEY")
    issue_type = config.get("issue_type", "Task")

    if not all([jira_url, jira_user, jira_token, project_key]):
        return ActionResult(
            success=False,
            message="Jira configuration incomplete. Set JIRA_URL, JIRA_USER, JIRA_API_TOKEN, JIRA_PROJECT_KEY."
        )

    priority_map = {
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Highest"
    }

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[{incident_id}] {title}",
            "description": f"Incident ID: {incident_id}\n\n{description}\n\nCreated by: Defensive Toolkit IR",
            "issuetype": {"name": issue_type},
            "priority": {"name": priority_map.get(priority.lower(), "Medium")}
        }
    }

    if assignee:
        payload["fields"]["assignee"] = {"name": assignee}

    try:
        import base64
        auth = base64.b64encode(f"{jira_user}:{jira_token}".encode()).decode()

        url = f"{jira_url.rstrip('/')}/rest/api/2/issue"
        data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}"
        })
        response = urlopen(req, timeout=30)

        result = json.loads(response.read().decode("utf-8"))

        return ActionResult(
            success=True,
            message=f"Jira ticket created: {result.get('key')}",
            data={
                "ticket_key": result.get("key"),
                "ticket_id": result.get("id"),
                "url": f"{jira_url}/browse/{result.get('key')}"
            }
        )

    except (HTTPError, URLError) as e:
        return ActionResult(success=False, message=f"Failed to create Jira ticket: {e}")


def _create_servicenow_ticket(
    title: str,
    description: str,
    priority: str,
    incident_id: str,
    assignee: Optional[str],
    config: Dict
) -> ActionResult:
    """Create ServiceNow incident"""
    snow_url = config.get("url") or os.getenv("SERVICENOW_URL")
    snow_user = config.get("user") or os.getenv("SERVICENOW_USER")
    snow_password = config.get("password") or os.getenv("SERVICENOW_PASSWORD")

    if not all([snow_url, snow_user, snow_password]):
        return ActionResult(
            success=False,
            message="ServiceNow configuration incomplete. Set SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD."
        )

    # ServiceNow priority: 1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning
    priority_map = {
        "critical": "1",
        "high": "2",
        "medium": "3",
        "low": "4"
    }

    payload = {
        "short_description": f"[{incident_id}] {title}",
        "description": f"Incident ID: {incident_id}\n\n{description}\n\nCreated by: Defensive Toolkit IR",
        "priority": priority_map.get(priority.lower(), "3"),
        "urgency": priority_map.get(priority.lower(), "3"),
        "impact": priority_map.get(priority.lower(), "3")
    }

    if assignee:
        payload["assigned_to"] = assignee

    try:
        import base64
        auth = base64.b64encode(f"{snow_user}:{snow_password}".encode()).decode()

        url = f"{snow_url.rstrip('/')}/api/now/table/incident"
        data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Basic {auth}"
        })
        response = urlopen(req, timeout=30)

        result = json.loads(response.read().decode("utf-8"))
        incident = result.get("result", {})

        return ActionResult(
            success=True,
            message=f"ServiceNow incident created: {incident.get('number')}",
            data={
                "incident_number": incident.get("number"),
                "sys_id": incident.get("sys_id"),
                "url": f"{snow_url}/nav_to.do?uri=incident.do?sys_id={incident.get('sys_id')}"
            }
        )

    except (HTTPError, URLError) as e:
        return ActionResult(success=False, message=f"Failed to create ServiceNow incident: {e}")


def update_severity(
    incident_id: str,
    new_severity: str,
    reason: str,
    notify: bool = True,
    config: Optional[Dict] = None
) -> ActionResult:
    """
    Update incident severity level.

    Args:
        incident_id: Incident identifier
        new_severity: New severity level
        reason: Reason for severity change
        notify: Send notification about change
        config: Configuration options

    Returns:
        ActionResult with update status
    """
    logger.info(f"[+] Updating severity for {incident_id} to {new_severity}")

    valid_severities = ["low", "medium", "high", "critical"]
    if new_severity.lower() not in valid_severities:
        return ActionResult(
            success=False,
            message=f"Invalid severity: {new_severity}. Must be one of: {valid_severities}"
        )

    # Log the severity change
    change_record = {
        "incident_id": incident_id,
        "new_severity": new_severity,
        "reason": reason,
        "changed_at": datetime.now().isoformat(),
        "changed_by": os.getenv("USERNAME", os.getenv("USER", "unknown")),
        "hostname": platform.node()
    }

    # If notification is requested
    if notify:
        config = config or {}
        alert_method = config.get("alert_method", "email")
        recipients = config.get("recipients", [])

        if recipients:
            send_alert(
                method=alert_method,
                recipients=recipients,
                subject=f"Severity Updated: {incident_id}",
                message=f"Incident severity changed to {new_severity.upper()}\n\nReason: {reason}",
                severity=new_severity,
                incident_id=incident_id,
                config=config
            )

    return ActionResult(
        success=True,
        message=f"Severity updated to {new_severity}",
        data=change_record
    )


def notify_oncall(
    team: str,
    message: str,
    severity: str = "high",
    incident_id: Optional[str] = None,
    config: Optional[Dict] = None
) -> ActionResult:
    """
    Notify on-call personnel.

    Args:
        team: Team or schedule name
        message: Notification message
        severity: Alert severity
        incident_id: Incident identifier
        config: Configuration for notification

    Returns:
        ActionResult with notification status
    """
    logger.info(f"[+] Notifying on-call: {team}")

    config = config or {}
    incident_id = incident_id or f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    # Check for PagerDuty configuration (most common for on-call)
    pagerduty_key = config.get("pagerduty_routing_key") or os.getenv("PAGERDUTY_ROUTING_KEY")

    if pagerduty_key:
        return _send_pagerduty_alert(
            recipients=[team],
            subject=f"On-Call Alert: {team}",
            message=message,
            severity=severity,
            incident_id=incident_id,
            config={"routing_key": pagerduty_key}
        )

    # Fallback to email if configured
    email_recipients = config.get("oncall_emails", {}).get(team, [])
    if email_recipients:
        return send_alert(
            method="email",
            recipients=email_recipients,
            subject=f"[ON-CALL] {team} - Incident Alert",
            message=message,
            severity=severity,
            incident_id=incident_id,
            config=config
        )

    return ActionResult(
        success=False,
        message=f"No on-call notification method configured for team: {team}"
    )


# Module test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("Escalation Actions Module")
    print("=" * 40)
    print("Available actions:")
    print("  - send_alert(method, recipients, subject, message, severity)")
    print("  - create_ticket(system, title, description, priority)")
    print("  - update_severity(incident_id, new_severity, reason)")
    print("  - notify_oncall(team, message, severity)")
    print("\nSupported alert methods: email, slack, teams, pagerduty")
    print("Supported ticket systems: jira, servicenow")
