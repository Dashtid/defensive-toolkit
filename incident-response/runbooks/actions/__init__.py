"""
Incident Response Actions

Containment, preservation, and escalation actions for automated IR.
"""

from .containment import (
    isolate_host,
    block_ip,
    disable_account,
    quarantine_file,
    kill_process,
)
from .preservation import (
    collect_evidence,
    create_forensic_package,
    capture_memory,
    snapshot_disk,
)
from .escalation import (
    send_alert,
    create_ticket,
    update_severity,
    notify_oncall,
)

__all__ = [
    # Containment
    "isolate_host",
    "block_ip",
    "disable_account",
    "quarantine_file",
    "kill_process",
    # Preservation
    "collect_evidence",
    "create_forensic_package",
    "capture_memory",
    "snapshot_disk",
    # Escalation
    "send_alert",
    "create_ticket",
    "update_severity",
    "notify_oncall",
]
