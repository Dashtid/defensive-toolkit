"""
Incident Response Actions

Containment, preservation, and escalation actions for automated IR.
"""

from .containment import (
    block_ip,
    disable_account,
    isolate_host,
    kill_process,
    quarantine_file,
)
from .escalation import (
    create_ticket,
    notify_oncall,
    send_alert,
    update_severity,
)
from .preservation import (
    capture_memory,
    collect_evidence,
    create_forensic_package,
    snapshot_disk,
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
