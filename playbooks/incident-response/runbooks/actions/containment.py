#!/usr/bin/env python3
"""
Containment Actions for Incident Response

Provides host isolation, IP blocking, account disabling, and file quarantine
capabilities for automated incident response.

Author: Defensive Toolkit
Version: 1.0.0
Date: 2025-11-30

IMPORTANT: These actions can have significant impact. They are designed
to be executed through the runbook engine with proper approval gates.
"""

import json
import logging
import os
import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

# Import ActionResult from parent - handle both direct and module import
try:
    from ..runbook_engine import ActionResult
except ImportError:
    # Fallback for direct execution
    class ActionResult:
        def __init__(
            self,
            success: bool,
            message: str,
            data: Optional[Dict] = None,
            rollback_info: Optional[Dict] = None,
        ):
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
                "timestamp": self.timestamp,
            }


logger = logging.getLogger(__name__)


def isolate_host(
    hostname: str,
    method: str = "firewall",
    allow_management: bool = True,
    management_ips: Optional[list] = None,
) -> ActionResult:
    """
    Isolate a host from the network.

    Args:
        hostname: Target hostname or IP (use 'localhost' for local machine)
        method: Isolation method - 'firewall' or 'network_disable'
        allow_management: Keep management access open
        management_ips: List of IPs to allow for management

    Returns:
        ActionResult with rollback information
    """
    logger.info(f"[+] Isolating host: {hostname} (method: {method})")

    if hostname.lower() in ("localhost", "127.0.0.1", platform.node()):
        return _isolate_local_host(method, allow_management, management_ips or [])
    else:
        return _isolate_remote_host(hostname, method, allow_management, management_ips or [])


def _isolate_local_host(method: str, allow_management: bool, management_ips: list) -> ActionResult:
    """Isolate the local machine"""
    is_windows = platform.system() == "Windows"

    if method == "firewall":
        if is_windows:
            return _windows_firewall_isolate(allow_management, management_ips)
        else:
            return _linux_firewall_isolate(allow_management, management_ips)

    elif method == "network_disable":
        return ActionResult(
            success=False, message="Network disable method not recommended for local host"
        )

    return ActionResult(success=False, message=f"Unknown isolation method: {method}")


def _windows_firewall_isolate(allow_management: bool, management_ips: list) -> ActionResult:
    """Isolate Windows host using firewall rules"""
    rule_name = "IR-Containment-Block-All"
    allow_rule_name = "IR-Containment-Allow-Management"

    try:
        # Create blocking rule for all outbound traffic
        block_cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            "enable=yes",
        ]

        result = subprocess.run(block_cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return ActionResult(
                success=False, message=f"Failed to create firewall rule: {result.stderr}"
            )

        rollback_cmds = [f"netsh advfirewall firewall delete rule name={rule_name}"]

        # Allow management IPs if specified
        if allow_management and management_ips:
            for ip in management_ips:
                allow_cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={allow_rule_name}-{ip}",
                    "dir=out",
                    f"remoteip={ip}",
                    "action=allow",
                    "enable=yes",
                ]
                subprocess.run(allow_cmd, capture_output=True)
                rollback_cmds.append(
                    f"netsh advfirewall firewall delete rule name={allow_rule_name}-{ip}"
                )

        return ActionResult(
            success=True,
            message=f"Host isolated via Windows Firewall (rule: {rule_name})",
            data={"rule_name": rule_name, "management_ips": management_ips},
            rollback_info={"action": "remove_firewall_rules", "commands": rollback_cmds},
        )

    except Exception as e:
        return ActionResult(success=False, message=f"Firewall isolation failed: {e}")


def _linux_firewall_isolate(allow_management: bool, management_ips: list) -> ActionResult:
    """Isolate Linux host using iptables"""
    chain_name = "IR_CONTAINMENT"

    try:
        commands = [
            # Create containment chain
            f"iptables -N {chain_name}",
            # Drop all outbound by default
            f"iptables -A {chain_name} -j DROP",
            # Insert chain into OUTPUT
            f"iptables -I OUTPUT 1 -j {chain_name}",
        ]

        # Allow management IPs
        if allow_management and management_ips:
            for ip in management_ips:
                commands.insert(-1, f"iptables -I {chain_name} 1 -d {ip} -j ACCEPT")

        # Execute commands
        for cmd in commands:
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning(f"Command warning: {cmd} - {result.stderr}")

        return ActionResult(
            success=True,
            message=f"Host isolated via iptables (chain: {chain_name})",
            data={"chain_name": chain_name, "management_ips": management_ips},
            rollback_info={
                "action": "remove_iptables_chain",
                "commands": [
                    f"iptables -D OUTPUT -j {chain_name}",
                    f"iptables -F {chain_name}",
                    f"iptables -X {chain_name}",
                ],
            },
        )

    except Exception as e:
        return ActionResult(success=False, message=f"iptables isolation failed: {e}")


def _isolate_remote_host(
    hostname: str, method: str, allow_management: bool, management_ips: list
) -> ActionResult:
    """Isolate a remote host (requires remote execution capability)"""
    # This would integrate with remote execution tools like:
    # - SSH for Linux hosts
    # - WinRM/PSRemoting for Windows hosts
    # - EDR API for managed endpoints

    return ActionResult(
        success=False,
        message=f"Remote host isolation not implemented. Configure EDR integration for {hostname}",
    )


def block_ip(
    ip_address: str, direction: str = "both", duration_hours: Optional[int] = None
) -> ActionResult:
    """
    Block an IP address via firewall rules.

    Args:
        ip_address: IP address to block
        direction: 'inbound', 'outbound', or 'both'
        duration_hours: Auto-remove after this many hours (optional)

    Returns:
        ActionResult with rollback information
    """
    logger.info(f"[+] Blocking IP: {ip_address} (direction: {direction})")

    is_windows = platform.system() == "Windows"
    rule_name = f"IR-Block-{ip_address.replace('.', '-')}"

    try:
        if is_windows:
            return _windows_block_ip(ip_address, direction, rule_name)
        else:
            return _linux_block_ip(ip_address, direction, rule_name)

    except Exception as e:
        return ActionResult(success=False, message=f"Failed to block IP: {e}")


def _windows_block_ip(ip_address: str, direction: str, rule_name: str) -> ActionResult:
    """Block IP on Windows using netsh"""
    rollback_cmds = []

    directions = []
    if direction in ("inbound", "both"):
        directions.append("in")
    if direction in ("outbound", "both"):
        directions.append("out")

    for dir_type in directions:
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}-{dir_type}",
            f"dir={dir_type}",
            f"remoteip={ip_address}",
            "action=block",
            "enable=yes",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return ActionResult(
                success=False, message=f"Failed to create block rule: {result.stderr}"
            )

        rollback_cmds.append(f"netsh advfirewall firewall delete rule name={rule_name}-{dir_type}")

    return ActionResult(
        success=True,
        message=f"Blocked IP {ip_address} ({direction})",
        data={"ip": ip_address, "rule_name": rule_name, "direction": direction},
        rollback_info={"action": "unblock_ip", "commands": rollback_cmds},
    )


def _linux_block_ip(ip_address: str, direction: str, rule_name: str) -> ActionResult:
    """Block IP on Linux using iptables"""
    rollback_cmds = []

    if direction in ("inbound", "both"):
        cmd = f"iptables -I INPUT -s {ip_address} -j DROP -m comment --comment {rule_name}"
        subprocess.run(cmd.split(), capture_output=True)
        rollback_cmds.append(f"iptables -D INPUT -s {ip_address} -j DROP")

    if direction in ("outbound", "both"):
        cmd = f"iptables -I OUTPUT -d {ip_address} -j DROP -m comment --comment {rule_name}"
        subprocess.run(cmd.split(), capture_output=True)
        rollback_cmds.append(f"iptables -D OUTPUT -d {ip_address} -j DROP")

    return ActionResult(
        success=True,
        message=f"Blocked IP {ip_address} ({direction})",
        data={"ip": ip_address, "direction": direction},
        rollback_info={"action": "unblock_ip", "commands": rollback_cmds},
    )


def disable_account(
    username: str, domain: Optional[str] = None, method: str = "disable"
) -> ActionResult:
    """
    Disable a user account.

    Args:
        username: Username to disable
        domain: Domain name (for AD accounts)
        method: 'disable', 'lock', or 'reset_password'

    Returns:
        ActionResult with rollback information
    """
    logger.info(f"[+] Disabling account: {username} (method: {method})")

    is_windows = platform.system() == "Windows"

    if domain:
        return _disable_ad_account(username, domain, method)
    elif is_windows:
        return _disable_local_windows_account(username, method)
    else:
        return _disable_local_linux_account(username, method)


def _disable_local_windows_account(username: str, method: str) -> ActionResult:
    """Disable local Windows account"""
    try:
        if method == "disable":
            cmd = ["net", "user", username, "/active:no"]
            rollback_cmd = f"net user {username} /active:yes"
        elif method == "lock":
            # Windows doesn't have native lock, use disable
            cmd = ["net", "user", username, "/active:no"]
            rollback_cmd = f"net user {username} /active:yes"
        else:
            return ActionResult(success=False, message=f"Unknown method: {method}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return ActionResult(
                success=False, message=f"Failed to disable account: {result.stderr}"
            )

        return ActionResult(
            success=True,
            message=f"Account {username} disabled",
            data={"username": username, "method": method},
            rollback_info={"action": "enable_account", "command": rollback_cmd},
        )

    except Exception as e:
        return ActionResult(success=False, message=f"Failed to disable account: {e}")


def _disable_local_linux_account(username: str, method: str) -> ActionResult:
    """Disable local Linux account"""
    try:
        if method == "disable":
            cmd = ["usermod", "-L", username]  # Lock password
            rollback_cmd = f"usermod -U {username}"
        elif method == "lock":
            cmd = ["passwd", "-l", username]
            rollback_cmd = f"passwd -u {username}"
        else:
            return ActionResult(success=False, message=f"Unknown method: {method}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return ActionResult(
                success=False, message=f"Failed to disable account: {result.stderr}"
            )

        return ActionResult(
            success=True,
            message=f"Account {username} disabled",
            data={"username": username, "method": method},
            rollback_info={"action": "enable_account", "command": rollback_cmd},
        )

    except Exception as e:
        return ActionResult(success=False, message=f"Failed to disable account: {e}")


def _disable_ad_account(username: str, domain: str, method: str) -> ActionResult:
    """Disable Active Directory account (requires PowerShell AD module)"""
    try:
        if method == "disable":
            ps_cmd = f"Disable-ADAccount -Identity {username} -Server {domain}"
            rollback_cmd = f"Enable-ADAccount -Identity {username} -Server {domain}"
        else:
            return ActionResult(success=False, message=f"Method {method} not supported for AD")

        cmd = ["powershell.exe", "-Command", ps_cmd]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return ActionResult(
                success=False, message=f"Failed to disable AD account: {result.stderr}"
            )

        return ActionResult(
            success=True,
            message=f"AD account {domain}\\{username} disabled",
            data={"username": username, "domain": domain, "method": method},
            rollback_info={"action": "enable_ad_account", "powershell_command": rollback_cmd},
        )

    except Exception as e:
        return ActionResult(success=False, message=f"Failed to disable AD account: {e}")


def quarantine_file(
    file_path: str, quarantine_dir: Optional[str] = None, preserve_metadata: bool = True
) -> ActionResult:
    """
    Quarantine a suspicious file.

    Args:
        file_path: Path to file to quarantine
        quarantine_dir: Directory to move file to
        preserve_metadata: Save file metadata before moving

    Returns:
        ActionResult with rollback information
    """
    logger.info(f"[+] Quarantining file: {file_path}")

    source = Path(file_path)

    if not source.exists():
        return ActionResult(success=False, message=f"File not found: {file_path}")

    # Set up quarantine directory
    if quarantine_dir:
        quarantine = Path(quarantine_dir)
    else:
        quarantine = Path.home() / ".ir-quarantine"

    quarantine.mkdir(parents=True, exist_ok=True)

    try:
        # Generate quarantine filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        dest_name = f"{timestamp}_{source.name}"
        dest = quarantine / dest_name

        # Save metadata
        metadata = {}
        if preserve_metadata:
            stat = source.stat()
            metadata = {
                "original_path": str(source.absolute()),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "quarantined_at": datetime.now().isoformat(),
                "quarantined_by": os.getenv("USERNAME", os.getenv("USER", "unknown")),
            }

            metadata_file = quarantine / f"{dest_name}.metadata.json"
            with open(metadata_file, "w") as f:
                json.dump(metadata, f, indent=2)

        # Move file to quarantine
        shutil.move(str(source), str(dest))

        return ActionResult(
            success=True,
            message=f"File quarantined: {dest}",
            data={"original_path": str(source), "quarantine_path": str(dest), "metadata": metadata},
            rollback_info={
                "action": "restore_file",
                "source": str(dest),
                "destination": str(source),
            },
        )

    except Exception as e:
        return ActionResult(success=False, message=f"Failed to quarantine file: {e}")


def kill_process(
    process_name: Optional[str] = None, pid: Optional[int] = None, force: bool = False
) -> ActionResult:
    """
    Terminate a process.

    Args:
        process_name: Name of process to kill
        pid: Process ID to kill
        force: Force termination

    Returns:
        ActionResult (no rollback available for this action)
    """
    if not process_name and not pid:
        return ActionResult(success=False, message="Either process_name or pid required")

    logger.info(f"[+] Killing process: {process_name or pid}")

    is_windows = platform.system() == "Windows"

    try:
        if is_windows:
            if pid:
                cmd = ["taskkill", "/PID", str(pid)]
            else:
                cmd = ["taskkill", "/IM", process_name]

            if force:
                cmd.append("/F")
        else:
            if pid:
                signal = "-9" if force else "-15"
                cmd = ["kill", signal, str(pid)]
            else:
                cmd = ["pkill", "-9" if force else "-15", process_name]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return ActionResult(success=False, message=f"Failed to kill process: {result.stderr}")

        return ActionResult(
            success=True,
            message=f"Process terminated: {process_name or pid}",
            data={"process": process_name, "pid": pid, "forced": force},
            # No rollback - process termination is irreversible
        )

    except Exception as e:
        return ActionResult(success=False, message=f"Failed to kill process: {e}")


# Module test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("Containment Actions Module")
    print("=" * 40)
    print("Available actions:")
    print("  - isolate_host(hostname, method, allow_management, management_ips)")
    print("  - block_ip(ip_address, direction, duration_hours)")
    print("  - disable_account(username, domain, method)")
    print("  - quarantine_file(file_path, quarantine_dir, preserve_metadata)")
    print("  - kill_process(process_name, pid, force)")
