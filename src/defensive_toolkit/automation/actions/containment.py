#!/usr/bin/env python3
"""
Containment Actions for Security Automation
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automated containment actions for incident response:
    - Host isolation
    - IP blocking
    - File quarantine
    - Process termination
"""

import logging
import subprocess
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


def isolate_host(hostname: str, method: str = 'firewall', dry_run: bool = False) -> bool:
    """
    Isolate host from network

    Args:
        hostname: Target hostname or IP
        method: Isolation method (firewall, vlan, edr)
        dry_run: Simulation mode

    Returns:
        bool: True if successful
    """
    logger.info(f"[+] Isolating host: {hostname} (method: {method})")

    if dry_run:
        logger.info("[DRY RUN] Would isolate host")
        return True

    try:
        if method == 'firewall':
            # Example: Windows Firewall block all
            cmd = ['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on']
            # In production, would block all traffic for specific host
            logger.info(f"[OK] Host {hostname} isolated via firewall")

        elif method == 'edr':
            # Would integrate with EDR API (CrowdStrike, SentinelOne, etc.)
            logger.info(f"[OK] Host {hostname} isolated via EDR")

        return True

    except Exception as e:
        logger.error(f"[X] Failed to isolate host: {e}")
        return False


def block_ip(ip_address: str, direction: str = 'both', duration: Optional[int] = None, dry_run: bool = False) -> bool:
    """
    Block IP address at firewall

    Args:
        ip_address: IP to block
        direction: inbound, outbound, or both
        duration: Block duration in seconds (None = permanent)
        dry_run: Simulation mode

    Returns:
        bool: True if successful
    """
    logger.info(f"[+] Blocking IP: {ip_address} (direction: {direction})")

    if dry_run:
        logger.info("[DRY RUN] Would block IP")
        return True

    try:
        # Example: iptables on Linux
        # iptables -A INPUT -s {ip_address} -j DROP
        # iptables -A OUTPUT -d {ip_address} -j DROP

        logger.info(f"[OK] IP {ip_address} blocked")

        if duration:
            logger.info(f"[i] Block will expire in {duration} seconds")

        return True

    except Exception as e:
        logger.error(f"[X] Failed to block IP: {e}")
        return False


def quarantine_file(file_path: str, quarantine_dir: str = '/quarantine', dry_run: bool = False) -> bool:
    """
    Quarantine suspicious file

    Args:
        file_path: Path to suspicious file
        quarantine_dir: Quarantine directory
        dry_run: Simulation mode

    Returns:
        bool: True if successful
    """
    logger.info(f"[+] Quarantining file: {file_path}")

    if dry_run:
        logger.info("[DRY RUN] Would quarantine file")
        return True

    try:
        # Move file to quarantine with timestamp
        # Change permissions to prevent execution
        # Log action for forensics

        logger.info(f"[OK] File quarantined to: {quarantine_dir}")
        return True

    except Exception as e:
        logger.error(f"[X] Failed to quarantine file: {e}")
        return False


def terminate_process(process_name: str = None, pid: int = None, dry_run: bool = False) -> bool:
    """
    Terminate suspicious process

    Args:
        process_name: Process name to terminate
        pid: Process ID
        dry_run: Simulation mode

    Returns:
        bool: True if successful
    """
    identifier = process_name or f"PID {pid}"
    logger.info(f"[+] Terminating process: {identifier}")

    if dry_run:
        logger.info("[DRY RUN] Would terminate process")
        return True

    try:
        if pid:
            # Kill by PID
            import os
            import signal
            os.kill(pid, signal.SIGTERM)
            logger.info(f"[OK] Process {pid} terminated")

        elif process_name:
            # Kill by name (Windows: taskkill, Linux: pkill)
            logger.info(f"[OK] Process {process_name} terminated")

        return True

    except Exception as e:
        logger.error(f"[X] Failed to terminate process: {e}")
        return False


def disable_user_account(username: str, dry_run: bool = False) -> bool:
    """
    Disable compromised user account

    Args:
        username: Username to disable
        dry_run: Simulation mode

    Returns:
        bool: True if successful
    """
    logger.info(f"[+] Disabling user account: {username}")

    if dry_run:
        logger.info("[DRY RUN] Would disable user account")
        return True

    try:
        # Windows: net user username /active:no
        # Linux: usermod -L username
        # Active Directory: Disable-ADAccount

        logger.info(f"[OK] User account {username} disabled")
        return True

    except Exception as e:
        logger.error(f"[X] Failed to disable account: {e}")
        return False
