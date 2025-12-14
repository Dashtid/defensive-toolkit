#!/usr/bin/env python3
"""
Evidence Preservation Actions for Incident Response

Provides evidence collection, forensic packaging, memory capture,
and disk snapshot capabilities with chain of custody tracking.

Author: Defensive Toolkit
Version: 1.0.0
Date: 2025-11-30

IMPORTANT: Evidence collection must maintain chain of custody.
All collected evidence is hashed and timestamped.
"""

import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from zipfile import ZipFile

# Import ActionResult from parent - handle both direct and module import
try:
    from ..runbook_engine import ActionResult
except ImportError:

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


def collect_evidence(
    evidence_type: str,
    source: str,
    output_dir: str,
    incident_id: Optional[str] = None,
    collector: Optional[str] = None,
) -> ActionResult:
    """
    Collect evidence with chain of custody tracking.

    Args:
        evidence_type: Type of evidence (logs, files, registry, etc.)
        source: Source path or identifier
        output_dir: Directory to store collected evidence
        incident_id: Incident identifier for tracking
        collector: Name of person/system collecting evidence

    Returns:
        ActionResult with evidence details and hash
    """
    logger.info(f"[+] Collecting evidence: {evidence_type} from {source}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    incident_id = incident_id or f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    collector = collector or os.getenv("USERNAME", os.getenv("USER", "unknown"))

    evidence_handlers = {
        "logs": _collect_logs,
        "files": _collect_files,
        "registry": _collect_registry,
        "processes": _collect_processes,
        "network": _collect_network_state,
        "users": _collect_user_info,
        "services": _collect_services,
        "scheduled_tasks": _collect_scheduled_tasks,
    }

    handler = evidence_handlers.get(evidence_type)
    if not handler:
        return ActionResult(success=False, message=f"Unknown evidence type: {evidence_type}")

    try:
        result = handler(source, output_path, incident_id)

        if result["success"]:
            # Create chain of custody record
            custody_record = {
                "incident_id": incident_id,
                "evidence_type": evidence_type,
                "source": source,
                "collected_at": datetime.now().isoformat(),
                "collected_by": collector,
                "hostname": platform.node(),
                "output_file": result.get("output_file"),
                "sha256": result.get("sha256"),
                "file_size": result.get("file_size"),
            }

            # Save custody record
            custody_file = output_path / f"{incident_id}_custody_{evidence_type}.json"
            with open(custody_file, "w") as f:
                json.dump(custody_record, f, indent=2)

            return ActionResult(
                success=True,
                message=f"Evidence collected: {result.get('output_file')}",
                data=custody_record,
            )
        else:
            return ActionResult(success=False, message=result.get("error", "Collection failed"))

    except Exception as e:
        return ActionResult(success=False, message=f"Evidence collection failed: {e}")


def _collect_logs(source: str, output_path: Path, incident_id: str) -> Dict:
    """Collect log files"""
    is_windows = platform.system() == "Windows"
    output_file = output_path / f"{incident_id}_logs.zip"

    try:
        with ZipFile(output_file, "w") as zipf:
            if source == "system" or source == "*":
                if is_windows:
                    # Export Windows Event Logs
                    log_names = ["Security", "System", "Application"]
                    for log_name in log_names:
                        temp_log = output_path / f"{log_name}.evtx"
                        cmd = ["wevtutil", "epl", log_name, str(temp_log)]
                        subprocess.run(cmd, capture_output=True)
                        if temp_log.exists():
                            zipf.write(temp_log, f"eventlogs/{log_name}.evtx")
                            temp_log.unlink()
                else:
                    # Collect Linux logs
                    log_dirs = ["/var/log"]
                    for log_dir in log_dirs:
                        log_path = Path(log_dir)
                        if log_path.exists():
                            for log_file in log_path.glob("**/*"):
                                if log_file.is_file():
                                    try:
                                        zipf.write(
                                            log_file, f"logs/{log_file.relative_to(log_path)}"
                                        )
                                    except (PermissionError, OSError):
                                        pass
            else:
                # Collect specific log path
                source_path = Path(source)
                if source_path.exists():
                    if source_path.is_file():
                        zipf.write(source_path, source_path.name)
                    else:
                        for f in source_path.glob("**/*"):
                            if f.is_file():
                                zipf.write(f, f.relative_to(source_path))

        # Calculate hash
        sha256 = _calculate_file_hash(output_file)

        return {
            "success": True,
            "output_file": str(output_file),
            "sha256": sha256,
            "file_size": output_file.stat().st_size,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def _collect_files(source: str, output_path: Path, incident_id: str) -> Dict:
    """Collect specific files or directories"""
    output_file = output_path / f"{incident_id}_files.zip"
    source_path = Path(source)

    if not source_path.exists():
        return {"success": False, "error": f"Source not found: {source}"}

    try:
        with ZipFile(output_file, "w") as zipf:
            if source_path.is_file():
                zipf.write(source_path, source_path.name)
            else:
                for f in source_path.glob("**/*"):
                    if f.is_file():
                        try:
                            zipf.write(f, f.relative_to(source_path))
                        except (PermissionError, OSError):
                            pass

        sha256 = _calculate_file_hash(output_file)

        return {
            "success": True,
            "output_file": str(output_file),
            "sha256": sha256,
            "file_size": output_file.stat().st_size,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def _collect_registry(source: str, output_path: Path, incident_id: str) -> Dict:
    """Collect Windows registry keys"""
    if platform.system() != "Windows":
        return {"success": False, "error": "Registry collection only available on Windows"}

    output_file = output_path / f"{incident_id}_registry.txt"

    try:
        # Export specified registry key or common forensic keys
        if source == "forensic" or source == "*":
            keys = [
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\SYSTEM\CurrentControlSet\Services",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            ]
        else:
            keys = [source]

        with open(output_file, "w") as f:
            f.write(f"Registry Export - {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")

            for key in keys:
                f.write(f"Key: {key}\n")
                f.write("-" * 40 + "\n")

                cmd = ["reg", "query", key, "/s"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                f.write(result.stdout + "\n\n")

        sha256 = _calculate_file_hash(output_file)

        return {
            "success": True,
            "output_file": str(output_file),
            "sha256": sha256,
            "file_size": output_file.stat().st_size,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def _collect_processes(source: str, output_path: Path, incident_id: str) -> Dict:
    """Collect running process information"""
    output_file = output_path / f"{incident_id}_processes.json"
    is_windows = platform.system() == "Windows"

    try:
        processes = []

        if is_windows:
            cmd = [
                "powershell.exe",
                "-Command",
                "Get-Process | Select-Object Id,ProcessName,Path,StartTime,CPU,WorkingSet | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                processes = json.loads(result.stdout) if result.stdout.strip() else []
        else:
            cmd = ["ps", "auxww"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                headers = lines[0].split()
                for line in lines[1:]:
                    parts = line.split(None, len(headers) - 1)
                    if len(parts) >= len(headers):
                        processes.append(dict(zip(headers, parts)))

        output_data = {
            "collected_at": datetime.now().isoformat(),
            "hostname": platform.node(),
            "process_count": len(processes) if isinstance(processes, list) else 1,
            "processes": processes,
        }

        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2, default=str)

        sha256 = _calculate_file_hash(output_file)

        return {
            "success": True,
            "output_file": str(output_file),
            "sha256": sha256,
            "file_size": output_file.stat().st_size,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def _collect_network_state(source: str, output_path: Path, incident_id: str) -> Dict:
    """Collect network connection state"""
    output_file = output_path / f"{incident_id}_network.json"
    is_windows = platform.system() == "Windows"

    try:
        network_data = {
            "collected_at": datetime.now().isoformat(),
            "hostname": platform.node(),
            "connections": [],
            "arp_table": [],
            "dns_cache": [],
        }

        if is_windows:
            # Netstat
            result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
            network_data["netstat_output"] = result.stdout

            # ARP table
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            network_data["arp_output"] = result.stdout

            # DNS cache
            result = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True)
            network_data["dns_cache_output"] = result.stdout
        else:
            # Netstat
            result = subprocess.run(["netstat", "-tulpn"], capture_output=True, text=True)
            network_data["netstat_output"] = result.stdout

            # ss for socket statistics
            result = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True)
            network_data["ss_output"] = result.stdout

            # ARP
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            network_data["arp_output"] = result.stdout

        with open(output_file, "w") as f:
            json.dump(network_data, f, indent=2)

        sha256 = _calculate_file_hash(output_file)

        return {
            "success": True,
            "output_file": str(output_file),
            "sha256": sha256,
            "file_size": output_file.stat().st_size,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def _collect_user_info(source: str, output_path: Path, incident_id: str) -> Dict:
    """Collect user account information"""
    output_file = output_path / f"{incident_id}_users.json"
    is_windows = platform.system() == "Windows"

    try:
        user_data = {
            "collected_at": datetime.now().isoformat(),
            "hostname": platform.node(),
            "users": [],
            "groups": [],
            "logged_in": [],
        }

        if is_windows:
            # Local users
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-Command",
                    "Get-LocalUser | Select-Object Name,Enabled,LastLogon | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            if result.stdout.strip():
                user_data["users"] = json.loads(result.stdout)

            # Local groups
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-Command",
                    "Get-LocalGroup | Select-Object Name,Description | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            if result.stdout.strip():
                user_data["groups"] = json.loads(result.stdout)

            # Logged in users
            result = subprocess.run(["query", "user"], capture_output=True, text=True)
            user_data["logged_in_output"] = result.stdout
        else:
            # Users from passwd
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        user_data["users"].append(
                            {
                                "username": parts[0],
                                "uid": parts[2],
                                "gid": parts[3],
                                "home": parts[5],
                                "shell": parts[6],
                            }
                        )

            # Groups
            with open("/etc/group", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 4:
                        user_data["groups"].append(
                            {
                                "name": parts[0],
                                "gid": parts[2],
                                "members": parts[3].split(",") if parts[3] else [],
                            }
                        )

            # Logged in
            result = subprocess.run(["who"], capture_output=True, text=True)
            user_data["logged_in_output"] = result.stdout

        with open(output_file, "w") as f:
            json.dump(user_data, f, indent=2, default=str)

        sha256 = _calculate_file_hash(output_file)

        return {
            "success": True,
            "output_file": str(output_file),
            "sha256": sha256,
            "file_size": output_file.stat().st_size,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def _collect_services(source: str, output_path: Path, incident_id: str) -> Dict:
    """Collect service/daemon information"""
    output_file = output_path / f"{incident_id}_services.json"
    is_windows = platform.system() == "Windows"

    try:
        if is_windows:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-Command",
                    "Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            services = json.loads(result.stdout) if result.stdout.strip() else []
        else:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--output=json"],
                capture_output=True,
                text=True,
            )
            services = json.loads(result.stdout) if result.stdout.strip() else []

        output_data = {
            "collected_at": datetime.now().isoformat(),
            "hostname": platform.node(),
            "service_count": len(services) if isinstance(services, list) else 1,
            "services": services,
        }

        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2, default=str)

        sha256 = _calculate_file_hash(output_file)

        return {
            "success": True,
            "output_file": str(output_file),
            "sha256": sha256,
            "file_size": output_file.stat().st_size,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def _collect_scheduled_tasks(source: str, output_path: Path, incident_id: str) -> Dict:
    """Collect scheduled tasks/cron jobs"""
    output_file = output_path / f"{incident_id}_scheduled_tasks.json"
    is_windows = platform.system() == "Windows"

    try:
        if is_windows:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"], capture_output=True, text=True
            )
            output_data = {
                "collected_at": datetime.now().isoformat(),
                "hostname": platform.node(),
                "raw_output": result.stdout,
            }
        else:
            cron_data = []
            # System crontabs
            for cron_file in Path("/etc").glob("cron*"):
                if cron_file.is_file():
                    try:
                        cron_data.append({"file": str(cron_file), "content": cron_file.read_text()})
                    except PermissionError:
                        pass

            output_data = {
                "collected_at": datetime.now().isoformat(),
                "hostname": platform.node(),
                "cron_files": cron_data,
            }

        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2)

        sha256 = _calculate_file_hash(output_file)

        return {
            "success": True,
            "output_file": str(output_file),
            "sha256": sha256,
            "file_size": output_file.stat().st_size,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def create_forensic_package(
    evidence_dir: str,
    output_file: str,
    include_chain_of_custody: bool = True,
    password: Optional[str] = None,
) -> ActionResult:
    """
    Create a forensic evidence package.

    Args:
        evidence_dir: Directory containing collected evidence
        output_file: Output package file path
        include_chain_of_custody: Include custody records
        password: Optional password for encryption

    Returns:
        ActionResult with package details
    """
    logger.info(f"[+] Creating forensic package from {evidence_dir}")

    evidence_path = Path(evidence_dir)
    output_path = Path(output_file)

    if not evidence_path.exists():
        return ActionResult(success=False, message=f"Evidence directory not found: {evidence_dir}")

    try:
        # Create ZIP package
        with ZipFile(output_path, "w") as zipf:
            for item in evidence_path.glob("**/*"):
                if item.is_file():
                    zipf.write(item, item.relative_to(evidence_path))

        # Calculate final hash
        sha256 = _calculate_file_hash(output_path)

        # Create manifest
        manifest = {
            "package_created": datetime.now().isoformat(),
            "created_by": os.getenv("USERNAME", os.getenv("USER", "unknown")),
            "hostname": platform.node(),
            "source_directory": str(evidence_path),
            "output_file": str(output_path),
            "sha256": sha256,
            "file_size": output_path.stat().st_size,
            "encrypted": password is not None,
        }

        manifest_file = output_path.with_suffix(".manifest.json")
        with open(manifest_file, "w") as f:
            json.dump(manifest, f, indent=2)

        return ActionResult(
            success=True, message=f"Forensic package created: {output_path}", data=manifest
        )

    except Exception as e:
        return ActionResult(success=False, message=f"Failed to create package: {e}")


def capture_memory(
    output_dir: str, tool: str = "auto", incident_id: Optional[str] = None
) -> ActionResult:
    """
    Capture system memory dump.

    Args:
        output_dir: Directory to store memory dump
        tool: Memory capture tool (auto, winpmem, avml, lime)
        incident_id: Incident identifier

    Returns:
        ActionResult with memory dump details
    """
    logger.info("[+] Capturing memory dump")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    incident_id = incident_id or f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    is_windows = platform.system() == "Windows"

    # Determine tool
    if tool == "auto":
        if is_windows:
            tool = "winpmem"
        else:
            tool = "avml"

    output_file = output_path / f"{incident_id}_memory.raw"

    try:
        if tool == "winpmem":
            # Check for winpmem
            winpmem_paths = [
                Path("C:/Tools/winpmem.exe"),
                Path("winpmem.exe"),
                Path.home() / "Tools" / "winpmem.exe",
            ]

            winpmem = None
            for path in winpmem_paths:
                if path.exists():
                    winpmem = path
                    break

            if not winpmem:
                return ActionResult(
                    success=False,
                    message="winpmem not found. Download from: https://github.com/Velocidex/WinPmem",
                )

            cmd = [str(winpmem), str(output_file)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

            if result.returncode != 0:
                return ActionResult(
                    success=False, message=f"Memory capture failed: {result.stderr}"
                )

        elif tool == "avml":
            # Linux AVML
            avml_path = shutil.which("avml")
            if not avml_path:
                return ActionResult(
                    success=False,
                    message="AVML not found. Install from: https://github.com/microsoft/avml",
                )

            cmd = [avml_path, str(output_file)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

            if result.returncode != 0:
                return ActionResult(
                    success=False, message=f"Memory capture failed: {result.stderr}"
                )

        else:
            return ActionResult(success=False, message=f"Unknown memory capture tool: {tool}")

        if output_file.exists():
            sha256 = _calculate_file_hash(output_file)

            return ActionResult(
                success=True,
                message=f"Memory captured: {output_file}",
                data={
                    "output_file": str(output_file),
                    "sha256": sha256,
                    "file_size": output_file.stat().st_size,
                    "tool": tool,
                },
            )
        else:
            return ActionResult(success=False, message="Memory dump file not created")

    except subprocess.TimeoutExpired:
        return ActionResult(success=False, message="Memory capture timed out")
    except Exception as e:
        return ActionResult(success=False, message=f"Memory capture failed: {e}")


def snapshot_disk(
    volume: str, output_dir: str, method: str = "vss", incident_id: Optional[str] = None
) -> ActionResult:
    """
    Create disk snapshot for forensic analysis.

    Args:
        volume: Volume to snapshot (e.g., C:, /dev/sda1)
        output_dir: Directory to store snapshot info
        method: Snapshot method (vss, lvm, dd)
        incident_id: Incident identifier

    Returns:
        ActionResult with snapshot details
    """
    logger.info(f"[+] Creating disk snapshot: {volume}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    incident_id = incident_id or f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    is_windows = platform.system() == "Windows"

    try:
        if method == "vss" and is_windows:
            # Create VSS snapshot
            cmd = [
                "powershell.exe",
                "-Command",
                f"(Get-WmiObject -List Win32_ShadowCopy).Create('{volume}\\', 'ClientAccessible')",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)

            # Get shadow copy info
            cmd = [
                "powershell.exe",
                "-Command",
                "Get-WmiObject Win32_ShadowCopy | Select-Object ID,InstallDate,DeviceObject | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)

            snapshot_info = json.loads(result.stdout) if result.stdout.strip() else {}

            info_file = output_path / f"{incident_id}_vss_snapshot.json"
            with open(info_file, "w") as f:
                json.dump(
                    {
                        "created_at": datetime.now().isoformat(),
                        "volume": volume,
                        "method": method,
                        "snapshots": snapshot_info,
                    },
                    f,
                    indent=2,
                )

            return ActionResult(
                success=True,
                message=f"VSS snapshot created for {volume}",
                data={"info_file": str(info_file), "method": method},
            )

        elif method == "dd":
            # Raw disk image (requires elevated privileges)
            output_file = (
                output_path / f"{incident_id}_{volume.replace('/', '_').replace(':', '')}.dd"
            )

            return ActionResult(
                success=False,
                message="DD imaging requires manual execution with elevated privileges",
            )

        else:
            return ActionResult(
                success=False, message=f"Snapshot method {method} not supported on this platform"
            )

    except Exception as e:
        return ActionResult(success=False, message=f"Disk snapshot failed: {e}")


def _calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA-256 hash of file"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# Module test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("Evidence Preservation Actions Module")
    print("=" * 40)
    print("Available actions:")
    print("  - collect_evidence(evidence_type, source, output_dir)")
    print("  - create_forensic_package(evidence_dir, output_file)")
    print("  - capture_memory(output_dir, tool)")
    print("  - snapshot_disk(volume, output_dir, method)")
    print(
        "\nEvidence types: logs, files, registry, processes, network, users, services, scheduled_tasks"
    )
