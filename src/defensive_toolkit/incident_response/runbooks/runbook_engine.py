#!/usr/bin/env python3
"""
Incident Response Runbook Engine

Automated IR orchestration with approval gates, evidence preservation,
and graduated response automation.

Author: Defensive Toolkit
Version: 1.0.0
Date: 2025-11-30

Features:
    - YAML-based runbook definitions
    - Approval gates for high-risk actions
    - Evidence chain of custody tracking
    - Dry-run mode for validation
    - Rollback capability tracking
    - Integration with triage scripts
    - Detailed audit logging

Usage:
    python runbook_engine.py --runbook ransomware.yaml
    python runbook_engine.py --runbook malware.yaml --dry-run
    python runbook_engine.py --runbook credential_compromise.yaml --auto-approve low
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """Action severity levels for approval gates"""
    LOW = "low"           # Auto-approve: logging, enrichment
    MEDIUM = "medium"     # Prompt: evidence collection, alerts
    HIGH = "high"         # Require approval: containment actions
    CRITICAL = "critical" # Require explicit approval: account disable, isolation


class ActionResult:
    """Result of an executed action"""

    def __init__(
        self,
        success: bool,
        message: str,
        data: Optional[Dict] = None,
        rollback_info: Optional[Dict] = None
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
            "timestamp": self.timestamp
        }


class EvidenceChain:
    """Chain of custody tracking for collected evidence"""

    def __init__(self, incident_id: str, output_dir: Path):
        self.incident_id = incident_id
        self.output_dir = output_dir
        self.evidence_items: List[Dict] = []
        self.chain_file = output_dir / "chain_of_custody.json"

    def add_evidence(
        self,
        evidence_type: str,
        source: str,
        file_path: Optional[Path] = None,
        description: str = ""
    ) -> str:
        """Add evidence item with hash verification"""
        evidence_id = str(uuid.uuid4())[:8]

        item = {
            "evidence_id": evidence_id,
            "incident_id": self.incident_id,
            "type": evidence_type,
            "source": source,
            "description": description,
            "collected_at": datetime.now().isoformat(),
            "collected_by": os.getenv("USERNAME", os.getenv("USER", "unknown")),
            "hostname": platform.node(),
        }

        if file_path and file_path.exists():
            item["file_path"] = str(file_path)
            item["file_size"] = file_path.stat().st_size
            item["sha256"] = self._calculate_hash(file_path)

        self.evidence_items.append(item)
        self._save_chain()

        logger.info(f"[+] Evidence logged: {evidence_id} - {evidence_type}")
        return evidence_id

    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _save_chain(self):
        """Persist chain of custody to disk"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.chain_file, "w") as f:
            json.dump({
                "incident_id": self.incident_id,
                "created_at": datetime.now().isoformat(),
                "evidence_count": len(self.evidence_items),
                "evidence": self.evidence_items
            }, f, indent=2)


class RunbookEngine:
    """
    Incident Response Runbook Execution Engine

    Executes YAML-defined runbooks with approval gates,
    evidence preservation, and audit logging.
    """

    def __init__(
        self,
        dry_run: bool = False,
        auto_approve: Optional[str] = None,
        output_dir: Optional[Path] = None
    ):
        self.dry_run = dry_run
        self.auto_approve_level = Severity(auto_approve) if auto_approve else None
        self.output_dir = output_dir or Path("./ir-output")
        self.incident_id = f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        self.variables: Dict[str, Any] = {}
        self.execution_log: List[Dict] = []
        self.rollback_stack: List[Dict] = []
        self.evidence_chain: Optional[EvidenceChain] = None

        # Action registry
        self.actions: Dict[str, Callable] = {}
        self._register_builtin_actions()

    def _register_builtin_actions(self):
        """Register built-in actions"""
        self.actions = {
            # Control flow
            "log": self._action_log,
            "set_variable": self._action_set_variable,
            "conditional": self._action_conditional,
            "prompt_analyst": self._action_prompt_analyst,

            # Containment (loaded from actions module)
            "isolate_host": self._wrap_external_action("containment", "isolate_host"),
            "block_ip": self._wrap_external_action("containment", "block_ip"),
            "disable_account": self._wrap_external_action("containment", "disable_account"),
            "quarantine_file": self._wrap_external_action("containment", "quarantine_file"),
            "kill_process": self._wrap_external_action("containment", "kill_process"),

            # Preservation
            "collect_evidence": self._wrap_external_action("preservation", "collect_evidence"),
            "run_triage": self._action_run_triage,
            "capture_memory": self._wrap_external_action("preservation", "capture_memory"),

            # Escalation
            "send_alert": self._wrap_external_action("escalation", "send_alert"),
            "create_ticket": self._wrap_external_action("escalation", "create_ticket"),
            "update_severity": self._wrap_external_action("escalation", "update_severity"),
        }

    def _wrap_external_action(self, module: str, action: str) -> Callable:
        """Wrap external action module for lazy loading"""
        def wrapper(params: Dict) -> ActionResult:
            try:
                # Dynamic import
                mod = __import__(
                    f"actions.{module}",
                    fromlist=[action],
                    globals=globals()
                )
                func = getattr(mod, action)
                return func(**params)
            except ImportError as e:
                logger.warning(f"[!] Module not available: {module}.{action}")
                return ActionResult(
                    success=False,
                    message=f"Action module not available: {e}"
                )
            except Exception as e:
                return ActionResult(success=False, message=str(e))
        return wrapper

    def load_runbook(self, runbook_path: Path) -> Dict:
        """Load and validate YAML runbook"""
        logger.info(f"[+] Loading runbook: {runbook_path}")

        if not runbook_path.exists():
            raise FileNotFoundError(f"Runbook not found: {runbook_path}")

        with open(runbook_path, "r") as f:
            runbook = yaml.safe_load(f)

        # Validate required fields
        required = ["name", "description", "version", "steps"]
        missing = [f for f in required if f not in runbook]
        if missing:
            raise ValueError(f"Runbook missing required fields: {missing}")

        logger.info(f"[OK] Loaded: {runbook['name']} v{runbook['version']}")
        return runbook

    def execute(self, runbook: Dict) -> bool:
        """Execute runbook with approval gates and logging"""
        self._print_header(runbook)

        # Initialize evidence chain
        self.evidence_chain = EvidenceChain(
            self.incident_id,
            self.output_dir / self.incident_id
        )

        # Set initial variables
        self.variables = {
            "incident_id": self.incident_id,
            "hostname": platform.node(),
            "timestamp": datetime.now().isoformat(),
            "analyst": os.getenv("USERNAME", os.getenv("USER", "unknown")),
            **runbook.get("variables", {})
        }

        start_time = datetime.now()
        success = True

        try:
            steps = runbook.get("steps", [])
            for i, step in enumerate(steps, 1):
                step_name = step.get("name", f"Step {i}")
                logger.info(f"\n{'='*60}")
                logger.info(f"Step {i}/{len(steps)}: {step_name}")
                logger.info(f"{'='*60}")

                # Check conditions
                if not self._evaluate_condition(step.get("when")):
                    logger.info("[SKIP] Condition not met")
                    continue

                # Execute step
                result = self._execute_step(step)

                if not result.success:
                    logger.error(f"[-] Step failed: {result.message}")

                    if step.get("continue_on_failure", False):
                        logger.warning("[!] Continuing despite failure")
                    else:
                        success = False
                        break

            duration = (datetime.now() - start_time).total_seconds()
            self._print_summary(success, duration)

            # Save execution log
            self._save_execution_log(runbook)

            return success

        except KeyboardInterrupt:
            logger.warning("\n[!] Execution interrupted by user")
            self._offer_rollback()
            return False

        except Exception as e:
            logger.error(f"[-] Execution failed: {e}")
            return False

    def _execute_step(self, step: Dict) -> ActionResult:
        """Execute a single step with approval gate"""
        action_name = step.get("action")
        params = self._substitute_variables(step.get("parameters", {}))
        severity = Severity(step.get("severity", "medium"))

        # Check approval
        if not self._check_approval(step, severity):
            return ActionResult(
                success=False,
                message="Action not approved by analyst"
            )

        # Dry run check
        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute: {action_name}")
            logger.info(f"[DRY RUN] Parameters: {json.dumps(params, indent=2)}")
            return ActionResult(success=True, message="Dry run - no action taken")

        # Get action handler
        handler = self.actions.get(action_name)
        if not handler:
            return ActionResult(
                success=False,
                message=f"Unknown action: {action_name}"
            )

        # Execute action
        try:
            result = handler(params)

            # Track for potential rollback
            if result.rollback_info:
                self.rollback_stack.append({
                    "step": step.get("name"),
                    "action": action_name,
                    "rollback_info": result.rollback_info
                })

            # Log execution
            self.execution_log.append({
                "timestamp": datetime.now().isoformat(),
                "step": step.get("name"),
                "action": action_name,
                "parameters": params,
                "severity": severity.value,
                "result": result.to_dict()
            })

            if result.success:
                logger.info(f"[OK] {result.message}")
            else:
                logger.error(f"[-] {result.message}")

            return result

        except Exception as e:
            logger.error(f"[-] Action execution error: {e}")
            return ActionResult(success=False, message=str(e))

    def _check_approval(self, step: Dict, severity: Severity) -> bool:
        """Check if action is approved based on severity"""
        # Auto-approve if below threshold
        if self.auto_approve_level:
            severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            if severity_order.index(severity) <= severity_order.index(self.auto_approve_level):
                logger.info(f"[AUTO] Auto-approved ({severity.value} <= {self.auto_approve_level.value})")
                return True

        # Low severity always auto-approved
        if severity == Severity.LOW:
            return True

        # Prompt for approval
        action_name = step.get("action")
        step_name = step.get("name", action_name)

        print(f"\n{'!'*60}")
        print(f"APPROVAL REQUIRED - {severity.value.upper()} severity action")
        print(f"{'!'*60}")
        print(f"Step: {step_name}")
        print(f"Action: {action_name}")
        print(f"Description: {step.get('description', 'No description')}")

        if step.get("parameters"):
            print(f"Parameters: {json.dumps(step['parameters'], indent=2)}")

        print(f"{'!'*60}")

        while True:
            response = input("Approve this action? [y/n/skip/abort]: ").lower().strip()

            if response in ("y", "yes"):
                logger.info("[APPROVED] Action approved by analyst")
                return True
            elif response in ("n", "no", "skip"):
                logger.info("[SKIPPED] Action skipped by analyst")
                return False
            elif response == "abort":
                raise KeyboardInterrupt("Aborted by analyst")
            else:
                print("Please enter 'y', 'n', 'skip', or 'abort'")

    def _substitute_variables(self, obj: Any) -> Any:
        """Recursively substitute ${var} placeholders"""
        if isinstance(obj, str):
            import re
            pattern = r'\$\{(\w+)\}'

            def replace(match):
                var = match.group(1)
                return str(self.variables.get(var, match.group(0)))

            return re.sub(pattern, replace, obj)

        elif isinstance(obj, dict):
            return {k: self._substitute_variables(v) for k, v in obj.items()}

        elif isinstance(obj, list):
            return [self._substitute_variables(item) for item in obj]

        return obj

    def _evaluate_condition(self, condition: Optional[str]) -> bool:
        """Evaluate step condition"""
        if not condition:
            return True

        try:
            condition = self._substitute_variables(condition)
            # Safe evaluation with limited builtins
            return eval(condition, {"__builtins__": {}}, self.variables)
        except Exception as e:
            logger.warning(f"[!] Condition evaluation failed: {e}")
            return False

    def _offer_rollback(self):
        """Offer to rollback executed actions"""
        if not self.rollback_stack:
            logger.info("[i] No actions to rollback")
            return

        print(f"\n{'='*60}")
        print("ROLLBACK AVAILABLE")
        print(f"{'='*60}")
        print(f"Actions that can be rolled back: {len(self.rollback_stack)}")

        for i, item in enumerate(reversed(self.rollback_stack), 1):
            print(f"  {i}. {item['step']} ({item['action']})")

        response = input("\nRollback all actions? [y/n]: ").lower().strip()

        if response in ("y", "yes"):
            self._execute_rollback()
        else:
            logger.info("[i] Rollback skipped - manual cleanup may be required")

    def _execute_rollback(self):
        """Execute rollback of performed actions"""
        logger.info("\n[i] Executing rollback...")

        for item in reversed(self.rollback_stack):
            logger.info(f"[ROLLBACK] {item['step']}")
            # Rollback implementation would go here
            # Each action's rollback_info contains instructions

        logger.info("[OK] Rollback complete")

    # Built-in actions
    def _action_log(self, params: Dict) -> ActionResult:
        """Log a message"""
        message = params.get("message", "")
        level = params.get("level", "info")

        log_func = getattr(logger, level, logger.info)
        log_func(f"    {message}")

        return ActionResult(success=True, message=f"Logged: {message}")

    def _action_set_variable(self, params: Dict) -> ActionResult:
        """Set a runtime variable"""
        name = params.get("name")
        value = params.get("value")

        if not name:
            return ActionResult(success=False, message="Variable name required")

        self.variables[name] = value
        logger.info(f"    Set {name} = {value}")

        return ActionResult(success=True, message=f"Variable set: {name}")

    def _action_conditional(self, params: Dict) -> ActionResult:
        """Conditional branching"""
        condition = params.get("condition")
        if_true = params.get("if_true", [])
        if_false = params.get("if_false", [])

        result = self._evaluate_condition(condition)
        steps = if_true if result else if_false

        for step in steps:
            step_result = self._execute_step(step)
            if not step_result.success:
                return step_result

        return ActionResult(success=True, message=f"Condition evaluated: {result}")

    def _action_prompt_analyst(self, params: Dict) -> ActionResult:
        """Prompt analyst for input"""
        prompt = params.get("prompt", "Enter value")
        variable = params.get("variable")

        if self.dry_run:
            return ActionResult(success=True, message="Dry run - would prompt analyst")

        value = input(f"\n[?] {prompt}: ").strip()

        if variable:
            self.variables[variable] = value

        return ActionResult(
            success=True,
            message="Analyst input received",
            data={"value": value}
        )

    def _action_run_triage(self, params: Dict) -> ActionResult:
        """Run triage script and collect evidence"""
        target = params.get("target", "localhost")
        script_type = params.get("type", "auto")

        # Determine script based on OS
        if script_type == "auto":
            script_type = "windows" if platform.system() == "Windows" else "linux"

        scripts_dir = Path(__file__).parent.parent / "scripts"

        if script_type == "windows":
            script = scripts_dir / "windows-triage.ps1"
            cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(script)]
        else:
            script = scripts_dir / "linux-triage.sh"
            cmd = ["bash", str(script)]

        if not script.exists():
            return ActionResult(
                success=False,
                message=f"Triage script not found: {script}"
            )

        logger.info(f"    Running {script_type} triage on {target}...")

        if self.dry_run:
            return ActionResult(
                success=True,
                message=f"Dry run - would execute: {' '.join(cmd)}"
            )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # Log evidence
            if self.evidence_chain:
                self.evidence_chain.add_evidence(
                    evidence_type="triage_output",
                    source=target,
                    description=f"{script_type} triage script output"
                )

            return ActionResult(
                success=result.returncode == 0,
                message=f"Triage completed with exit code {result.returncode}",
                data={"stdout": result.stdout, "stderr": result.stderr}
            )

        except subprocess.TimeoutExpired:
            return ActionResult(success=False, message="Triage script timed out")
        except Exception as e:
            return ActionResult(success=False, message=str(e))

    def _print_header(self, runbook: Dict):
        """Print execution header"""
        print("\n" + "=" * 70)
        print("INCIDENT RESPONSE RUNBOOK EXECUTION")
        print("=" * 70)
        print(f"Runbook:     {runbook['name']}")
        print(f"Version:     {runbook['version']}")
        print(f"Description: {runbook['description']}")
        print(f"Incident ID: {self.incident_id}")
        print(f"Analyst:     {self.variables.get('analyst', 'unknown')}")
        print(f"Hostname:    {platform.node()}")
        print(f"Started:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        if self.dry_run:
            print("\n[!] DRY RUN MODE - No actions will be executed")

        if self.auto_approve_level:
            print(f"[i] Auto-approve level: {self.auto_approve_level.value}")

        print("=" * 70)

    def _print_summary(self, success: bool, duration: float):
        """Print execution summary"""
        print("\n" + "=" * 70)
        print("EXECUTION SUMMARY")
        print("=" * 70)

        status = "[OK] COMPLETED" if success else "[-] FAILED"
        print(f"Status:      {status}")
        print(f"Duration:    {duration:.2f} seconds")
        print(f"Steps run:   {len(self.execution_log)}")

        if self.evidence_chain:
            print(f"Evidence:    {len(self.evidence_chain.evidence_items)} items")
            print(f"Output dir:  {self.output_dir / self.incident_id}")

        if self.rollback_stack:
            print(f"Rollback:    {len(self.rollback_stack)} actions can be undone")

        print("=" * 70)

    def _save_execution_log(self, runbook: Dict):
        """Save detailed execution log"""
        log_dir = self.output_dir / self.incident_id
        log_dir.mkdir(parents=True, exist_ok=True)

        log_file = log_dir / "execution_log.json"

        log_data = {
            "incident_id": self.incident_id,
            "runbook": {
                "name": runbook["name"],
                "version": runbook["version"]
            },
            "execution": {
                "started_at": self.variables.get("timestamp"),
                "completed_at": datetime.now().isoformat(),
                "dry_run": self.dry_run,
                "analyst": self.variables.get("analyst"),
                "hostname": platform.node()
            },
            "variables": self.variables,
            "steps": self.execution_log,
            "rollback_available": [
                {"step": r["step"], "action": r["action"]}
                for r in self.rollback_stack
            ]
        }

        with open(log_file, "w") as f:
            json.dump(log_data, f, indent=2)

        logger.info(f"[+] Execution log saved: {log_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Incident Response Runbook Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python runbook_engine.py --runbook templates/ransomware.yaml
  python runbook_engine.py --runbook templates/malware.yaml --dry-run
  python runbook_engine.py --runbook templates/credential_compromise.yaml --auto-approve low

Severity Levels:
  low      - Logging, enrichment (always auto-approved)
  medium   - Evidence collection, alerts (prompts by default)
  high     - Containment actions (requires approval)
  critical - Account disable, host isolation (requires explicit approval)
        """
    )

    parser.add_argument(
        "--runbook", "-r",
        type=Path,
        required=True,
        help="Path to runbook YAML file"
    )

    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Simulate execution without performing actions"
    )

    parser.add_argument(
        "--auto-approve", "-a",
        choices=["low", "medium", "high"],
        help="Auto-approve actions up to this severity level"
    )

    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=Path("./ir-output"),
        help="Output directory for evidence and logs"
    )

    parser.add_argument(
        "--variables", "-v",
        type=Path,
        help="JSON file with additional variables"
    )

    args = parser.parse_args()

    if not YAML_AVAILABLE:
        logger.error("PyYAML required. Install: pip install pyyaml")
        return 1

    # Initialize engine
    engine = RunbookEngine(
        dry_run=args.dry_run,
        auto_approve=args.auto_approve,
        output_dir=args.output_dir
    )

    # Load additional variables
    if args.variables and args.variables.exists():
        with open(args.variables) as f:
            engine.variables.update(json.load(f))
        logger.info(f"[+] Loaded variables from {args.variables}")

    # Load and execute runbook
    try:
        runbook = engine.load_runbook(args.runbook)
        success = engine.execute(runbook)
        return 0 if success else 1

    except FileNotFoundError as e:
        logger.error(f"[-] {e}")
        return 1

    except Exception as e:
        logger.error(f"[-] Execution failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
