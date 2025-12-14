#!/usr/bin/env python3
"""
Security Automation Playbook Engine
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    YAML-based playbook execution engine for security automation.
    Supports sequential/parallel tasks, conditional logic, error handling.

Requirements:
    - PyYAML (pip install pyyaml)
    - Python 3.8+

Usage:
    python playbook-engine.py --playbook phishing-response.yaml
    python playbook-engine.py --playbook malware-containment.yaml --dry-run
    python playbook-engine.py --playbook alert-enrichment.yaml --variables vars.json
"""

import argparse
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logging.error("PyYAML required. Install: pip install pyyaml")

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class PlaybookEngine:
    """Execute security automation playbooks"""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.variables = {}
        self.execution_log = []
        self.actions_registry = {}
        self._register_builtin_actions()

    def _register_builtin_actions(self):
        """Register built-in actions"""
        self.actions_registry = {
            "log": self._action_log,
            "set_variable": self._action_set_variable,
            "sleep": self._action_sleep,
            "conditional": self._action_conditional,
            "loop": self._action_loop,
        }

    def load_playbook(self, playbook_file: Path) -> Dict:
        """Load YAML playbook"""
        logger.info(f"[+] Loading playbook: {playbook_file}")

        try:
            with open(playbook_file, "r") as f:
                playbook = yaml.safe_load(f)

            # Validate playbook structure
            required_fields = ["name", "description", "tasks"]
            for field in required_fields:
                if field not in playbook:
                    raise ValueError(f"Missing required field: {field}")

            logger.info(f"[OK] Loaded playbook: {playbook['name']}")
            return playbook

        except Exception as e:
            logger.error(f"[X] Error loading playbook: {e}")
            raise

    def execute_playbook(self, playbook: Dict) -> bool:
        """Execute playbook"""
        logger.info("\n" + "=" * 70)
        logger.info(f"Executing Playbook: {playbook['name']}")
        logger.info("=" * 70)
        logger.info(f"Description: {playbook['description']}")

        if self.dry_run:
            logger.info("[i] DRY RUN MODE - No actions will be executed\n")

        start_time = datetime.now()

        try:
            # Execute tasks
            tasks = playbook.get("tasks", [])
            for i, task in enumerate(tasks, 1):
                logger.info(f"\n[+] Task {i}/{len(tasks)}: {task.get('name', 'Unnamed')}")

                if not self.execute_task(task):
                    logger.error(f"[X] Task {i} failed")

                    # Check if we should continue on failure
                    if not task.get("continue_on_failure", False):
                        logger.error("[X] Playbook execution stopped due to task failure")
                        return False

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            logger.info("\n" + "=" * 70)
            logger.info("[OK] Playbook execution completed successfully")
            logger.info(f"Duration: {duration:.2f} seconds")
            logger.info("=" * 70)

            return True

        except Exception as e:
            logger.error(f"[X] Playbook execution failed: {e}")
            return False

    def execute_task(self, task: Dict) -> bool:
        """Execute single task"""
        action = task.get("action")
        if not action:
            logger.error("[X] Task missing 'action' field")
            return False

        # Check if action is registered
        if action not in self.actions_registry:
            logger.warning(f"[!] Action '{action}' not in registry, attempting module import")
            # Try to import action module
            try:
                action_result = self.execute_external_action(action, task.get("parameters", {}))
                return action_result
            except Exception as e:
                logger.error(f"[X] Failed to execute action '{action}': {e}")
                return False

        # Execute registered action
        parameters = task.get("parameters", {})

        # Substitute variables
        parameters = self._substitute_variables(parameters)

        try:
            if self.dry_run:
                logger.info(f"[DRY RUN] Would execute: {action}")
                logger.info(f"[DRY RUN] Parameters: {parameters}")
                return True

            # Execute action
            result = self.actions_registry[action](parameters)

            # Log execution
            self.execution_log.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "task": task.get("name"),
                    "action": action,
                    "parameters": parameters,
                    "result": result,
                    "success": True,
                }
            )

            return result

        except Exception as e:
            logger.error(f"[X] Action execution failed: {e}")

            self.execution_log.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "task": task.get("name"),
                    "action": action,
                    "parameters": parameters,
                    "error": str(e),
                    "success": False,
                }
            )

            return False

    def execute_external_action(self, action: str, parameters: Dict) -> bool:
        """Execute external action by importing module"""
        # Map action names to module paths
        action_modules = {
            "isolate_host": "actions.containment",
            "block_ip": "actions.containment",
            "quarantine_file": "actions.containment",
            "enrich_ioc": "actions.enrichment",
            "send_email": "actions.notification",
            "create_ticket": "integrations.ticket_connector",
            "analyze_email": "integrations.email_connector",
        }

        module_path = action_modules.get(action)
        if not module_path:
            logger.error(f"[X] Unknown action: {action}")
            return False

        try:
            # Dynamic import
            module_name, function_name = module_path.rsplit(".", 1)
            module = __import__(f"automation.{module_path}", fromlist=[function_name])

            # Get function
            func = getattr(module, action)

            # Execute
            result = func(**parameters)
            return result

        except Exception as e:
            logger.error(f"[X] External action failed: {e}")
            return False

    def _substitute_variables(self, obj: Any) -> Any:
        """Recursively substitute variables in strings"""
        if isinstance(obj, str):
            # Simple variable substitution: ${variable_name}
            import re

            pattern = r"\$\{(\w+)\}"

            def replace_var(match):
                var_name = match.group(1)
                return str(self.variables.get(var_name, match.group(0)))

            return re.sub(pattern, replace_var, obj)

        elif isinstance(obj, dict):
            return {k: self._substitute_variables(v) for k, v in obj.items()}

        elif isinstance(obj, list):
            return [self._substitute_variables(item) for item in obj]

        return obj

    # Built-in actions
    def _action_log(self, parameters: Dict) -> bool:
        """Log message"""
        message = parameters.get("message", "")
        level = parameters.get("level", "info").lower()

        if level == "info":
            logger.info(f"    {message}")
        elif level == "warning":
            logger.warning(f"    {message}")
        elif level == "error":
            logger.error(f"    {message}")

        return True

    def _action_set_variable(self, parameters: Dict) -> bool:
        """Set variable"""
        name = parameters.get("name")
        value = parameters.get("value")

        if not name:
            logger.error("[X] Variable name required")
            return False

        self.variables[name] = value
        logger.info(f"    Set variable: {name} = {value}")
        return True

    def _action_sleep(self, parameters: Dict) -> bool:
        """Sleep for specified duration"""
        duration = parameters.get("seconds", 1)
        logger.info(f"    Sleeping for {duration} seconds...")
        time.sleep(duration)
        return True

    def _action_conditional(self, parameters: Dict) -> bool:
        """Conditional execution"""
        condition = parameters.get("condition")
        if_true = parameters.get("if_true", [])
        if_false = parameters.get("if_false", [])

        # Simple condition evaluation
        result = self._evaluate_condition(condition)

        logger.info(f"    Condition result: {result}")

        tasks = if_true if result else if_false

        for task in tasks:
            if not self.execute_task(task):
                return False

        return True

    def _action_loop(self, parameters: Dict) -> bool:
        """Loop execution"""
        items = parameters.get("items", [])
        tasks = parameters.get("tasks", [])
        var_name = parameters.get("variable", "item")

        for item in items:
            logger.info(f"    Processing: {item}")
            self.variables[var_name] = item

            for task in tasks:
                if not self.execute_task(task):
                    return False

        return True

    def _evaluate_condition(self, condition: str) -> bool:
        """Evaluate simple condition"""
        # Simple condition evaluation (can be extended)
        # Supports: variable == value, variable != value, variable in list

        try:
            # Substitute variables
            condition = self._substitute_variables(condition)

            # Evaluate (limited to safe operations)
            # WARNING: eval is dangerous, use with caution
            # In production, implement proper expression parser
            return eval(condition, {"__builtins__": {}}, self.variables)

        except Exception as e:
            logger.error(f"[X] Condition evaluation failed: {e}")
            return False

    def save_execution_log(self, output_file: Path):
        """Save execution log"""
        logger.info(f"\n[+] Saving execution log to: {output_file}")

        log_data = {
            "timestamp": datetime.now().isoformat(),
            "dry_run": self.dry_run,
            "variables": self.variables,
            "execution_log": self.execution_log,
        }

        with open(output_file, "w") as f:
            json.dump(log_data, f, indent=2)

        logger.info(f"[OK] Log saved: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Security automation playbook engine")
    parser.add_argument("--playbook", type=Path, required=True, help="Playbook YAML file")
    parser.add_argument("--variables", type=Path, help="Variables JSON file")
    parser.add_argument("--dry-run", action="store_true", help="Dry run (no actions executed)")
    parser.add_argument("--log-output", type=Path, help="Save execution log to file")

    args = parser.parse_args()

    if not YAML_AVAILABLE:
        return 1

    if not args.playbook.exists():
        logger.error(f"[X] Playbook not found: {args.playbook}")
        return 1

    # Initialize engine
    engine = PlaybookEngine(dry_run=args.dry_run)

    # Load variables if provided
    if args.variables and args.variables.exists():
        with open(args.variables, "r") as f:
            engine.variables = json.load(f)
        logger.info(f"[+] Loaded {len(engine.variables)} variables")

    # Load and execute playbook
    try:
        playbook = engine.load_playbook(args.playbook)
        success = engine.execute_playbook(playbook)

        # Save execution log
        if args.log_output:
            engine.save_execution_log(args.log_output)

        return 0 if success else 1

    except Exception as e:
        logger.error(f"[X] Execution failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
