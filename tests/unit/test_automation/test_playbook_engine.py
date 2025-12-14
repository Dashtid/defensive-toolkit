#!/usr/bin/env python3
"""
Unit tests for automation/playbooks/playbook-engine.py
"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from defensive_toolkit.automation.playbooks.playbook_engine import PlaybookEngine


class TestPlaybookEngine:
    """Test PlaybookEngine class"""

    def test_init_default(self):
        """Test engine initialization with defaults"""
        engine = PlaybookEngine()

        assert engine.dry_run is False
        assert engine.variables == {}
        assert engine.execution_log == []
        assert isinstance(engine.actions_registry, dict)
        assert "log" in engine.actions_registry
        assert "set_variable" in engine.actions_registry

    def test_init_dry_run(self):
        """Test engine initialization with dry_run"""
        engine = PlaybookEngine(dry_run=True)
        assert engine.dry_run is True

    def test_register_builtin_actions(self):
        """Test built-in actions are registered"""
        engine = PlaybookEngine()

        expected_actions = ["log", "set_variable", "sleep", "conditional", "loop"]
        for action in expected_actions:
            assert action in engine.actions_registry

    def test_load_playbook_success(self, sample_playbook_file):
        """Test loading valid playbook"""
        engine = PlaybookEngine()
        playbook = engine.load_playbook(sample_playbook_file)

        assert isinstance(playbook, dict)
        assert "name" in playbook
        assert "description" in playbook
        assert "tasks" in playbook
        assert playbook["name"] == "Test Playbook"

    def test_load_playbook_missing_file(self, tmp_path):
        """Test loading non-existent playbook"""
        engine = PlaybookEngine()
        missing_file = tmp_path / "nonexistent.yaml"

        with pytest.raises(FileNotFoundError):
            engine.load_playbook(missing_file)

    def test_load_playbook_invalid_yaml(self, tmp_path):
        """Test loading invalid YAML"""
        engine = PlaybookEngine()
        invalid_file = tmp_path / "invalid.yaml"
        invalid_file.write_text("{ invalid yaml content")

        with pytest.raises(Exception):
            engine.load_playbook(invalid_file)

    def test_load_playbook_missing_required_fields(self, tmp_path):
        """Test loading playbook with missing required fields"""
        engine = PlaybookEngine()
        incomplete_file = tmp_path / "incomplete.yaml"

        incomplete_data = {"name": "Test"}  # Missing 'description' and 'tasks'
        with open(incomplete_file, "w") as f:
            yaml.dump(incomplete_data, f)

        with pytest.raises(ValueError, match="Missing required field"):
            engine.load_playbook(incomplete_file)

    def test_action_log_info(self):
        """Test log action with info level"""
        engine = PlaybookEngine()
        params = {"message": "Test info message", "level": "info"}

        result = engine._action_log(params)
        assert result is True

    def test_action_log_warning(self):
        """Test log action with warning level"""
        engine = PlaybookEngine()
        params = {"message": "Test warning", "level": "warning"}

        result = engine._action_log(params)
        assert result is True

    def test_action_log_error(self):
        """Test log action with error level"""
        engine = PlaybookEngine()
        params = {"message": "Test error", "level": "error"}

        result = engine._action_log(params)
        assert result is True

    def test_action_set_variable_success(self):
        """Test set_variable action"""
        engine = PlaybookEngine()
        params = {"name": "test_var", "value": "test_value"}

        result = engine._action_set_variable(params)

        assert result is True
        assert engine.variables["test_var"] == "test_value"

    def test_action_set_variable_missing_name(self):
        """Test set_variable action without name"""
        engine = PlaybookEngine()
        params = {"value": "test_value"}  # Missing 'name'

        result = engine._action_set_variable(params)
        assert result is False

    @patch("time.sleep")
    def test_action_sleep(self, mock_sleep):
        """Test sleep action"""
        engine = PlaybookEngine()
        params = {"seconds": 5}

        result = engine._action_sleep(params)

        assert result is True
        mock_sleep.assert_called_once_with(5)

    def test_substitute_variables_simple(self):
        """Test simple variable substitution"""
        engine = PlaybookEngine()
        engine.variables = {"username": "admin", "server": "web01"}

        template = "User ${username} logged into ${server}"
        result = engine._substitute_variables(template)

        assert result == "User admin logged into web01"

    def test_substitute_variables_dict(self):
        """Test variable substitution in dictionary"""
        engine = PlaybookEngine()
        engine.variables = {"host": "localhost"}

        template = {"server": "${host}", "port": 8080}
        result = engine._substitute_variables(template)

        assert result["server"] == "localhost"
        assert result["port"] == 8080

    def test_substitute_variables_list(self):
        """Test variable substitution in list"""
        engine = PlaybookEngine()
        engine.variables = {"env": "production"}

        template = ["${env}", "staging", "dev"]
        result = engine._substitute_variables(template)

        assert result[0] == "production"
        assert result[1] == "staging"

    def test_substitute_variables_missing(self):
        """Test substitution with missing variable"""
        engine = PlaybookEngine()
        engine.variables = {}

        template = "User ${unknown_var}"
        result = engine._substitute_variables(template)

        # Should keep placeholder if variable not found
        assert "${unknown_var}" in result

    def test_execute_task_success(self, sample_playbook_dict):
        """Test executing valid task"""
        engine = PlaybookEngine()
        task = sample_playbook_dict["tasks"][0]  # Log task

        result = engine.execute_task(task)

        assert result is True
        assert len(engine.execution_log) == 1
        assert engine.execution_log[0]["action"] == "log"
        assert engine.execution_log[0]["success"] is True

    def test_execute_task_missing_action(self):
        """Test executing task without action"""
        engine = PlaybookEngine()
        task = {"name": "Invalid task"}  # Missing 'action'

        result = engine.execute_task(task)
        assert result is False

    def test_execute_task_dry_run(self):
        """Test executing task in dry_run mode"""
        engine = PlaybookEngine(dry_run=True)
        task = {"name": "Test task", "action": "log", "parameters": {"message": "test"}}

        result = engine.execute_task(task)

        assert result is True
        assert len(engine.execution_log) == 0  # No log in dry_run

    def test_execute_playbook_success(self, sample_playbook_dict):
        """Test successful playbook execution"""
        engine = PlaybookEngine()

        result = engine.execute_playbook(sample_playbook_dict)

        assert result is True
        assert len(engine.execution_log) == 2  # 2 tasks executed

    def test_execute_playbook_task_failure(self):
        """Test playbook execution with task failure"""
        engine = PlaybookEngine()

        playbook = {
            "name": "Test Playbook",
            "description": "Test",
            "tasks": [{"name": "Invalid task", "action": "invalid_action", "parameters": {}}],
        }

        result = engine.execute_playbook(playbook)
        assert result is False

    def test_execute_playbook_continue_on_failure(self):
        """Test playbook with continue_on_failure flag"""
        engine = PlaybookEngine()

        playbook = {
            "name": "Test Playbook",
            "description": "Test",
            "tasks": [
                {
                    "name": "Failing task",
                    "action": "invalid_action",
                    "parameters": {},
                    "continue_on_failure": True,
                },
                {"name": "Success task", "action": "log", "parameters": {"message": "test"}},
            ],
        }

        result = engine.execute_playbook(playbook)
        # Should succeed because first task has continue_on_failure
        assert result is True

    def test_action_loop(self):
        """Test loop action"""
        engine = PlaybookEngine()

        params = {
            "items": ["item1", "item2", "item3"],
            "variable": "current_item",
            "tasks": [
                {"name": "Log item", "action": "log", "parameters": {"message": "${current_item}"}}
            ],
        }

        result = engine._action_loop(params)

        assert result is True
        assert len(engine.execution_log) == 3  # 3 items processed

    def test_action_conditional_true(self):
        """Test conditional action with true condition"""
        engine = PlaybookEngine()
        engine.variables = {"status": "active"}

        params = {
            "condition": "'active' == 'active'",
            "if_true": [
                {"name": "True branch", "action": "log", "parameters": {"message": "true"}}
            ],
            "if_false": [],
        }

        result = engine._action_conditional(params)
        assert result is True

    def test_save_execution_log(self, tmp_path):
        """Test saving execution log"""
        engine = PlaybookEngine()
        engine.variables = {"test": "value"}
        engine.execution_log = [
            {"timestamp": "2025-10-15T00:00:00", "action": "log", "success": True}
        ]

        output_file = tmp_path / "execution.json"
        engine.save_execution_log(output_file)

        assert output_file.exists()

        with open(output_file, "r") as f:
            log_data = json.load(f)

        assert "execution_log" in log_data
        assert "variables" in log_data
        assert log_data["variables"]["test"] == "value"

    def test_evaluate_condition_simple(self):
        """Test simple condition evaluation"""
        engine = PlaybookEngine()
        engine.variables = {"count": 5}

        # Test equality
        assert engine._evaluate_condition("5 == 5") is True
        assert engine._evaluate_condition("5 != 3") is True
        assert engine._evaluate_condition("5 > 3") is True

    def test_evaluate_condition_with_variables(self):
        """Test condition evaluation with variables"""
        engine = PlaybookEngine()
        engine.variables = {"status": "active", "count": 10}

        # _evaluate_condition internally substitutes variables,
        # so we test with the raw condition containing ${var}
        condition = "'${status}' == 'active'"

        result = engine._evaluate_condition(condition)
        assert result is True


class TestPlaybookEngineIntegration:
    """Integration tests for PlaybookEngine"""

    def test_full_playbook_execution(self, sample_playbook_file):
        """Test complete playbook execution"""
        engine = PlaybookEngine()

        playbook = engine.load_playbook(sample_playbook_file)
        result = engine.execute_playbook(playbook)

        assert result is True
        assert engine.variables.get("test_var") == "test_value"

    def test_playbook_with_variable_substitution(self, tmp_path):
        """Test playbook with variable substitution"""
        playbook_data = {
            "name": "Variable Test",
            "description": "Test variable substitution",
            "tasks": [
                {
                    "name": "Set server",
                    "action": "set_variable",
                    "parameters": {"name": "server", "value": "web01"},
                },
                {
                    "name": "Log server",
                    "action": "log",
                    "parameters": {"message": "Server: ${server}"},
                },
            ],
        }

        playbook_file = tmp_path / "var_test.yaml"
        with open(playbook_file, "w") as f:
            yaml.dump(playbook_data, f)

        engine = PlaybookEngine()
        playbook = engine.load_playbook(playbook_file)
        result = engine.execute_playbook(playbook)

        assert result is True
        assert engine.variables["server"] == "web01"


class TestMainFunction:
    """Test main function and CLI"""

    @patch("sys.argv", ["playbook_engine.py", "--playbook", "test.yaml"])
    @patch("defensive_toolkit.automation.playbooks.playbook_engine.Path.exists")
    @patch("defensive_toolkit.automation.playbooks.playbook_engine.PlaybookEngine")
    def test_main_basic(self, mock_engine_class, mock_exists, sample_playbook_file):
        """Test main function basic execution"""
        mock_exists.return_value = True
        mock_engine = Mock()
        mock_engine.load_playbook.return_value = {
            "name": "Test",
            "description": "Test",
            "tasks": [],
        }
        mock_engine.execute_playbook.return_value = True
        mock_engine_class.return_value = mock_engine

        # Note: We can't easily test main() without mocking argparse
        # This test demonstrates the structure but may need adjustment

    def test_main_with_nonexistent_playbook(self, tmp_path, capsys):
        """Test main with non-existent playbook file"""
        # This would require more complex mocking of argparse
        pass  # Placeholder for CLI testing


# [+] Parametrized Tests
@pytest.mark.parametrize("log_level", ["info", "warning", "error"])
def test_log_levels(log_level):
    """Test all log levels"""
    engine = PlaybookEngine()
    params = {"message": f"Test {log_level}", "level": log_level}

    result = engine._action_log(params)
    assert result is True


@pytest.mark.parametrize("dry_run", [True, False])
def test_dry_run_modes(dry_run):
    """Test both dry_run modes"""
    engine = PlaybookEngine(dry_run=dry_run)
    assert engine.dry_run == dry_run


# [+] Mark slow tests
@pytest.mark.slow
def test_large_playbook_execution(tmp_path):
    """Test execution of large playbook"""
    # Create large playbook with many tasks
    tasks = []
    for i in range(100):
        tasks.append(
            {"name": f"Task {i}", "action": "log", "parameters": {"message": f"Message {i}"}}
        )

    playbook_data = {"name": "Large Playbook", "description": "Test large playbook", "tasks": tasks}

    playbook_file = tmp_path / "large.yaml"
    with open(playbook_file, "w") as f:
        yaml.dump(playbook_data, f)

    engine = PlaybookEngine()
    playbook = engine.load_playbook(playbook_file)
    result = engine.execute_playbook(playbook)

    assert result is True
    assert len(engine.execution_log) == 100
