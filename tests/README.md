# Defensive Toolkit - Test Suite

Comprehensive test suite for the Defensive Toolkit security tools using pytest, uv, and modern testing practices.

## Overview

This test suite provides extensive coverage for all 10 categories of the defensive toolkit:

- [OK] **Automation** - SOAR playbook engine and actions
- [OK] **Compliance** - CIS and NIST compliance checkers
- [OK] **Forensics** - Memory, disk, and artifact collection
- [OK] **Log Analysis** - Universal log parsing and anomaly detection
- [OK] **Vulnerability Management** - Scanners, SBOM, and risk scoring
- [OK] **Integration Tests** - End-to-end workflow testing

## Test Structure

```
tests/
├── conftest.py                 # Shared fixtures and pytest configuration
├── unit/                       # Unit tests for individual modules
│   ├── test_automation/
│   │   └── test_playbook_engine.py
│   ├── test_compliance/
│   │   └── test_cis_checker.py
│   ├── test_forensics/
│   │   └── test_forensics_collector.py
│   ├── test_log_analysis/
│   │   └── test_log_parser.py
│   └── test_vulnerability_mgmt/
│       └── test_vulnerability_scanner.py
├── integration/                # Integration tests for workflows
│   └── test_soar_workflows.py
├── fixtures/                   # Test data and mock files
│   ├── sample_logs/
│   ├── sample_configs/
│   └── mock_data/
└── README.md                   # This file
```

## Quick Start

### Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) package manager

### Installation

1. Install uv (if not already installed):

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Or via pip
pip install uv
```

2. Install project dependencies:

```bash
# Install all dependencies including dev dependencies
uv sync --all-extras --dev

# Or just dev dependencies
uv sync --dev
```

### Running Tests

#### Run All Tests

```bash
# Run all tests with coverage
uv run pytest tests/ -v --cov=. --cov-report=html --cov-report=term-missing

# Run with parallel execution (faster)
uv run pytest tests/ -v -n auto
```

#### Run Specific Test Categories

```bash
# Unit tests only
uv run pytest tests/unit/ -v

# Integration tests only
uv run pytest tests/integration/ -v -m integration

# Specific module
uv run pytest tests/unit/test_automation/ -v

# Specific test file
uv run pytest tests/unit/test_log_analysis/test_log_parser.py -v

# Specific test function
uv run pytest tests/unit/test_log_analysis/test_log_parser.py::TestLogParser::test_parse_syslog_basic -v
```

#### Run Tests by Markers

```bash
# Run only unit tests
uv run pytest -m unit

# Run only integration tests
uv run pytest -m integration

# Skip slow tests
uv run pytest -m "not slow"

# Run only Windows-specific tests
uv run pytest -m windows

# Run only Linux-specific tests
uv run pytest -m linux
```

### Coverage Reports

```bash
# Generate HTML coverage report
uv run pytest tests/ --cov=. --cov-report=html

# Open coverage report
# Windows
start htmlcov/index.html

# macOS
open htmlcov/index.html

# Linux
xdg-open htmlcov/index.html

# Generate terminal report with missing lines
uv run pytest tests/ --cov=. --cov-report=term-missing

# Generate JSON report for CI/CD
uv run pytest tests/ --cov=. --cov-report=json

# View coverage summary
uv run coverage report
```

### Test Markers

The test suite uses pytest markers to categorize tests:

| Marker | Description | Usage |
|--------|-------------|-------|
| `unit` | Unit tests | `pytest -m unit` |
| `integration` | Integration tests | `pytest -m integration` |
| `slow` | Slow-running tests | `pytest -m "not slow"` to skip |
| `windows` | Windows-specific tests | Auto-skipped on non-Windows |
| `linux` | Linux-specific tests | Auto-skipped on non-Linux |
| `requires_network` | Tests requiring network | Skip in offline environments |
| `requires_root` | Tests requiring admin/root | Skip if not elevated |

### Test Configuration

#### pytest.ini (in pyproject.toml)

Key configuration options:

```toml
[tool.pytest.ini_options]
minversion = "8.0"
testpaths = ["tests"]
addopts = [
    "-ra",                     # Show summary of all test outcomes
    "-v",                      # Verbose output
    "--strict-markers",        # Strict marker usage
    "--cov=.",                 # Coverage for all files
    "--cov-report=html",       # HTML coverage report
    "--cov-fail-under=70",     # Fail if coverage below 70%
]
```

#### Coverage Configuration

Coverage settings in `pyproject.toml`:

```toml
[tool.coverage.run]
branch = true
source = ["."]
omit = [
    "*/tests/*",
    "*/__pycache__/*",
    "*/venv/*",
]

[tool.coverage.report]
precision = 2
show_missing = true
exclude_lines = [
    "pragma: no cover",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:",
]
```

## Writing Tests

### Test Structure

```python
#!/usr/bin/env python3
"""
Unit tests for module_name
"""

import pytest
from module_name import MyClass


class TestMyClass:
    """Test MyClass functionality"""

    def test_init(self):
        """Test class initialization"""
        obj = MyClass()
        assert obj is not None

    def test_method(self):
        """Test specific method"""
        obj = MyClass()
        result = obj.method()
        assert result == expected_value


# Parametrized tests
@pytest.mark.parametrize("input,expected", [
    ("test1", "result1"),
    ("test2", "result2"),
])
def test_with_parameters(input, expected):
    """Test with multiple inputs"""
    assert process(input) == expected


# Integration test
@pytest.mark.integration
def test_end_to_end_workflow():
    """Test complete workflow"""
    # Test implementation
    pass


# Slow test
@pytest.mark.slow
def test_performance():
    """Test performance"""
    # Long-running test
    pass
```

### Using Fixtures

Common fixtures are defined in `conftest.py`:

```python
def test_with_fixture(sample_syslog_line, tmp_path):
    """Test using fixtures"""
    # sample_syslog_line provides test data
    # tmp_path provides temporary directory

    log_file = tmp_path / "test.log"
    log_file.write_text(sample_syslog_line)

    assert log_file.exists()
```

### Mocking External Dependencies

```python
from unittest.mock import Mock, patch

@patch('subprocess.run')
def test_with_mock(mock_run):
    """Test with mocked subprocess"""
    mock_run.return_value = Mock(returncode=0, stdout="success")

    # Your test code
    result = run_command(['echo', 'test'])

    assert result is not None
    mock_run.assert_called_once()
```

## CI/CD Integration

### GitHub Actions

Tests run automatically on:
- Push to `main` or `develop` branches
- Pull requests to `main`
- Manual workflow dispatch

Workflow file: [.github/workflows/tests.yml](.github/workflows/tests.yml)

### Test Matrix

Tests run on multiple configurations:

- **Operating Systems**: Ubuntu, Windows
- **Python Versions**: 3.10, 3.11, 3.12

### Coverage Reports

Coverage reports are automatically:
- Generated for each test run
- Uploaded to Codecov (on main branch)
- Available as workflow artifacts

## Code Quality Tools

### Security Linting with Bandit

```bash
# Run Bandit security linter
uv run bandit -r . -x tests,venv -f screen

# Generate JSON report
uv run bandit -r . -x tests,venv -f json -o bandit-report.json
```

### Code Formatting with Black

```bash
# Check formatting
uv run black --check --diff .

# Auto-format code
uv run black .
```

### Linting with Ruff

```bash
# Run Ruff linter
uv run ruff check .

# Auto-fix issues
uv run ruff check --fix .
```

### Type Checking with mypy

```bash
# Run mypy type checker
uv run mypy .
```

## Performance Testing

### Running Performance Tests

```bash
# Run slow tests (includes performance tests)
uv run pytest -m slow -v

# Run with performance profiling
uv run pytest --profile tests/

# Generate performance report
uv run py-spy record -o profile.svg -- pytest tests/
```

## Troubleshooting

### Common Issues

**Import Errors**

```bash
# Ensure dependencies are installed
uv sync --dev

# Check Python path
uv run python -c "import sys; print(sys.path)"
```

**Test Discovery Issues**

```bash
# Verify test discovery
uv run pytest --collect-only

# Check for naming issues (files must start with test_ or end with _test.py)
```

**Coverage Issues**

```bash
# Clean coverage data
rm .coverage coverage.json
rm -rf htmlcov/

# Re-run with fresh coverage
uv run pytest tests/ --cov=. --cov-report=html
```

**Windows-Specific Issues**

```bash
# Use proper path separators
# File paths should use forward slashes or Path objects

# Ensure Git Bash or PowerShell is used (not CMD)
```

## Best Practices

### Test Naming

- Test files: `test_*.py` or `*_test.py`
- Test classes: `Test*`
- Test functions: `test_*`

### Test Organization

- One test file per module
- Group related tests in classes
- Use descriptive test names
- Keep tests independent

### Test Data

- Use fixtures for reusable data
- Mock external dependencies
- Use temporary directories for file I/O
- Clean up resources in teardown

### Assertions

- Use clear assertion messages
- Test one thing per test function
- Use pytest assertions (not unittest style)

### Coverage Goals

- Target: 70%+ overall coverage
- Critical modules: 80%+ coverage
- Focus on testing logic, not boilerplate

## Resources

- [pytest Documentation](https://docs.pytest.org/)
- [uv Documentation](https://docs.astral.sh/uv/)
- [Coverage.py](https://coverage.readthedocs.io/)
- [Python Testing Best Practices](https://realpython.com/pytest-python-testing/)

## Contributing

When adding new tests:

1. Follow existing test structure
2. Add appropriate markers
3. Include docstrings
4. Update this README if needed
5. Ensure tests pass locally before PR

## License

MIT License - See [LICENSE](../LICENSE) for details

---

**Test Suite Version**: 1.0
**Last Updated**: 2025-10-18
**Coverage Target**: 70%+
**Test Count**: 100+ tests across all categories
