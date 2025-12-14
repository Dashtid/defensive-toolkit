# Defensive Toolkit - Utility Scripts

This directory contains utility scripts for maintaining, validating, and documenting the defensive-toolkit project.

## Available Scripts

### cleanup.py

**Purpose**: Deep cleanup of temporary files, caches, and build artifacts

**Usage**:
```bash
# From project root
python scripts/cleanup.py

# Or with uv
uv run python scripts/cleanup.py
```

**What it cleans**:
- `__pycache__/` directories
- `.pyc` and `.pyo` compiled Python files
- `.log` files
- OS-specific files (`.DS_Store`, `Thumbs.db`, `desktop.ini`)
- Pytest cache (`.pytest_cache/`)
- Coverage files (`.coverage`, `htmlcov/`, etc.)
- Temporary files (`*.tmp`, `*.temp`, `*.bak`, `*.backup`, `*~`)

**When to use**:
- Before committing to Git
- After running tests
- Before creating releases
- When troubleshooting build issues
- General project maintenance

**Example output**:
```
======================================================================
Defensive Toolkit - Deep Cleanup
======================================================================

[+] Removing __pycache__ directories...
    Removed: automation/__pycache__
    Removed: tests/__pycache__
[OK] Removed 15 __pycache__ directories

[+] Removing .pyc and .pyo files...
[OK] Removed 23 compiled Python files

[+] Removing .log files...
[OK] Removed 0 log files

[+] Removing OS-specific files (.DS_Store, Thumbs.db)...
[OK] Removed 0 OS-specific files

[+] Removing pytest cache...
    Removed: .pytest_cache
[OK] Removed pytest cache

[+] Removing coverage files...
    Removed: .coverage
    Removed: htmlcov
[OK] Removed 2 coverage files

[+] Removing temporary files...
[OK] Removed 0 temporary files

======================================================================
[OK] Deep cleanup completed!
======================================================================
```

---

### validate_project.py

**Purpose**: Validate project structure, imports, and configuration

**Usage**:
```bash
# Validate entire project
python scripts/validate_project.py

# Check specific aspects
python scripts/validate_project.py --check-structure
python scripts/validate_project.py --check-imports
python scripts/validate_project.py --check-tests
python scripts/validate_project.py --check-docs
```

**Validations performed**:
- [OK] Project directory structure matches expected layout
- [OK] All Python modules have `__init__.py` files
- [OK] All imports are resolvable
- [OK] All tests can be discovered
- [OK] Documentation files exist
- [OK] pyproject.toml is valid
- [OK] requirements.txt matches pyproject.toml dependencies
- [OK] No circular imports detected
- [OK] All README files exist in expected locations

**When to use**:
- Before committing major changes
- After restructuring directories
- During CI/CD pipeline
- When troubleshooting import errors
- Before releases

**Exit codes**:
- `0`: All validations passed
- `1`: One or more validations failed

---

### generate_docs.py

**Purpose**: Auto-generate API documentation from Python docstrings

**Usage**:
```bash
# Generate all documentation
python scripts/generate_docs.py

# Generate for specific module
python scripts/generate_docs.py --module automation

# Output to specific directory
python scripts/generate_docs.py --output docs/api/
```

**Features**:
- Extracts docstrings from all Python modules
- Generates markdown documentation
- Creates function/class reference
- Includes usage examples from docstrings
- Links to source code locations
- Supports Google and NumPy docstring formats

**Output**:
- Creates/updates `docs/API_REFERENCE.md`
- Organized by module category
- Includes function signatures with type hints
- Cross-references between modules

**When to use**:
- After adding new modules
- After updating docstrings
- Before releases
- During documentation updates
- As part of CI/CD documentation build

---

## Development Workflow

### Before Committing

```bash
# 1. Clean the project
python scripts/cleanup.py

# 2. Validate structure
python scripts/validate_project.py

# 3. Run tests
uv run pytest tests/ -v

# 4. Check code quality
uv run ruff check .
uv run black --check .

# 5. Update documentation
python scripts/generate_docs.py

# 6. Review changes
git status
git diff
```

### Adding New Scripts

When adding new utility scripts to this directory:

1. **Create the script** with proper documentation:
   ```python
   #!/usr/bin/env python3
   """
   Brief description of what the script does

   Usage:
       python scripts/your_script.py [options]
   """
   ```

2. **Add executable permissions** (Linux/macOS):
   ```bash
   chmod +x scripts/your_script.py
   ```

3. **Document in this README**:
   - Add a new section describing the script
   - Include usage examples
   - Describe when to use it
   - Document any command-line options

4. **Update pyproject.toml** if creating CLI tools:
   ```toml
   [project.scripts]
   your-tool = "scripts.your_script:main"
   ```

5. **Add tests** if the script is complex:
   ```bash
   tests/test_scripts/test_your_script.py
   ```

## Script Design Guidelines

All scripts in this directory should follow these guidelines:

### 1. Shebang and Encoding
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
```

### 2. Module Docstring
```python
"""
Brief description

Longer description with usage examples
"""
```

### 3. Imports Organization
```python
# Standard library
import os
import sys

# Third-party
import click

# Local
from automation import playbook_engine
```

### 4. Error Handling
```python
try:
    # Operation
except SpecificError as e:
    print(f"[!] Error: {e}", file=sys.stderr)
    sys.exit(1)
```

### 5. Output Formatting
Use consistent symbols:
- `[+]` - Starting operation
- `[OK]` - Success
- `[!]` - Warning
- `[-]` - Error/failure
- `[*]` - Information

### 6. Main Function Pattern
```python
def main():
    """Main entry point"""
    # Script logic here
    return 0  # Exit code

if __name__ == '__main__':
    sys.exit(main())
```

### 7. Argument Parsing
Use `argparse` for command-line arguments:
```python
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Script description')
    parser.add_argument('--option', help='Option description')
    return parser.parse_args()
```

## Integration with CI/CD

These scripts are designed to integrate with GitHub Actions workflows:

```yaml
# .github/workflows/validate.yml
- name: Validate project structure
  run: python scripts/validate_project.py

- name: Generate documentation
  run: python scripts/generate_docs.py

- name: Clean artifacts
  run: python scripts/cleanup.py
```

## Troubleshooting

### Script Not Found

**Problem**: `python scripts/script.py` fails with "No such file or directory"

**Solution**:
```bash
# Ensure you're in project root
cd /path/to/defensive-toolkit

# Verify script exists
ls -la scripts/

# Check current directory
pwd
```

### Import Errors

**Problem**: Script fails with "ModuleNotFoundError"

**Solution**:
```bash
# Install all dependencies
uv sync --all-extras --dev

# Or with pip
pip install -r requirements.txt
```

### Permission Denied (Linux/macOS)

**Problem**: `./scripts/script.py` fails with "Permission denied"

**Solution**:
```bash
# Add executable permission
chmod +x scripts/script.py

# Or run with python explicitly
python scripts/script.py
```

## Contributing

When contributing new utility scripts:

1. Follow the design guidelines above
2. Add comprehensive documentation to this README
3. Include error handling and helpful output
4. Test on both Windows and Linux
5. Update relevant CI/CD workflows

## Resources

- [Python Scripting Best Practices](https://docs.python-guide.org/writing/scripts/)
- [Click Documentation](https://click.palletsprojects.com/) - For advanced CLI tools
- [argparse Tutorial](https://docs.python.org/3/howto/argparse.html)

---

**Questions or suggestions for new scripts?** Open an issue or submit a pull request!
