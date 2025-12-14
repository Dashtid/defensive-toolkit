#!/usr/bin/env python3
"""
Deep cleanup script for defensive-toolkit project
Removes temporary files, caches, and organizes project structure
"""

import os
import shutil
from pathlib import Path


def cleanup_pycache():
    """Remove all __pycache__ directories"""
    print("[+] Removing __pycache__ directories...")
    count = 0
    for root, dirs, files in os.walk('.'):
        if '__pycache__' in dirs:
            pycache_path = Path(root) / '__pycache__'
            try:
                shutil.rmtree(pycache_path)
                count += 1
                print(f"    Removed: {pycache_path}")
            except Exception as e:
                print(f"    [!] Failed to remove {pycache_path}: {e}")
    print(f"[OK] Removed {count} __pycache__ directories\n")


def cleanup_pyc_files():
    """Remove .pyc and .pyo files"""
    print("[+] Removing .pyc and .pyo files...")
    count = 0
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith(('.pyc', '.pyo')):
                file_path = Path(root) / file
                try:
                    file_path.unlink()
                    count += 1
                except Exception as e:
                    print(f"    [!] Failed to remove {file_path}: {e}")
    print(f"[OK] Removed {count} compiled Python files\n")


def cleanup_logs():
    """Remove .log files"""
    print("[+] Removing .log files...")
    count = 0
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.log'):
                file_path = Path(root) / file
                try:
                    file_path.unlink()
                    count += 1
                    print(f"    Removed: {file_path}")
                except Exception as e:
                    print(f"    [!] Failed to remove {file_path}: {e}")
    print(f"[OK] Removed {count} log files\n")


def cleanup_os_files():
    """Remove OS-specific files"""
    print("[+] Removing OS-specific files (.DS_Store, Thumbs.db)...")
    count = 0
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file in ('.DS_Store', 'Thumbs.db', 'desktop.ini'):
                file_path = Path(root) / file
                try:
                    file_path.unlink()
                    count += 1
                    print(f"    Removed: {file_path}")
                except Exception as e:
                    print(f"    [!] Failed to remove {file_path}: {e}")
    print(f"[OK] Removed {count} OS-specific files\n")


def cleanup_pytest_cache():
    """Remove pytest cache"""
    print("[+] Removing pytest cache...")
    pytest_cache = Path('.pytest_cache')
    if pytest_cache.exists():
        try:
            shutil.rmtree(pytest_cache)
            print(f"    Removed: {pytest_cache}")
            print("[OK] Removed pytest cache\n")
        except Exception as e:
            print(f"    [!] Failed to remove pytest cache: {e}\n")
    else:
        print("    No pytest cache found\n")


def cleanup_coverage():
    """Remove coverage files"""
    print("[+] Removing coverage files...")
    coverage_files = ['.coverage', 'coverage.json', '.coverage.*']
    coverage_dir = Path('htmlcov')

    count = 0
    for pattern in coverage_files:
        for file in Path('.').glob(pattern):
            try:
                if file.is_file():
                    file.unlink()
                    count += 1
                    print(f"    Removed: {file}")
            except Exception as e:
                print(f"    [!] Failed to remove {file}: {e}")

    if coverage_dir.exists():
        try:
            shutil.rmtree(coverage_dir)
            count += 1
            print(f"    Removed: {coverage_dir}")
        except Exception as e:
            print(f"    [!] Failed to remove {coverage_dir}: {e}")

    print(f"[OK] Removed {count} coverage files\n")


def cleanup_temp_files():
    """Remove temporary files"""
    print("[+] Removing temporary files...")
    temp_patterns = ['*.tmp', '*.temp', '*.bak', '*.backup', '*~']
    count = 0

    for pattern in temp_patterns:
        for file in Path('.').rglob(pattern):
            if file.is_file():
                try:
                    file.unlink()
                    count += 1
                    print(f"    Removed: {file}")
                except Exception as e:
                    print(f"    [!] Failed to remove {file}: {e}")

    print(f"[OK] Removed {count} temporary files\n")


def main():
    """Run all cleanup operations"""
    print("="*70)
    print("Defensive Toolkit - Deep Cleanup")
    print("="*70 + "\n")

    cleanup_pycache()
    cleanup_pyc_files()
    cleanup_logs()
    cleanup_os_files()
    cleanup_pytest_cache()
    cleanup_coverage()
    cleanup_temp_files()

    print("="*70)
    print("[OK] Deep cleanup completed!")
    print("="*70)


if __name__ == '__main__':
    main()
