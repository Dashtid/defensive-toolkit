#!/usr/bin/env python3
"""
API Documentation Generator for Defensive Toolkit

Extracts docstrings from Python modules and generates markdown documentation.

Usage:
    python scripts/generate_docs.py
    python scripts/generate_docs.py --module automation
    python scripts/generate_docs.py --output docs/api/
"""

import argparse
import ast
import sys
from pathlib import Path
from typing import Dict, List, Optional


class DocGenerator:
    """Generates API documentation from Python docstrings"""

    def __init__(self, root_dir: Optional[Path] = None, output_dir: Optional[Path] = None):
        self.root = root_dir or Path(__file__).parent.parent
        self.output_dir = output_dir or (self.root / "docs")
        self.modules_info = {}

    def extract_docstring(self, node: ast.AST) -> Optional[str]:
        """Extract docstring from AST node"""
        return ast.get_docstring(node)

    def get_function_signature(self, node: ast.FunctionDef) -> str:
        """Get function signature with arguments"""
        args = []

        # Regular arguments
        for arg in node.args.args:
            arg_str = arg.arg
            if arg.annotation:
                arg_str += f": {ast.unparse(arg.annotation)}"
            args.append(arg_str)

        # Return annotation
        returns = ""
        if node.returns:
            returns = f" -> {ast.unparse(node.returns)}"

        signature = f"{node.name}({', '.join(args)}){returns}"
        return signature

    def parse_module(self, module_path: Path) -> Dict:
        """Parse a Python module and extract documentation"""
        try:
            with open(module_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read())
        except Exception as e:
            print(f"[!] Error parsing {module_path}: {e}")
            return {}

        module_info = {
            "path": module_path,
            "docstring": self.extract_docstring(tree),
            "classes": [],
            "functions": [],
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_info = {
                    "name": node.name,
                    "docstring": self.extract_docstring(node),
                    "methods": [],
                }

                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        method_info = {
                            "name": item.name,
                            "signature": self.get_function_signature(item),
                            "docstring": self.extract_docstring(item),
                        }
                        class_info["methods"].append(method_info)

                module_info["classes"].append(class_info)

            elif isinstance(node, ast.FunctionDef):
                # Only top-level functions (not in classes)
                if isinstance(getattr(node, "parent", None), ast.Module) or not hasattr(
                    node, "parent"
                ):
                    func_info = {
                        "name": node.name,
                        "signature": self.get_function_signature(node),
                        "docstring": self.extract_docstring(node),
                    }
                    module_info["functions"].append(func_info)

        return module_info

    def scan_category(self, category_path: Path) -> List[Dict]:
        """Scan all Python files in a category"""
        modules = []

        for py_file in category_path.rglob("*.py"):
            if py_file.name == "__init__.py":
                continue
            if ".venv" in str(py_file) or ".git" in str(py_file):
                continue

            module_info = self.parse_module(py_file)
            if module_info:
                modules.append(module_info)

        return modules

    def generate_module_docs(self, module_info: Dict) -> str:
        """Generate markdown documentation for a module"""
        lines = []

        module_path = module_info["path"]
        relative_path = module_path.relative_to(self.root)

        lines.append(f"### {relative_path}\n")

        if module_info["docstring"]:
            lines.append(f"{module_info['docstring']}\n")

        # Document classes
        if module_info["classes"]:
            lines.append("**Classes:**\n")
            for cls in module_info["classes"]:
                lines.append(f"#### `{cls['name']}`\n")
                if cls["docstring"]:
                    lines.append(f"{cls['docstring']}\n")

                if cls["methods"]:
                    lines.append("**Methods:**\n")
                    for method in cls["methods"]:
                        if method["name"].startswith("_") and method["name"] != "__init__":
                            continue  # Skip private methods

                        lines.append(f"- `{method['signature']}`")
                        if method["docstring"]:
                            # Get first line of docstring
                            first_line = method["docstring"].split("\n")[0]
                            lines.append(f"  - {first_line}")
                        lines.append("")

        # Document functions
        if module_info["functions"]:
            lines.append("**Functions:**\n")
            for func in module_info["functions"]:
                if func["name"].startswith("_"):
                    continue  # Skip private functions

                lines.append(f"#### `{func['signature']}`\n")
                if func["docstring"]:
                    lines.append(f"{func['docstring']}\n")

        lines.append("---\n")
        return "\n".join(lines)

    def generate_category_docs(self, category_name: str, modules: List[Dict]) -> str:
        """Generate documentation for a category"""
        lines = []

        lines.append(f"## {category_name.replace('-', ' ').replace('_', ' ').title()}\n")

        for module_info in modules:
            lines.append(self.generate_module_docs(module_info))

        return "\n".join(lines)

    def generate_api_reference(self, specific_module: Optional[str] = None) -> str:
        """Generate complete API reference documentation"""
        lines = []

        lines.append("# Defensive Toolkit - API Reference\n")
        lines.append("Auto-generated API documentation from Python docstrings.\n")
        lines.append("**Last Updated**: " + "2025-10-18\n")
        lines.append("---\n")

        # Categories to document
        categories = [
            "automation",
            "compliance",
            "forensics",
            "log-analysis",
            "vulnerability-mgmt",
            "scripts",
        ]

        if specific_module:
            categories = [c for c in categories if c == specific_module]

        for category in categories:
            category_path = self.root / category
            if not category_path.exists():
                continue

            print(f"[+] Scanning {category}...")
            modules = self.scan_category(category_path)

            if modules:
                print(f"    Found {len(modules)} modules")
                lines.append(self.generate_category_docs(category, modules))

        return "\n".join(lines)

    def write_api_reference(self, content: str):
        """Write API reference to file"""
        output_file = self.output_dir / "API_REFERENCE.md"

        self.output_dir.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"\n[OK] API reference written to: {output_file}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Generate API documentation from Python docstrings"
    )
    parser.add_argument("--module", type=str, help="Generate docs for specific module only")
    parser.add_argument("--output", type=Path, help="Output directory for documentation")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print("=" * 70)
    print("Defensive Toolkit - API Documentation Generator")
    print("=" * 70 + "\n")

    generator = DocGenerator(output_dir=args.output)
    api_docs = generator.generate_api_reference(specific_module=args.module)
    generator.write_api_reference(api_docs)

    print("=" * 70)
    print("[OK] Documentation generation complete!")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
