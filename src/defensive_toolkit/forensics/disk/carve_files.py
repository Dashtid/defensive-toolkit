#!/usr/bin/env python3
"""
File Carving Automation Script
Author: Defensive Toolkit
Date: 2025-10-15

Description:
    Automates file carving from disk images using bulk_extractor and foremost.
    Useful for recovering deleted files and extracting evidence.

Requirements:
    - bulk_extractor (apt install bulk-extractor)
    - foremost (apt install foremost)
    - Python 3.8+

Usage:
    python carve-files.py --image disk.img --output carved/
    python carve-files.py --image disk.dd --tool foremost
    python carve-files.py --image disk.img --types jpg,png,pdf,doc
"""

import argparse
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class FileCarver:
    """Automate file carving from disk images"""

    def __init__(self, image_file: Path, output_dir: Path):
        self.image_file = image_file
        self.output_dir = output_dir
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "image_file": str(image_file),
            "output_dir": str(output_dir),
            "tools_run": [],
            "files_carved": {},
        }

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def check_tool(self, tool_name: str) -> bool:
        """
        Check if carving tool is installed

        Args:
            tool_name: Name of tool (bulk_extractor, foremost)

        Returns:
            bool: True if tool is available
        """
        try:
            result = subprocess.run([tool_name, "-h"], capture_output=True, timeout=5)
            return result.returncode in [0, 1]  # Some tools return 1 for help
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def run_bulk_extractor(self) -> bool:
        """
        Run bulk_extractor for comprehensive data extraction

        Returns:
            bool: True if successful
        """
        logger.info("Running bulk_extractor...")

        if not self.check_tool("bulk_extractor"):
            logger.error("[X] bulk_extractor not found. Install: apt install bulk-extractor")
            return False

        output_subdir = self.output_dir / "bulk_extractor"
        output_subdir.mkdir(exist_ok=True)

        try:
            cmd = [
                "bulk_extractor",
                "-o",
                str(output_subdir),
                "-E",
                "wordlist",  # Enable wordlist extraction
                "-E",
                "net",  # Enable network artifact extraction
                str(self.image_file),
            ]

            logger.info(f"Command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800  # 30 minute timeout
            )

            if result.returncode == 0:
                # Count extracted files
                carved_files = list(output_subdir.rglob("*"))
                file_count = len([f for f in carved_files if f.is_file()])

                self.results["tools_run"].append(
                    {
                        "tool": "bulk_extractor",
                        "status": "success",
                        "output_dir": str(output_subdir),
                        "files_carved": file_count,
                    }
                )

                self.results["files_carved"]["bulk_extractor"] = file_count
                logger.info(f"[OK] bulk_extractor completed ({file_count} files)")
                return True
            else:
                logger.error(f"[X] bulk_extractor failed: {result.stderr}")
                self.results["tools_run"].append(
                    {"tool": "bulk_extractor", "status": "failed", "error": result.stderr}
                )
                return False

        except subprocess.TimeoutExpired:
            logger.error("[X] bulk_extractor timed out (30 minutes)")
            return False
        except Exception as e:
            logger.error(f"[X] Error running bulk_extractor: {e}")
            return False

    def run_foremost(self, file_types: Optional[List[str]] = None) -> bool:
        """
        Run foremost for file carving

        Args:
            file_types: List of file types to carve (e.g., ['jpg', 'pdf'])

        Returns:
            bool: True if successful
        """
        logger.info("Running foremost...")

        if not self.check_tool("foremost"):
            logger.error("[X] foremost not found. Install: apt install foremost")
            return False

        output_subdir = self.output_dir / "foremost"
        output_subdir.mkdir(exist_ok=True)

        try:
            cmd = [
                "foremost",
                "-o",
                str(output_subdir),
                "-v",  # Verbose
            ]

            # Add file type filters if specified
            if file_types:
                cmd.extend(["-t", ",".join(file_types)])

            cmd.append(str(self.image_file))

            logger.info(f"Command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800  # 30 minute timeout
            )

            if result.returncode == 0:
                # Count extracted files
                carved_files = list(output_subdir.rglob("*"))
                file_count = len([f for f in carved_files if f.is_file()])

                self.results["tools_run"].append(
                    {
                        "tool": "foremost",
                        "status": "success",
                        "output_dir": str(output_subdir),
                        "files_carved": file_count,
                        "file_types": file_types or "all",
                    }
                )

                self.results["files_carved"]["foremost"] = file_count
                logger.info(f"[OK] foremost completed ({file_count} files)")
                return True
            else:
                logger.error(f"[X] foremost failed: {result.stderr}")
                self.results["tools_run"].append(
                    {"tool": "foremost", "status": "failed", "error": result.stderr}
                )
                return False

        except subprocess.TimeoutExpired:
            logger.error("[X] foremost timed out (30 minutes)")
            return False
        except Exception as e:
            logger.error(f"[X] Error running foremost: {e}")
            return False

    def analyze_carved_files(self) -> None:
        """Analyze carved files and generate statistics"""
        logger.info("Analyzing carved files...")

        stats = {"total_files": 0, "total_size": 0, "file_types": {}, "largest_files": []}

        all_files = []

        for subdir in self.output_dir.iterdir():
            if subdir.is_dir():
                for file_path in subdir.rglob("*"):
                    if file_path.is_file():
                        stats["total_files"] += 1
                        file_size = file_path.stat().st_size
                        stats["total_size"] += file_size

                        # Track file types
                        ext = file_path.suffix.lower()
                        if ext:
                            stats["file_types"][ext] = stats["file_types"].get(ext, 0) + 1

                        all_files.append(
                            {
                                "path": str(file_path.relative_to(self.output_dir)),
                                "size": file_size,
                                "type": ext,
                            }
                        )

        # Find largest files
        all_files.sort(key=lambda x: x["size"], reverse=True)
        stats["largest_files"] = all_files[:20]

        self.results["statistics"] = stats

        logger.info("\n[+] Carving Statistics:")
        logger.info(f"  Total files carved: {stats['total_files']}")
        logger.info(f"  Total size: {stats['total_size'] / (1024*1024):.2f} MB")
        logger.info(f"  Unique file types: {len(stats['file_types'])}")

        if stats["file_types"]:
            logger.info("\n[+] File Types:")
            for ext, count in sorted(stats["file_types"].items(), key=lambda x: x[1], reverse=True)[
                :10
            ]:
                logger.info(f"  {ext}: {count} files")

    def generate_report(self) -> None:
        """Generate carving report"""
        logger.info("\n" + "=" * 70)
        logger.info("File Carving Report")
        logger.info("=" * 70)

        logger.info(f"\nImage File: {self.image_file}")
        logger.info(f"Output Directory: {self.output_dir}")
        logger.info(f"Timestamp: {self.results['timestamp']}")

        logger.info("\n[+] Tools Run:")
        for tool_result in self.results["tools_run"]:
            status_icon = "[OK]" if tool_result["status"] == "success" else "[X]"
            logger.info(f"  {status_icon} {tool_result['tool']}")
            if tool_result["status"] == "success":
                logger.info(f"      Files carved: {tool_result['files_carved']}")
            else:
                logger.info(f"      Error: {tool_result.get('error', 'Unknown')}")

        if "statistics" in self.results:
            stats = self.results["statistics"]
            logger.info("\n[+] Summary:")
            logger.info(f"  Total files: {stats['total_files']}")
            logger.info(f"  Total size: {stats['total_size'] / (1024*1024):.2f} MB")
            logger.info(f"  File types: {len(stats['file_types'])}")

        # Save JSON report
        report_file = self.output_dir / "carving_report.json"
        with open(report_file, "w") as f:
            json.dump(self.results, f, indent=2)

        logger.info(f"\n[OK] Report saved to: {report_file}")
        logger.info("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="File Carving Automation")
    parser.add_argument("--image", type=Path, required=True, help="Disk image file")
    parser.add_argument(
        "--output", type=Path, default=Path("carved_files"), help="Output directory"
    )
    parser.add_argument(
        "--tool",
        choices=["bulk_extractor", "foremost", "both"],
        default="both",
        help="Carving tool to use",
    )
    parser.add_argument("--types", help="File types to carve (comma-separated, foremost only)")

    args = parser.parse_args()

    if not args.image.exists():
        logger.error(f"[X] Image file not found: {args.image}")
        return 1

    carver = FileCarver(args.image, args.output)

    # Parse file types
    file_types = args.types.split(",") if args.types else None

    # Run carving tools
    success = False

    if args.tool in ["bulk_extractor", "both"]:
        if carver.run_bulk_extractor():
            success = True

    if args.tool in ["foremost", "both"]:
        if carver.run_foremost(file_types):
            success = True

    if not success:
        logger.error("[X] No carving tools succeeded")
        return 1

    # Analyze results
    carver.analyze_carved_files()

    # Generate report
    carver.generate_report()

    return 0


if __name__ == "__main__":
    exit(main())
