#!/usr/bin/env python3
"""
Multi-Framework Compliance Mapper
Maps controls between CIS, NIST 800-53, ISO 27001, PCI-DSS, and SOC2
Helps organizations understand control overlap and compliance synergies
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# Control mapping database
CONTROL_MAPPINGS = {
    # CIS Control 1 -> Other frameworks
    "CIS-1": {
        "title": "Inventory and Control of Enterprise Assets",
        "mappings": {
            "NIST-800-53": ["CM-8", "PM-5"],
            "ISO-27001": ["A.8.1.1", "A.8.1.2"],
            "PCI-DSS": ["2.4", "11.1"],
            "SOC2": ["CC6.1", "CC6.6"],
        },
    },
    # CIS Control 2 -> Other frameworks
    "CIS-2": {
        "title": "Inventory and Control of Software Assets",
        "mappings": {
            "NIST-800-53": ["CM-8", "SA-22", "SI-7"],
            "ISO-27001": ["A.8.1.1", "A.12.5.1", "A.14.2.4"],
            "PCI-DSS": ["2.4", "6.3.2", "11.5"],
            "SOC2": ["CC6.1", "CC7.1"],
        },
    },
    # CIS Control 3 -> Other frameworks
    "CIS-3": {
        "title": "Data Protection",
        "mappings": {
            "NIST-800-53": ["SC-28", "MP-5", "MP-6"],
            "ISO-27001": ["A.8.2.3", "A.10.1.1", "A.10.1.2"],
            "PCI-DSS": ["3.4", "3.5", "3.6", "9.8"],
            "SOC2": ["CC6.1", "C1.1"],
        },
    },
    # CIS Control 4 -> Other frameworks
    "CIS-4": {
        "title": "Secure Configuration of Enterprise Assets",
        "mappings": {
            "NIST-800-53": ["CM-6", "CM-7", "CM-2"],
            "ISO-27001": ["A.12.5.1", "A.12.6.2", "A.14.2.3"],
            "PCI-DSS": ["2.2", "2.2.2", "2.2.5"],
            "SOC2": ["CC6.1", "CC6.6", "CC7.2"],
        },
    },
    # CIS Control 5 -> Other frameworks
    "CIS-5": {
        "title": "Account Management",
        "mappings": {
            "NIST-800-53": ["AC-2", "IA-2", "IA-4", "IA-5"],
            "ISO-27001": ["A.9.2.1", "A.9.2.2", "A.9.2.4", "A.9.3.1"],
            "PCI-DSS": ["8.1", "8.2", "8.3", "8.5"],
            "SOC2": ["CC6.1", "CC6.2"],
        },
    },
    # CIS Control 6 -> Other frameworks
    "CIS-6": {
        "title": "Access Control Management",
        "mappings": {
            "NIST-800-53": ["AC-3", "AC-6", "AC-17"],
            "ISO-27001": ["A.9.1.2", "A.9.2.3", "A.9.4.1"],
            "PCI-DSS": ["7.1", "7.2", "8.6"],
            "SOC2": ["CC6.1", "CC6.3"],
        },
    },
    # CIS Control 10 -> Other frameworks
    "CIS-10": {
        "title": "Malware Defenses",
        "mappings": {
            "NIST-800-53": ["SI-3", "SI-8"],
            "ISO-27001": ["A.12.2.1", "A.14.2.8"],
            "PCI-DSS": ["5.1", "5.2", "5.3"],
            "SOC2": ["CC6.8", "CC7.2"],
        },
    },
    # NIST 800-53 AC (Access Control) family
    "NIST-AC": {
        "title": "Access Control Family",
        "mappings": {
            "CIS": ["5", "6"],
            "ISO-27001": ["A.9.1", "A.9.2", "A.9.4"],
            "PCI-DSS": ["7", "8"],
            "SOC2": ["CC6.1", "CC6.2", "CC6.3"],
        },
    },
    "NIST-AU": {
        "title": "Audit and Accountability Family",
        "mappings": {
            "CIS": ["8"],
            "ISO-27001": ["A.12.4.1", "A.12.4.2", "A.12.4.3"],
            "PCI-DSS": ["10.1", "10.2", "10.3"],
            "SOC2": ["CC4.1", "CC7.2"],
        },
    },
    "NIST-CM": {
        "title": "Configuration Management Family",
        "mappings": {
            "CIS": ["4"],
            "ISO-27001": ["A.12.5.1", "A.12.6.2"],
            "PCI-DSS": ["2.2"],
            "SOC2": ["CC6.6", "CC7.2"],
        },
    },
    "NIST-IA": {
        "title": "Identification and Authentication Family",
        "mappings": {
            "CIS": ["5"],
            "ISO-27001": ["A.9.2", "A.9.3", "A.9.4"],
            "PCI-DSS": ["8.1", "8.2", "8.3"],
            "SOC2": ["CC6.1", "CC6.2"],
        },
    },
    "NIST-SC": {
        "title": "System and Communications Protection Family",
        "mappings": {
            "CIS": ["3", "13"],
            "ISO-27001": ["A.10.1", "A.13.1", "A.14.1"],
            "PCI-DSS": ["4.1", "4.2"],
            "SOC2": ["CC6.6", "CC6.7"],
        },
    },
    "NIST-SI": {
        "title": "System and Information Integrity Family",
        "mappings": {
            "CIS": ["7", "10"],
            "ISO-27001": ["A.12.2.1", "A.12.6.1", "A.16.1.3"],
            "PCI-DSS": ["5", "6", "11.2"],
            "SOC2": ["CC7.1", "CC7.2"],
        },
    },
    # ISO 27001 controls
    "ISO-A.9.2": {
        "title": "User access management",
        "mappings": {
            "CIS": ["5", "6"],
            "NIST-800-53": ["AC-2", "IA-2", "IA-4"],
            "PCI-DSS": ["8.1", "8.2"],
            "SOC2": ["CC6.1", "CC6.2"],
        },
    },
    "ISO-A.12.4": {
        "title": "Logging and monitoring",
        "mappings": {
            "CIS": ["8"],
            "NIST-800-53": ["AU-2", "AU-3", "AU-6"],
            "PCI-DSS": ["10"],
            "SOC2": ["CC4.1", "CC7.2"],
        },
    },
    # PCI-DSS requirements
    "PCI-2": {
        "title": "Do not use vendor-supplied defaults",
        "mappings": {
            "CIS": ["4"],
            "NIST-800-53": ["CM-6", "IA-5"],
            "ISO-27001": ["A.9.2.2", "A.12.5.1"],
            "SOC2": ["CC6.1", "CC6.6"],
        },
    },
    "PCI-8": {
        "title": "Identify and authenticate access",
        "mappings": {
            "CIS": ["5", "6"],
            "NIST-800-53": ["AC-2", "IA-2", "IA-5"],
            "ISO-27001": ["A.9.2", "A.9.3", "A.9.4"],
            "SOC2": ["CC6.1", "CC6.2"],
        },
    },
    "PCI-10": {
        "title": "Track and monitor all access",
        "mappings": {
            "CIS": ["8"],
            "NIST-800-53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "ISO-27001": ["A.12.4.1", "A.12.4.3"],
            "SOC2": ["CC4.1", "CC7.2"],
        },
    },
    # SOC2 Trust Service Criteria
    "SOC2-CC6.1": {
        "title": "Logical and physical access controls",
        "mappings": {
            "CIS": ["1", "4", "5", "6"],
            "NIST-800-53": ["AC-2", "AC-3", "PE-2", "PE-3"],
            "ISO-27001": ["A.9.1", "A.9.2", "A.11.1"],
            "PCI-DSS": ["7", "8", "9"],
        },
    },
    "SOC2-CC7.2": {
        "title": "System monitoring",
        "mappings": {
            "CIS": ["8", "10"],
            "NIST-800-53": ["AU-6", "SI-4"],
            "ISO-27001": ["A.12.4.1", "A.16.1.2"],
            "PCI-DSS": ["10.6", "11"],
        },
    },
}


class FrameworkMapper:
    """Multi-framework compliance mapper"""

    def __init__(self):
        self.mappings = CONTROL_MAPPINGS

    def map_control(self, control_id: str) -> Optional[Dict]:
        """
        Map a specific control to other frameworks

        Args:
            control_id: Control identifier (e.g., 'CIS-1', 'NIST-AC', 'ISO-A.9.2')

        Returns:
            Dictionary with control details and mappings
        """
        control_id = control_id.upper()

        if control_id in self.mappings:
            return {
                "control_id": control_id,
                "title": self.mappings[control_id]["title"],
                "mappings": self.mappings[control_id]["mappings"],
            }

        logger.warning(f"Control {control_id} not found in mapping database")
        return None

    def find_overlaps(self, frameworks: List[str]) -> Dict:
        """
        Find control overlaps between multiple frameworks

        Args:
            frameworks: List of framework names (e.g., ['CIS', 'NIST-800-53', 'PCI-DSS'])

        Returns:
            Dictionary showing overlapping controls
        """
        frameworks_upper = [f.upper() for f in frameworks]
        overlaps = {}

        for control_id, control_data in self.mappings.items():
            # Check if this control belongs to one of the requested frameworks
            control_framework = control_id.split("-")[0]

            if control_framework in frameworks_upper:
                # Find mappings to other requested frameworks
                relevant_mappings = {}
                for target_framework in frameworks_upper:
                    if target_framework != control_framework:
                        # Check if there's a mapping to this framework
                        for map_key, map_values in control_data["mappings"].items():
                            if map_key.upper().startswith(target_framework):
                                relevant_mappings[map_key] = map_values

                if relevant_mappings:
                    overlaps[control_id] = {
                        "title": control_data["title"],
                        "overlaps": relevant_mappings,
                    }

        return overlaps

    def generate_coverage_matrix(self, target_framework: str) -> Dict:
        """
        Generate a coverage matrix showing which controls in target framework
        are covered by implementing controls from other frameworks

        Args:
            target_framework: Framework to analyze (e.g., 'PCI-DSS', 'ISO-27001')

        Returns:
            Coverage matrix dictionary
        """
        target_upper = target_framework.upper()
        coverage = {
            "target_framework": target_framework,
            "coverage_by_control": {},
            "summary": {"total_target_controls": 0, "covered_controls": 0, "coverage_sources": {}},
        }

        # Find all target framework controls
        target_controls = set()
        for control_id, control_data in self.mappings.items():
            for map_key, map_values in control_data["mappings"].items():
                if map_key.upper() == target_upper:
                    for control in map_values:
                        target_controls.add(control)

        # For each target control, find what covers it
        for target_control in sorted(target_controls):
            covering_controls = []

            for control_id, control_data in self.mappings.items():
                mappings = control_data["mappings"].get(target_upper, [])
                if target_control in mappings:
                    source_framework = control_id.split("-")[0]
                    covering_controls.append(
                        {
                            "source_framework": source_framework,
                            "control_id": control_id,
                            "title": control_data["title"],
                        }
                    )

            coverage["coverage_by_control"][target_control] = covering_controls

        # Calculate summary statistics
        coverage["summary"]["total_target_controls"] = len(target_controls)
        coverage["summary"]["covered_controls"] = sum(
            1 for controls in coverage["coverage_by_control"].values() if controls
        )

        # Count coverage by source framework
        for controls in coverage["coverage_by_control"].values():
            for control in controls:
                source = control["source_framework"]
                coverage["summary"]["coverage_sources"][source] = (
                    coverage["summary"]["coverage_sources"].get(source, 0) + 1
                )

        return coverage

    def recommend_implementation_order(self, target_frameworks: List[str]) -> List[Dict]:
        """
        Recommend which controls to implement first for maximum multi-framework coverage

        Args:
            target_frameworks: List of frameworks to achieve compliance with

        Returns:
            Ordered list of controls by coverage value
        """
        control_scores = {}
        frameworks_upper = [f.upper() for f in target_frameworks]

        # Score each control by how many target frameworks it covers
        for control_id, control_data in self.mappings.items():
            score = 0
            covered_frameworks = set()

            for map_key in control_data["mappings"].keys():
                map_key_upper = map_key.upper()
                for target in frameworks_upper:
                    if map_key_upper.startswith(target) or map_key_upper == target:
                        covered_frameworks.add(target)
                        score += 1

            if score > 0:
                control_scores[control_id] = {
                    "control_id": control_id,
                    "title": control_data["title"],
                    "coverage_score": score,
                    "frameworks_covered": list(covered_frameworks),
                    "mappings": control_data["mappings"],
                }

        # Sort by coverage score (descending)
        recommendations = sorted(
            control_scores.values(), key=lambda x: x["coverage_score"], reverse=True
        )

        return recommendations

    def export_mapping(
        self, output_format: str = "json", output_file: Optional[Path] = None
    ) -> str:
        """Export complete mapping database"""
        if output_format == "json":
            output = json.dumps(self.mappings, indent=2)
        else:
            # Text format
            lines = []
            lines.append("=" * 80)
            lines.append("Multi-Framework Control Mapping Database")
            lines.append("=" * 80)
            lines.append("")

            for control_id, control_data in sorted(self.mappings.items()):
                lines.append(f"\n[+] {control_id}: {control_data['title']}")
                lines.append("    Maps to:")
                for framework, controls in control_data["mappings"].items():
                    lines.append(f"      - {framework}: {', '.join(controls)}")

            lines.append("\n" + "=" * 80)
            output = "\n".join(lines)

        if output_file:
            with open(output_file, "w") as f:
                f.write(output)
            logger.info(f"Mapping exported to {output_file}")

        return output


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Framework Compliance Mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Map a specific control
  python framework-mapper.py --map CIS-5

  # Find overlaps between frameworks
  python framework-mapper.py --overlaps CIS NIST-800-53 PCI-DSS

  # Generate coverage matrix
  python framework-mapper.py --coverage PCI-DSS

  # Get implementation recommendations
  python framework-mapper.py --recommend NIST-800-53 ISO-27001 SOC2

  # Export full mapping database
  python framework-mapper.py --export --output-format json
        """,
    )

    parser.add_argument("--map", type=str, help="Map a specific control (e.g., CIS-1, NIST-AC)")
    parser.add_argument("--overlaps", nargs="+", type=str, help="Find overlaps between frameworks")
    parser.add_argument(
        "--coverage", type=str, help="Generate coverage matrix for target framework"
    )
    parser.add_argument(
        "--recommend",
        nargs="+",
        type=str,
        help="Recommend implementation order for target frameworks",
    )
    parser.add_argument("--export", action="store_true", help="Export full mapping database")
    parser.add_argument(
        "--output-format", choices=["json", "text"], default="text", help="Output format"
    )
    parser.add_argument("--output", "-o", type=Path, help="Output file path")

    args = parser.parse_args()

    mapper = FrameworkMapper()

    if args.map:
        result = mapper.map_control(args.map)
        if result:
            print(
                json.dumps(result, indent=2)
                if args.output_format == "json"
                else f"\n{result['control_id']}: {result['title']}\nMappings:\n"
                + "\n".join([f"  - {k}: {', '.join(v)}" for k, v in result["mappings"].items()])
            )

    elif args.overlaps:
        result = mapper.find_overlaps(args.overlaps)
        print(
            json.dumps(result, indent=2)
            if args.output_format == "json"
            else f"\nControl Overlaps for {', '.join(args.overlaps)}:\n"
            + "\n".join(
                [
                    f"\n{cid}: {data['title']}\n  "
                    + "\n  ".join([f"{k}: {v}" for k, v in data["overlaps"].items()])
                    for cid, data in result.items()
                ]
            )
        )

    elif args.coverage:
        result = mapper.generate_coverage_matrix(args.coverage)
        if args.output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"\nCoverage Matrix for {args.coverage}:")
            print(f"Total Controls: {result['summary']['total_target_controls']}")
            print(f"Covered Controls: {result['summary']['covered_controls']}")
            print("\nCoverage by Source Framework:")
            for source, count in result["summary"]["coverage_sources"].items():
                print(f"  - {source}: {count} controls")

    elif args.recommend:
        result = mapper.recommend_implementation_order(args.recommend)
        if args.output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"\nRecommended Implementation Order for {', '.join(args.recommend)}:")
            print("(Ordered by multi-framework coverage value)\n")
            for i, control in enumerate(result[:20], 1):  # Top 20
                print(f"{i}. {control['control_id']}: {control['title']}")
                print(f"   Coverage Score: {control['coverage_score']}")
                print(f"   Covers: {', '.join(control['frameworks_covered'])}\n")

    elif args.export:
        result = mapper.export_mapping(args.output_format, args.output)
        if not args.output:
            print(result)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
