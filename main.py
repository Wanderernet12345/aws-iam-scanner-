#!/usr/bin/env python3
"""
AWS IAM Misconfiguration Scanner - Main Entry Point

Usage examples:
    python main.py
    python main.py --severity HIGH --output both
    python main.py --profile myprofile --entity-type USER
    python main.py --output json

    # File mode example (load pre-pulled data from BishopFox iam-vulnerable export or saved scan)
    python main.py --data-source file --input-file exported_data.json
"""

import argparse
import sys
from datetime import datetime, timezone
import os

# Add local package to path when running directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.iam_collector import IamCollector
from scanner.rule_engine import RuleEngine
from scanner.report_generator import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description="AWS IAM Security Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --severity CRITICAL --output both
  python main.py --profile prod --entity-type ROLE
  python main.py --output json --severity HIGH

  # Load data from exported JSON file (no live AWS calls)
  python main.py --data-source file --input-file exported_data.json
        """
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Minimum severity to include in report (default: show all)"
    )
    parser.add_argument(
        "--output",
        choices=["terminal", "json", "both"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    parser.add_argument(
        "--entity-type",
        choices=["USER", "ROLE", "GROUP", "ACCOUNT"],
        default=None,
        help="Filter findings to specific entity type (default: all)"
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS profile name to use from ~/.aws/credentials (default: default profile)"
    )
    parser.add_argument(
        "--data-source",
        choices=["live", "file"],
        default="live",
        help="Source of IAM data: 'live' to query AWS in real-time, or 'file' to load from a pre-collected JSON (default: live)"
    )
    parser.add_argument(
        "--input-file",
        default=None,
        help="Path to JSON file containing IAM data (required when --data-source=file)"
    )
    return parser.parse_args()


def filter_findings(findings, min_severity=None, entity_type=None):
    """
    Apply CLI filters to findings list.
    """
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    filtered = findings

    if min_severity:
        min_rank = severity_order.get(min_severity, 0)
        filtered = [f for f in filtered if severity_order.get(f.get("severity", "INFO"), 0) >= min_rank]

    if entity_type:
        filtered = [f for f in filtered if f.get("entity_type") == entity_type]

    return filtered


def main():
    args = parse_args()

    # Validate file mode requirements
    if args.data_source == "file" and not args.input_file:
        print("ERROR: --input-file is required when using --data-source file")
        print("Example: python main.py --data-source file --input-file exported_data.json")
        sys.exit(1)

    print(f"Starting IAM Security Scan... {datetime.now(timezone.utc).isoformat()}")

    # 1. Collect data
    # File mode example:
    #   python main.py --data-source file --input-file exported_data.json
    try:
        collector = IamCollector(profile_name=args.profile)
        iam_data = collector.collect_all(
            data_source=args.data_source,
            input_file=args.input_file
        )
    except Exception as e:
        if args.data_source == "file":
            print(f"ERROR: Failed to load IAM data from file: {e}")
        else:
            print(f"ERROR: Failed to collect IAM data: {e}")
            print("Ensure you have valid AWS credentials and iam:Read permissions.")
        sys.exit(1)

    # Extract metadata
    account_id = iam_data.get('account_id', 'UNKNOWN')
    scan_time = iam_data.get('scan_time', datetime.now(timezone.utc).isoformat())
    users = iam_data.get('users', [])
    roles = iam_data.get('roles', [])
    groups = iam_data.get('groups', [])

    print(f"Collected data for {len(users)} users, {len(roles)} roles, {len(groups)} groups")

    # 2. Run rules
    engine = RuleEngine()
    all_findings = engine.run_all_rules(iam_data)

    # 3. Apply filters
    findings = filter_findings(all_findings, args.severity, args.entity_type)

    # Prepare scan metadata for reports
    scan_metadata = {
        "account_id": account_id,
        "scan_time": scan_time,
        "total_users": len(users),
        "total_roles": len(roles),
        "total_groups": len(groups)
    }

    # 4. Generate reports
    report_gen = ReportGenerator()

    if args.output in ("terminal", "both"):
        # Sort by cvss descending for terminal
        sorted_findings = sorted(findings, key=lambda x: x.get("cvss_score", 0), reverse=True)
        report_gen.print_terminal_report(sorted_findings, scan_metadata)

    json_path = None
    if args.output in ("json", "both"):
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join("output", f"scan_report_{timestamp}.json")
        report_gen.save_json_report(findings, scan_metadata, json_path)
        print(f"JSON report saved to: {json_path}")

    # 5. Final summary
    print(f"Scan complete. {len(findings)} findings. Report saved to output/")

    if args.output == "json" and json_path:
        print(f"Full report: {json_path}")


if __name__ == "__main__":
    main()
