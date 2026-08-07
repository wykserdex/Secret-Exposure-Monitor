"""CLI for Secret Exposure Monitor."""

import argparse
import json
import sys
from uuid import UUID


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="sem",
        description="Secret Exposure Monitor - Detect and remediate exposed secrets",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a repository for secrets")
    scan_parser.add_argument("path", help="Path to repository or file")
    scan_parser.add_argument("--tenant-id", required=True, type=UUID, help="Tenant ID")
    scan_parser.add_argument("--repository-id", required=True, type=UUID, help="Repository ID")
    scan_parser.add_argument("--history", action="store_true", help="Scan full git history")
    scan_parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")

    # Remediate command
    remediate_parser = subparsers.add_parser("remediate", help="Remediate a finding")
    remediate_parser.add_argument("--finding-json", required=True, help="Finding JSON")
    remediate_parser.add_argument("--approved-by", required=True, help="User approving remediation")
    remediate_parser.add_argument("--force", action="store_true", help="Force execution without approval")

    args = parser.parse_args()

    if args.command == "scan":
        print(f"Scanning {args.path} for tenant {args.tenant_id}...")
        # In production: run actual scan
        result = {"status": "scan_not_implemented_in_cli", "message": "Use API for full scanning"}
        if args.json_output:
            print(json.dumps(result))
        else:
            print("Scan initiated (mock)")

    elif args.command == "remediate":
        finding = json.loads(args.finding_json)
        print(f"Remediating finding {finding.get('finding_id', 'unknown')}...")
        # In production: execute remediation workflow
        result = {"status": "remediation_not_implemented_in_cli", "message": "Use API for remediation"}
        print(json.dumps(result))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
