#!/usr/bin/env python3
"""Simple Vuln Scanner - entry point."""

import argparse
import sys

from scanner import __version__
from scanner.engine import VulnerabilityScanner
from scanner.report import print_report, save_json_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Simple Vuln Scanner — passive web security checks for authorized targets",
        epilog="Only scan systems you own or have explicit permission to test.",
    )
    parser.add_argument("target", help="Hostname or URL to scan (e.g. example.com or https://example.com)")
    parser.add_argument("-o", "--output", help="Save JSON report to this file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-headers", action="store_true", help="Skip HTTP header checks")
    parser.add_argument("--skip-ssl", action="store_true", help="Skip TLS/SSL checks")
    parser.add_argument("--skip-paths", action="store_true", help="Skip sensitive path checks")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    scanner = VulnerabilityScanner(
        scan_ports=not args.skip_ports,
        scan_headers=not args.skip_headers,
        scan_ssl=not args.skip_ssl,
        scan_paths=not args.skip_paths,
    )

    print(f"Scanning {args.target}...")
    try:
        result = scanner.run(args.target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        return 1

    print_report(result, use_color=not args.no_color)

    if args.output:
        path = save_json_report(result, args.output)
        print(f"JSON report saved to {path}")

    # Non-zero exit when anything medium or above was found
    risky = {"medium", "high", "critical"}
    if result.highest_severity.value in risky:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
