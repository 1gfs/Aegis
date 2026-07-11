"""Format and export scan results."""

import json
from pathlib import Path

from scanner.models import SEVERITY_ORDER, Finding, ScanResult, Severity

SEVERITY_COLORS = {
    Severity.INFO: "\033[36m",      # cyan
    Severity.LOW: "\033[32m",        # green
    Severity.MEDIUM: "\033[33m",     # yellow
    Severity.HIGH: "\033[91m",       # bright red
    Severity.CRITICAL: "\033[35m",   # magenta
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _colorize(text: str, severity: Severity, use_color: bool) -> str:
    if not use_color:
        return text
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}{text}{RESET}"


def print_report(result: ScanResult, *, use_color: bool = True) -> None:
    """Print a human-readable scan report to the terminal."""
    duration = ""
    if result.finished_at:
        seconds = (result.finished_at - result.started_at).total_seconds()
        duration = f" in {seconds:.1f}s"

    print()
    print(f"{BOLD}Scan Report{RESET}" if use_color else "Scan Report")
    print("=" * 60)
    print(f"Target:    {result.target}")
    print(f"Findings:  {len(result.findings)}")
    print(f"Risk:      {result.highest_severity.value.upper()}{duration}")
    print("=" * 60)

    sorted_findings = sorted(result.findings, key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)

    for finding in sorted_findings:
        badge = f"[{finding.severity.value.upper()}]"
        badge = _colorize(badge, finding.severity, use_color)
        print(f"\n{badge} {finding.title}")
        print(f"  Category: {finding.category}")
        print(f"  {finding.description}")
        if finding.recommendation:
            print(f"  Fix: {finding.recommendation}")

    print()
    _print_summary(sorted_findings, use_color)


def _print_summary(findings: list[Finding], use_color: bool) -> None:
    counts = {severity: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity] += 1

    parts = []
    for severity in reversed(list(Severity)):
        count = counts[severity]
        if count:
            label = f"{severity.value.upper()}: {count}"
            parts.append(_colorize(label, severity, use_color))

    summary = "  |  ".join(parts) if parts else "No findings"
    print(f"Summary: {summary}")
    print()


def save_json_report(result: ScanResult, path: str | Path) -> Path:
    """Write scan results to a JSON file."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return output
