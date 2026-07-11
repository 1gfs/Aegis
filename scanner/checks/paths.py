"""Probe for commonly exposed sensitive files and directories."""

from scanner.models import Finding, Severity
from scanner.utils import fetch_url

# Path -> what finding to raise if it responds
SENSITIVE_PATHS = {
    "/.env": {
        "title": "Environment file exposed",
        "severity": Severity.CRITICAL,
        "description": "/.env is accessible. This file often contains API keys and database credentials.",
        "recommendation": "Block web access to .env files and rotate any exposed secrets.",
    },
    "/.git/config": {
        "title": "Git repository exposed",
        "severity": Severity.HIGH,
        "description": "/.git/config is accessible. Source code and secrets may be downloadable.",
        "recommendation": "Remove .git from the web root and audit for leaked credentials.",
    },
    "/.git/HEAD": {
        "title": "Git metadata exposed",
        "severity": Severity.HIGH,
        "description": "/.git/HEAD is accessible, indicating a exposed Git directory.",
        "recommendation": "Remove .git from the web root.",
    },
    "/admin": {
        "title": "Admin panel reachable",
        "severity": Severity.LOW,
        "description": "/admin returned a successful response. Admin interfaces should be access-controlled.",
        "recommendation": "Protect admin routes with authentication and IP allowlists.",
    },
    "/phpinfo.php": {
        "title": "PHP info page exposed",
        "severity": Severity.MEDIUM,
        "description": "phpinfo.php is accessible and may leak server configuration details.",
        "recommendation": "Remove phpinfo pages from production environments.",
    },
    "/server-status": {
        "title": "Server status page exposed",
        "severity": Severity.MEDIUM,
        "description": "/server-status is accessible and may reveal internal server metrics.",
        "recommendation": "Restrict server-status to trusted networks only.",
    },
    "/backup": {
        "title": "Backup directory reachable",
        "severity": Severity.MEDIUM,
        "description": "/backup returned a successful response.",
        "recommendation": "Store backups outside the public web root.",
    },
    "/robots.txt": {
        "title": "robots.txt found",
        "severity": Severity.INFO,
        "description": "robots.txt is present. Review it for paths that should stay private.",
        "recommendation": "Do not rely on robots.txt for security — protect sensitive paths directly.",
    },
}


def check_sensitive_paths(base_url: str) -> list[Finding]:
    """Send HEAD requests to a small set of well-known sensitive paths."""
    findings: list[Finding] = []
    base = base_url.rstrip("/")

    for path, meta in SENSITIVE_PATHS.items():
        url = f"{base}{path}"
        try:
            status, _, body = fetch_url(url, method="GET")
        except ConnectionError:
            continue

        # Only flag real hits — skip generic error pages when we can tell
        if status >= 400:
            continue

        if path == "/robots.txt" and b"user-agent" not in body.lower():
            continue

        findings.append(
            Finding(
                title=meta["title"],
                severity=meta["severity"],
                description=f"{meta['description']} (HTTP {status})",
                category="sensitive_paths",
                recommendation=meta["recommendation"],
            )
        )

    if not any(f.category == "sensitive_paths" and f.severity != Severity.INFO for f in findings):
        findings.append(
            Finding(
                title="No critical sensitive paths found",
                severity=Severity.INFO,
                description=f"Checked {len(SENSITIVE_PATHS)} common paths — nothing critical was exposed.",
                category="sensitive_paths",
            )
        )

    return findings
