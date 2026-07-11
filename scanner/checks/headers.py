"""Check HTTP response headers for common security misconfigurations."""

from scanner.models import Finding, Severity
from scanner.utils import fetch_url

# Header -> why it matters
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": Severity.MEDIUM,
        "recommendation": "Add a Strict-Transport-Security header to force HTTPS connections.",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": Severity.MEDIUM,
        "recommendation": "Define a Content-Security-Policy to reduce XSS and data injection risk.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": Severity.LOW,
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": Severity.LOW,
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": Severity.LOW,
        "recommendation": "Add a Referrer-Policy header to control leaked referrer data.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": Severity.LOW,
        "recommendation": "Use Permissions-Policy to restrict browser features like camera and geolocation.",
    },
}

INFO_HEADERS = ("server", "x-powered-by")


def check_headers(url: str) -> list[Finding]:
    """Fetch a URL and evaluate its security-related HTTP headers."""
    findings: list[Finding] = []

    try:
        status, headers, _ = fetch_url(url)
    except ConnectionError as exc:
        findings.append(
            Finding(
                title="Could not fetch target for header check",
                severity=Severity.INFO,
                description=str(exc),
                category="http_headers",
            )
        )
        return findings

    findings.append(
        Finding(
            title="HTTP response received",
            severity=Severity.INFO,
            description=f"Server responded with status {status}.",
            category="http_headers",
        )
    )

    for header_key, meta in SECURITY_HEADERS.items():
        if header_key not in headers:
            findings.append(
                Finding(
                    title=f"Missing {meta['name']}",
                    severity=meta["severity"],
                    description=f"The {meta['name']} header was not present in the response.",
                    category="http_headers",
                    recommendation=meta["recommendation"],
                )
            )

    for header_key in INFO_HEADERS:
        if header_key in headers:
            findings.append(
                Finding(
                    title=f"Information disclosure: {header_key}",
                    severity=Severity.LOW,
                    description=f"Response includes '{header_key}: {headers[header_key]}'.",
                    category="http_headers",
                    recommendation="Remove or genericize server version headers in production.",
                )
            )

    return findings
