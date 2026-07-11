"""Check TLS certificate health and configuration."""

import socket
import ssl
from datetime import datetime, timezone

from scanner.models import Finding, Severity


def check_ssl(hostname: str, port: int = 443) -> list[Finding]:
    """Inspect the TLS certificate and protocol version."""
    findings: list[Finding] = []
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            Finding(
                title="Certificate verification failed",
                severity=Severity.HIGH,
                description=str(exc),
                category="ssl_tls",
                recommendation="Use a valid certificate from a trusted certificate authority.",
            )
        )
        return findings
    except OSError as exc:
        findings.append(
            Finding(
                title="TLS not available",
                severity=Severity.INFO,
                description=f"Could not establish a TLS connection on port {port}: {exc}",
                category="ssl_tls",
            )
        )
        return findings

    findings.append(
        Finding(
            title="TLS connection established",
            severity=Severity.INFO,
            description=f"Negotiated protocol: {protocol}",
            category="ssl_tls",
        )
    )

    if protocol in {"TLSv1", "TLSv1.1", "SSLv3"}:
        findings.append(
            Finding(
                title="Outdated TLS protocol",
                severity=Severity.HIGH,
                description=f"Server supports {protocol}, which is deprecated and insecure.",
                category="ssl_tls",
                recommendation="Disable TLS 1.0/1.1 and require TLS 1.2 or higher.",
            )
        )

    if not cert:
        findings.append(
            Finding(
                title="No certificate details returned",
                severity=Severity.MEDIUM,
                description="The server did not provide parseable certificate information.",
                category="ssl_tls",
            )
        )
        return findings

    _check_expiry(cert, findings)
    _check_hostname(hostname, cert, findings)

    return findings


def _check_expiry(cert: dict, findings: list[Finding]) -> None:
    not_after = cert.get("notAfter")
    if not not_after:
        return

    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days

    if days_left < 0:
        findings.append(
            Finding(
                title="Certificate expired",
                severity=Severity.CRITICAL,
                description=f"The certificate expired on {not_after}.",
                category="ssl_tls",
                recommendation="Renew the TLS certificate immediately.",
            )
        )
    elif days_left <= 30:
        findings.append(
            Finding(
                title="Certificate expiring soon",
                severity=Severity.MEDIUM,
                description=f"The certificate expires in {days_left} day(s) on {not_after}.",
                category="ssl_tls",
                recommendation="Renew the certificate before it expires.",
            )
        )
    else:
        findings.append(
            Finding(
                title="Certificate valid",
                severity=Severity.INFO,
                description=f"Certificate is valid for another {days_left} day(s).",
                category="ssl_tls",
            )
        )


def _check_hostname(hostname: str, cert: dict, findings: list[Finding]) -> None:
    """Flag when the certificate CN/SAN does not appear to cover the hostname."""
    subject = dict(x[0] for x in cert.get("subject", ()))
    common_name = subject.get("commonName", "")

    san_entries = []
    for san_type, value in cert.get("subjectAltName", ()):
        if san_type == "DNS":
            san_entries.append(value)

    covered = hostname == common_name or hostname in san_entries
    if common_name.startswith("*.") and hostname.endswith(common_name[1:]):
        covered = True

    if not covered and common_name:
        findings.append(
            Finding(
                title="Certificate hostname mismatch",
                severity=Severity.MEDIUM,
                description=f"Certificate is issued for '{common_name}' but target is '{hostname}'.",
                category="ssl_tls",
                recommendation="Use a certificate that matches the scanned hostname.",
            )
        )
