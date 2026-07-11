"""Orchestrates all security checks against a target."""

from scanner.checks.headers import check_headers
from scanner.checks.paths import check_sensitive_paths
from scanner.checks.ports import check_ports
from scanner.checks.ssl_check import check_ssl
from scanner.models import ScanResult, utc_now
from scanner.utils import normalize_target


def _build_url(hostname: str, port: int, use_https: bool) -> str:
    scheme = "https" if use_https else "http"
    default_port = 443 if use_https else 80
    if port == default_port:
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port}"


class VulnerabilityScanner:
    """Runs a configurable set of passive security checks."""

    def __init__(
        self,
        *,
        scan_ports: bool = True,
        scan_headers: bool = True,
        scan_ssl: bool = True,
        scan_paths: bool = True,
    ) -> None:
        self.scan_ports = scan_ports
        self.scan_headers = scan_headers
        self.scan_ssl = scan_ssl
        self.scan_paths = scan_paths

    def run(self, raw_target: str) -> ScanResult:
        display_target, hostname, port, use_https = normalize_target(raw_target)
        result = ScanResult(target=display_target, started_at=utc_now())

        if self.scan_ports:
            result.extend(check_ports(hostname))

        if self.scan_headers:
            result.extend(check_headers(_build_url(hostname, port, use_https)))

        if self.scan_ssl and (use_https or port == 443):
            ssl_port = port if use_https else 443
            result.extend(check_ssl(hostname, ssl_port))

        if self.scan_paths:
            result.extend(check_sensitive_paths(_build_url(hostname, port, use_https)))

        result.finished_at = utc_now()
        return result
