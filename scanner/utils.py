"""Shared helpers for parsing targets and making HTTP requests."""

import socket
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT = 8
USER_AGENT = "SimpleVulnScanner/1.0 (+https://github.com/yourusername/simple-vuln-scanner)"


def normalize_target(raw: str) -> tuple[str, str, int, bool]:
    """
    Turn user input into a consistent scan target.

    Returns (display_target, hostname, port, use_https).
    """
    text = raw.strip()
    if not text:
        raise ValueError("Target cannot be empty")

    if "://" not in text:
        text = f"https://{text}"

    parsed = urlparse(text)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not parse hostname from: {raw}")

    use_https = parsed.scheme == "https"
    port = parsed.port or (443 if use_https else 80)
    display = f"{parsed.scheme}://{hostname}:{port}"

    return display, hostname, port, use_https


def resolve_host(hostname: str) -> str:
    """Resolve hostname to an IP address for socket operations."""
    return socket.gethostbyname(hostname)


def fetch_url(url: str, method: str = "GET", timeout: int = DEFAULT_TIMEOUT) -> tuple[int, dict[str, str], bytes]:
    """
    Make an HTTP request and return status code, headers, and body.

    Headers are returned with lowercase keys for easy lookup.
    """
    request = Request(url, method=method, headers={"User-Agent": USER_AGENT})
    context = ssl.create_default_context()

    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.read()
            return response.status, headers, body
    except HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        body = exc.read() if exc.fp else b""
        return exc.code, headers, body
    except URLError as exc:
        raise ConnectionError(str(exc.reason)) from exc


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if a TCP port accepts connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
