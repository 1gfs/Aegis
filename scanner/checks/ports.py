"""Check for open ports on common services."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.models import Finding, Severity
from scanner.utils import is_port_open, resolve_host

# Port -> friendly service name
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Ports that are risky when exposed to the internet
RISKY_PORTS = {21, 23, 445, 3306, 3389, 5432, 5900, 6379, 27017}


def check_ports(hostname: str, ports: list[int] | None = None) -> list[Finding]:
    """Scan common TCP ports and report anything that's open."""
    findings: list[Finding] = []
    host = resolve_host(hostname)
    ports_to_scan = ports or list(COMMON_PORTS.keys())

    open_ports: list[tuple[int, str]] = []

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(is_port_open, host, port): port for port in ports_to_scan}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                service = COMMON_PORTS.get(port, "Unknown")
                open_ports.append((port, service))

    open_ports.sort()

    if not open_ports:
        findings.append(
            Finding(
                title="No common ports open",
                severity=Severity.INFO,
                description=f"None of the {len(ports_to_scan)} scanned ports responded on {hostname}.",
                category="port_scan",
            )
        )
        return findings

    port_list = ", ".join(f"{port}/{name}" for port, name in open_ports)
    findings.append(
        Finding(
            title="Open ports detected",
            severity=Severity.INFO,
            description=f"Found {len(open_ports)} open port(s): {port_list}",
            category="port_scan",
            recommendation="Review exposed services and close anything that is not required.",
        )
    )

    for port, name in open_ports:
        if port in RISKY_PORTS:
            findings.append(
                Finding(
                    title=f"Risky service exposed: {name}",
                    severity=Severity.MEDIUM,
                    description=f"Port {port} ({name}) is open. These services are often targeted when left public.",
                    category="port_scan",
                    recommendation=f"Restrict access to port {port} with a firewall or VPN.",
                )
            )

        if port == 23:
            findings.append(
                Finding(
                    title="Telnet service detected",
                    severity=Severity.HIGH,
                    description="Telnet sends credentials in plaintext and should not be used.",
                    category="port_scan",
                    recommendation="Disable Telnet and use SSH instead.",
                )
            )

    return findings
