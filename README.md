# Simple Vuln Scanner

A lightweight web vulnerability scanner written in Python. Runs passive security checks — port discovery, HTTP header analysis, TLS inspection, and sensitive path detection — with clear terminal output and JSON reports.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)

## Features

- **Port scanning** — Detects open ports on 18 common services (SSH, HTTP, MySQL, Redis, etc.)
- **HTTP security headers** — Flags missing HSTS, CSP, X-Frame-Options, and other headers
- **TLS/SSL checks** — Certificate expiry, hostname mismatch, and outdated protocol detection
- **Sensitive path probing** — Looks for exposed `.env`, `.git`, admin panels, and backup dirs
- **Clean CLI output** — Color-coded severity levels with remediation tips
- **JSON export** — Save results for dashboards, CI pipelines, or further analysis
- **Zero dependencies** — Standard library only, easy to run anywhere

## Quick Start

```bash
git clone https://github.com/yourusername/simple-vuln-scanner.git
cd simple-vuln-scanner

python3 main.py example.com
```

Scan a specific URL:

```bash
python3 main.py https://example.com
python3 main.py http://localhost:8080
```

Save a JSON report:

```bash
python3 main.py example.com -o reports/scan.json
```

## Example Output

```
Scanning example.com...

Scan Report
============================================================
Target:    https://example.com:443
Findings:  12
Risk:      MEDIUM in 4.2s
============================================================

[MEDIUM] Missing Strict-Transport-Security (HSTS)
  Category: http_headers
  The Strict-Transport-Security (HSTS) header was not present in the response.
  Fix: Add a Strict-Transport-Security header to force HTTPS connections.

[LOW] Information disclosure: server
  Category: http_headers
  Response includes 'server: nginx/1.18.0'.
  Fix: Remove or genericize server version headers in production.

[INFO] Open ports detected
  Category: port_scan
  Found 2 open port(s): 80/HTTP, 443/HTTPS
```

## CLI Options

| Flag | Description |
|------|-------------|
| `target` | Hostname or URL to scan (required) |
| `-o, --output` | Write JSON report to a file |
| `--no-color` | Plain text output |
| `--skip-ports` | Skip port scanning |
| `--skip-headers` | Skip HTTP header checks |
| `--skip-ssl` | Skip TLS/SSL checks |
| `--skip-paths` | Skip sensitive path checks |
| `-v, --version` | Show version |

Exit codes: `0` = clean or low risk, `1` = error, `2` = medium+ findings detected.

## Project Structure

```
simple-vuln-scanner/
├── main.py                     # CLI entry point
├── requirements.txt
├── scanner/
│   ├── engine.py               # Orchestrates all checks
│   ├── models.py               # Finding & ScanResult dataclasses
│   ├── report.py               # Terminal and JSON reporting
│   ├── utils.py                # HTTP helpers and target parsing
│   └── checks/
│       ├── ports.py            # TCP port scanner
│       ├── headers.py          # HTTP security header audit
│       ├── ssl_check.py        # TLS certificate checks
│       └── paths.py            # Sensitive path detection
```

## How It Works

Each check module returns a list of `Finding` objects with a severity, description, and fix recommendation. The scanner engine runs them in sequence and aggregates everything into a `ScanResult`.

| Check | What it looks for |
|-------|-------------------|
| Port scan | Open services on common ports; flags risky ones like Telnet, RDP, Redis |
| Headers | Missing security headers and version leaks via `Server` / `X-Powered-By` |
| SSL/TLS | Expired certs, hostname mismatches, deprecated TLS 1.0/1.1 |
| Paths | Publicly reachable `.env`, `.git`, admin pages, and backup dirs |

## Responsible Use

**Only scan systems you own or have written permission to test.** Unauthorized scanning may violate computer fraud laws and terms of service.

This tool performs passive, non-destructive checks. It does not exploit vulnerabilities, brute-force credentials, or inject payloads.

## Resume / Portfolio Notes

Good talking points for interviews:

- Built a modular scanner architecture with pluggable check modules
- Used Python dataclasses and enums for structured findings with severity scoring
- Implemented concurrent port scanning with `ThreadPoolExecutor`
- Parsed X.509 certificates and evaluated TLS configuration via the `ssl` module
- Designed CLI tooling with argparse, colored output, and machine-readable JSON export

## License

MIT License — feel free to use, modify, and share.
