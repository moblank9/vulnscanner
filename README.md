# VulnScanner — Automated Vulnerability Scanner

> **WARNING: This tool is intended ONLY for authorized security assessments.**
> Unauthorized scanning of systems you do not own or have explicit written
> permission to test is **illegal** under the Computer Fraud and Abuse Act
> (CFAA) and similar laws worldwide. The authors assume **no liability**
> for misuse.

## Overview

VulnScanner is a modular, asynchronous vulnerability scanner that goes far
beyond simple port scanning. It performs eight analysis phases and produces a
rich HTML report with findings, severity ratings, and remediation suggestions.

### Features

| Feature | Description |
|---|---|
| **Asynchronous Port Scanner** | Fast TCP connect scan with configurable concurrency |
| **Banner Grabbing** | Retrieves service banners from open ports, including SSL-wrapped services |
| **Service Fingerprinting** | Identifies exact service names and versions from banner patterns |
| **SSL/TLS Certificate Checks** | Validates certificates (expiry, self-signed, SANs), detects weak protocols |
| **HTTP Security Headers Audit** | Checks for missing security headers (HSTS, CSP, X-Frame-Options, etc.) |
| **Directory Enumeration** | Discovers hidden paths, admin panels, config files, and sensitive resources |
| **CVE Matching** | Matches discovered services/versions against a local database of high-profile CVEs |
| **Risk Scoring** | Aggregates all findings into a weighted 0–10 risk score with severity labels |
| **HTML Report** | Self-contained dark-mode report with collapsible findings, filters, and remediation |

## Architecture

```
vulnscanner/
├── README.md
├── pyproject.toml
├── requirements.txt
└── vulnscanner/
    ├── __init__.py          # Package metadata + version
    ├── __main__.py          # python -m entry point
    ├── cli.py               # CLI argument parsing + orchestration (9 phases)
    ├── utils.py             # DNS resolution, URL normalization, progress bar
    ├── scanner/
    │   ├── port_scanner.py          # Async TCP connect scanner
    │   ├── banner_grabber.py        # Service banner retrieval
    │   ├── service_fingerprinter.py # Regex-based service/version identification
    │   ├── ssl_checker.py           # Certificate & protocol checks
    │   ├── http_headers.py          # HTTP security header audit
    │   └── directory_enum.py        # Path discovery via wordlist
    ├── cve/
    │   └── matcher.py       # CVE database loader + matcher engine
    ├── risk/
    │   └── scorer.py        # Risk aggregation and severity computation
    ├── report/
    │   └── generator.py     # HTML report builder (dark theme, collapsible UI)
    └── data/
        └── cve_db.json      # Local CVE database (27 entries)
```

### Scanning Pipeline

```
  1. Port Scan  ──►  2. Banner Grab  ──►  3. Fingerprint  ──►  4. SSL Check
        │                                                             │
        ▼                                                             ▼
  5. HTTP Headers  ──►  6. Dir Enum  ──►  7. CVE Match  ──►  8. Risk Score
                                                                    │
                                                                    ▼
                                                            9. HTML Report
```

All I/O-bound phases use `asyncio` for parallel execution with configurable
concurrency limits.

## Installation

### Prerequisites

- Python 3.10+
- pip

### From source

```bash
git clone https://github.com/example/vulnscanner.git
cd vulnscanner
pip install -e .
```

### With pip

```bash
pip install vulnscanner
```

### Dependencies

- `aiohttp` — async HTTP client for header checks and directory enumeration
- `cryptography` — X.509 certificate parsing

Install with:

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan — port range 1–1024, all checks enabled
vulnscanner scanme.example.com

# Scan specific ports
vulnscanner 192.168.1.1 -p 22,80,443,8080

# Scan a port range with custom output
vulnscanner target.example.com --port-range 1-10000 -o report.html

# Quick scan (skip time-consuming checks)
vulnscanner https://example.com --no-ssl --no-dir-enum --no-cve -q

# Custom wordlist for directory enumeration
vulnscanner https://example.com --dir-wordlist ./my_wordlist.txt
```

### All Options

| Argument | Default | Description |
|---|---|---|
| `target` | — | Hostname, IP, or URL to scan |
| `-p`, `--ports` | — | Comma or range-separated ports (e.g. `22,80,443` or `1-65535`) |
| `--port-range` | `1-1024` | Port range when `-p` is not specified |
| `--timeout` | `3.0` | Connection timeout in seconds |
| `--concurrency` | `200` | Maximum concurrent port connections |
| `-o`, `--output` | auto | Output HTML report path |
| `--no-ssl` | — | Skip SSL/TLS certificate checks |
| `--no-http-headers` | — | Skip HTTP security header analysis |
| `--no-dir-enum` | — | Skip directory enumeration |
| `--no-cve` | — | Skip CVE matching |
| `--no-banner` | — | Skip banner grabbing |
| `--dir-wordlist` | — | Custom wordlist file (one path per line) |
| `-q`, `--quiet` | — | Minimize console output |
| `--version` | — | Show version and exit |

## Report

The generated HTML report is self-contained (no external resources) and includes:

- **Summary cards** — risk score, open port count, finding counts by severity
- **Risk meter** — visual 0–10 score bar
- **Open ports table** — port, service, banner, version
- **Filterable findings** — all findings grouped and filterable by severity
- **CVE details** — matched CVEs with CVSS scores and remediation
- **SSL certificate** — full certificate details, expiry, weak protocols
- **HTTP headers** — check/uncheck for each security header
- **Discovered paths** — enumerated directories and files
- **Service fingerprints** — identified services with confidence levels
- **Disclaimer** — embedded legal notice

### Report Preview

```
┌────────────────────────────────────────────┐
│        Vulnerability Scan Report           │
│     Target: scanme.example.com (1.2.3.4)   │
│     Scan Date: 2026-07-07 12:34:56         │
├────────────────────────────────────────────┤
│  Risk Score       Open Ports   Critical   │
│    6.8 / 10           7           2        │
│     MEDIUM                                 │
├────────────────────────────────────────────┤
│  [████████████████░░░░░░░░░░] 68%          │
├────────────────────────────────────────────┤
│  Findings: [All] [Critical] [High] ...     │
│                                            │
│  ⚠ HIGH  CVE-2024-6387 (openssh)          │
│  ⚠ MED  Missing HSTS Header               │
│  ⚠ HIGH  Port 445 (SMB) open              │
│  ℹ INFO  Path /robots.txt (200)           │
└────────────────────────────────────────────┘
```

## CVE Database

The built-in database (`data/cve_db.json`) contains 27 high-profile CVEs for
common services: SSH, Apache, Nginx, IIS, MySQL, PostgreSQL, Redis, MongoDB,
OpenSSL, Tomcat, JBoss, and more.

To update the database:
1. Edit `vulnscanner/data/cve_db.json` directly
2. Or use the NVD API (feature planned) to fetch latest CVEs

CVE matching uses both the identified service name and version string. The
matcher extracts version numbers using flexible regex patterns.

## Risk Scoring Methodology

Findings are scored in these categories with the following weights:

| Severity | Weight | Examples |
|---|---|---|
| **Critical** | 10.0 | RCE vulnerabilities, exposed .git/config |
| **High** | 7.5 | SSL expiry, missing HSTS/CSP, SMB open |
| **Medium** | 5.0 | Self-signed cert, directory listing, info disclosure |
| **Low** | 2.5 | Missing low-severity headers, redirect paths |
| **Info** | 0.5 | Authenticated endpoints, informational items |

The **overall risk score** (0–10) is the mean of all finding weights, capped
at 10. The final severity label maps as:

| Score Range | Label |
|---|---|
| 7.5 – 10.0 | Critical |
| 5.0 – 7.4 | High |
| 2.5 – 4.9 | Medium |
| 0.1 – 2.4 | Low |
| 0.0 | None |

## Limitations

1. **Port scanning**: TCP connect scan only (no SYN stealth). Easily detected
   by IDS/IPS.
2. **CVE database**: Local, static, and limited to ~30 entries. Does not
   query the NVD API in real time.
3. **Fingerprinting**: Regex-based banner matching is fragile. Obfuscated or
   custom banners may not be identified.
4. **SSL checks**: Uses `ssl.CERT_NONE` — does not validate the certificate
   chain against trusted CAs.
5. **Directory enumeration**: Wordlist-based (no recursive crawling). May
   miss deeply nested paths.
6. **No authentication testing**: Does not attempt login, session testing, or
   authorization checks.
7. **False positives**: Port filtering may produce false "filtered" results.
   Banner-based version detection may be inaccurate.
8. **Speed vs. accuracy**: Higher concurrency may cause missed ports on
   rate-limited targets.
9. **IPv4 only**: No IPv6 support.
10. **No post-exploitation**: This is a reconnaissance tool only.

## Legal & Ethical Use

This tool is designed for:

- **Authorized penetration tests** with written consent
- **CTF competitions** and bug bounty programs
- **Local security research** on your own infrastructure

**DO NOT** use VulnScanner against any system unless:

- You are the system owner, OR
- You have explicit written authorization from the system owner

Violators may face criminal prosecution. When in doubt, **do not scan**.

## Development

```bash
# Install in development mode
pip install -e .

# Run from source
python -m vulnscanner scanme.example.com

# Linting
pip install ruff
ruff check vulnscanner/

# Type checking
pip install mypy
mypy vulnscanner/
```

## License

MIT License. See `LICENSE` for details.

---

*VulnScanner is a demonstration project for educational and authorized
security testing purposes only.*
