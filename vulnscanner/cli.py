"""Command-line interface for VulnScanner."""
import argparse
import asyncio
import os
import sys
from typing import Any, Optional

from vulnscanner import __version__
from vulnscanner.scanner.port_scanner import PortScanner, ScanTarget
from vulnscanner.scanner.banner_grabber import grab_all_banners
from vulnscanner.scanner.service_fingerprinter import fingerprint_service
from vulnscanner.scanner.ssl_checker import check_ssl
from vulnscanner.scanner.http_headers import check_http_headers
from vulnscanner.scanner.directory_enum import enumerate_directories
from vulnscanner.cve.matcher import get_cve_db
from vulnscanner.risk.scorer import RiskScorer
from vulnscanner.report.generator import ReportGenerator
from vulnscanner.utils import resolve_host, normalize_url


BANNER = r"""

  __   __                 _   ___                                
  \ \ / /_ _____ __ _____| | / __| ___ __ _ _ _  _ __  __ _ _ _ 
   \ V / _ \ V  V / -_) \ / \__ \/ -_) _` | ' \| '_ \/ _` | '_|
    \_/\___/\_/\_/\___|_\_\ |___/\___\__,_|_||_| .__/\__,_|_|  
                                                |_|              
  Automated Vulnerability Scanner v{version}
  For authorized testing only.
"""


def _parse_args():
    parser = argparse.ArgumentParser(
        description="VulnScanner - Automated Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnscanner scanme.example.com
  vulnscanner 192.168.1.1 -p 22,80,443 -o report.html
  vulnscanner https://example.com --no-dir-enum --ports 1-1000
        """,
    )
    parser.add_argument("target", help="Target hostname, IP, or URL")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g. 22,80,443 or 1-1024)")
    parser.add_argument("--port-range", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Connection timeout in seconds (default: 3.0)")
    parser.add_argument("--concurrency", type=int, default=200, help="Max concurrent connections (default: 200)")
    parser.add_argument("-o", "--output", help="Output HTML report path")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL/TLS checks")
    parser.add_argument("--no-http-headers", action="store_true", help="Skip HTTP header analysis")
    parser.add_argument("--no-dir-enum", action="store_true", help="Skip directory enumeration")
    parser.add_argument("--no-cve", action="store_true", help="Skip CVE matching")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    parser.add_argument("--dir-wordlist", help="Custom wordlist file for directory enumeration")
    parser.add_argument("--quiet", "-q", action="store_true", help="Reduce output verbosity")
    parser.add_argument("--version", action="version", version=f"vulnscanner {__version__}")
    return parser.parse_args()


def _parse_ports(port_arg: str) -> Optional[list[int]]:
    if not port_arg:
        return None
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo.strip()), int(hi.strip())
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def _load_wordlist(path: str) -> list[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _print_status(msg: str, quiet: bool = False):
    if not quiet:
        print(f"[*] {msg}")


def main():
    args = _parse_args()
    target = args.target
    quiet = args.quiet

    if not quiet:
        print(BANNER.format(version=__version__))
        print(f"  Target: {target}")
        print(f"  Timeout: {args.timeout}s  Concurrency: {args.concurrency}")
        print()

    from urllib.parse import urlparse

    url = None
    effective_host = target
    try:
        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            url = normalize_url(target)
            effective_host = parsed.hostname or target
        else:
            url = normalize_url(target)
            effective_host = target
    except Exception:
        effective_host = target

    ip = resolve_host(effective_host)
    if not ip:
        print(f"[!] Could not resolve target: {effective_host}")
        sys.exit(1)

    open_ports_list: list[dict] = []
    ssl_result: Any = None
    header_result: Any = None
    dir_result: Any = None
    cve_results: list[dict] = []
    fingerprints_list: list[dict] = []

    ports = _parse_ports(args.ports) if args.ports else None

    url_port = None
    if url:
        try:
            parsed = urlparse(url)
            if parsed.port:
                url_port = parsed.port
        except Exception:
            pass

    if ports is None and args.port_range:
        try:
            lo, hi = args.port_range.split("-")
            ports = list(range(int(lo), int(hi) + 1))
        except ValueError:
            print(f"[!] Invalid port range: {args.port_range}")
            sys.exit(1)

    if ports and url_port and url_port not in ports:
        ports.append(url_port)
    elif not ports and url_port:
        ports = [url_port]

    scan_target = ScanTarget(
        host=ip,
        ports=ports or [],
        port_range=(1, 1024) if not ports else (ports[0], ports[-1]),
        timeout=args.timeout,
        max_concurrency=args.concurrency,
    )

    # --- Phase 1: Port Scan ---
    _print_status("Phase 1: Port scanning...", quiet)
    scanner = PortScanner(scan_target)
    asyncio.run(scanner.scan())

    open_ports = scanner.get_open_ports()
    _print_status(f"  Found {len(open_ports)} open port(s).", quiet)

    # --- Phase 2: Banner Grabbing ---
    banner_results: dict[int, Optional[str]] = {}
    if not args.no_banner and open_ports:
        _print_status("Phase 2: Banner grabbing...", quiet)
        banner_results = asyncio.run(grab_all_banners(ip, open_ports, args.timeout))
        _print_status(f"  Grabbed {sum(1 for v in banner_results.values() if v)} banner(s).", quiet)

    # --- Phase 3: Service Fingerprinting ---
    _print_status("Phase 3: Service fingerprinting...", quiet)
    for port, pr in open_ports.items():
        fp = fingerprint_service(port, pr.service, banner_results.get(port))
        fingerprints_list.append({
            "port": port,
            "service_name": fp.service_name,
            "service_version": fp.service_version,
            "confidence": fp.confidence,
            "raw_banner": fp.raw_banner[:200],
        })

    # Build open_ports_list
    for port, pr in open_ports.items():
        open_ports_list.append({
            "port": port,
            "state": pr.state,
            "service": pr.service,
            "banner": banner_results.get(port) or "",
            "version": next(
                (fp["service_version"] for fp in fingerprints_list if fp["port"] == port),
                "",
            ),
        })

    # --- Phase 4: SSL/TLS Check ---
    if not args.no_ssl and (443 in open_ports or 8443 in open_ports):
        ssl_port = 443 if 443 in open_ports else 8443
        _print_status(f"Phase 4: SSL/TLS check on port {ssl_port}...", quiet)
        ssl_result = asyncio.run(check_ssl(ip, ssl_port, args.timeout))
        if ssl_result.certificate:
            _print_status("  Certificate obtained.", quiet)

    # --- Phase 5: HTTP Headers ---
    if not args.no_http_headers and url:
        _print_status(f"Phase 5: HTTP security headers check...", quiet)
        header_result = asyncio.run(check_http_headers(url, args.timeout))
        _print_status(f"  Status: {header_result.status_code}, {len(header_result.findings)} header checks.", quiet)

    # --- Phase 6: Directory Enumeration ---
    if not args.no_dir_enum and url:
        _print_status(f"Phase 6: Directory enumeration...", quiet)
        wordlist = None
        if args.dir_wordlist and os.path.exists(args.dir_wordlist):
            wordlist = _load_wordlist(args.dir_wordlist)
            _print_status(f"  Using custom wordlist: {args.dir_wordlist}", quiet)
        dir_result = asyncio.run(enumerate_directories(url, wordlist=wordlist))
        _print_status(f"  Found {len(dir_result.findings)} interesting path(s).", quiet)

    # --- Phase 7: CVE Matching ---
    if not args.no_cve:
        _print_status("Phase 7: CVE matching...", quiet)
        cve_db = get_cve_db()
        for fp in fingerprints_list:
            if fp["service_version"] or fp["service_name"]:
                match = cve_db.match(
                    fp["service_name"],
                    fp["service_version"],
                    fp["port"],
                )
                if match.matches:
                    cve_results.append({
                        "service": fp["service_name"],
                        "version": fp["service_version"],
                        "matches": [
                            {
                                "cve_id": m.cve_id,
                                "description": m.description,
                                "cvss_score": m.cvss_score,
                                "severity": m.severity,
                                "affected_version": m.affected_version,
                                "remediation": m.remediation,
                            }
                            for m in match.matches
                        ],
                    })
        if cve_results:
            total = sum(len(cr["matches"]) for cr in cve_results)
            _print_status(f"  Found {total} CVE match(es).", quiet)
        else:
            _print_status("  No CVE matches found.", quiet)

    # --- Risk Scoring ---
    _print_status("Phase 8: Risk scoring...", quiet)
    scorer = RiskScorer()

    for port in open_ports_list:
        scorer.add_from_port_scan(open_ports, port["port"], port["service"])

    scorer.add_from_ssl(ssl_result)
    scorer.add_from_http_headers(header_result)
    for cr in cve_results:
        class _CVEResult:
            def __init__(self, data):
                self.service = data["service"]
                self.matches = [type("_m", (), m)() for m in data["matches"]]
        scorer.add_from_cve(_CVEResult(cr))
    scorer.add_from_directory_enum(dir_result)

    risk_score = scorer.compute()
    _print_status(f"  Overall risk score: {risk_score.overall_score:.1f}/10 ({risk_score.overall_severity})", quiet)
    _print_status(f"  Findings: {risk_score.finding_counts}", quiet)

    # --- Report Generation ---
    _print_status("Phase 9: Generating report...", quiet)
    report_gen = ReportGenerator(risk_score)
    html = report_gen.generate(
        target=target,
        ip_address=ip,
        open_ports=open_ports_list,
        ssl_result=ssl_result,
        header_result=header_result,
        cve_results=cve_results,
        dir_result=dir_result,
        fingerprints=fingerprints_list,
    )

    output_path = args.output or f"vulnscan_report_{ip}.html"
    with open(output_path, "w") as f:
        f.write(html)

    print(f"\n[+] Report saved to: {output_path}")
    if not quiet:
        print(f"\n=== Scan Summary ===")
        print(f"  Target:    {target} ({ip})")
        print(f"  Open Ports: {len(open_ports)}")
        print(f"  Risk Score: {risk_score.overall_score:.1f}/10 ({risk_score.overall_severity})")
        print(f"  Report:    {output_path}")


if __name__ == "__main__":
    main()
