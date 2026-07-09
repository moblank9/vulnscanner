"""Risk scoring engine - evaluates overall risk based on all findings."""
from dataclasses import dataclass, field
from typing import Any, Optional


SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
    "none": 0.0,
}

SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d",
    "none": "#28a745",
}


@dataclass
class RiskFinding:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    cvss_score: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskScore:
    overall_score: float = 0.0
    overall_severity: str = "none"
    max_possible: float = 0.0
    findings: list[RiskFinding] = field(default_factory=list)
    finding_counts: dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })


class RiskScorer:
    def __init__(self):
        self.findings: list[RiskFinding] = []

    def add_finding(
        self,
        category: str,
        title: str,
        description: str,
        severity: str,
        remediation: str = "",
        cvss_score: float = 0.0,
        details: Optional[dict] = None,
    ):
        self.findings.append(RiskFinding(
            category=category,
            title=title,
            description=description,
            severity=severity,
            remediation=remediation,
            cvss_score=cvss_score,
            details=details or {},
        ))

    def add_from_ssl(self, ssl_result: Any):
        if not ssl_result or not ssl_result.certificate:
            return

        cert = ssl_result.certificate
        if cert.expired:
            self.add_finding(
                category="SSL/TLS",
                title="Expired SSL Certificate",
                description=f"SSL certificate for has expired on {cert.not_after}.",
                severity="high",
                remediation="Renew the SSL certificate immediately.",
                cvss_score=7.5,
                details={"expired": True, "not_after": cert.not_after},
            )
        elif cert.days_remaining < 30:
            self.add_finding(
                category="SSL/TLS",
                title="SSL Certificate Expiring Soon",
                description=f"SSL certificate expires in {cert.days_remaining} days on {cert.not_after}.",
                severity="medium",
                remediation="Renew the SSL certificate before it expires.",
                cvss_score=5.0,
                details={"days_remaining": cert.days_remaining},
            )

        if cert.self_signed:
            self.add_finding(
                category="SSL/TLS",
                title="Self-Signed SSL Certificate",
                description="The server uses a self-signed certificate which cannot be verified.",
                severity="medium",
                remediation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt).",
                cvss_score=5.0,
                details={"self_signed": True},
            )

        if ssl_result.weak_protocols:
            self.add_finding(
                category="SSL/TLS",
                title="Weak SSL/TLS Protocols Supported",
                description=f"Server supports weak protocols: {', '.join(ssl_result.weak_protocols)}.",
                severity="high",
                remediation="Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1. Enable TLSv1.2 and TLSv1.3 only.",
                cvss_score=7.0,
                details={"weak_protocols": ssl_result.weak_protocols},
            )

    def add_from_http_headers(self, header_result: Any):
        if not header_result:
            return
        for finding in header_result.findings:
            if finding.severity == "missing" and finding.score > 1:
                sev = "high" if finding.score >= 3 else "medium"
                self.add_finding(
                    category="HTTP Headers",
                    title=f"Missing Security Header: {finding.header}",
                    description=finding.description,
                    severity=sev,
                    remediation=finding.remediation,
                    details={"header": finding.header, "score": finding.score},
                )
            elif finding.score > 0:
                sev = "low" if finding.score == 1 else "medium"
                self.add_finding(
                    category="HTTP Headers",
                    title=f"Information Disclosure: {finding.header}",
                    description=finding.description,
                    severity=sev,
                    remediation=finding.remediation,
                    details={"header": finding.header, "value": finding.value},
                )

    def add_from_cve(self, cve_result: Any):
        if not cve_result:
            return
        for match in cve_result.matches:
            self.add_finding(
                category="CVE",
                title=f"{match.cve_id} ({cve_result.service})",
                description=match.description,
                severity=match.severity,
                remediation=match.remediation,
                cvss_score=match.cvss_score,
                details={
                    "cve_id": match.cve_id,
                    "cvss_score": match.cvss_score,
                    "affected_version": match.affected_version,
                },
            )

    def add_from_directory_enum(self, dir_result: Any):
        if not dir_result:
            return
        sensitive = {"/.git", "/.env", "/admin", "/config", "/backup", "/wp-admin"}
        for finding in dir_result.findings:
            severity = "high"
            remediation = "Restrict access to sensitive paths."
            for s in sensitive:
                if s in finding.path:
                    severity = "critical"
                    remediation = "Remove or password-protect the exposed sensitive path immediately."
                    break
            if finding.status_code in (200, 201, 204):
                sev = "high" if severity == "critical" else "medium"
            elif finding.status_code in (301, 302, 303, 307, 308):
                sev = "low"
            elif finding.status_code in (401, 403):
                sev = "info"
            else:
                sev = "info"

            self.add_finding(
                category="Directory Enumeration",
                title=f"Exposed Path: {finding.path} ({finding.status_code})",
                description=f"Path '{finding.path}' returned HTTP {finding.status_code} (length: {finding.content_length}).",
                severity=sev,
                remediation=remediation,
                details={
                    "path": finding.path,
                    "status_code": finding.status_code,
                    "content_length": finding.content_length,
                },
            )

    def add_from_port_scan(
        self, open_ports: dict[int, Any], port: int, service: str
    ):
        high_risk_ports = {23, 21, 135, 139, 445, 3389, 5900, 6379}
        if port in high_risk_ports:
            self.add_finding(
                category="Open Ports",
                title=f"High-Risk Port Open: {port}/{service}",
                description=f"Port {port} ({service}) is open and accessible.",
                severity="high" if port in (23, 135, 139, 445) else "medium",
                remediation=f"Restrict access to port {port} using a firewall if not required.",
                details={"port": port, "service": service},
            )

    def compute(self) -> RiskScore:
        score = RiskScore()
        score.findings = self.findings

        for f in self.findings:
            sev_lower = f.severity.lower()
            if sev_lower in score.finding_counts:
                score.finding_counts[sev_lower] += 1

        total_weighted = 0.0
        for f in self.findings:
            sev = f.severity.lower()
            weight = SEVERITY_WEIGHTS.get(sev, 0.0)
            total_weighted += weight

        count = len(self.findings)
        if count > 0:
            score.overall_score = min(10.0, total_weighted / count)
        else:
            score.overall_score = 0.0

        if score.overall_score >= 7.5:
            score.overall_severity = "critical"
        elif score.overall_score >= 5.0:
            score.overall_severity = "high"
        elif score.overall_score >= 2.5:
            score.overall_severity = "medium"
        elif score.overall_score > 0:
            score.overall_severity = "low"
        else:
            score.overall_severity = "none"

        score.max_possible = count * 10.0
        return score
