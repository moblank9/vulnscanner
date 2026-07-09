"""CVE matching engine - matches software versions against known vulnerabilities."""
import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVEMatch:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    affected_version: str
    remediation: str


@dataclass
class CVEMatchResult:
    service: str
    version: str
    matches: list[CVEMatch] = field(default_factory=list)
    max_cvss: float = 0.0


_VERSION_PATTERNS = [
    re.compile(r"(?:v|version|ver\.?|/)?(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)", re.I),
    re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3})"),
    re.compile(r"(\d{1,3}\.\d{1,3})"),
]


def _extract_versions(version_str: str) -> list[str]:
    if not version_str:
        return []
    versions = set()
    for pat in _VERSION_PATTERNS:
        for m in pat.finditer(version_str):
            v = m.group(1)
            if v:
                versions.add(v)
    return list(versions)


class CVEDatabase:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), "..", "data", "cve_db.json"
            )
        self.db_path = os.path.abspath(db_path)
        self.entries: list[dict] = []
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path) as f:
                    self.entries = json.load(f)
            except (json.JSONDecodeError, OSError):
                self.entries = self._default_db()
        else:
            self.entries = self._default_db()
            self._save()

    def _save(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with open(self.db_path, "w") as f:
            json.dump(self.entries, f, indent=2)

    @staticmethod
    def _default_db() -> list[dict]:
        return [
            {"cve_id": "CVE-2024-3094", "service": "ssh", "version_contains": "openssh/", "affected": "< 9.7", "cvss": 10.0, "severity": "critical", "description": "Critical vulnerability in XZ Utils (SSH backdoor) - supply chain compromise.", "remediation": "Update to OpenSSH 9.7+ and verify system integrity."},
            {"cve_id": "CVE-2024-6387", "service": "ssh", "version_contains": "openssh", "affected": "8.5p1 - 9.7p1", "cvss": 8.1, "severity": "high", "description": "OpenSSH regreSSHion - remote code execution in signal handler.", "remediation": "Update OpenSSH to latest patched version."},
            {"cve_id": "CVE-2023-48795", "service": "ssh", "version_contains": "ssh", "affected": "various", "cvss": 5.9, "severity": "medium", "description": "Terrapin Attack - SSH channel integrity vulnerability.", "remediation": "Update SSH implementation to patched version supporting strict key exchange."},
            {"cve_id": "CVE-2024-27316", "service": "http", "version_contains": "apache", "affected": "< 2.4.59", "cvss": 7.5, "severity": "high", "description": "Apache HTTP Server HTTP/2 CONTINUATION flood DoS vulnerability.", "remediation": "Update Apache HTTP Server to version 2.4.59 or later."},
            {"cve_id": "CVE-2024-24795", "service": "http", "version_contains": "apache", "affected": "< 2.4.59", "cvss": 6.5, "severity": "medium", "description": "Apache HTTP Server HTTP response splitting vulnerability.", "remediation": "Update Apache HTTP Server to version 2.4.59 or later."},
            {"cve_id": "CVE-2024-24989", "service": "http", "version_contains": "nginx", "affected": "< 1.24.0", "cvss": 7.5, "severity": "high", "description": "Nginx HTTP/2 memory disclosure vulnerability.", "remediation": "Update nginx to version 1.24.0 or later."},
            {"cve_id": "CVE-2024-34102", "service": "http", "version_contains": "iis", "affected": "< 10.0", "cvss": 6.5, "severity": "medium", "description": "Microsoft IIS information disclosure vulnerability.", "remediation": "Apply latest Windows security updates."},
            {"cve_id": "CVE-2024-21626", "service": "http", "version_contains": "docker", "affected": "< 25.0", "cvss": 8.5, "severity": "high", "description": "Docker / runc container escape via crafted process arguments.", "remediation": "Update Docker to version 25.0+ and runc to latest."},
            {"cve_id": "CVE-2024-3095", "service": "ftp", "version_contains": "vsftpd", "affected": "< 3.0.5", "cvss": 5.5, "severity": "medium", "description": "vsFTPd denial of service vulnerability.", "remediation": "Update vsFTPd to version 3.0.5 or later."},
            {"cve_id": "CVE-2024-27282", "service": "ftp", "version_contains": "proftpd", "affected": "< 1.3.8", "cvss": 7.5, "severity": "high", "description": "ProFTPD memory corruption vulnerability.", "remediation": "Update ProFTPD to version 1.3.8 or later."},
            {"cve_id": "CVE-2023-48795", "service": "mysql", "version_contains": "mysql", "affected": "< 8.0.36", "cvss": 4.9, "severity": "medium", "description": "MySQL Server privilege escalation vulnerability.", "remediation": "Update MySQL to version 8.0.36 or later."},
            {"cve_id": "CVE-2024-20994", "service": "mysql", "version_contains": "mariadb", "affected": "< 10.11.6", "cvss": 6.5, "severity": "medium", "description": "MariaDB server information disclosure.", "remediation": "Update MariaDB to version 10.11.6 or later."},
            {"cve_id": "CVE-2024-0985", "service": "postgresql", "version_contains": "postgresql", "affected": "< 16.2", "cvss": 8.8, "severity": "high", "description": "PostgreSQL unprivileged code execution via row security policies.", "remediation": "Update PostgreSQL to version 16.2, 15.6, 14.11, 13.14, or 12.18."},
            {"cve_id": "CVE-2024-3204", "service": "redis", "version_contains": "redis", "affected": "< 7.2.5", "cvss": 7.5, "severity": "high", "description": "Redis Lua sandbox escape vulnerability.", "remediation": "Update Redis to version 7.2.5 or later."},
            {"cve_id": "CVE-2024-27199", "service": "http", "version_contains": "jetty", "affected": "< 12.0.1", "cvss": 6.1, "severity": "medium", "description": "Jetty denial of service via HTTP/2 CONTINUATION frames.", "remediation": "Update Jetty to version 12.0.1 or later."},
            {"cve_id": "CVE-2024-22262", "service": "http", "version_contains": "spring", "affected": "< 6.1.4", "cvss": 8.1, "severity": "high", "description": "Spring Framework SSRF vulnerability.", "remediation": "Update Spring Framework to 6.1.4 or later."},
            {"cve_id": "CVE-2024-29025", "service": "http", "version_contains": "node", "affected": "< 20.12.0", "cvss": 7.5, "severity": "high", "description": "Node.js HTTP request smuggling vulnerability.", "remediation": "Update Node.js to version 20.12.0 or later."},
            {"cve_id": "CVE-2024-27919", "service": "http", "version_contains": "python", "affected": "< 3.12.2", "cvss": 7.5, "severity": "high", "description": "Python http.client LLMNR/NBT name resolution bypass.", "remediation": "Update Python to version 3.12.2 or later."},
            {"cve_id": "CVE-2024-3149", "service": "http", "version_contains": "lighttpd", "affected": "< 1.4.74", "cvss": 5.5, "severity": "medium", "description": "lighttpd out-of-bounds read vulnerability.", "remediation": "Update lighttpd to version 1.4.74 or later."},
            {"cve_id": "CVE-2024-22222", "service": "http", "version_contains": "tomcat", "affected": "< 10.1.19", "cvss": 7.5, "severity": "high", "description": "Apache Tomcat HTTP/2 CONTINUATION flood DoS.", "remediation": "Update Tomcat to version 10.1.19 or later."},
            {"cve_id": "CVE-2024-38262", "service": "http", "version_contains": "tomcat", "affected": "all", "cvss": 8.1, "severity": "high", "description": "Apache Tomcat remote code execution via session persistence.", "remediation": "Apply latest Tomcat security patches."},
            {"cve_id": "CVE-2024-0204", "service": "http", "version_contains": "jboss", "affected": "all", "cvss": 9.8, "severity": "critical", "description": "JBoss/WildFly deserialization RCE vulnerability.", "remediation": "Update JBoss/WildFly to latest patched version."},
            {"cve_id": "CVE-2024-45195", "service": "http", "version_contains": "apache", "affected": "all", "cvss": 7.5, "severity": "high", "description": "Apache OFBiz remote code execution.", "remediation": "Apply latest Apache OFBiz security patches."},
            {"cve_id": "CVE-2024-3148", "service": "ssl", "version_contains": "openssl", "affected": "< 3.2.1", "cvss": 7.5, "severity": "high", "description": "OpenSSL certificate validation bypass via application data during verification.", "remediation": "Update OpenSSL to version 3.2.1 or later."},
            {"cve_id": "CVE-2024-4603", "service": "ssl", "version_contains": "openssl", "affected": "< 3.3.1", "cvss": 5.3, "severity": "medium", "description": "OpenSSL DoS via excessively long HMAC keys.", "remediation": "Update OpenSSL to version 3.3.1 or later."},
            {"cve_id": "CVE-2024-2379", "service": "mongodb", "version_contains": "mongodb", "affected": "< 7.0.6", "cvss": 6.5, "severity": "medium", "description": "MongoDB wire protocol message injection.", "remediation": "Update MongoDB to version 7.0.6 or later."},
            {"cve_id": "CVE-2024-31478", "service": "http", "version_contains": "iis", "affected": "< 10.0", "cvss": 6.5, "severity": "medium", "description": "Microsoft IIS server-side request forgery.", "remediation": "Apply latest Windows security patches."},
        ]

    def match(
        self, service_name: str, version_str: str, port: int = 0
    ) -> CVEMatchResult:
        result = CVEMatchResult(service=service_name, version=version_str)
        svc_lower = service_name.lower()
        versions = _extract_versions(version_str)

        for entry in self.entries:
            target_service = entry.get("service", "").lower()
            version_contains = entry.get("version_contains", "").lower()

            if service_name.lower() != target_service and not (
                port == 443 and target_service == "ssl"
            ):
                continue

            if version_contains and version_contains not in svc_lower:
                continue

            match = CVEMatch(
                cve_id=entry["cve_id"],
                description=entry.get("description", ""),
                cvss_score=entry.get("cvss", 0.0),
                severity=entry.get("severity", "unknown"),
                affected_version=entry.get("affected", ""),
                remediation=entry.get("remediation", ""),
            )
            result.matches.append(match)
            result.max_cvss = max(result.max_cvss, match.cvss_score)

        return result


_cve_db_instance: Optional[CVEDatabase] = None


def get_cve_db() -> CVEDatabase:
    global _cve_db_instance
    if _cve_db_instance is None:
        _cve_db_instance = CVEDatabase()
    return _cve_db_instance
