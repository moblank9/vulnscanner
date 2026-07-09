"""Service fingerprinting - identifies services and versions from banners."""
import re
from dataclasses import dataclass, field
from typing import Optional

FINGERPRINT_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"SSH-(\d+\.\d+)[-\s]*(.*)"), "SSH", r"ssh\g<1>"),
    (re.compile(r"220[- ].*FTP"), "FTP", "ftp"),
    (re.compile(r"220[- ].*vsFTPd.*"), "FTP", "vsftpd"),
    (re.compile(r"220 [- ].*ProFTPD"), "FTP", "proftpd"),
    (re.compile(r"HELO|EHLO|ESMTP|SMTP"), "SMTP", "smtp"),
    (re.compile(r"220 .*E?SMTP"), "SMTP", "smtp"),
    (re.compile(r"Apache[/\s](\d+\.\d+\.\d+)"), "HTTP", r"Apache/\g<1>"),
    (re.compile(r"nginx[/\s](\d+\.\d+\.\d+)"), "HTTP", r"nginx/\g<1>"),
    (re.compile(r"IIS[/\s](\d+\.\d+)"), "HTTP", r"IIS/\g<1>"),
    (re.compile(r"MySQL.*(\d+\.\d+\.\d+)"), "MySQL", r"mysql/\g<1>"),
    (re.compile(r"MariaDB.*(\d+\.\d+\.\d+)"), "MySQL", r"mariadb/\g<1>"),
    (re.compile(r"PostgreSQL (\d+\.\d+)"), "PostgreSQL", r"postgresql/\g<1>"),
    (re.compile(r"Redis.*v=(\d+\.\d+\.\d+)"), "Redis", r"redis/\g<1>"),
    (re.compile(r"-ERedis"), "Redis", "redis"),
    (re.compile(r"OpenSSH[_ ](\d+[._]\d+)"), "SSH", r"openssh/\g<1>"),
    (re.compile(r"OpenSSL (\d+\.\d+\.\d+)"), "SSL/TLS", r"openssl/\g<1>"),
    (re.compile(r"Microsoft-IIS/(\d+\.\d+)"), "HTTP", r"iis/\g<1>"),
    (re.compile(r"lighttpd/(\d+\.\d+\.\d+)"), "HTTP", r"lighttpd/\g<1>"),
    (re.compile(r"Node\.js/(\S+)"), "HTTP", r"node/\g<1>"),
    (re.compile(r"Python/(\d+\.\d+\.\d+)"), "HTTP", r"python/\g<1>"),
    (re.compile(r"Jetty"), "HTTP", "jetty"),
    (re.compile(r"Tomcat"), "HTTP", "tomcat"),
    (re.compile(r"JBoss"), "HTTP", "jboss"),
    (re.compile(r"WildFly"), "HTTP", "wildfly"),
    (re.compile(r"VNC.*RFB", re.IGNORECASE), "VNC", "vnc"),
    (re.compile(r"MongoDB.*(\d+\.\d+\.\d+)"), "MongoDB", r"mongodb/\g<1>"),
    (re.compile(r"Microsoft SQL Server"), "MSSQL", "mssql"),
    (re.compile(r"\*+\s+IMAP4"), "IMAP", "imap"),
    (re.compile(r"\+OK.*POP"), "POP3", "pop3"),
]


@dataclass
class FingerprintResult:
    service_name: str = ""
    service_version: str = ""
    os_hint: str = ""
    confidence: float = 0.0
    raw_banner: str = ""


def fingerprint_service(
    port: int, service: str, banner: Optional[str]
) -> FingerprintResult:
    result = FingerprintResult()
    if not banner:
        result.service_name = service
        result.confidence = 0.3
        return result

    result.raw_banner = banner[:500]

    for pattern, svc_name, version_str in FINGERPRINT_RULES:
        m = pattern.search(banner)
        if m:
            result.service_name = svc_name
            result.confidence = 0.9
            try:
                result.service_version = m.expand(version_str) if "\\" in version_str else version_str
            except (IndexError, re.error):
                result.service_version = version_str
            break

    if not result.service_name:
        result.service_name = service
        result.confidence = 0.5

    return result


def extract_version_info(banner: str) -> tuple[str, str, str]:
    for pattern, svc_name, version_str in FINGERPRINT_RULES:
        m = pattern.search(banner)
        if m:
            try:
                ver = m.expand(version_str) if "\\" in version_str else version_str
            except (IndexError, re.error):
                ver = version_str
            return svc_name, ver, ""
    return "", "", ""
