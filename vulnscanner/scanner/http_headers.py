"""HTTP security headers checker - audits response headers for security best practices."""
import asyncio
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security enforces HTTPS connections.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "score": 3,
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy mitigates XSS and data injection.",
        "remediation": "Add a Content-Security-Policy header with appropriate directives.",
        "score": 3,
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "score": 2,
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
        "score": 2,
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filter (deprecated but still recommended for older browsers).",
        "remediation": "Add 'X-XSS-Protection: 1; mode=block' header.",
        "score": 1,
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "score": 1,
    },
    "Permissions-Policy": {
        "description": "Controls which browser features can be used.",
        "remediation": "Add a Permissions-Policy header to restrict feature access.",
        "score": 1,
    },
    "Access-Control-Allow-Origin": {
        "description": "CORS header present (should be restrictive).",
        "remediation": "Ensure CORS is properly configured and not set to '*'.",
        "score": 0,
    },
    "Cache-Control": {
        "description": "Cache control for sensitive data.",
        "remediation": "Add 'Cache-Control: no-store, no-cache, must-revalidate' for sensitive pages.",
        "score": 1,
    },
    "Set-Cookie": {
        "description": "Cookies should have Secure, HttpOnly, SameSite flags.",
        "remediation": "Set Secure, HttpOnly, and SameSite=Lax/Strict flags on cookies.",
        "score": 2,
    },
}

DANGEROUS_HEADERS = {
    "Server": {"description": "Exposes server software version.", "remediation": "Remove or obfuscate the Server header.", "score": 1},
    "X-Powered-By": {"description": "Exposes technology stack.", "remediation": "Remove the X-Powered-By header.", "score": 1},
    "X-AspNet-Version": {"description": "Exposes ASP.NET version.", "remediation": "Remove the X-AspNet-Version header.", "score": 1},
    "X-AspNetMvc-Version": {"description": "Exposes ASP.NET MVC version.", "remediation": "Remove X-AspNetMvc-Version header.", "score": 1},
}


@dataclass
class HeaderFinding:
    header: str
    present: bool
    value: str = ""
    severity: str = "info"
    description: str = ""
    remediation: str = ""
    score: int = 0


@dataclass
class HTTPHeaderResult:
    url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    findings: list[HeaderFinding] = field(default_factory=list)
    score: int = 0
    max_score: int = 0
    errors: list[str] = field(default_factory=list)


async def check_http_headers(
    url: str, timeout: float = 10.0
) -> HTTPHeaderResult:
    result = HTTPHeaderResult(url=url)
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            async with session.get(url, ssl=False, allow_redirects=True) as resp:
                result.status_code = resp.status
                result.headers = dict(resp.headers)

                for hdr, info in SECURITY_HEADERS.items():
                    raw_hdr = resp.headers.get(hdr, "")
                    finding = HeaderFinding(
                        header=hdr,
                        present=hdr in resp.headers,
                        value=raw_hdr[:200] if raw_hdr else "",
                        description=info["description"],
                        remediation=info["remediation"],
                        score=info["score"],
                        severity="missing" if hdr not in resp.headers else "present",
                    )
                    result.findings.append(finding)
                    if hdr not in resp.headers:
                        result.max_score += info["score"]

                for hdr, info in DANGEROUS_HEADERS.items():
                    raw_val = resp.headers.get(hdr, "")
                    if hdr in resp.headers:
                        finding = HeaderFinding(
                            header=hdr,
                            present=True,
                            value=raw_val[:200],
                            severity="info",
                            description=info["description"],
                            remediation=info["remediation"],
                            score=info["score"],
                        )
                        result.findings.append(finding)
                        result.score += info["score"]

                result.score = min(result.score, result.max_score) if result.max_score else 0
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
        result.errors.append(str(e))
    return result
