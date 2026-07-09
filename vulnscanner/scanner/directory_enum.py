"""Directory enumeration module - discovers hidden paths on web servers."""
import asyncio
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/administrator", "/backup",
    "/config", "/conf", "/db", "/database", "/backups",
    "/.env", "/.git/config", "/.git/HEAD", "/.svn", "/.DS_Store",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/phpinfo.php", "/info.php", "/test.php",
    "/api", "/api/v1", "/graphql", "/swagger.json", "/openapi.json",
    "/wsdl", "/soap", "/xmlrpc.php",
    "/.htaccess", "/.htpasswd",
    "/server-status", "/server-info",
    "/wp-content", "/wp-includes", "/wp-json",
    "/.well-known/security.txt",
    "/vendor", "/node_modules",
    "/debug", "/console", "/management",
    "/upload", "/uploads", "/files", "/download",
    "/api/health", "/health", "/healthcheck", "/actuator/health",
    "/web-inf/web.xml", "/web-inf",
    "/shell", "/cmd", "/exec",
    "/index.php", "/index.html", "/default.aspx",
    "/README.md", "/CHANGELOG.md",
    "/package.json", "/composer.json", "/requirements.txt",
]

EXTENSIONS = ["", ".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".html", ".htm", ".json", ".xml"]


@dataclass
class DirectoryResult:
    path: str
    status_code: int
    content_length: int = 0
    title: str = ""


@dataclass
class DirectoryEnumResult:
    base_url: str
    findings: list[DirectoryResult] = field(default_factory=list)
    total_checked: int = 0
    errors: list[str] = field(default_factory=list)


async def enumerate_directories(
    base_url: str,
    wordlist: Optional[list[str]] = None,
    extensions: Optional[list[str]] = None,
    max_concurrency: int = 20,
    timeout: float = 5.0,
    status_filter: Optional[set[int]] = None,
) -> DirectoryEnumResult:
    words = wordlist or COMMON_PATHS
    exts = extensions or [""]
    status_filter = status_filter or {200, 201, 202, 203, 204, 205, 206, 301, 302, 303, 307, 308, 401, 403, 405, 500}
    result = DirectoryEnumResult(base_url=base_url)

    base_url = base_url.rstrip("/")

    paths = []
    for w in words:
        for ext in exts:
            path = f"{w}{ext}"
            paths.append(path)

    result.total_checked = len(paths)
    sem = asyncio.Semaphore(max_concurrency)

    async def check_path(path: str) -> Optional[DirectoryResult]:
        url = f"{base_url}{path}"
        async with sem:
            try:
                timeout_obj = aiohttp.ClientTimeout(total=timeout)
                async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                    async with session.get(url, ssl=False, timeout=timeout_obj) as resp:
                        if resp.status in status_filter:
                            body = await resp.text()
                            title = ""
                            import re
                            m = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
                            if m:
                                title = m.group(1)[:100]
                            return DirectoryResult(
                                path=path, status_code=resp.status,
                                content_length=len(body), title=title
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                pass
            return None

    tasks = [check_path(p) for p in paths]
    for future in asyncio.as_completed(tasks):
        dr = await future
        if dr:
            result.findings.append(dr)

    result.findings.sort(key=lambda x: x.path)
    return result
