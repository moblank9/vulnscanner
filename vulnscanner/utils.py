"""Shared utility functions."""
import socket
from typing import Optional


def resolve_host(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def is_valid_port(port: int) -> bool:
    return 1 <= port <= 65535


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


class ProgressBar:
    def __init__(self, total: int, prefix: str = "Progress"):
        self.total = total
        self.prefix = prefix
        self.current = 0

    def update(self, n: int = 1):
        self.current += n

    def __str__(self) -> str:
        if self.total == 0:
            return ""
        pct = int(self.current / self.total * 100)
        bar = "=" * (pct // 2) + ">" + "." * (50 - pct // 2)
        return f"\r{self.prefix}: [{bar}] {pct}% ({self.current}/{self.total})"
