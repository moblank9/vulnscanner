"""Asynchronous TCP port scanner with service detection."""
import asyncio
import socket
from dataclasses import dataclass, field
from typing import Callable, Optional

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5985: "winrm-http",
    5986: "winrm-https", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb",
}


@dataclass
class PortResult:
    port: int
    state: str  # open, closed, filtered
    service: str = ""
    banner: str = ""
    protocol: str = "tcp"


@dataclass
class ScanTarget:
    host: str
    ports: list[int] = field(default_factory=list)
    port_range: tuple[int, int] = (1, 1024)
    timeout: float = 2.0
    max_concurrency: int = 200
    progress_callback: Optional[Callable] = None


class PortScanner:
    def __init__(self, target: ScanTarget):
        self.target = target
        self.results: dict[int, PortResult] = {}
        self._scan_task: Optional[asyncio.Task] = None

    def _resolve_ports(self) -> list[int]:
        if self.target.ports:
            return sorted(set(self.target.ports))
        lo, hi = self.target.port_range
        return list(range(lo, hi + 1))

    async def _scan_port(self, port: int, sem: asyncio.Semaphore) -> PortResult:
        async with sem:
            result = PortResult(port=port, state="closed")
            try:
                await asyncio.wait_for(
                    self._try_connect(port), timeout=self.target.timeout
                )
                result.state = "open"
                result.service = COMMON_PORTS.get(port, "unknown")
            except (asyncio.TimeoutError, OSError):
                result.state = "filtered"
            except ConnectionRefusedError:
                result.state = "closed"
            return result

    async def _try_connect(self, port: int):
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.target.timeout)
        try:
            await loop.sock_connect(sock, (self.target.host, port))
        finally:
            sock.close()

    async def scan(self) -> dict[int, PortResult]:
        ports = self._resolve_ports()
        sem = asyncio.Semaphore(self.target.max_concurrency)
        tasks = [self._scan_port(p, sem) for p in ports]
        total = len(tasks)
        results: list[PortResult] = []

        for i, coro in enumerate(asyncio.as_completed(tasks), 1):
            result = await coro
            results.append(result)
            self.results[result.port] = result
            if self.target.progress_callback:
                self.target.progress_callback(i, total)

        return self.results

    def get_open_ports(self) -> dict[int, PortResult]:
        return {p: r for p, r in self.results.items() if r.state == "open"}
