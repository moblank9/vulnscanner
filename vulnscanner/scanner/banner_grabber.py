"""Banner grabbing module - retrieves service banners from open ports."""
import asyncio
import socket
import ssl
from typing import Optional

from vulnscanner.scanner.port_scanner import PortResult

BANNER_PROBES: dict[int, bytes] = {
    21: b"",  # FTP - read banner
    22: b"",  # SSH - read banner
    23: b"",  # Telnet
    25: b"",  # SMTP
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"",  # POP3
    143: b"",  # IMAP
    443: b"",  # HTTPS - handled via SSL
    445: b"",  # SMB
    993: b"",  # IMAPS - SSL
    995: b"",  # POP3S - SSL
    1433: b"",  # MSSQL
    3306: b"",  # MySQL
    3389: b"",  # RDP
    5432: b"",  # PostgreSQL
    5900: b"",  # VNC
    6379: b"",  # Redis
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"",  # HTTPS-alt - SSL
    27017: b"",  # MongoDB
}

TCP_PROBE = b"\r\n"


async def grab_banner(
    host: str, port: int, timeout: float = 3.0
) -> Optional[str]:
    probe = BANNER_PROBES.get(port, TCP_PROBE)
    use_ssl = port in (443, 993, 995, 5986, 8443)

    try:
        return await asyncio.wait_for(
            _grab(host, port, probe, use_ssl, timeout), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return None


async def _grab(
    host: str, port: int, probe: bytes, use_ssl: bool, timeout: float
) -> Optional[str]:
    loop = asyncio.get_event_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        await loop.sock_connect(sock, (host, port))
        if probe:
            await loop.sock_sendall(sock, probe)
        data = await loop.sock_recv(sock, 2048)
        banner = data.decode("utf-8", errors="replace").strip()
        return banner if banner else None
    finally:
        sock.close()


async def grab_all_banners(
    host: str, open_ports: dict[int, PortResult], timeout: float = 3.0
) -> dict[int, Optional[str]]:
    tasks = {p: grab_banner(host, p, timeout) for p in open_ports}
    results: dict[int, Optional[str]] = {}
    for port, task in tasks.items():
        results[port] = await task
    return results
