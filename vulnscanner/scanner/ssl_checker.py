"""SSL/TLS certificate checker - validates certificates and cipher strength."""
import asyncio
import ssl
import socket
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "SHA1", "EXPORT", "NULL",
    "anon", "LOW", "ADH", "AECDH",
}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}


@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    expired: bool = False
    days_remaining: int = 0
    valid: bool = False
    san: list[str] = field(default_factory=list)
    self_signed: bool = False


@dataclass
class SSLResult:
    certificate: Optional[CertificateInfo] = None
    protocol_version: str = ""
    weak_protocols: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    supports_tls12: bool = False
    supports_tls13: bool = False
    errors: list[str] = field(default_factory=list)


async def check_ssl(host: str, port: int = 443, timeout: float = 5.0) -> SSLResult:
    result = SSLResult()
    try:
        cert_info = await asyncio.wait_for(
            _get_cert_info(host, port), timeout=timeout
        )
        result.certificate = cert_info
        result._version_checks = await _check_protocols(host, port, timeout)
        result.protocol_version = result._version_checks.get("best", "")
        result.weak_protocols = result._version_checks.get("weak", [])
        result.supports_tls12 = "TLSv1.2" in result._version_checks.get("supported", [])
        result.supports_tls13 = "TLSv1.3" in result._version_checks.get("supported", [])
    except (asyncio.TimeoutError, OSError, ssl.SSLError) as e:
        result.errors.append(str(e))
    return result


async def _get_cert_info(host: str, port: int) -> Optional[CertificateInfo]:
    loop = asyncio.get_event_loop()

    def _fetch():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                if not cert:
                    return None
                parsed = ssl.DER_cert_to_PEM_cert(cert)
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                pem = parsed.encode()
                cert_obj = x509.load_pem_x509_certificate(pem, default_backend())

                ci = CertificateInfo()
                ci.subject = str(cert_obj.subject)
                ci.issuer = str(cert_obj.issuer)
                ci.serial = str(cert_obj.serial_number)
                ci.not_before = cert_obj.not_valid_before_utc.isoformat()
                ci.not_after = cert_obj.not_valid_after_utc.isoformat()
                ci.expired = cert_obj.not_valid_after_utc < datetime.now(timezone.utc)
                ci.days_remaining = (
                    cert_obj.not_valid_after_utc - datetime.now(timezone.utc)
                ).days
                ci.valid = not ci.expired and ci.days_remaining > 0

                try:
                    ext = cert_obj.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    ci.san = ext.value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    pass

                ci.self_signed = ci.subject == ci.issuer
                return ci
    return await loop.run_in_executor(None, _fetch)


async def _check_protocols(
    host: str, port: int, timeout: float
) -> dict:
    import struct

    result = {"supported": [], "weak": [], "best": ""}
    protocols = {
        "SSLv2": ssl.PROTOCOL_SSLv23 if hasattr(ssl, "PROTOCOL_SSLv2") else None,
        "SSLv3": ssl.PROTOCOL_SSLv3 if hasattr(ssl, "PROTOCOL_SSLv3") else None,
        "TLSv1.0": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, "PROTOCOL_TLSv1_2") else None,
        "TLSv1.3": ssl.PROTOCOL_TLSv1_3 if hasattr(ssl, "PROTOCOL_TLSv1_3") else ssl.PROTOCOL_TLS_CLIENT,
    }

    for name, proto in protocols.items():
        if proto is None:
            if name in WEAK_PROTOCOLS:
                result["weak"].append(name)
            continue
        try:
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            ssock.connect((host, port))
            result["supported"].append(name)
            ssock.close()
        except (ssl.SSLError, OSError, ConnectionRefusedError):
            if name in WEAK_PROTOCOLS:
                result["weak"].append(name)

    if "TLSv1.3" in result["supported"]:
        result["best"] = "TLSv1.3"
    elif "TLSv1.2" in result["supported"]:
        result["best"] = "TLSv1.2"
    elif result["supported"]:
        result["best"] = result["supported"][-1]

    for w in WEAK_PROTOCOLS:
        if w not in result["supported"]:
            result["weak"] = [w for w in result["weak"] if w != w]

    return result
