from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from pq_surface_audit.models import AssetResult, Finding, ScanReport, ServiceObservation
from pq_surface_audit.scoring import score_asset

try:
    import paramiko  # type: ignore
except Exception:  # pragma: no cover
    paramiko = None


@dataclass
class TargetSpec:
    raw: str
    hostname: str
    port: int | None
    scheme: str | None


def parse_target(raw: str) -> TargetSpec:
    raw = raw.strip()
    if not raw:
        raise ValueError("Target cannot be empty")

    if "://" in raw:
        parsed = urlparse(raw)
        return TargetSpec(raw=raw, hostname=parsed.hostname or raw, port=parsed.port, scheme=parsed.scheme)

    if raw.count(":") == 1 and not raw.startswith("["):
        host, port = raw.split(":", 1)
        if port.isdigit():
            return TargetSpec(raw=raw, hostname=host, port=int(port), scheme=None)

    return TargetSpec(raw=raw, hostname=raw, port=None, scheme=None)


CLASSICAL_CERT_ALGS = {"rsa", "ecdsa", "eddsa", "dsa", "ec"}
CLASSICAL_SSH_ALGS = {"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}


def _public_key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "rsa", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ecdsa", pub.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "dsa", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "eddsa", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "eddsa", 456
    return pub.__class__.__name__.lower(), None


def _safe_http_get(url: str, timeout: float) -> httpx.Response | None:
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:
            return client.get(url, headers={"User-Agent": "pq-surface-audit/0.1.0"})
    except Exception:
        return None


def _scan_https(hostname: str, port: int, timeout: float) -> tuple[ServiceObservation, list[Finding]]:
    findings: list[Finding] = []
    details: dict[str, object] = {}
    status = "closed"

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                status = "open"
                cert_bin = tls.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin)
                public_key_alg, key_size = _public_key_info(cert)
                sig_alg = getattr(cert.signature_algorithm_oid, "_name", cert.signature_algorithm_oid.dotted_string)

                details.update({
                    "tls_version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_before": cert.not_valid_before_utc.isoformat(),
                    "not_after": cert.not_valid_after_utc.isoformat(),
                    "cert_public_key_algorithm": public_key_alg,
                    "cert_public_key_size": key_size,
                    "cert_signature_algorithm": sig_alg,
                    "sans": [],
                })

                try:
                    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    details["sans"] = sans.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass

                now = datetime.now(timezone.utc)
                if cert.not_valid_after_utc <= now:
                    findings.append(Finding(
                        severity="high",
                        category="certificate",
                        title="Expired certificate",
                        description="The presented certificate is expired.",
                        evidence={"not_after": cert.not_valid_after_utc.isoformat()},
                        recommendation="Renew and redeploy the certificate immediately.",
                    ))
                elif (cert.not_valid_after_utc - now).days <= 30:
                    findings.append(Finding(
                        severity="medium",
                        category="certificate",
                        title="Certificate near expiry",
                        description="The certificate expires within 30 days.",
                        evidence={"not_after": cert.not_valid_after_utc.isoformat()},
                        recommendation="Schedule renewal and validate automation around certificate lifecycle.",
                    ))

                if public_key_alg in CLASSICAL_CERT_ALGS:
                    findings.append(Finding(
                        severity="medium",
                        category="pq-readiness",
                        title="Classical public-key certificate in use",
                        description="The endpoint uses a classical public-key certificate. This is normal today on the public internet, but it should be tracked in your PQ migration inventory.",
                        evidence={"algorithm": public_key_alg, "key_size": key_size, "signature_algorithm": sig_alg},
                        recommendation="Add this service to your cryptographic inventory and monitor vendor support for PQ or hybrid certificate deployments.",
                    ))

                if tls.version() in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
                    findings.append(Finding(
                        severity="high",
                        category="tls",
                        title="Legacy TLS version negotiated",
                        description="The endpoint negotiated an outdated TLS version.",
                        evidence={"tls_version": tls.version()},
                        recommendation="Disable legacy protocol versions and move to modern TLS configurations.",
                    ))
    except Exception as exc:
        details["error"] = str(exc)

    return ServiceObservation(service="https", status=status, details=details), findings


def _scan_http_headers(hostname: str, port: int, timeout: float) -> tuple[ServiceObservation, list[Finding]]:
    findings: list[Finding] = []
    details: dict[str, object] = {}
    url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"

    resp = _safe_http_get(url, timeout)
    if resp is None:
        return ServiceObservation(service="http-headers", status="unknown", details={"error": "Unable to fetch HTTPS response"}), findings

    details.update({
        "status_code": resp.status_code,
        "server": resp.headers.get("server"),
        "hsts": resp.headers.get("strict-transport-security"),
        "csp": resp.headers.get("content-security-policy"),
    })

    if "strict-transport-security" not in {k.lower(): v for k, v in resp.headers.items()}:
        findings.append(Finding(
            severity="low",
            category="http",
            title="HSTS header missing",
            description="The HTTPS response did not include Strict-Transport-Security.",
            evidence={"url": url},
            recommendation="Consider enabling HSTS for suitable internet-facing services.",
        ))

    if "content-security-policy" not in {k.lower(): v for k, v in resp.headers.items()}:
        findings.append(Finding(
            severity="low",
            category="http",
            title="CSP header missing",
            description="The HTTPS response did not include Content-Security-Policy.",
            evidence={"url": url},
            recommendation="Consider deploying a Content-Security-Policy after validating application behavior.",
        ))

    http_url = f"http://{hostname}:{80}" if port == 443 else f"http://{hostname}:{port}"
    http_resp = _safe_http_get(http_url, timeout)
    if http_resp is not None:
        details["http_status_code"] = http_resp.status_code
        details["http_location"] = http_resp.headers.get("location")
        redirected = http_resp.status_code in {301, 302, 307, 308} and str(http_resp.headers.get("location", "")).startswith("https://")
        if not redirected:
            findings.append(Finding(
                severity="medium",
                category="http",
                title="HTTP does not cleanly redirect to HTTPS",
                description="The HTTP endpoint did not clearly redirect to HTTPS.",
                evidence={"status_code": http_resp.status_code, "location": http_resp.headers.get("location")},
                recommendation="Prefer redirecting cleartext HTTP to HTTPS or disable unnecessary HTTP listeners.",
            ))

    return ServiceObservation(service="http-headers", status="open", details=details), findings


def _scan_ssh(hostname: str, timeout: float) -> tuple[ServiceObservation, list[Finding]]:
    findings: list[Finding] = []
    details: dict[str, object] = {}
    status = "closed"

    try:
        with socket.create_connection((hostname, 22), timeout=timeout) as sock:
            status = "open"
            sock.settimeout(timeout)
            banner = sock.recv(255).decode("utf-8", errors="replace").strip()
            details["banner"] = banner
    except Exception as exc:
        details["error"] = str(exc)
        return ServiceObservation(service="ssh", status=status, details=details), findings

    if status == "open":
        findings.append(Finding(
            severity="info",
            category="surface",
            title="SSH exposed externally",
            description="An SSH service appears reachable on the standard port.",
            evidence={"port": 22},
            recommendation="Validate business need, source restriction, and inventory this dependency for PQ migration planning.",
        ))

    if paramiko is not None:
        try:
            transport = paramiko.Transport((hostname, 22))
            transport.banner_timeout = timeout
            transport.start_client(timeout=timeout)
            key = transport.get_remote_server_key()
            if key is not None:
                key_type = key.get_name()
                details["host_key_type"] = key_type
                if key_type in CLASSICAL_SSH_ALGS:
                    findings.append(Finding(
                        severity="medium",
                        category="pq-readiness",
                        title="Classical SSH host key observed",
                        description="The SSH service presented a classical host key algorithm that will need migration planning for a PQ future.",
                        evidence={"host_key_type": key_type},
                        recommendation="Track SSH dependencies and monitor your platform's support for PQ or hybrid key exchange and host-key options.",
                    ))
            transport.close()
        except Exception as exc:
            details["paramiko_error"] = str(exc)
    else:
        details["host_key_type"] = None
        details["paramiko_available"] = False

    return ServiceObservation(service="ssh", status=status, details=details), findings


def scan_target(target: str, timeout: float = 5.0, include_ssh: bool = True) -> AssetResult:
    spec = parse_target(target)
    hostname = spec.hostname
    https_port = spec.port or 443

    asset = AssetResult(target=target, hostname=hostname, port=spec.port)

    https_obs, https_findings = _scan_https(hostname, https_port, timeout)
    asset.observations.append(https_obs)
    asset.findings.extend(https_findings)

    if https_obs.status == "open":
        headers_obs, headers_findings = _scan_http_headers(hostname, https_port, timeout)
        asset.observations.append(headers_obs)
        asset.findings.extend(headers_findings)
    else:
        asset.notes.append("HTTPS scan did not complete successfully; HTTP header checks were skipped.")

    if include_ssh:
        ssh_obs, ssh_findings = _scan_ssh(hostname, timeout)
        asset.observations.append(ssh_obs)
        asset.findings.extend(ssh_findings)

    return score_asset(asset)


def summarize_assets(assets: list[AssetResult]) -> dict[str, int]:
    return {
        "assets_scanned": len(assets),
        "high_priority": sum(1 for a in assets if a.priority == "high"),
        "medium_priority": sum(1 for a in assets if a.priority == "medium"),
        "low_priority": sum(1 for a in assets if a.priority == "low"),
    }


def scan_batch(targets: Iterable[str], timeout: float = 5.0, include_ssh: bool = True) -> ScanReport:
    assets: list[AssetResult] = []
    for target in targets:
        target = target.strip()
        if not target or target.startswith("#"):
            continue
        assets.append(scan_target(target, timeout=timeout, include_ssh=include_ssh))

    return ScanReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        assets=assets,
        summary=summarize_assets(assets),
    )


def load_targets_file(path: str | Path) -> list[str]:
    return Path(path).read_text(encoding="utf-8").splitlines()
