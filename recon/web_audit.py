from datetime import datetime, timezone
import logging
import re
import socket
import ssl
from urllib.parse import urljoin
from recon.logger import get_logger, log_event
from recon.validator import TargetValidationError, normalize_and_validate

logger = get_logger("netrecon.web")

MAX_HEADER_BYTES = 16384

SECURITY_HEADERS: list[tuple[str, str, int, str]] = [
    ("Strict-Transport-Security", "HSTS", 20, "Enforces HTTPS connections against downgrade attacks"),
    ("Content-Security-Policy", "CSP", 25, "Mitigates XSS and unauthorized script injection"),
    ("X-Frame-Options", "X-Frame-Options", 15, "Prevents clickjacking via iframe embedding"),
    ("X-Content-Type-Options", "X-Content-Type-Options", 15, "Blocks MIME type sniffing"),
    ("Referrer-Policy", "Referrer-Policy", 10, "Controls referrer leakage across origins"),
    ("Permissions-Policy", "Permissions-Policy", 15, "Restricts browser APIs (camera, mic, geolocation)"),
]


def _format_host_header(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _extract_cert_fields(cert: dict, host: str) -> dict:
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    not_after_str = cert.get("notAfter", "")
    days_left = None
    if not_after_str:
        try:
            expires_dt = datetime.strptime(
                not_after_str, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            days_left = (expires_dt - datetime.now(timezone.utc)).days
        except ValueError:
            days_left = None

    sans = [
        val
        for kind, val in cert.get("subjectAltName", ())
        if kind in {"DNS", "IP Address"}
    ]
    return {
        "common_name": subject.get("commonName", host),
        "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Unknown CA",
        "expires_on": not_after_str,
        "days_remaining": days_left,
        "san_count": len(sans),
        "sans": sans[:10],
    }


def _read_head_block(sock: socket.socket, host: str) -> tuple[int, dict[str, str]]:
    """Send an HTTP/1.1 HEAD request over an already connected pinned socket and parse headers only."""
    host_header = _format_host_header(host)
    req = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: NetRecon/2.2 Security Audit\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    sock.sendall(req)

    raw = b""
    while b"\r\n\r\n" not in raw and len(raw) < MAX_HEADER_BYTES:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw += chunk

    if not raw:
        raise OSError("Empty HTTP response from pinned socket.")

    head_text = raw.split(b"\r\n\r\n", 1)[0].decode("latin1", errors="replace")
    lines = head_text.splitlines()
    if not lines or not lines[0].startswith("HTTP/"):
        raise ValueError("Malformed HTTP status line.")

    parts = lines[0].split()
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key_lower = k.strip().lower()
        val_clean = v.strip()
        if key_lower in headers:
            headers[key_lower] = f"{headers[key_lower]}, {val_clean}"
        else:
            headers[key_lower] = val_clean

    return status_code, headers


def _probe_pinned_https(
    host: str, ip: str, is_ip: bool = False
) -> tuple[dict, tuple[int, dict[str, str]] | None]:
    """Connect directly to pinned IP on 443/tcp, verify TLS certificate, and read HEAD headers."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    verify_error: str | None = None
    sni_host = None if is_ip else host

    try:
        ctx = ssl.create_default_context()
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(2.5)
            raw_sock.connect((ip, 443))
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                tls_sock.settimeout(2.5)
                cert = tls_sock.getpeercert() or {}
                protocol = tls_sock.version() or "Unknown"
                cipher_info = tls_sock.cipher()
                cipher = cipher_info[0] if cipher_info else "Unknown"
                fields = _extract_cert_fields(cert, host)
                tls_info = {
                    "available": True,
                    "verified": True,
                    "verify_error": None,
                    "protocol": protocol,
                    "cipher": cipher,
                    **fields,
                }
                head_res = _read_head_block(tls_sock, host)
                return tls_info, head_res
    except ssl.SSLCertVerificationError as exc:
        verify_error = getattr(exc, "verify_message", None) or str(exc)
        log_event(logger, logging.INFO, "tls_verification_failed", host=host, reason=verify_error)
    except Exception as exc:
        log_event(
            logger,
            logging.DEBUG,
            "https_pinned_probe_failed",
            host=host,
            error_type=type(exc).__name__,
        )
        return {"available": False, "verified": False, "verify_error": None}, None

    try:
        unverified_ctx = ssl.create_default_context()
        unverified_ctx.check_hostname = False
        unverified_ctx.verify_mode = ssl.CERT_NONE
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(2.5)
            raw_sock.connect((ip, 443))
            with unverified_ctx.wrap_socket(raw_sock, server_hostname=sni_host) as tls_sock:
                tls_sock.settimeout(2.5)
                protocol = tls_sock.version() or "Unknown"
                cipher_info = tls_sock.cipher()
                cipher = cipher_info[0] if cipher_info else "Unknown"
                tls_info = {
                    "available": True,
                    "verified": False,
                    "verify_error": verify_error,
                    "protocol": protocol,
                    "cipher": cipher,
                    "common_name": host,
                    "issuer": "Unverified / Invalid Certificate",
                    "expires_on": "",
                    "days_remaining": None,
                    "san_count": 0,
                    "sans": [],
                }
                head_res = _read_head_block(tls_sock, host)
                return tls_info, head_res
    except Exception as exc:
        log_event(
            logger,
            logging.DEBUG,
            "https_unverified_fallback_failed",
            host=host,
            error_type=type(exc).__name__,
        )
        return {"available": False, "verified": False, "verify_error": verify_error}, None


def _probe_pinned_http(host: str, ip: str) -> tuple[int, dict[str, str]] | None:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(2.5)
            raw_sock.connect((ip, 80))
            return _read_head_block(raw_sock, host)
    except Exception as exc:
        log_event(
            logger,
            logging.DEBUG,
            "http_pinned_probe_failed",
            host=host,
            error_type=type(exc).__name__,
        )
        return None


def _evaluate_header_score(header_key: str, val: str | None, max_weight: int) -> tuple[int, str]:
    if not val:
        return 0, "Missing"

    lower = val.lower()
    if header_key == "Strict-Transport-Security":
        match = re.search(r"max-age=(\d+)", lower)
        max_age = int(match.group(1)) if match else 0
        if max_age >= 15552000:
            return max_weight, "Strong (max-age >= 180d)"
        if max_age > 0:
            return max_weight // 2, "Weak max-age (< 180d)"
        return 0, "Invalid max-age=0"

    if header_key == "Content-Security-Policy":
        if re.search(r"(default-src|script-src)\s+[^;]*\*", lower) or "'unsafe-inline'" in lower:
            return max_weight // 2, "Permissive wildcard or unsafe-inline"
        return max_weight, "Restrictive policy"

    if header_key == "X-Frame-Options":
        if "deny" in lower or "sameorigin" in lower:
            return max_weight, "Enforced"
        return max_weight // 2, "Non standard directive"

    if header_key == "X-Content-Type-Options":
        if "nosniff" in lower:
            return max_weight, "Enforced (nosniff)"
        return 0, "Invalid directive"

    return max_weight, "Configured"


def _compute_grade(score: int, https_active: bool, tls_verified: bool) -> str:
    if not https_active:
        return "F"
    if not tls_verified and score > 55:
        score = 55
    if score >= 90:
        return "A+"
    if score >= 75:
        return "A"
    if score >= 60:
        return "B"
    if score >= 45:
        return "C"
    if score >= 25:
        return "D"
    return "F"


def _inspect_redirect_location(base_url: str, location: str | None) -> dict | None:
    if not location:
        return None
    resolved_target = urljoin(base_url, location)
    ssrf_blocked = False
    ssrf_reason = ""
    try:
        normalize_and_validate(resolved_target)
    except TargetValidationError as exc:
        ssrf_blocked = True
        ssrf_reason = str(exc)

    return {
        "location": resolved_target[:240],
        "followed": False,
        "ssrf_target_blocked": ssrf_blocked,
        "note": ssrf_reason or "Redirect not followed (pinned single hop audit).",
    }


def audit_web_posture(host: str, ip: str, is_ip: bool) -> dict:
    """Inspect TLS certificate health and HTTP security headers over a pinned socket without following redirects."""
    tls_info, head_result = _probe_pinned_https(host, ip, is_ip=is_ip)
    scheme = "https"

    if head_result is None:
        scheme = "http"
        head_result = _probe_pinned_http(host, ip)

    if head_result is None:
        return {
            "reachable": False,
            "grade": "N/A",
            "score": 0,
            "tls": tls_info,
            "headers": [],
            "disclosures": [],
            "redirect": None,
        }

    status_code, resp_headers = head_result
    host_url = _format_host_header(host)
    final_url = f"{scheme}://{host_url}/"
    https_active = scheme == "https"
    tls_verified = bool(tls_info.get("verified"))

    redirect_info = None
    if status_code in {301, 302, 303, 307, 308}:
        redirect_info = _inspect_redirect_location(final_url, resp_headers.get("location"))

    score = 0
    header_results: list[dict] = []

    for header_key, label, weight, advice in SECURITY_HEADERS:
        val = resp_headers.get(header_key.lower())
        earned, quality = _evaluate_header_score(header_key, val, weight)
        score += earned
        header_results.append({
            "header": header_key,
            "label": label,
            "present": bool(val),
            "quality": quality,
            "points": earned,
            "max_points": weight,
            "value": val[:140] if val else None,
            "advice": advice,
        })

    disclosures: list[dict] = []
    for leak_key in ("Server", "X-Powered-By", "X-AspNet-Version", "Via"):
        leak_val = resp_headers.get(leak_key.lower())
        if leak_val:
            disclosures.append({"header": leak_key, "value": leak_val[:100]})

    return {
        "reachable": True,
        "status_code": status_code,
        "final_url": final_url,
        "https_active": https_active,
        "score": score,
        "grade": _compute_grade(score, https_active, tls_verified),
        "tls": tls_info,
        "headers": header_results,
        "disclosures": disclosures,
        "redirect": redirect_info,
    }
