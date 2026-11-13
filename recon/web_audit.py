from datetime import datetime, timezone
import socket
import ssl
import requests

SECURITY_HEADERS: list[tuple[str, str, int, str]] = [
    ("Strict-Transport-Security", "HSTS", 20, "Enforces HTTPS connections against downgrade attacks"),
    ("Content-Security-Policy", "CSP", 25, "Mitigates XSS and unauthorized script injection"),
    ("X-Frame-Options", "X-Frame-Options", 15, "Prevents clickjacking via iframe embedding"),
    ("X-Content-Type-Options", "X-Content-Type-Options", 15, "Blocks MIME-type sniffing"),
    ("Referrer-Policy", "Referrer-Policy", 10, "Controls referrer leakage across origins"),
    ("Permissions-Policy", "Permissions-Policy", 15, "Restricts browser APIs (camera, mic, geolocation)"),
]


def _inspect_tls(host: str, ip: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(2.2)
            raw_sock.connect((ip, 443))
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                protocol = tls_sock.version() or "Unknown"
                cipher_info = tls_sock.cipher()
                cipher = cipher_info[0] if cipher_info else "Unknown"

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                not_after_str = cert.get("notAfter", "")
                days_left = None
                if not_after_str:
                    expires_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expires_dt - datetime.now(timezone.utc)).days

                sans = [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"]

                return {
                    "available": True,
                    "protocol": protocol,
                    "cipher": cipher,
                    "common_name": subject.get("commonName", host),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Unknown CA",
                    "expires_on": not_after_str,
                    "days_remaining": days_left,
                    "san_count": len(sans),
                    "sans": sans[:10],
                }
    except Exception:
        return {"available": False}


def _compute_grade(score: int, https_active: bool) -> str:
    if not https_active:
        return "F"
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


def audit_web_posture(host: str, ip: str, is_ip: bool) -> dict:
    """Inspect TLS certificate health and HTTP defensive security headers."""
    tls_info = _inspect_tls(host, ip) if not is_ip else {"available": False}

    target_url = f"https://{host}" if not is_ip else f"http://{ip}"
    req_headers = {"User-Agent": "NetRecon/2.0 Security Audit"}

    resp = None
    final_url = target_url
    try:
        resp = requests.get(target_url, headers=req_headers, timeout=3.0, allow_redirects=True)
        final_url = resp.url
    except Exception:
        if target_url.startswith("https://"):
            try:
                resp = requests.get(f"http://{host}", headers=req_headers, timeout=2.5, allow_redirects=True)
                final_url = resp.url
            except Exception:
                resp = None

    if resp is None:
        return {
            "reachable": False,
            "grade": "N/A",
            "score": 0,
            "tls": tls_info,
            "headers": [],
            "disclosures": [],
        }

    https_active = final_url.startswith("https://")
    score = 0
    header_results: list[dict] = []

    for header_key, label, weight, advice in SECURITY_HEADERS:
        val = resp.headers.get(header_key)
        present = bool(val)
        if present:
            score += weight
        header_results.append({
            "header": header_key,
            "label": label,
            "present": present,
            "value": val[:140] if val else None,
            "advice": advice,
        })

    disclosures: list[dict] = []
    for leak_key in ("Server", "X-Powered-By", "X-AspNet-Version", "Via"):
        leak_val = resp.headers.get(leak_key)
        if leak_val:
            disclosures.append({"header": leak_key, "value": leak_val[:100]})

    return {
        "reachable": True,
        "status_code": resp.status_code,
        "final_url": final_url,
        "https_active": https_active,
        "score": score,
        "grade": _compute_grade(score, https_active),
        "tls": tls_info,
        "headers": header_results,
        "disclosures": disclosures,
    }
