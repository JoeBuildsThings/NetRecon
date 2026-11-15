from concurrent.futures import ThreadPoolExecutor
import re
import socket
import ssl
import time

TIMEOUT = 2.5
MAX_HEAD_BYTES = 16384

# (header, label, weight, advice). Weights add up to 100.
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", 20, "Enforces HTTPS connections against downgrade attacks"),
    ("Content-Security-Policy", "CSP", 25, "Mitigates XSS and unauthorized script injection"),
    ("X-Frame-Options", "X-Frame-Options", 15, "Prevents clickjacking via iframe embedding"),
    ("X-Content-Type-Options", "X-Content-Type-Options", 15, "Blocks MIME type sniffing"),
    ("Referrer-Policy", "Referrer-Policy", 10, "Controls referrer leakage across origins"),
    ("Permissions-Policy", "Permissions-Policy", 15, "Restricts browser APIs such as camera and microphone"),
]

HSTS_MIN_AGE = 15552000  # 180 days


def _family(ip):
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def _host_header(host):
    return f"[{host}]" if ":" in host else host


def _read_response_head(sock, host):
    """Send HEAD over an already pinned socket and parse status plus headers only.

    No redirects are followed and no body is ever read, so a hostile server cannot
    redirect us to internal addresses or stream unbounded data at us.
    """
    request = (
        f"HEAD / HTTP/1.1\r\nHost: {_host_header(host)}\r\n"
        "User-Agent: NetRecon/2.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
    sock.sendall(request.encode("ascii", errors="ignore"))

    raw = b""
    while b"\r\n\r\n" not in raw and len(raw) < MAX_HEAD_BYTES:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw += chunk

    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin1")
    lines = head.split("\r\n")
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    if not match:
        return None

    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key and key not in headers:
            headers[key] = value.strip()
    return {"status": int(match.group(1)), "headers": headers}


def _safe_head(sock, host):
    try:
        return _read_response_head(sock, host)
    except Exception:
        return None


def _handshake(ip, server_name, verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.socket(_family(ip), socket.SOCK_STREAM)
    raw.settimeout(TIMEOUT)
    try:
        raw.connect((ip, 443))
        return ctx.wrap_socket(raw, server_hostname=server_name)
    except Exception:
        raw.close()
        raise


def _cipher_name(tls_sock):
    info = tls_sock.cipher()
    return info[0] if info else "Unknown"


def _tls_probe(host, ip):
    """Verified TLS handshake against the pinned IP. Falls back to an unverified one so
    headers can still be read, and records why verification failed."""
    try:
        tls = _handshake(ip, host, True)
    except ssl.SSLCertVerificationError as exc:
        info = {
            "available": True,
            "valid": False,
            "error": (exc.verify_message or "Certificate failed verification")[:140],
        }
        try:
            tls = _handshake(ip, host, False)
        except Exception:
            return info, None
        with tls:
            info["protocol"] = tls.version() or "Unknown"
            info["cipher"] = _cipher_name(tls)
            head = _safe_head(tls, host)
        return info, head
    except Exception:
        return {"available": False}, None

    with tls:
        cert = tls.getpeercert() or {}
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        not_after = cert.get("notAfter", "")
        days_left = None
        if not_after:
            try:
                days_left = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
            except Exception:
                days_left = None
        sans = [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"]
        info = {
            "available": True,
            "valid": True,
            "error": None,
            "protocol": tls.version() or "Unknown",
            "cipher": _cipher_name(tls),
            "common_name": subject.get("commonName", host),
            "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Unknown CA",
            "expires_on": not_after,
            "days_remaining": days_left,
            "san_count": len(sans),
            "sans": sans[:10],
        }
        head = _safe_head(tls, host)
    return info, head


def _ip_literal_probe(ip):
    """IP targets have no hostname to verify, so read headers over unverified TLS."""
    try:
        tls = _handshake(ip, None, False)
    except Exception:
        return None
    with tls:
        return _safe_head(tls, ip)


def _http_probe(host, ip):
    try:
        with socket.socket(_family(ip), socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((ip, 80))
            return _read_response_head(sock, host)
    except Exception:
        return None


def _hsts_status(value):
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    if match and int(match.group(1)) >= HSTS_MIN_AGE:
        return "pass", "Max age is long enough"
    return "weak", "Max age under 180 days or missing"


def _csp_status(value):
    lowered = value.lower()
    if "unsafe-eval" in lowered or "unsafe-inline" in lowered:
        return "weak", "Allows unsafe inline or eval"
    if re.search(r"(?:default|script)-src[^;]*\s\*(?:\s|;|$)", lowered):
        return "weak", "Wildcard source in script policy"
    return "pass", ""


def evaluate_headers(headers):
    """Score defensive headers by value, not just presence. Takes lowercase header keys."""
    csp_value = headers.get("content-security-policy", "")
    results = []
    score = 0.0

    for key, label, weight, advice in SECURITY_HEADERS:
        value = headers.get(key.lower())
        status, note = "missing", ""

        if value:
            if key == "Strict-Transport-Security":
                status, note = _hsts_status(value)
            elif key == "Content-Security-Policy":
                status, note = _csp_status(value)
            elif key == "X-Frame-Options":
                status = "pass" if value.strip().lower() in ("deny", "sameorigin") else "weak"
            elif key == "X-Content-Type-Options":
                status = "pass" if value.strip().lower() == "nosniff" else "weak"
            elif key == "Referrer-Policy":
                bad = value.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade")
                status = "weak" if bad else "pass"
            else:
                status = "pass"
        elif key == "X-Frame-Options" and "frame-ancestors" in csp_value.lower():
            status, note = "pass", "Covered by CSP frame ancestors"

        if status == "pass":
            score += weight
        elif status == "weak":
            score += weight / 2

        results.append({
            "header": key,
            "label": label,
            "present": bool(value),
            "status": status,
            "note": note,
            "value": value[:140] if value else None,
            "advice": advice,
        })

    return int(round(score)), results


def _compute_grade(score, https_active, cert_valid=True):
    if not https_active:
        return "F"
    if score >= 90:
        grade = "A+"
    elif score >= 75:
        grade = "A"
    elif score >= 60:
        grade = "B"
    elif score >= 45:
        grade = "C"
    elif score >= 25:
        grade = "D"
    else:
        grade = "F"
    if not cert_valid and grade in ("A+", "A", "B", "C"):
        return "D"
    return grade


def _disclosures(headers):
    found = []
    for leak_key in ("server", "x-powered-by", "x-aspnet-version", "via"):
        value = headers.get(leak_key)
        if value:
            found.append({
                "header": "-".join(part.capitalize() for part in leak_key.split("-")),
                "value": value[:100],
                "versioned": bool(re.search(r"\d+\.\d+", value)),
            })
    return found


def _redirect_info(http_head):
    if http_head is None:
        return {"http_to_https": None, "location": None}
    location = http_head["headers"].get("location")
    redirects = http_head["status"] in (301, 302, 307, 308) and bool(location) and location.lower().startswith("https://")
    return {"http_to_https": redirects, "location": location[:140] if location else None}


def unreachable_result():
    return {
        "reachable": False,
        "status_code": None,
        "https_active": False,
        "redirect": {"http_to_https": None, "location": None},
        "score": 0,
        "grade": "N/A",
        "tls": {"available": False},
        "headers": [],
        "disclosures": [],
    }


def audit_web_posture(host, ip, is_ip):
    """Inspect TLS certificate health and HTTP defensive headers over pinned, validated sockets."""
    with ThreadPoolExecutor(max_workers=2) as pool:
        if is_ip:
            tls_future = pool.submit(lambda: ({"available": False}, _ip_literal_probe(ip)))
        else:
            tls_future = pool.submit(_tls_probe, host, ip)
        http_future = pool.submit(_http_probe, host, ip)
        tls_info, https_head = tls_future.result()
        http_head = http_future.result()

    chosen = https_head or http_head
    if chosen is None:
        result = unreachable_result()
        result["tls"] = tls_info
        return result

    https_active = https_head is not None
    score, header_results = evaluate_headers(chosen["headers"])
    cert_valid = tls_info.get("valid", True) is not False

    return {
        "reachable": True,
        "status_code": chosen["status"],
        "https_active": https_active,
        "redirect": _redirect_info(http_head),
        "score": score,
        "grade": _compute_grade(score, https_active, cert_valid),
        "tls": tls_info,
        "headers": header_results,
        "disclosures": _disclosures(chosen["headers"]),
    }
