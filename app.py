from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import secrets
import time
from urllib.parse import urlparse

import requests
from flask import Flask, g, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from recon.dns_intel import empty_result as empty_dns
from recon.dns_intel import resolve_dns_intel
from recon.findings import build_findings, summarize
from recon.geo_intel import fetch_geo_intel, unavailable_geo
from recon.port_scanner import scan_common_ports
from recon.validator import TargetValidationError, normalize_and_validate
from recon.web_audit import audit_web_posture, unreachable_result

VERSION = "2.1.0"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("netrecon")

# Only trust the forwarded for header for as many proxy hops as we actually run behind.
_TRUSTED_PROXIES = int(os.environ.get("TRUSTED_PROXIES", "1" if os.environ.get("VERCEL") else "0"))
if _TRUSTED_PROXIES:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_TRUSTED_PROXIES, x_proto=_TRUSTED_PROXIES)

RATE_WINDOW = 60.0
RATE_LIMITS = {"scan": 25, "active": 6}
MODULE_BUDGET = 8.0
_local_hits = defaultdict(deque)
_LOCAL_KEYS_MAX = 4096


def _remote_count(key):
    """Shared counter via Upstash REST when configured. Returns None when unavailable."""
    base = os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    if not base or not token:
        return None
    try:
        resp = requests.post(
            f"{base.rstrip('/')}/pipeline",
            json=[["INCR", key], ["EXPIRE", key, int(RATE_WINDOW) + 5]],
            headers={"Authorization": f"Bearer {token}"},
            timeout=1.0,
        )
        resp.raise_for_status()
        return int(resp.json()[0]["result"])
    except Exception:
        log.warning("rate limit backend unavailable, using local counter")
        return None


def _local_limited(key, limit):
    now = time.monotonic()
    if len(_local_hits) > _LOCAL_KEYS_MAX:
        for stale in [k for k, v in _local_hits.items() if not v or now - v[-1] > RATE_WINDOW]:
            _local_hits.pop(stale, None)
    bucket = _local_hits[key]
    while bucket and now - bucket[0] > RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


def _is_limited(name, ip):
    limit = RATE_LIMITS[name]
    window = int(time.time() // RATE_WINDOW)
    count = _remote_count(f"nr:{name}:{ip}:{window}")
    if count is not None:
        return count > limit
    return _local_limited(f"{name}:{ip}", limit)


def _client_ip():
    return request.remote_addr or "unknown"


def _error(message, status, **extra):
    body = {"ok": False, "error": message}
    body.update(extra)
    response = jsonify(body)
    response.status_code = status
    if status == 429:
        response.headers["Retry-After"] = str(int(RATE_WINDOW))
    return response


@app.errorhandler(413)
def too_large(_exc):
    return _error("Request body is too large.", 413)


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

    nonce = getattr(g, "csp_nonce", None)
    if nonce:
        response.headers["Content-Security-Policy"] = "; ".join([
            "default-src 'none'",
            f"script-src 'nonce-{nonce}'",
            f"style-src 'nonce-{nonce}' https://fonts.googleapis.com",
            "font-src https://fonts.gstatic.com",
            "img-src 'self' data:",
            "connect-src 'self' https://cdn.jsdelivr.net",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
            "object-src 'none'",
        ])
    else:
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _page(template):
    g.csp_nonce = secrets.token_urlsafe(18)
    return render_template(template, nonce=g.csp_nonce, version=VERSION)


@app.route("/", methods=["GET"])
def index():
    return _page("index.html")


@app.route("/privacy", methods=["GET"])
def privacy():
    return _page("privacy.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "netrecon", "version": VERSION})


def _empty_ports(skipped):
    return {"skipped": skipped, "scanned_count": 0, "open_count": 0, "scan_ms": 0, "open_ports": []}


def _fallback(name, target):
    if name == "geo":
        return unavailable_geo(target.primary_ip)
    if name == "dns":
        return empty_dns()
    if name == "web":
        return unreachable_result()
    return _empty_ports(False)


def _run_modules(target, active):
    pool = ThreadPoolExecutor(max_workers=4)
    results, failed = {}, []
    try:
        futures = {
            "geo": pool.submit(fetch_geo_intel, target.primary_ip),
            "dns": pool.submit(resolve_dns_intel, target.host, target.primary_ip, target.is_ip),
            "web": pool.submit(audit_web_posture, target.host, target.primary_ip, target.is_ip),
        }
        if active:
            futures["ports"] = pool.submit(scan_common_ports, target.primary_ip, target.host)

        deadline = time.monotonic() + MODULE_BUDGET
        for name, future in futures.items():
            try:
                results[name] = future.result(timeout=max(0.1, deadline - time.monotonic()))
            except Exception:
                log.warning("module %s failed or timed out", name)
                failed.append(name)
                results[name] = _fallback(name, target)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    if not active:
        results["ports"] = _empty_ports(True)
    return results, failed


@app.route("/api/recon", methods=["POST"])
def api_recon():
    origin = request.headers.get("Origin")
    if origin and urlparse(origin).netloc != request.host:
        return _error("Cross origin requests are not allowed.", 403)
    if not request.is_json:
        return _error("Send a JSON body.", 415)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = {}

    client = _client_ip()
    active = payload.get("active") is True
    authorized = payload.get("authorized") is True

    if _is_limited("scan", client) or (active and _is_limited("active", client)):
        return _error("Rate limit exceeded. Wait a minute before running another scan.", 429)

    if active and not authorized:
        return _error("Confirm you have permission to run the active port probe.", 400, code="authorization_required")

    t_start = time.perf_counter()
    try:
        target = normalize_and_validate(payload.get("target"))
    except TargetValidationError as exc:
        return _error(str(exc), 400)
    except Exception:
        return _error("Unable to validate target input.", 400)

    log.info("scan host=%s active=%s client=%s", target.host, active, client)
    results, failed = _run_modules(target, active)
    findings = build_findings(
        results["geo"], results["ports"], results["dns"], results["web"],
        target.is_ip, active, failed,
    )
    total_ms = round((time.perf_counter() - t_start) * 1000, 1)

    return jsonify({
        "ok": True,
        "version": VERSION,
        "elapsed_ms": total_ms,
        "scan": {"active": active, "partial": failed},
        "target": {
            "input": target.raw_input,
            "host": target.host,
            "primary_ip": target.primary_ip,
            "all_ips": target.all_ips,
            "is_ip": target.is_ip,
        },
        "geo": results["geo"],
        "ports": results["ports"],
        "dns": results["dns"],
        "web": results["web"],
        "findings": findings,
        "summary": summarize(findings),
    })


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000)
