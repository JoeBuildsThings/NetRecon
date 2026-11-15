from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import json
import logging
import os
import time
import urllib.parse
import urllib.request
from flask import Flask, Response, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from recon import __version__
from recon.dns_intel import resolve_dns_intel
from recon.geo_intel import fetch_geo_intel
from recon.logger import get_logger, log_event
from recon.ownership import build_challenge, verify_domain_ownership
from recon.port_scanner import scan_common_ports
from recon.validator import TargetValidationError, normalize_and_validate
from recon.web_audit import audit_web_posture

logger = get_logger("netrecon.app")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]

RATE_LIMIT_MAX = 25
RATE_LIMIT_WINDOW = 60
MAX_TRACKED_IPS = 2048
MODULE_TIMEOUT_SEC = 4.5

_request_log: OrderedDict[str, deque[float]] = OrderedDict()


def _client_ip() -> str:
    vercel_ip = request.headers.get("x-real-ip", "").strip()
    if vercel_ip:
        return vercel_ip
    return request.remote_addr or "unknown"


def _check_upstash_rate_limit(client_ip: str) -> bool | None:
    rest_url = os.environ.get("UPSTASH_REDIS_REST_URL", "").strip().rstrip("/")
    rest_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "").strip()
    if not rest_url or not rest_token:
        return None
    window_bucket = int(time.time() // RATE_LIMIT_WINDOW)
    key = urllib.parse.quote(f"netrecon:rl:{client_ip}:{window_bucket}", safe="")
    pipeline_url = f"{rest_url}/pipeline"
    body = json.dumps([["INCR", key], ["EXPIRE", key, RATE_LIMIT_WINDOW + 5]]).encode("utf-8")
    req = urllib.request.Request(pipeline_url, data=body, headers={"Authorization": f"Bearer {rest_token}", "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=1.2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            count = int(data[0].get("result", 1))
            return count > RATE_LIMIT_MAX
    except Exception as exc:
        log_event(logger, logging.WARNING, "upstash_rate_limit_fallback", error_type=type(exc).__name__)
        return None


def _is_rate_limited(client_ip: str) -> bool:
    distributed = _check_upstash_rate_limit(client_ip)
    if distributed is not None:
        return distributed
    now = time.monotonic()
    if client_ip in _request_log:
        _request_log.move_to_end(client_ip)
    else:
        if len(_request_log) >= MAX_TRACKED_IPS:
            _request_log.popitem(last=False)
        _request_log[client_ip] = deque()
    bucket = _request_log[client_ip]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX:
        return True
    bucket.append(now)
    return False


@app.after_request
def apply_security_headers(response: Response) -> Response:
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", version=__version__)


@app.route("/privacy", methods=["GET"])
def privacy():
    return render_template("privacy.html", version=__version__)


@app.route("/robots.txt", methods=["GET"])
def robots_txt():
    body = "User-agent: *\nAllow: /\nSitemap: https://netrecon.vercel.app/sitemap.xml\n"
    return Response(body, mimetype="text/plain")


@app.route("/sitemap.xml", methods=["GET"])
def sitemap_xml():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://netrecon.vercel.app/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>"
        "<url><loc>https://netrecon.vercel.app/privacy</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>"
        "</urlset>"
    )
    return Response(xml, mimetype="application/xml")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "netrecon", "version": __version__})


@app.route("/api/ownership/challenge", methods=["GET"])
def ownership_challenge():
    raw_target = request.args.get("target", "")
    try:
        target = normalize_and_validate(raw_target)
    except TargetValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    challenge = build_challenge(target.host, target.is_ip)
    return jsonify({"ok": True, "target": target.host, **challenge})


@app.route("/api/recon", methods=["POST"])
def api_recon():
    client = _client_ip()
    if _is_rate_limited(client):
        log_event(logger, logging.WARNING, "rate_limit_exceeded", client_ip=client)
        return jsonify({"ok": False, "error": "Rate limit exceeded. Wait one minute before running another scan."}), 429
    payload = request.get_json(silent=True) or {}
    raw_target = payload.get("target") or request.form.get("target") or ""
    include_ports = bool(payload.get("include_ports", True))
    t_start = time.perf_counter()
    try:
        target = normalize_and_validate(raw_target)
    except TargetValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        log_event(logger, logging.ERROR, "validation_unexpected_error", error_type=type(exc).__name__)
        return jsonify({"ok": False, "error": "Unable to validate target input."}), 400
    partial_errors: list[str] = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        geo_future = pool.submit(fetch_geo_intel, target.primary_ip)
        dns_future = pool.submit(resolve_dns_intel, target.host, target.primary_ip, target.is_ip)
        web_future = pool.submit(audit_web_posture, target.host, target.primary_ip, target.is_ip)
        own_future = pool.submit(verify_domain_ownership, target.host, target.is_ip) if include_ports else None
        try:
            geo = geo_future.result(timeout=MODULE_TIMEOUT_SEC)
        except (FuturesTimeoutError, Exception) as exc:
            partial_errors.append("geo")
            log_event(logger, logging.WARNING, "geo_module_timeout", host=target.host, error_type=type(exc).__name__)
            geo = {"ip": target.primary_ip, "ip_version": "IPv6" if ":" in target.primary_ip else "IPv4", "city": "Unavailable", "region": "", "country": "Unknown", "country_code": "", "latitude": 0.0, "longitude": 0.0, "timezone": "UTC", "asn": "N/A", "org": "Timed out", "isp": "Timed out", "domain": "", "source": "timeout"}
        try:
            dns_info = dns_future.result(timeout=MODULE_TIMEOUT_SEC)
        except (FuturesTimeoutError, Exception) as exc:
            partial_errors.append("dns")
            log_event(logger, logging.WARNING, "dns_module_timeout", host=target.host, error_type=type(exc).__name__)
            dns_info = {"ptr": [], "records": {}, "posture": {"dns_provider": "Timed out", "mail_provider": "Timed out", "spf_configured": False, "spf_status": "Timed out", "dmarc_configured": False, "dmarc_policy": "timeout", "dmarc_status": "Timed out"}}
        try:
            web_audit = web_future.result(timeout=MODULE_TIMEOUT_SEC)
        except (FuturesTimeoutError, Exception) as exc:
            partial_errors.append("web")
            log_event(logger, logging.WARNING, "web_module_timeout", host=target.host, error_type=type(exc).__name__)
            web_audit = {"reachable": False, "grade": "N/A", "score": 0, "tls": {"available": False, "verified": False, "verify_error": None}, "headers": [], "disclosures": [], "redirect": None}
        if not include_ports or own_future is None:
            ownership = build_challenge(target.host, target.is_ip)
            ownership["verified"] = False
            ports = {"status": "skipped", "reason": "Passive audit mode requested.", "scanned_count": 0, "open_count": 0, "scan_ms": 0.0, "open_ports": []}
        else:
            try:
                ownership = own_future.result(timeout=MODULE_TIMEOUT_SEC)
            except Exception:
                ownership = build_challenge(target.host, target.is_ip)
                ownership["verified"] = False
            if ownership.get("verified"):
                dns_prov = dns_info.get("posture", {}).get("dns_provider", "")
                ports_future = pool.submit(scan_common_ports, target.primary_ip, target.host, geo.get("org", ""), dns_prov)
                try:
                    ports = ports_future.result(timeout=MODULE_TIMEOUT_SEC)
                except (FuturesTimeoutError, Exception) as exc:
                    partial_errors.append("ports")
                    log_event(logger, logging.WARNING, "ports_module_timeout", host=target.host, error_type=type(exc).__name__)
                    ports = {"status": "timeout", "reason": "Port scan exceeded module timeout budget.", "scanned_count": 0, "open_count": 0, "scan_ms": 0.0, "open_ports": []}
            else:
                ports = {"status": "verification_required", "reason": ownership.get("reason", "Domain ownership verification required before active port probing."), "txt_host": ownership.get("txt_host", ""), "txt_value": ownership.get("txt_value", ""), "scanned_count": 0, "open_count": 0, "scan_ms": 0.0, "open_ports": []}
    total_ms = round((time.perf_counter() - t_start) * 1000, 1)
    log_event(logger, logging.INFO, "recon_scan_complete", host=target.host, primary_ip=target.primary_ip, elapsed_ms=total_ms, partial=bool(partial_errors))
    return jsonify({"ok": True, "partial": bool(partial_errors), "partial_errors": partial_errors, "elapsed_ms": total_ms, "target": {"input": target.raw_input, "host": target.host, "primary_ip": target.primary_ip, "all_ips": target.all_ips, "is_ip": target.is_ip}, "ownership": ownership, "geo": geo, "ports": ports, "dns": dns_info, "web": web_audit})


@app.errorhandler(404)
def not_found(_err):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "API endpoint not found."}), 404
    return render_template("404.html", version=__version__), 404


@app.errorhandler(500)
def server_error(_err):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "Internal service error."}), 500
    return render_template("404.html", version=__version__), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
