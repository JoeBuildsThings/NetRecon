from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import logging
import os
import threading
import time
import urllib.parse
import urllib.request

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from recon import __version__
from recon.dns_intel import resolve_dns_intel
from recon.geo_intel import fetch_geo_intel
from recon.logger import get_logger, log_event
from recon.port_scanner import detect_edge_network, scan_common_ports
from recon.scope import active_scan_scope
from recon.validator import TargetValidationError, normalize_and_validate
from recon.web_audit import audit_web_posture

logger = get_logger("netrecon.app")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 4096
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # type: ignore[method-assign]

RATE_LIMIT_MAX = 25
RATE_LIMIT_WINDOW = 60
MAX_TRACKED_IPS = 2048
MODULE_TIMEOUT_SEC = 6.0

_request_log: OrderedDict[str, deque[float]] = OrderedDict()
_rate_limit_lock = threading.Lock()


def _client_ip() -> str:
    return request.remote_addr or "unknown"


def _check_upstash_rate_limit(client_ip: str) -> bool | None:
    rest_url = os.environ.get("UPSTASH_REDIS_REST_URL", "").strip().rstrip("/")
    rest_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "").strip()
    if not rest_url or not rest_token:
        return None

    parsed = urllib.parse.urlparse(rest_url)
    if parsed.scheme != "https" or not parsed.netloc:
        log_event(logger, logging.WARNING, "upstash_rate_limit_config_invalid")
        return None

    window_bucket = int(time.time() // RATE_LIMIT_WINDOW)
    key = urllib.parse.quote(f"netrecon:rl:{client_ip}:{window_bucket}", safe="")
    body = json.dumps([["INCR", key], ["EXPIRE", key, RATE_LIMIT_WINDOW + 5]]).encode("utf-8")
    req = urllib.request.Request(
        f"{rest_url}/pipeline",
        data=body,
        headers={
            "Authorization": f"Bearer {rest_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=1.2) as response:
            data = json.loads(response.read().decode("utf-8"))
            count = int(data[0].get("result", 1))
            return count > RATE_LIMIT_MAX
    except Exception as exc:
        log_event(
            logger,
            logging.WARNING,
            "upstash_rate_limit_fallback",
            error_type=type(exc).__name__,
        )
        return None


def _is_rate_limited(client_ip: str) -> bool:
    distributed = _check_upstash_rate_limit(client_ip)
    if distributed is not None:
        return distributed

    now = time.monotonic()
    with _rate_limit_lock:
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
        "style-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://*.basemaps.cartocdn.com; "
        "connect-src 'self' https://*.basemaps.cartocdn.com; "
        "font-src 'self' data:; "
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


def _geo_fallback(ip: str) -> dict:
    return {
        "ip": ip,
        "ip_version": "IPv6" if ":" in ip else "IPv4",
        "city": "Unavailable",
        "region": "",
        "country": "Unknown",
        "country_code": "",
        "latitude": None,
        "longitude": None,
        "timezone": "UTC",
        "asn": "N/A",
        "org": "Lookup unavailable",
        "isp": "Lookup unavailable",
        "domain": "",
        "source": "unavailable",
        "cached": False,
    }


def _dns_fallback() -> dict:
    return {
        "ptr": [],
        "records": {},
        "posture": {
            "dns_provider": "Unavailable",
            "mail_provider": "Unavailable",
            "spf_configured": False,
            "spf_status": "Unavailable",
            "dmarc_configured": False,
            "dmarc_policy": "unavailable",
            "dmarc_status": "Unavailable",
        },
    }


def _web_fallback() -> dict:
    return {
        "reachable": False,
        "grade": "N/A",
        "score": 0,
        "tls": {"available": False, "verified": False, "verify_error": None},
        "headers": [],
        "disclosures": [],
        "redirect": None,
    }


def _ports_fallback(status: str, reason: str) -> dict:
    return {
        "status": status,
        "reason": reason,
        "scanned_count": 0,
        "open_count": 0,
        "scan_ms": 0.0,
        "open_ports": [],
    }


def _collect_module(future, module: str, fallback: dict, host: str, partial_errors: list[str]) -> dict:
    try:
        result = future.result(timeout=MODULE_TIMEOUT_SEC)
        if not isinstance(result, dict):
            raise TypeError("Module returned an invalid result")
        return result
    except Exception as exc:
        partial_errors.append(module)
        log_event(
            logger,
            logging.WARNING,
            "recon_module_failed",
            module=module,
            host=host,
            error_type=type(exc).__name__,
        )
        return fallback


@app.route("/api/recon", methods=["POST"])
def api_recon():
    client = _client_ip()
    if _is_rate_limited(client):
        log_event(logger, logging.WARNING, "rate_limit_exceeded")
        response = jsonify({
            "ok": False,
            "error": "Scan limit reached. Please wait one minute before trying again.",
        })
        response.headers["Retry-After"] = str(RATE_LIMIT_WINDOW)
        return response, 429

    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "Request body must be a JSON object."}), 400

    raw_target = payload.get("target") or request.form.get("target") or ""
    if not isinstance(raw_target, str):
        return jsonify({"ok": False, "error": "Target must be a domain, URL, or public IP address."}), 400

    started_at = time.perf_counter()
    try:
        target = normalize_and_validate(raw_target)
    except TargetValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        log_event(
            logger,
            logging.ERROR,
            "validation_unexpected_error",
            error_type=type(exc).__name__,
        )
        return jsonify({"ok": False, "error": "Unable to validate this target."}), 400

    active_scope = active_scan_scope(target.host, target.primary_ip)
    active_allowed = bool(active_scope["allowed"])
    partial_errors: list[str] = []

    # All eligible modules are submitted together. The active probe therefore
    # runs concurrently with DNS and geolocation rather than after them.
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="netrecon") as pool:
        geo_future = pool.submit(fetch_geo_intel, target.primary_ip)
        dns_future = pool.submit(resolve_dns_intel, target.host, target.primary_ip, target.is_ip)
        web_future = pool.submit(audit_web_posture, target.host, target.primary_ip, target.is_ip)
        ports_future = (
            pool.submit(
                scan_common_ports,
                target.primary_ip,
                target.host,
                "",
                "",
            )
            if active_allowed
            else None
        )

        geo = _collect_module(geo_future, "geo", _geo_fallback(target.primary_ip), target.host, partial_errors)
        dns_info = _collect_module(dns_future, "dns", _dns_fallback(), target.host, partial_errors)
        web_audit = _collect_module(web_future, "web", _web_fallback(), target.host, partial_errors)

        if ports_future is not None:
            ports = _collect_module(
                ports_future,
                "ports",
                _ports_fallback("error", "The active probe could not be completed."),
                target.host,
                partial_errors,
            )
            if ports.get("status") != "completed" and "ports" not in partial_errors:
                partial_errors.append("ports")
        elif active_scope["status"] == "disabled":
            ports = _ports_fallback(
                "disabled",
                "Active probing is disabled until the operator configures an explicit target scope.",
            )
        else:
            ports = _ports_fallback(
                "scope_required",
                "This target is outside the server-configured active scan scope. Passive checks completed.",
            )

        edge_cdn, edge_provider = detect_edge_network(
            geo.get("org", ""),
            dns_info.get("posture", {}).get("dns_provider", ""),
        )
        if ports.get("status") == "completed":
            ports["edge_cdn"] = edge_cdn
            ports["edge_provider"] = edge_provider

    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    geo["lookup_at"] = scanned_at
    geo["location_kind"] = "approximate"

    total_ms = round((time.perf_counter() - started_at) * 1000, 1)
    log_event(
        logger,
        logging.INFO,
        "recon_scan_complete",
        host=target.host,
        primary_ip=target.primary_ip,
        elapsed_ms=total_ms,
        active_probe=active_allowed,
        partial=bool(partial_errors),
    )

    return jsonify({
        "ok": True,
        "partial": bool(partial_errors),
        "partial_errors": partial_errors,
        "elapsed_ms": total_ms,
        "scanned_at": scanned_at,
        "target": {
            "input": target.raw_input,
            "host": target.host,
            "primary_ip": target.primary_ip,
            "all_ips": target.all_ips,
            "is_ip": target.is_ip,
        },
        "active_scope": {
            "status": active_scope["status"],
            "active_probe_started": active_allowed,
        },
        "geo": geo,
        "ports": ports,
        "dns": dns_info,
        "web": web_audit,
    })


@app.errorhandler(404)
def not_found(_err):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "API endpoint not found."}), 404
    return render_template("404.html", version=__version__), 404


@app.errorhandler(413)
def request_too_large(_err):
    return jsonify({"ok": False, "error": "Request body is too large."}), 413


@app.errorhandler(500)
def server_error(_err):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "Internal service error."}), 500
    return render_template("404.html", version=__version__), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
