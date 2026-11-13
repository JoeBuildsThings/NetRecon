from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import time
from flask import Flask, jsonify, render_template, request

from recon.dns_intel import resolve_dns_intel
from recon.geo_intel import fetch_geo_intel
from recon.port_scanner import scan_common_ports
from recon.validator import TargetValidationError, normalize_and_validate
from recon.web_audit import audit_web_posture

app = Flask(__name__)

RATE_LIMIT_MAX = 25
RATE_LIMIT_WINDOW = 60.0
_request_log: dict[str, deque[float]] = defaultdict(deque)


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    bucket = _request_log[ip]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX:
        return True
    bucket.append(now)
    return False


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "netrecon", "version": "2.0.0"})


@app.route("/api/recon", methods=["POST"])
def api_recon():
    client = _client_ip()
    if _is_rate_limited(client):
        return jsonify({"ok": False, "error": "Rate limit exceeded. Wait a minute before running another scan."}), 429

    payload = request.get_json(silent=True) or {}
    raw_target = payload.get("target") or request.form.get("target") or ""

    t_start = time.perf_counter()
    try:
        target = normalize_and_validate(raw_target)
    except TargetValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception:
        return jsonify({"ok": False, "error": "Unable to validate target input."}), 400

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            geo_future = pool.submit(fetch_geo_intel, target.primary_ip)
            ports_future = pool.submit(scan_common_ports, target.primary_ip, target.host)
            dns_future = pool.submit(resolve_dns_intel, target.host, target.primary_ip, target.is_ip)
            web_future = pool.submit(audit_web_posture, target.host, target.primary_ip, target.is_ip)

            geo = geo_future.result()
            ports = ports_future.result()
            dns_info = dns_future.result()
            web_audit = web_future.result()
    except Exception:
        return jsonify({"ok": False, "error": "Reconnaissance probe encountered an upstream timeout."}), 502

    total_ms = round((time.perf_counter() - t_start) * 1000, 1)

    return jsonify({
        "ok": True,
        "elapsed_ms": total_ms,
        "target": {
            "input": target.raw_input,
            "host": target.host,
            "primary_ip": target.primary_ip,
            "all_ips": target.all_ips,
            "is_ip": target.is_ip,
        },
        "geo": geo,
        "ports": ports,
        "dns": dns_info,
        "web": web_audit,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
