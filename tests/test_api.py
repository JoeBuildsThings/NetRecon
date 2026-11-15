import pytest

import app as app_module
from recon.validator import ValidatedTarget


@pytest.fixture()
def client(monkeypatch):
    app_module.app.config["TESTING"] = True
    app_module._local_hits.clear()
    target = ValidatedTarget("example.com", "example.com", "93.184.216.34", ["93.184.216.34"], False)
    monkeypatch.setattr(app_module, "normalize_and_validate", lambda raw: target)
    monkeypatch.setattr(app_module, "fetch_geo_intel", lambda ip: app_module.unavailable_geo(ip))
    monkeypatch.setattr(app_module, "resolve_dns_intel", lambda *a: app_module.empty_dns())
    monkeypatch.setattr(app_module, "audit_web_posture", lambda *a: app_module.unreachable_result())
    monkeypatch.setattr(app_module, "scan_common_ports", lambda *a: {
        "scanned_count": 22, "open_count": 1, "scan_ms": 10,
        "open_ports": [{"port": 6379, "service": "Redis", "risk": "high", "latency_ms": 4, "banner": "", "note": ""}],
    })
    return app_module.app.test_client()


def post(client, body, **kw):
    return client.post("/api/recon", json=body, **kw)


def test_passive_scan_skips_ports(client):
    data = post(client, {"target": "example.com"}).get_json()
    assert data["ok"] and data["ports"]["skipped"] is True and data["scan"]["active"] is False


def test_active_requires_authorization(client):
    resp = post(client, {"target": "example.com", "active": True})
    assert resp.status_code == 400
    assert resp.get_json()["code"] == "authorization_required"


def test_active_with_authorization_runs_ports_and_flags_redis(client):
    data = post(client, {"target": "example.com", "active": True, "authorized": True}).get_json()
    assert data["ports"]["open_count"] == 1
    assert data["summary"]["critical"] == 1


def test_form_posts_rejected(client):
    assert client.post("/api/recon", data={"target": "example.com"}).status_code == 415


def test_cross_origin_rejected(client):
    resp = post(client, {"target": "example.com"}, headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403


def test_same_origin_allowed(client):
    resp = post(client, {"target": "example.com"}, headers={"Origin": "http://localhost"})
    assert resp.status_code == 200


def test_oversized_body_rejected(client):
    assert post(client, {"target": "a" * 6000}).status_code == 413


def test_rate_limit_with_retry_after(client):
    for _ in range(app_module.RATE_LIMITS["scan"]):
        assert post(client, {"target": "example.com"}).status_code == 200
    resp = post(client, {"target": "example.com"})
    assert resp.status_code == 429 and resp.headers["Retry-After"] == "60"


def test_active_has_stricter_limit(client):
    body = {"target": "example.com", "active": True, "authorized": True}
    for _ in range(app_module.RATE_LIMITS["active"]):
        assert post(client, body).status_code == 200
    assert post(client, body).status_code == 429


def test_spoofed_forwarded_header_ignored_without_proxy(client):
    for i in range(app_module.RATE_LIMITS["scan"]):
        post(client, {"target": "example.com"}, headers={"X-Forwarded-For": f"9.9.9.{i}"})
    resp = post(client, {"target": "example.com"}, headers={"X-Forwarded-For": "8.8.4.4"})
    assert resp.status_code == 429


def test_index_has_nonce_csp_and_no_inline_style_attrs(client):
    resp = client.get("/")
    csp = resp.headers["Content-Security-Policy"]
    assert "script-src 'nonce-" in csp and "unsafe-inline" not in csp
    nonce = csp.split("script-src 'nonce-")[1].split("'")[0]
    html = resp.get_data(as_text=True)
    assert f'nonce="{nonce}"' in html
    assert ' style="' not in html and " onclick=" not in html
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_privacy_page_and_health(client):
    assert client.get("/privacy").status_code == 200
    assert client.get("/api/health").get_json()["status"] == "ok"


def test_api_responses_not_cached(client):
    assert post(client, {"target": "example.com"}).headers["Cache-Control"] == "no-store"
