import pytest

import app as app_module
from app import app
from recon.dns_intel import evaluate_dmarc_policy
from recon.scope import active_scan_scope
from recon.validator import (
    TargetValidationError,
    ValidatedTarget,
    is_disallowed_ip,
    normalize_and_validate,
)
from recon.web_audit import _evaluate_header_score, _inspect_redirect_location


@pytest.mark.parametrize(
    "bad_ip",
    [
        "127.0.0.1",
        "127.1",
        "0x7f.1",
        "2130706433",
        "::1",
        "::ffff:127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "0.0.0.0",
    ],
)
def test_blocks_private_loopback_cgnat_and_mapped_ipv6(bad_ip: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_and_validate(bad_ip)


@pytest.mark.parametrize("public_ip", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
def test_allows_globally_routable_ips(public_ip: str) -> None:
    assert is_disallowed_ip(public_ip) is False
    target = normalize_and_validate(public_ip)
    assert target.primary_ip == public_ip
    assert target.is_ip is True


@pytest.mark.parametrize(
    "bad_host",
    [
        "localhost",
        "metadata.local",
        "internal.internal",
        "file:///etc/passwd",
        "https://user:pass@example.com",
        ("example.com" + chr(13) + chr(10) + "Host: attacker.test"),
    ],
)
def test_blocks_internal_hosts_unsafe_schemes_and_credentials(bad_host: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_and_validate(bad_host)


def test_redirect_location_ssrf_detection() -> None:
    finding = _inspect_redirect_location(
        "https://example.com/",
        "http://169.254.169.254/latest/meta-data/",
    )
    assert finding is not None
    assert finding["followed"] is False
    assert finding["ssrf_target_blocked"] is True


def test_header_value_grading() -> None:
    assert _evaluate_header_score("Strict-Transport-Security", "max-age=63072000", 20)[0] == 20
    assert _evaluate_header_score("Strict-Transport-Security", "max-age=300", 20)[0] == 10
    assert _evaluate_header_score("Content-Security-Policy", "default-src *", 25)[0] == 12
    assert _evaluate_header_score("Content-Security-Policy", "default-src 'self'", 25)[0] == 25


def test_dmarc_and_spf_enforcement_checks() -> None:
    assert evaluate_dmarc_policy(["v=DMARC1; p=none; rua=mailto:a@b.com"])[0] is False
    assert evaluate_dmarc_policy(["v=DMARC1; p=reject; rua=mailto:a@b.com"])[0] is True


def test_scope_is_disabled_without_operator_configuration(monkeypatch) -> None:
    monkeypatch.delenv("NETRECON_ACTIVE_SCAN_ALLOWLIST", raising=False)
    result = active_scan_scope("example.com", "93.184.216.34")
    assert result == {"allowed": False, "status": "disabled"}


def test_scope_matches_exact_host_and_wildcard(monkeypatch) -> None:
    monkeypatch.setenv("NETRECON_ACTIVE_SCAN_ALLOWLIST", "example.com,*.owned.test")
    assert active_scan_scope("example.com", "93.184.216.34")["allowed"] is True
    assert active_scan_scope("api.owned.test", "93.184.216.34")["allowed"] is True
    assert active_scan_scope("owned.test", "93.184.216.34")["allowed"] is False
    assert active_scan_scope("other.test", "93.184.216.34")["allowed"] is False


def test_scope_matches_configured_ip_network(monkeypatch) -> None:
    monkeypatch.setenv("NETRECON_ACTIVE_SCAN_ALLOWLIST", "93.184.216.0/24")
    assert active_scan_scope("unrelated.test", "93.184.216.34")["allowed"] is True
    assert active_scan_scope("unrelated.test", "8.8.8.8")["allowed"] is False


def _mock_recon_modules(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "_is_rate_limited", lambda _client: False)
    monkeypatch.setattr(
        app_module,
        "normalize_and_validate",
        lambda raw: ValidatedTarget(
            raw_input=raw,
            host="example.com",
            primary_ip="93.184.216.34",
            all_ips=["93.184.216.34"],
            is_ip=False,
        ),
    )
    monkeypatch.setattr(
        app_module,
        "fetch_geo_intel",
        lambda ip: {
            "ip": ip,
            "city": "Example",
            "country": "Exampleland",
            "latitude": 12.0,
            "longitude": 18.0,
            "source": "unit-test",
        },
    )
    monkeypatch.setattr(app_module, "resolve_dns_intel", lambda *_args: {"records": {}, "ptr": [], "posture": {}})
    monkeypatch.setattr(app_module, "audit_web_posture", lambda *_args: {"reachable": True, "grade": "A", "score": 95})
    monkeypatch.setattr(
        app_module,
        "scan_common_ports",
        lambda *_args: {
            "status": "completed",
            "scanned_count": 20,
            "open_count": 0,
            "scan_ms": 20.0,
            "open_ports": [],
        },
    )


def test_active_scan_starts_automatically_for_configured_scope(monkeypatch) -> None:
    _mock_recon_modules(monkeypatch)
    monkeypatch.setenv("NETRECON_ACTIVE_SCAN_ALLOWLIST", "example.com")

    response = app.test_client().post("/api/recon", json={"target": "example.com"})
    data = response.get_json()

    assert response.status_code == 200
    assert data["active_scope"]["active_probe_started"] is True
    assert data["ports"]["status"] == "completed"
    assert "scanned_at" in data
    assert data["geo"]["location_kind"] == "approximate"


def test_passive_checks_complete_outside_active_scope(monkeypatch) -> None:
    _mock_recon_modules(monkeypatch)
    monkeypatch.setenv("NETRECON_ACTIVE_SCAN_ALLOWLIST", "owned.example")

    response = app.test_client().post("/api/recon", json={"target": "example.com"})
    data = response.get_json()

    assert response.status_code == 200
    assert data["active_scope"]["active_probe_started"] is False
    assert data["ports"]["status"] == "scope_required"
    assert data["geo"]["city"] == "Example"
    assert data["dns"]["records"] == {}


def test_ownership_challenge_route_is_removed() -> None:
    response = app.test_client().get("/api/ownership/challenge?target=example.com")
    assert response.status_code == 404


def test_recon_rejects_non_object_json(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "_is_rate_limited", lambda _client: False)
    response = app.test_client().post(
        "/api/recon",
        data='["not", "an", "object"]',
        content_type="application/json",
    )
    assert response.status_code == 400


def test_health_endpoint() -> None:
    response = app.test_client().get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "netrecon"


def test_rate_limit_returns_retry_after(monkeypatch) -> None:
    monkeypatch.setattr(app_module, "_is_rate_limited", lambda _client: True)
    response = app.test_client().post("/api/recon", json={"target": "example.com"})
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"
    assert response.get_json()["ok"] is False


def test_dashboard_renders_new_workbench() -> None:
    response = app.test_client().get("/")
    assert response.status_code == 200
    assert b"Hosting location" in response.data
    assert b"TCP probes start automatically" in response.data
    assert response.headers["Content-Security-Policy"]


def test_privacy_page_discloses_current_geo_and_map_providers() -> None:
    response = app.test_client().get("/privacy")
    assert response.status_code == 200
    assert b"ipwho.is and ipapi.co" in response.data
    assert b"CARTO and OpenStreetMap" in response.data
    assert b"Google Fonts" not in response.data


def test_not_found_page_uses_new_workbench_shell() -> None:
    response = app.test_client().get("/missing-route")
    assert response.status_code == 404
    assert b"REQUEST / 404" in response.data
    assert b"Return to workbench" in response.data
