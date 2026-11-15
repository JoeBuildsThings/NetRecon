import pytest
from app import app
from recon.dns_intel import evaluate_dmarc_policy
from recon.ownership import build_challenge
from recon.validator import TargetValidationError, is_disallowed_ip, normalize_and_validate
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


@pytest.mark.parametrize("bad_host", ["localhost", "metadata.local", "internal.internal", "file:///etc/passwd"])
def test_blocks_internal_hostnames_and_non_http_schemes(bad_host: str) -> None:
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


def test_ownership_challenge_shape() -> None:
    challenge = build_challenge("example.com", False)
    assert "txt_host" in challenge or "txt_value" in challenge or "verified" in challenge


def test_health_endpoint() -> None:
    client = app.test_client()
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "netrecon"
