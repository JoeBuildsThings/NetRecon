from recon.web_audit import _compute_grade, _redirect_info, evaluate_headers

GOOD = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def test_all_good_scores_100():
    score, rows = evaluate_headers(GOOD)
    assert score == 100
    assert all(r["status"] == "pass" for r in rows)


def test_empty_scores_zero():
    score, rows = evaluate_headers({})
    assert score == 0
    assert all(r["status"] == "missing" for r in rows)


def test_wildcard_csp_is_weak_not_full_marks():
    headers = dict(GOOD, **{"content-security-policy": "default-src *"})
    score, rows = evaluate_headers(headers)
    csp = next(r for r in rows if r["label"] == "CSP")
    assert csp["status"] == "weak"
    assert score < 100


def test_unsafe_inline_csp_is_weak():
    headers = dict(GOOD, **{"content-security-policy": "script-src 'self' 'unsafe-inline'"})
    csp = next(r for r in evaluate_headers(headers)[1] if r["label"] == "CSP")
    assert csp["status"] == "weak"


def test_short_hsts_is_weak():
    headers = dict(GOOD, **{"strict-transport-security": "max-age=300"})
    hsts = next(r for r in evaluate_headers(headers)[1] if r["label"] == "HSTS")
    assert hsts["status"] == "weak"


def test_frame_ancestors_covers_xfo():
    headers = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"}
    xfo = next(r for r in evaluate_headers(headers)[1] if r["label"] == "X-Frame-Options")
    assert xfo["status"] == "pass"


def test_grades():
    assert _compute_grade(95, True) == "A+"
    assert _compute_grade(95, False) == "F"
    assert _compute_grade(95, True, cert_valid=False) == "D"


def test_redirect_info():
    assert _redirect_info(None)["http_to_https"] is None
    ok = {"status": 301, "headers": {"location": "https://example.com/"}}
    assert _redirect_info(ok)["http_to_https"] is True
    plain = {"status": 200, "headers": {}}
    assert _redirect_info(plain)["http_to_https"] is False
    sneaky = {"status": 302, "headers": {"location": "http://169.254.169.254/"}}
    assert _redirect_info(sneaky)["http_to_https"] is False
