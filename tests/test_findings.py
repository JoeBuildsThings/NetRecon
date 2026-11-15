from recon.findings import build_findings, summarize

GEO = {"org": "Example Hosting", "isp": ""}
WEB_OK = {
    "reachable": True, "https_active": True, "redirect": {"http_to_https": True},
    "tls": {"available": True, "valid": True, "days_remaining": 90}, "headers": [], "disclosures": [],
}
DNS_OK = {"records": {"MX": ["10 mail.example.com"]}, "posture": {"spf_policy": "fail", "dmarc_policy": "reject"}}
PORTS_OFF = {"skipped": True, "open_ports": []}


def titles(findings):
    return [f["title"] for f in findings]


def test_clean_target_only_notes_probe_off():
    out = build_findings(GEO, PORTS_OFF, DNS_OK, WEB_OK, False, False)
    assert titles(out) == ["Active port probe was off"]


def test_exposed_database_is_critical_and_sorted_first():
    ports = {"skipped": False, "open_ports": [{"port": 3306, "latency_ms": 12}, {"port": 22, "latency_ms": 9}]}
    out = build_findings(GEO, ports, DNS_OK, WEB_OK, False, True)
    assert out[0]["severity"] == "critical"
    assert summarize(out)["critical"] == 1


def test_invalid_cert_is_high():
    web = dict(WEB_OK, tls={"available": True, "valid": False, "error": "certificate has expired"})
    out = build_findings(GEO, PORTS_OFF, DNS_OK, web, False, False)
    assert any(f["id"] == "tls.invalid" and f["severity"] == "high" for f in out)


def test_spf_plus_all_is_high_and_dmarc_none_is_low():
    dns = {"records": {}, "posture": {"spf_policy": "pass", "dmarc_policy": "none"}}
    out = build_findings(GEO, PORTS_OFF, dns, WEB_OK, False, False)
    ids = {f["id"]: f["severity"] for f in out}
    assert ids["dns.spf.open"] == "high"
    assert ids["dns.dmarc.monitor"] == "low"


def test_ip_targets_skip_dns_findings():
    dns = {"records": {}, "posture": {"spf_policy": None, "dmarc_policy": None}}
    out = build_findings(GEO, PORTS_OFF, dns, WEB_OK, True, False)
    assert not any(f["area"] == "DNS" for f in out)


def test_cdn_note_added():
    ports = {"skipped": False, "open_ports": [{"port": 8080, "latency_ms": 5}]}
    out = build_findings({"org": "Cloudflare, Inc."}, ports, DNS_OK, WEB_OK, False, True)
    assert any(f["id"] == "ports.cdn" for f in out)


def test_partial_modules_reported():
    out = build_findings(GEO, PORTS_OFF, DNS_OK, WEB_OK, False, False, ["web"])
    assert any(f["id"] == "scan.partial" for f in out)
