"""Turn raw probe output into a ranked, human readable list of findings."""
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
CDN_MARKERS = ("cloudflare", "fastly", "akamai", "cloudfront", "vercel")

PORT_RULES = {
    21: ("medium", "FTP is reachable", "Cleartext file transfer exposes credentials.", "Use SFTP or FTPS and restrict by firewall."),
    22: ("low", "SSH is reachable", "Remote shell access is exposed to the internet.", "Use key auth only and restrict source IPs."),
    23: ("high", "Telnet is reachable", "Unencrypted legacy shell.", "Disable Telnet and use SSH."),
    110: ("medium", "POP3 is reachable", "Cleartext mail retrieval.", "Use POP3S on 995."),
    143: ("medium", "IMAP is reachable", "Cleartext mail access.", "Use IMAPS on 993."),
    445: ("high", "SMB is reachable", "Windows file sharing is exposed.", "Block 445 at the perimeter."),
    1433: ("critical", "MSSQL is reachable", "Database port is public.", "Bind to a private interface and firewall it."),
    3306: ("critical", "MySQL is reachable", "Database port is public.", "Bind to a private interface and firewall it."),
    3389: ("high", "RDP is reachable", "Remote desktop is exposed.", "Put RDP behind a VPN or gateway."),
    5432: ("critical", "PostgreSQL is reachable", "Database port is public.", "Bind to a private interface and firewall it."),
    6379: ("critical", "Redis is reachable", "In memory datastore is public.", "Bind to localhost and require auth."),
    27017: ("critical", "MongoDB is reachable", "NoSQL database is public.", "Bind to a private interface and enable auth."),
}

HEADER_SEVERITY = {
    "HSTS": ("medium", "low"),
    "CSP": ("medium", "low"),
    "X-Frame-Options": ("low", "low"),
    "X-Content-Type-Options": ("low", "low"),
    "Referrer-Policy": ("low", "low"),
    "Permissions-Policy": ("info", "info"),
}


def _finding(fid, severity, area, title, detail, fix):
    return {"id": fid, "severity": severity, "area": area, "title": title, "detail": detail, "fix": fix}


def _is_cdn(geo):
    text = f"{geo.get('org', '')} {geo.get('isp', '')}".lower()
    return any(marker in text for marker in CDN_MARKERS)


def _port_findings(ports, geo, active):
    out = []
    if not active:
        out.append(_finding("ports.skipped", "info", "Ports", "Active port probe was off",
                            "Only passive checks ran.", "Enable the probe on targets you are authorized to test."))
        return out
    for row in ports.get("open_ports", []):
        rule = PORT_RULES.get(row["port"])
        if rule:
            severity, title, detail, fix = rule
            out.append(_finding(f"port.{row['port']}", severity, "Ports", title,
                                f"{detail} Port {row['port']}/tcp answered in {row['latency_ms']} ms.", fix))
    if ports.get("open_ports") and _is_cdn(geo):
        out.append(_finding("ports.cdn", "info", "Ports", "Scan reached a CDN edge",
                            "Open ports describe the edge network, not the origin server.",
                            "Probe the origin directly if you own it."))
    return out


def _web_findings(web):
    out = []
    if not web.get("reachable"):
        out.append(_finding("web.unreachable", "info", "Web", "No web listener answered",
                            "Neither 443 nor 80 returned an HTTP response.", "Confirm the host serves web traffic."))
        return out

    tls = web.get("tls", {})
    if not web.get("https_active"):
        out.append(_finding("web.nohttps", "high", "Web", "HTTPS is not available",
                            "Only plain HTTP answered.", "Serve the site over TLS and redirect HTTP."))
    elif web.get("redirect", {}).get("http_to_https") is False:
        out.append(_finding("web.noredirect", "medium", "Web", "HTTP does not redirect to HTTPS",
                            "Port 80 answers without upgrading the connection.", "Redirect all HTTP traffic to HTTPS."))

    if tls.get("valid") is False:
        out.append(_finding("tls.invalid", "high", "TLS", "Certificate failed validation",
                            tls.get("error") or "The certificate was rejected.", "Install a valid certificate for this hostname."))
    elif tls.get("available"):
        days = tls.get("days_remaining")
        if days is not None and days <= 14:
            out.append(_finding("tls.expiring", "high", "TLS", "Certificate expires soon",
                                f"{days} days remaining.", "Renew now and automate renewal."))
        elif days is not None and days <= 30:
            out.append(_finding("tls.expiring", "medium", "TLS", "Certificate renewal due",
                                f"{days} days remaining.", "Renew and automate renewal."))

    for item in web.get("headers", []):
        if item.get("status") == "pass":
            continue
        missing_sev, weak_sev = HEADER_SEVERITY.get(item["label"], ("low", "low"))
        missing = item["status"] == "missing"
        out.append(_finding(
            f"header.{item['label']}.{item['status']}",
            missing_sev if missing else weak_sev,
            "Headers",
            f"{item['label']} is {'missing' if missing else 'weak'}",
            item.get("note") or item["advice"],
            item["advice"],
        ))

    for leak in web.get("disclosures", []):
        out.append(_finding(
            f"leak.{leak['header']}",
            "low" if leak.get("versioned") else "info",
            "Headers",
            f"{leak['header']} header discloses software",
            leak["value"],
            "Remove or genericize the header.",
        ))
    return out


def _dns_findings(dns, is_ip):
    if is_ip:
        return []
    out = []
    posture = dns.get("posture", {})
    has_mx = bool(dns.get("records", {}).get("MX"))

    spf = posture.get("spf_policy")
    if spf is None:
        out.append(_finding("dns.spf.missing", "medium" if has_mx else "low", "DNS", "SPF record is missing",
                            "Receivers cannot verify which servers may send mail for this domain.",
                            "Publish a v=spf1 record that ends in a hard or soft fail."))
    elif spf == "pass":
        out.append(_finding("dns.spf.open", "high", "DNS", "SPF allows any sender",
                            "The record ends in +all.", "Change the ending to a fail or soft fail."))
    elif spf in ("neutral", "none"):
        out.append(_finding("dns.spf.weak", "low", "DNS", "SPF does not restrict senders",
                            "The record has no enforcing ending.", "End the record with a fail or soft fail."))

    dmarc = posture.get("dmarc_policy")
    if dmarc is None:
        out.append(_finding("dns.dmarc.missing", "medium", "DNS", "DMARC record is missing",
                            "Spoofed mail from this domain will not be rejected.", "Publish a DMARC record and move toward reject."))
    elif dmarc == "none":
        out.append(_finding("dns.dmarc.monitor", "low", "DNS", "DMARC only monitors",
                            "Policy is none, so spoofed mail is still delivered.", "Move the policy to quarantine, then reject."))
    return out


def build_findings(geo, ports, dns, web, is_ip, active, partial=None):
    findings = []
    if partial:
        findings.append(_finding("scan.partial", "info", "Scan", "Some probes timed out",
                                 "No data from: " + ", ".join(partial) + ".", "Run the scan again."))
    findings += _port_findings(ports, geo, active)
    findings += _web_findings(web)
    findings += _dns_findings(dns, is_ip)
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return findings


def summarize(findings):
    counts = {name: 0 for name in SEVERITY_ORDER}
    for item in findings:
        counts[item["severity"]] += 1
    counts["total"] = len(findings)
    return counts
