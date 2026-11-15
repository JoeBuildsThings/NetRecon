from concurrent.futures import ThreadPoolExecutor
import re

import dns.resolver
import dns.reversename


def _make_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = 1.5
    resolver.lifetime = 2.5
    return resolver


def _clean_txt(text):
    return text.replace('" "', "").strip('"')


def _query_records(qname, rdtype):
    try:
        answers = _make_resolver().resolve(qname, rdtype)
        records = [_clean_txt(rdata.to_text().strip()) for rdata in answers]
        return records[:12]
    except Exception:
        return []


def _hosts(records):
    """Hostnames from NS or MX answers, lowercase, no priority, no trailing dot."""
    return [r.split()[-1].lower().rstrip(".") for r in records if r.split()]


def _matches(hosts, suffixes):
    return any(h == s or h.endswith("." + s) for h in hosts for s in suffixes)


NS_PROVIDERS = [
    ("Cloudflare DNS", ("cloudflare.com",)),
    ("Vercel DNS", ("vercel-dns.com",)),
    ("Google Cloud DNS", ("googledomains.com", "google.com")),
    ("Azure DNS", ("azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info")),
    ("DigitalOcean DNS", ("digitalocean.com",)),
    ("Namecheap DNS", ("registrar-servers.com", "namecheap.com")),
]

MX_PROVIDERS = [
    ("Google Workspace", ("google.com", "googlemail.com")),
    ("Microsoft 365", ("outlook.com", "protection.outlook.com")),
    ("Zoho Mail", ("zoho.com", "zoho.eu", "zoho.in")),
    ("Proton Mail", ("protonmail.ch", "proton.ch")),
    ("MXroute", ("mxroute.com",)),
    ("ImprovMX", ("improvmx.com",)),
]


def _spf_policy(txt_records):
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            match = re.search(r"(?:^|\s)([+~?-]?)all(?:\s|$)", record.lower())
            if not match:
                return "none"
            return {"-": "fail", "~": "softfail", "?": "neutral"}.get(match.group(1), "pass")
    return None


def _dmarc_policy(dmarc_records):
    for record in dmarc_records:
        if "v=dmarc1" in record.lower():
            match = re.search(r"(?:^|;)\s*p=(none|quarantine|reject)", record.lower())
            return match.group(1) if match else "none"
    return None


def _fingerprint_providers(ns_records, mx_records, txt_records, dmarc_records):
    ns_hosts = _hosts(ns_records)
    mx_hosts = _hosts(mx_records)

    dns_provider = "Custom / Other"
    if any(h.split(".")[-2].startswith("awsdns") for h in ns_hosts if h.count(".") >= 1):
        dns_provider = "AWS Route 53"
    else:
        for name, suffixes in NS_PROVIDERS:
            if _matches(ns_hosts, suffixes):
                dns_provider = name
                break

    mail_provider = "None / Self hosted"
    for name, suffixes in MX_PROVIDERS:
        if _matches(mx_hosts, suffixes):
            mail_provider = name
            break
    else:
        if mx_hosts:
            mail_provider = mx_hosts[0]

    spf_policy = _spf_policy(txt_records)
    dmarc_policy = _dmarc_policy(dmarc_records)

    return {
        "dns_provider": dns_provider if ns_records else "N/A (Direct IP)",
        "mail_provider": mail_provider if mx_records else "No MX Records",
        "spf_configured": spf_policy is not None,
        "dmarc_configured": dmarc_policy is not None,
        "spf_policy": spf_policy,
        "dmarc_policy": dmarc_policy,
    }


def empty_result():
    return {
        "ptr": [],
        "records": {},
        "posture": {
            "dns_provider": "N/A",
            "mail_provider": "N/A",
            "spf_configured": False,
            "dmarc_configured": False,
            "spf_policy": None,
            "dmarc_policy": None,
        },
    }


def resolve_dns_intel(host, primary_ip, is_ip):
    """Resolve DNS records, reverse PTR, and fingerprint cloud and mail posture."""
    try:
        ptr_name = str(dns.reversename.from_address(primary_ip))
    except Exception:
        ptr_name = None

    jobs = {}
    if ptr_name:
        jobs["PTR"] = (ptr_name, "PTR")
    if not is_ip:
        jobs.update({
            "A": (host, "A"),
            "AAAA": (host, "AAAA"),
            "CNAME": (host, "CNAME"),
            "MX": (host, "MX"),
            "NS": (host, "NS"),
            "TXT": (host, "TXT"),
            "DMARC": (f"_dmarc.{host}", "TXT"),
        })

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {key: pool.submit(_query_records, q, t) for key, (q, t) in jobs.items()}
        answers = {key: fut.result() for key, fut in futures.items()}

    ptr_records = [r.rstrip(".") for r in answers.get("PTR", [])]

    if is_ip:
        result = empty_result()
        result["ptr"] = ptr_records
        result["records"] = {
            "A": [primary_ip] if ":" not in primary_ip else [],
            "AAAA": [primary_ip] if ":" in primary_ip else [],
        }
        result["posture"]["dns_provider"] = "N/A (Direct IP)"
        result["posture"]["mail_provider"] = "N/A (Direct IP)"
        return result

    records = {
        "A": answers["A"],
        "AAAA": answers["AAAA"],
        "CNAME": [r.rstrip(".") for r in answers["CNAME"]],
        "MX": [r.rstrip(".") for r in answers["MX"]],
        "NS": [r.rstrip(".") for r in answers["NS"]],
        "TXT": answers["TXT"],
    }
    if answers["DMARC"]:
        records["DMARC"] = answers["DMARC"]

    posture = _fingerprint_providers(records["NS"], records["MX"], records["TXT"], answers["DMARC"])
    return {"ptr": ptr_records, "records": records, "posture": posture}
