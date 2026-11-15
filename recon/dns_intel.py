from concurrent.futures import ThreadPoolExecutor
import logging
import dns.resolver
import dns.reversename
from recon.logger import get_logger, log_event

logger = get_logger("netrecon.dns")


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = 1.2
    resolver.lifetime = 2.0
    return resolver


def _query_records(qname: str, rdtype: str) -> list[str]:
    resolver = _make_resolver()
    try:
        answers = resolver.resolve(qname, rdtype)
        records: list[str] = []
        for rdata in answers:
            if rdtype == "TXT" and hasattr(rdata, "strings"):
                joined = "".join(
                    part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                    for part in rdata.strings
                )
                records.append(joined)
            else:
                records.append(rdata.to_text().strip('"'))
        return records[:12]
    except Exception as exc:
        log_event(logger, logging.DEBUG, "dns_query_empty", qname=qname, rdtype=rdtype, error_type=type(exc).__name__)
        return []


def _host_matches_suffix(hostname: str, suffixes: tuple[str, ...]) -> bool:
    clean = hostname.strip().rstrip(".").lower()
    if " " in clean:
        clean = clean.split()[-1].rstrip(".")
    return any(clean == suffix or clean.endswith(f".{suffix}") for suffix in suffixes)


def evaluate_dmarc_policy(dmarc_records: list[str]) -> tuple[bool, str, str]:
    """Return (enforced, policy, summary) distinguishing p=none monitoring from active enforcement."""
    for rec in dmarc_records:
        lower = rec.lower()
        if "v=dmarc1" not in lower:
            continue
        tags = {}
        for part in lower.split(";"):
            kv = part.strip().split("=", 1)
            if len(kv) == 2:
                tags[kv[0].strip()] = kv[1].strip()
        policy = tags.get("p", "none")
        if policy in {"reject", "quarantine"}:
            return True, policy, f"Enforced (p={policy})"
        return False, policy, f"Monitoring only (p={policy})"
    return False, "missing", "Missing DMARC record"


def evaluate_spf_policy(txt_records: list[str]) -> tuple[bool, str]:
    for rec in txt_records:
        lower = rec.lower().strip()
        if not lower.startswith("v=spf1"):
            continue
        tokens = lower.split()
        if "+all" in tokens or "all" in tokens:
            return False, "Insecure (+all allows any sender)"
        if "-all" in tokens:
            return True, "Strict fail (-all)"
        if "~all" in tokens:
            return True, "Soft fail (~all)"
        if "?all" in tokens:
            return False, "Neutral (?all)"
        return True, "Configured"
    return False, "Missing SPF record"


def fingerprint_providers(
    ns_records: list[str],
    mx_records: list[str],
    txt_records: list[str],
    dmarc_records: list[str],
) -> dict:
    dns_provider = "Custom / Other"
    if any(_host_matches_suffix(ns, ("cloudflare.com",)) for ns in ns_records):
        dns_provider = "Cloudflare DNS"
    elif any(_host_matches_suffix(ns, ("awsdns-00.com", "awsdns-01.org", "awsdns-02.net", "awsdns-03.co.uk")) or ".awsdns-" in ns.lower() for ns in ns_records):
        dns_provider = "AWS Route 53"
    elif any(_host_matches_suffix(ns, ("vercel-dns.com",)) for ns in ns_records):
        dns_provider = "Vercel DNS"
    elif any(_host_matches_suffix(ns, ("googledomains.com", "google.com")) for ns in ns_records):
        dns_provider = "Google Cloud DNS"
    elif any(_host_matches_suffix(ns, ("azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info")) for ns in ns_records):
        dns_provider = "Azure DNS"
    elif any(_host_matches_suffix(ns, ("digitalocean.com",)) for ns in ns_records):
        dns_provider = "DigitalOcean DNS"
    elif any(_host_matches_suffix(ns, ("registrar-servers.com", "namecheaphosting.com")) for ns in ns_records):
        dns_provider = "Namecheap DNS"

    mail_provider = "None / Self hosted"
    if any(_host_matches_suffix(mx, ("google.com", "googlemail.com")) for mx in mx_records):
        mail_provider = "Google Workspace"
    elif any(_host_matches_suffix(mx, ("outlook.com", "protection.outlook.com")) for mx in mx_records):
        mail_provider = "Microsoft 365"
    elif any(_host_matches_suffix(mx, ("zoho.com", "zoho.eu", "zoho.in")) for mx in mx_records):
        mail_provider = "Zoho Mail"
    elif any(_host_matches_suffix(mx, ("protonmail.ch", "proton.ch")) for mx in mx_records):
        mail_provider = "Proton Mail"
    elif any(_host_matches_suffix(mx, ("mxroute.com",)) for mx in mx_records):
        mail_provider = "MXroute"
    elif any(_host_matches_suffix(mx, ("improvmx.com",)) for mx in mx_records):
        mail_provider = "ImprovMX"
    elif mx_records:
        mail_provider = mx_records[0].split()[-1].rstrip(".")

    spf_ok, spf_status = evaluate_spf_policy(txt_records)
    dmarc_enforced, dmarc_policy, dmarc_status = evaluate_dmarc_policy(dmarc_records)

    return {
        "dns_provider": dns_provider if ns_records else "N/A (Direct IP)",
        "mail_provider": mail_provider if mx_records else "No MX Records",
        "spf_configured": spf_ok,
        "spf_status": spf_status,
        "dmarc_configured": dmarc_enforced,
        "dmarc_policy": dmarc_policy,
        "dmarc_status": dmarc_status,
    }


def resolve_dns_intel(host: str, primary_ip: str, is_ip: bool) -> dict:
    """Resolve DNS records, reverse PTR, and mail posture concurrently."""
    rev_name = ""
    try:
        rev_name = str(dns.reversename.from_address(primary_ip))
    except Exception:
        rev_name = ""

    if is_ip:
        ptr_records = [r.rstrip(".") for r in _query_records(rev_name, "PTR")] if rev_name else []
        return {
            "ptr": ptr_records,
            "records": {
                "A": [primary_ip] if ":" not in primary_ip else [],
                "AAAA": [primary_ip] if ":" in primary_ip else [],
            },
            "posture": {
                "dns_provider": "N/A (Direct IP)",
                "mail_provider": "N/A (Direct IP)",
                "spf_configured": False,
                "spf_status": "N/A",
                "dmarc_configured": False,
                "dmarc_policy": "n/a",
                "dmarc_status": "N/A",
            },
        }

    queries = {
        "PTR": (rev_name, "PTR"),
        "A": (host, "A"),
        "AAAA": (host, "AAAA"),
        "CNAME": (host, "CNAME"),
        "MX": (host, "MX"),
        "NS": (host, "NS"),
        "TXT": (host, "TXT"),
        "DMARC": (f"_dmarc.{host}", "TXT"),
    }

    raw_results: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            key: pool.submit(_query_records, qname, rdtype)
            for key, (qname, rdtype) in queries.items()
            if qname
        }
        for key, fut in futures.items():
            try:
                raw_results[key] = fut.result(timeout=2.5)
            except Exception:
                raw_results[key] = []

    ptr_records = [r.rstrip(".") for r in raw_results.get("PTR", [])]
    records = {
        "A": raw_results.get("A", []),
        "AAAA": raw_results.get("AAAA", []),
        "CNAME": [r.rstrip(".") for r in raw_results.get("CNAME", [])],
        "MX": [r.rstrip(".") for r in raw_results.get("MX", [])],
        "NS": [r.rstrip(".") for r in raw_results.get("NS", [])],
        "TXT": raw_results.get("TXT", []),
    }
    dmarc_records = raw_results.get("DMARC", [])
    if dmarc_records:
        records["DMARC"] = dmarc_records

    posture = fingerprint_providers(records["NS"], records["MX"], records["TXT"], dmarc_records)

    return {
        "ptr": ptr_records,
        "records": records,
        "posture": posture,
    }
