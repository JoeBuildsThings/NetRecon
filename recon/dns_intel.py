import dns.resolver
import dns.reversename


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = 1.5
    resolver.lifetime = 2.5
    return resolver


def _query_records(resolver: dns.resolver.Resolver, qname: str, rdtype: str) -> list[str]:
    try:
        answers = resolver.resolve(qname, rdtype)
        records = [rdata.to_text().strip('"') for rdata in answers]
        return records[:12]
    except Exception:
        return []


def _fingerprint_providers(ns_records: list[str], mx_records: list[str], txt_records: list[str], dmarc_records: list[str]) -> dict:
    ns_joined = " ".join(ns_records).lower()
    mx_joined = " ".join(mx_records).lower()
    txt_joined = " ".join(txt_records).lower()

    dns_provider = "Custom / Other"
    if "cloudflare" in ns_joined:
        dns_provider = "Cloudflare DNS"
    elif "awsdns" in ns_joined:
        dns_provider = "AWS Route 53"
    elif "vercel-dns" in ns_joined:
        dns_provider = "Vercel DNS"
    elif "googledomains" in ns_joined or "google.com" in ns_joined:
        dns_provider = "Google Cloud DNS"
    elif "azure-dns" in ns_joined:
        dns_provider = "Azure DNS"
    elif "digitalocean" in ns_joined:
        dns_provider = "DigitalOcean DNS"
    elif "namecheap" in ns_joined or "registrar-servers" in ns_joined:
        dns_provider = "Namecheap DNS"

    mail_provider = "None / Self-hosted"
    if "google.com" in mx_joined or "googlemail.com" in mx_joined:
        mail_provider = "Google Workspace"
    elif "outlook.com" in mx_joined or "protection.outlook.com" in mx_joined:
        mail_provider = "Microsoft 365"
    elif "zoho." in mx_joined:
        mail_provider = "Zoho Mail"
    elif "protonmail" in mx_joined or "proton.ch" in mx_joined:
        mail_provider = "Proton Mail"
    elif "mxroute" in mx_joined:
        mail_provider = "MXroute"
    elif "improvmx" in mx_joined:
        mail_provider = "ImprovMX"
    elif mx_records:
        mail_provider = mx_records[0].split()[-1].rstrip(".")

    has_spf = "v=spf1" in txt_joined
    has_dmarc = any("v=dmarc1" in rec.lower() for rec in dmarc_records)

    return {
        "dns_provider": dns_provider if ns_records else "N/A (Direct IP)",
        "mail_provider": mail_provider if mx_records else "No MX Records",
        "spf_configured": has_spf,
        "dmarc_configured": has_dmarc,
    }


def resolve_dns_intel(host: str, primary_ip: str, is_ip: bool) -> dict:
    """Resolve DNS records, reverse PTR, and fingerprint cloud/mail posture."""
    resolver = _make_resolver()

    ptr_records: list[str] = []
    try:
        rev_name = dns.reversename.from_address(primary_ip)
        ptr_records = [r.rstrip(".") for r in _query_records(resolver, str(rev_name), "PTR")]
    except Exception:
        ptr_records = []

    if is_ip:
        return {
            "ptr": ptr_records,
            "records": {"A": [primary_ip] if ":" not in primary_ip else [], "AAAA": [primary_ip] if ":" in primary_ip else []},
            "posture": {
                "dns_provider": "N/A (Direct IP)",
                "mail_provider": "N/A (Direct IP)",
                "spf_configured": False,
                "dmarc_configured": False,
            },
        }

    records = {
        "A": _query_records(resolver, host, "A"),
        "AAAA": _query_records(resolver, host, "AAAA"),
        "CNAME": [r.rstrip(".") for r in _query_records(resolver, host, "CNAME")],
        "MX": [r.rstrip(".") for r in _query_records(resolver, host, "MX")],
        "NS": [r.rstrip(".") for r in _query_records(resolver, host, "NS")],
        "TXT": _query_records(resolver, host, "TXT"),
    }
    dmarc_records = _query_records(resolver, f"_dmarc.{host}", "TXT")
    if dmarc_records:
        records["DMARC"] = dmarc_records

    posture = _fingerprint_providers(records["NS"], records["MX"], records["TXT"], dmarc_records)

    return {
        "ptr": ptr_records,
        "records": records,
        "posture": posture,
    }
