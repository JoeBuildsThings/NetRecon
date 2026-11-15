import hashlib
import hmac
import logging
import os
import dns.resolver
from recon.logger import get_logger, log_event

logger = get_logger("netrecon.ownership")

DEFAULT_SECRET = "netrecon-ephemeral-dev-signing-key-change-in-prod"


def _signing_secret() -> bytes:
    secret = os.environ.get("NETRECON_SECRET_KEY", "").strip()
    return (secret or DEFAULT_SECRET).encode("utf-8")


def canonical_apex(host: str) -> str:
    cleaned = host.strip().rstrip(".").lower()
    if cleaned.startswith("www.") and cleaned.count(".") >= 2:
        return cleaned[4:]
    return cleaned


def build_challenge(host: str, is_ip: bool) -> dict:
    """Create a deterministic DNS TXT ownership challenge for a domain."""
    if is_ip:
        return {
            "eligible": False,
            "verified": False,
            "reason": "Direct IP targets cannot be verified via DNS TXT records.",
        }

    domain = canonical_apex(host)
    digest = hmac.new(_signing_secret(), f"netrecon-own:{domain}".encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    txt_host = f"_netrecon-verify.{domain}"
    txt_value = f"netrecon-verify={digest}"
    return {
        "eligible": True,
        "domain": domain,
        "txt_host": txt_host,
        "txt_value": txt_value,
    }


def verify_domain_ownership(host: str, is_ip: bool) -> dict:
    """Verify domain control via DNS TXT record before running active TCP port probes."""
    if os.environ.get("NETRECON_ALLOW_UNVERIFIED_PORTS", "0") == "1":
        return {
            "verified": True,
            "method": "local_override",
            "domain": host,
        }

    challenge = build_challenge(host, is_ip)
    if not challenge.get("eligible"):
        return {
            "verified": False,
            "method": "dns_txt",
            "reason": challenge["reason"],
        }

    txt_host = challenge["txt_host"]
    expected = challenge["txt_value"]

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = 1.5
    resolver.lifetime = 2.0

    found_records: list[str] = []
    try:
        answers = resolver.resolve(txt_host, "TXT")
        for rdata in answers:
            val = "".join(
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in getattr(rdata, "strings", [])
            ) or rdata.to_text().strip('"')
            found_records.append(val.strip())
    except Exception as exc:
        log_event(logger, logging.INFO, "ownership_txt_lookup_miss", txt_host=txt_host, error_type=type(exc).__name__)

    if expected in found_records:
        return {
            "verified": True,
            "method": "dns_txt",
            "domain": challenge["domain"],
            "txt_host": txt_host,
            "txt_value": expected,
        }

    return {
        "verified": False,
        "method": "dns_txt",
        "domain": challenge["domain"],
        "txt_host": txt_host,
        "txt_value": expected,
        "reason": f"Add TXT record at {txt_host} with value {expected} to unlock active port scanning.",
    }
