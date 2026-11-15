from dataclasses import dataclass
import ipaddress
import re
import socket
from urllib.parse import urlparse


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
NAT64_NET = ipaddress.ip_network("64:ff9b::/96")


class TargetValidationError(ValueError):
    """Raised when a user supplied target is malformed or points to a restricted network."""


@dataclass
class ValidatedTarget:
    raw_input: str
    host: str
    primary_ip: str
    all_ips: list
    is_ip: bool


def _embedded_ipv4(ip_obj):
    """Return the IPv4 address hidden inside a transition format IPv6 address, if any."""
    if ip_obj.version != 6:
        return None
    if ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    if ip_obj.sixtofour is not None:
        return ip_obj.sixtofour
    if ip_obj in NAT64_NET:
        return ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)
    return None


def _is_disallowed_ip(ip_str):
    """Allowlist check: only globally routable unicast addresses pass."""
    ip_obj = ipaddress.ip_address(ip_str)
    candidates = [ip_obj]
    embedded = _embedded_ipv4(ip_obj)
    if embedded is not None:
        candidates.append(embedded)

    for candidate in candidates:
        if not candidate.is_global:
            return True
        if candidate.is_multicast or candidate.is_unspecified:
            return True
        if candidate.version == 4 and candidate in CGNAT_NET:
            return True
    return False


def _extract_host(cleaned):
    if "://" in cleaned:
        try:
            parsed = urlparse(cleaned)
            return parsed.hostname or ""
        except ValueError:
            raise TargetValidationError("Could not extract a valid hostname or IP address.") from None

    without_path = cleaned.split("/")[0].split("?")[0].split("#")[0]
    if "@" in without_path:
        without_path = without_path.split("@")[-1]
    if without_path.startswith("["):
        return without_path.split("]")[0].lstrip("[")
    if without_path.count(":") == 1:
        return without_path.split(":")[0]
    return without_path


def normalize_and_validate(raw_target):
    if not raw_target or not isinstance(raw_target, str):
        raise TargetValidationError("Enter a public IPv4/IPv6 address or domain name.")

    cleaned = raw_target.strip()
    if len(cleaned) > 255:
        raise TargetValidationError("Target input exceeds maximum allowed length.")

    host = _extract_host(cleaned).strip().rstrip(".").lower()
    if not host:
        raise TargetValidationError("Could not extract a valid hostname or IP address.")

    if host in {"localhost", "ip6-localhost", "ip6-loopback"} or host.endswith(".local"):
        raise TargetValidationError("Local and internal hostnames are blocked.")

    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if _is_disallowed_ip(str(ip_obj)):
            raise TargetValidationError("Private, loopback, and reserved IP ranges are blocked.")
        return ValidatedTarget(
            raw_input=raw_target.strip(),
            host=str(ip_obj),
            primary_ip=str(ip_obj),
            all_ips=[str(ip_obj)],
            is_ip=True,
        )

    if not HOSTNAME_RE.match(host):
        raise TargetValidationError("Invalid domain or IP format. Example: example.com or 1.1.1.1")

    try:
        addr_info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise TargetValidationError(f"DNS resolution failed for '{host}'. Verify the domain exists.") from None

    resolved_ips = []
    for entry in addr_info:
        candidate = entry[4][0].split("%")[0]
        if _is_disallowed_ip(candidate):
            raise TargetValidationError("Target resolves to a private or restricted IP address.")
        if candidate not in resolved_ips:
            resolved_ips.append(candidate)

    if not resolved_ips:
        raise TargetValidationError(f"No routable public IP addresses found for '{host}'.")

    ipv4s = [ip for ip in resolved_ips if ":" not in ip]
    primary_ip = ipv4s[0] if ipv4s else resolved_ips[0]

    return ValidatedTarget(
        raw_input=raw_target.strip(),
        host=host,
        primary_ip=primary_ip,
        all_ips=resolved_ips,
        is_ip=False,
    )
