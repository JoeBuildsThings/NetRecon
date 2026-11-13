from dataclasses import dataclass
import ipaddress
import re
import socket
from urllib.parse import urlparse


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


class TargetValidationError(ValueError):
    """Raised when a user-supplied target is malformed or points to a restricted network."""


@dataclass
class ValidatedTarget:
    raw_input: str
    host: str
    primary_ip: str
    all_ips: list[str]
    is_ip: bool


def _is_disallowed_ip(ip_str: str) -> bool:
    ip_obj = ipaddress.ip_address(ip_str)
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return True
    if ip_obj.version == 4 and ip_obj in CGNAT_NET:
        return True
    return False


def normalize_and_validate(raw_target: str) -> ValidatedTarget:
    if not raw_target or not isinstance(raw_target, str):
        raise TargetValidationError("Enter a public IPv4/IPv6 address or domain name.")

    cleaned = raw_target.strip()
    if len(cleaned) > 255:
        raise TargetValidationError("Target input exceeds maximum allowed length.")

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        host = parsed.hostname or ""
    else:
        without_path = cleaned.split("/")[0].split("?")[0].split("#")[0]
        if "@" in without_path:
            without_path = without_path.split("@")[-1]
        if without_path.startswith("["):
            host = without_path.split("]")[0].lstrip("[")
        elif without_path.count(":") == 1:
            host = without_path.split(":")[0]
        else:
            host = without_path

    host = host.strip().rstrip(".").lower()
    if not host:
        raise TargetValidationError("Could not extract a valid hostname or IP address.")

    if host in {"localhost", "ip6-localhost", "ip6-loopback"} or host.endswith(".local"):
        raise TargetValidationError("Local and internal hostnames are blocked.")

    try:
        ip_obj = ipaddress.ip_address(host)
        if _is_disallowed_ip(str(ip_obj)):
            raise TargetValidationError("Private, loopback, and reserved IP ranges are blocked.")
        return ValidatedTarget(
            raw_input=raw_target.strip(),
            host=str(ip_obj),
            primary_ip=str(ip_obj),
            all_ips=[str(ip_obj)],
            is_ip=True,
        )
    except ValueError:
        pass

    if not HOSTNAME_RE.match(host):
        raise TargetValidationError("Invalid domain or IP format. Example: example.com or 1.1.1.1")

    try:
        addr_info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise TargetValidationError(f"DNS resolution failed for '{host}'. Verify the domain exists.")

    resolved_ips: list[str] = []
    for entry in addr_info:
        candidate = entry[4][0]
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
