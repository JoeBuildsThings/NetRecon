
from dataclasses import dataclass
import ipaddress
import re
import socket
from urllib.parse import urlparse


HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{0,61}[a-z][a-z0-9-]{0,61}(?<!-))+$"
)

CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


class TargetValidationError(ValueError):
    pass


@dataclass
class ValidatedTarget:
    raw_input: str
    host: str
    primary_ip: str
    all_ips: list[str]
    is_ip: bool


def is_disallowed_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    if ip_obj.version == 6 and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.version == 4 and ip_obj in CGNAT_NET:
        return True

    return (not ip_obj.is_global) or ip_obj.is_multicast


_is_disallowed_ip = is_disallowed_ip


def extract_host(raw_target: str) -> str:
    if not raw_target or not isinstance(raw_target, str):
        raise TargetValidationError("Enter a public IPv4, IPv6, or domain target.")

    cleaned = raw_target.strip()
    if len(cleaned) > 255:
        raise TargetValidationError("Target input exceeds maximum allowed length.")
    if any(ord(char) < 32 or ord(char) == 127 for char in cleaned) or "\\" in cleaned:
        raise TargetValidationError("Target contains unsupported characters.")
    if "@" in cleaned:
        raise TargetValidationError("Credentials are not accepted in target input.")

    try:
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            if parsed.scheme.lower() not in {"http", "https"}:
                raise TargetValidationError("Only HTTP and HTTPS schemes are supported.")
            if parsed.username is not None or parsed.password is not None:
                raise TargetValidationError("Credentials are not accepted in target input.")
            try:
                _ = parsed.port
            except ValueError as exc:
                raise TargetValidationError("Target URL contains an invalid port.") from exc
            host = parsed.hostname or ""
        else:
            without_path = cleaned.split("/")[0].split("?")[0].split("#")[0]
            if without_path.startswith("["):
                if "]" not in without_path:
                    raise TargetValidationError("Malformed bracketed IPv6 literal.")
                host = without_path.split("]")[0].lstrip("[")
            elif without_path.count(":") == 1:
                host = without_path.split(":")[0]
            else:
                host = without_path
    except ValueError as exc:
        raise TargetValidationError("Malformed target URL or address.") from exc

    host = host.strip().rstrip(".").lower()
    if not host:
        raise TargetValidationError("Could not extract a valid hostname or IP address.")

    if ":" not in host:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetValidationError("Target domain name is not valid.") from exc

    return host


def normalize_and_validate(raw_target: str) -> ValidatedTarget:
    host = extract_host(raw_target)

    if (
        host in {"localhost", "ip6-localhost", "ip6-loopback"}
        or host.endswith(".local")
        or host.endswith(".internal")
    ):
        raise TargetValidationError("Local and internal hostnames are blocked.")

    try:
        ip_obj = ipaddress.ip_address(host)
        if is_disallowed_ip(str(ip_obj)):
            raise TargetValidationError(
                "Private, loopback, link local, CGNAT, and reserved IP ranges are blocked."
            )
        canonical = str(ip_obj.ipv4_mapped) if ip_obj.version == 6 and ip_obj.ipv4_mapped else str(ip_obj)
        return ValidatedTarget(
            raw_input=raw_target.strip(),
            host=canonical,
            primary_ip=canonical,
            all_ips=[canonical],
            is_ip=True,
        )
    except ValueError as exc:
        if isinstance(exc, TargetValidationError):
            raise

    if not HOSTNAME_RE.fullmatch(host):
        raise TargetValidationError("Invalid domain or IP format. Example: example.com or 1.1.1.1")

    try:
        addr_info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetValidationError(
            f"DNS resolution failed for '{host}'. Verify the domain exists."
        ) from exc

    resolved_ips: list[str] = []
    for entry in addr_info:
        candidate = entry[4][0]
        if is_disallowed_ip(candidate):
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
