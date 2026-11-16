
import ipaddress
import os


def _configured_entries() -> list[str]:
    raw = os.environ.get("NETRECON_ACTIVE_SCAN_ALLOWLIST", "")
    return [entry.strip().lower().rstrip(".") for entry in raw.split(",") if entry.strip()]


def active_scan_scope(host: str, primary_ip: str) -> dict[str, object]:
    entries = _configured_entries()
    if not entries:
        return {"allowed": False, "status": "disabled"}

    clean_host = host.strip().lower().rstrip(".")
    try:
        target_ip = ipaddress.ip_address(primary_ip)
    except ValueError:
        target_ip = None

    for entry in entries:
        if entry.startswith("*."):
            suffix = entry[2:]
            if suffix and clean_host.endswith("." + suffix):
                return {"allowed": True, "status": "in_scope"}
            continue

        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if target_ip is not None and target_ip.version == network.version and target_ip in network:
                return {"allowed": True, "status": "in_scope"}
            continue

        try:
            configured_ip = ipaddress.ip_address(entry)
        except ValueError:
            if clean_host == entry:
                return {"allowed": True, "status": "in_scope"}
        else:
            if target_ip == configured_ip:
                return {"allowed": True, "status": "in_scope"}

    return {"allowed": False, "status": "out_of_scope"}
