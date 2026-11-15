import logging
import threading
import time

import requests

log = logging.getLogger("netrecon.geo")
_CACHE = {}
_CACHE_TTL = 600.0
_CACHE_MAX = 512
_CACHE_LOCK = threading.Lock()


def unavailable_geo(ip):
    return {
        "ip": ip,
        "ip_version": "IPv6" if ":" in ip else "IPv4",
        "city": "Unavailable",
        "region": "",
        "country": "Unknown",
        "country_code": "",
        "latitude": 0.0,
        "longitude": 0.0,
        "timezone": "UTC",
        "asn": "N/A",
        "org": "Lookup unavailable",
        "isp": "Lookup unavailable",
        "domain": "",
        "source": "fallback",
    }


def fetch_geo_intel(ip):
    """Cached geolocation lookup. Caching protects free tier quotas on the upstream providers."""
    now = time.monotonic()
    with _CACHE_LOCK:
        hit = _CACHE.get(ip)
        if hit and now - hit[0] < _CACHE_TTL:
            return dict(hit[1])

    result = _lookup(ip)
    if result.get("source") != "fallback":
        with _CACHE_LOCK:
            if len(_CACHE) >= _CACHE_MAX:
                _CACHE.clear()
            _CACHE[ip] = (now, result)
    return result


def _lookup(ip):
    """Resolve IP geolocation, ASN, and ISP metadata over HTTPS with provider fallback."""
    headers = {"User-Agent": "NetRecon/2.1 (+https://netrecon.vercel.app)"}

    try:
        resp = requests.get(f"https://ipwho.is/{ip}", headers=headers, timeout=3.0)
        if resp.ok:
            payload = resp.json()
            if payload.get("success") is True:
                conn = payload.get("connection") or {}
                tz = payload.get("timezone") or {}
                asn_num = conn.get("asn")
                return {
                    "ip": payload.get("ip", ip),
                    "ip_version": payload.get("type", "IPv6" if ":" in ip else "IPv4"),
                    "city": payload.get("city") or "Unknown",
                    "region": payload.get("region") or "",
                    "country": payload.get("country") or "Unknown",
                    "country_code": payload.get("country_code") or "",
                    "latitude": float(payload.get("latitude") or 0.0),
                    "longitude": float(payload.get("longitude") or 0.0),
                    "timezone": tz.get("id") or "UTC",
                    "asn": f"AS{asn_num}" if asn_num else "N/A",
                    "org": conn.get("org") or conn.get("isp") or "Unknown",
                    "isp": conn.get("isp") or conn.get("org") or "Unknown",
                    "domain": conn.get("domain") or "",
                    "source": "ipwho.is",
                }
    except Exception as exc:
        log.warning("geo provider failed: %s", type(exc).__name__)

    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", headers=headers, timeout=3.0)
        if resp.ok:
            payload = resp.json()
            if not payload.get("error"):
                return {
                    "ip": payload.get("ip", ip),
                    "ip_version": payload.get("version", "IPv6" if ":" in ip else "IPv4"),
                    "city": payload.get("city") or "Unknown",
                    "region": payload.get("region") or "",
                    "country": payload.get("country_name") or "Unknown",
                    "country_code": payload.get("country_code") or "",
                    "latitude": float(payload.get("latitude") or 0.0),
                    "longitude": float(payload.get("longitude") or 0.0),
                    "timezone": payload.get("timezone") or "UTC",
                    "asn": payload.get("asn") or "N/A",
                    "org": payload.get("org") or "Unknown",
                    "isp": payload.get("org") or "Unknown",
                    "domain": "",
                    "source": "ipapi.co",
                }
    except Exception as exc:
        log.warning("geo provider failed: %s", type(exc).__name__)

    return unavailable_geo(ip)
