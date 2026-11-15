import logging
import time
import requests
from recon.logger import get_logger, log_event

logger = get_logger("netrecon.geo")

GEO_CACHE_TTL = 900.0
GEO_CACHE_MAX = 1024
_geo_cache: dict[str, tuple[float, dict]] = {}


def _get_cached_geo(ip: str) -> dict | None:
    entry = _geo_cache.get(ip)
    if not entry:
        return None
    expires_at, payload = entry
    if time.monotonic() > expires_at:
        _geo_cache.pop(ip, None)
        return None
    return {**payload, "cached": True}


def _set_cached_geo(ip: str, payload: dict) -> None:
    if len(_geo_cache) >= GEO_CACHE_MAX:
        oldest_key = next(iter(_geo_cache))
        _geo_cache.pop(oldest_key, None)
    _geo_cache[ip] = (time.monotonic() + GEO_CACHE_TTL, payload)


def fetch_geo_intel(ip: str) -> dict:
    """Resolve IP geolocation, ASN, and ISP metadata over HTTPS with TTL caching and provider fallback."""
    cached = _get_cached_geo(ip)
    if cached is not None:
        return cached

    headers = {"User-Agent": "NetRecon/2.1 (+https://netrecon.vercel.app)"}

    try:
        resp = requests.get(f"https://ipwho.is/{ip}", headers=headers, timeout=2.5)
        if resp.ok:
            payload = resp.json()
            if payload.get("success") is True:
                conn = payload.get("connection") or {}
                tz = payload.get("timezone") or {}
                asn_num = conn.get("asn")
                result = {
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
                    "cached": False,
                }
                _set_cached_geo(ip, result)
                return result
    except Exception as exc:
        log_event(logger, logging.WARNING, "geo_primary_failed", ip=ip, error_type=type(exc).__name__)

    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", headers=headers, timeout=2.5)
        if resp.ok:
            payload = resp.json()
            if not payload.get("error"):
                result = {
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
                    "cached": False,
                }
                _set_cached_geo(ip, result)
                return result
    except Exception as exc:
        log_event(logger, logging.WARNING, "geo_fallback_failed", ip=ip, error_type=type(exc).__name__)

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
        "cached": False,
    }
