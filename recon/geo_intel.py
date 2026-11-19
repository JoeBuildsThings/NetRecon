from collections import OrderedDict
import logging
import math
import threading
import time
import requests
from recon.logger import get_logger, log_event

logger = get_logger("netrecon.geo")

GEO_CACHE_TTL = 900.0
GEO_CACHE_MAX = 1024
_geo_cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
_geo_cache_lock = threading.Lock()


def _safe_coord(value: object, low: float, high: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    if isinstance(value, str) and not value.strip():
        return None
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(num) or num < low or num > high:
        return None
    return num


def _get_cached_geo(ip: str) -> dict | None:
    now = time.monotonic()
    with _geo_cache_lock:
        entry = _geo_cache.get(ip)
        if not entry:
            return None
        expires_at, payload = entry
        if now > expires_at:
            _geo_cache.pop(ip, None)
            return None
        _geo_cache.move_to_end(ip)
        return {**payload, "cached": True}


def _set_cached_geo(ip: str, payload: dict) -> None:
    expires_at = time.monotonic() + GEO_CACHE_TTL
    with _geo_cache_lock:
        if ip in _geo_cache:
            _geo_cache.move_to_end(ip)
        elif len(_geo_cache) >= GEO_CACHE_MAX:
            _geo_cache.popitem(last=False)
        _geo_cache[ip] = (expires_at, dict(payload))


def fetch_geo_intel(ip: str) -> dict:
    """Resolve IP geolocation, ASN, and ISP metadata over HTTPS with thread-safe LRU caching."""
    cached = _get_cached_geo(ip)
    if cached is not None:
        return cached

    headers = {"User-Agent": "NetRecon/2.2"}

    try:
        resp = requests.get("https://" + "ipwho.is/" + ip, headers=headers, timeout=2.5)
        if resp.ok:
            payload = resp.json()
            if payload.get("success") is True:
                conn = payload.get("connection") or {}
                tz = payload.get("timezone") or {}
                asn_num = conn.get("asn")
                lat = _safe_coord(payload.get("latitude"), -90.0, 90.0)
                lon = _safe_coord(payload.get("longitude"), -180.0, 180.0)
                result = {
                    "ip": payload.get("ip", ip),
                    "ip_version": payload.get("type", "IPv6" if ":" in ip else "IPv4"),
                    "city": payload.get("city") or "Unknown",
                    "region": payload.get("region") or "",
                    "country": payload.get("country") or "Unknown",
                    "country_code": payload.get("country_code") or "",
                    "latitude": lat,
                    "longitude": lon,
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
        log_event(
            logger,
            logging.WARNING,
            "geo_primary_failed",
            ip=ip,
            error_type=type(exc).__name__,
        )

    try:
        resp = requests.get("https://" + "ipapi.co/" + ip + "/json/", headers=headers, timeout=2.5)
        if resp.ok:
            payload = resp.json()
            if not payload.get("error"):
                lat = _safe_coord(payload.get("latitude"), -90.0, 90.0)
                lon = _safe_coord(payload.get("longitude"), -180.0, 180.0)
                result = {
                    "ip": payload.get("ip", ip),
                    "ip_version": payload.get("version", "IPv6" if ":" in ip else "IPv4"),
                    "city": payload.get("city") or "Unknown",
                    "region": payload.get("region") or "",
                    "country": payload.get("country_name") or "Unknown",
                    "country_code": payload.get("country_code") or "",
                    "latitude": lat,
                    "longitude": lon,
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
        log_event(
            logger,
            logging.WARNING,
            "geo_fallback_failed",
            ip=ip,
            error_type=type(exc).__name__,
        )

    return {
        "ip": ip,
        "ip_version": "IPv6" if ":" in ip else "IPv4",
        "city": "Unavailable",
        "region": "",
        "country": "Unknown",
        "country_code": "",
        "latitude": None,
        "longitude": None,
        "timezone": "UTC",
        "asn": "N/A",
        "org": "Lookup unavailable",
        "isp": "Lookup unavailable",
        "domain": "",
        "source": "fallback",
        "cached": False,
    }
