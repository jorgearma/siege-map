import asyncio
import time
import logging
from typing import Optional
import httpx
from .models import GeoInfo
from .config import settings

logger = logging.getLogger(__name__)

# In-memory cache: ip -> (GeoInfo, timestamp)
_cache: dict[str, tuple[GeoInfo, float]] = {}

# Rate limit: ip-api allows 45 requests per minute
_semaphore = asyncio.Semaphore(5)
_last_requests: list[float] = []
MAX_REQUESTS_PER_MINUTE = 40  # leave some margin


async def _rate_limit():
    """Simple sliding window rate limiter."""
    now = time.time()
    while len(_last_requests) >= MAX_REQUESTS_PER_MINUTE:
        oldest = _last_requests[0]
        if now - oldest > 60:
            _last_requests.pop(0)
        else:
            wait = 60 - (now - oldest) + 0.1
            await asyncio.sleep(wait)
            now = time.time()
    _last_requests.append(now)


async def _lookup_ip_api(ip: str, client: httpx.AsyncClient) -> Optional[GeoInfo]:
    """Lookup using ip-api.com (free, no key needed)."""
    await _rate_limit()
    try:
        resp = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,lat,lon,as,org"},
            timeout=5.0,
        )
        data = resp.json()
        if data.get("status") == "success":
            return GeoInfo(
                country=data.get("country", "Unknown"),
                country_code=data.get("countryCode", "XX"),
                city=data.get("city", "Unknown"),
                lat=data.get("lat", 0.0),
                lon=data.get("lon", 0.0),
                asn=data.get("as", ""),
                org=data.get("org", ""),
            )
    except Exception as e:
        logger.warning(f"ip-api lookup failed for {ip}: {e}")
    return None


async def _lookup_ipinfo(ip: str, client: httpx.AsyncClient) -> Optional[GeoInfo]:
    """Lookup using ipinfo.io (needs token for higher limits)."""
    token = settings.IPINFO_TOKEN
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = await client.get(
            f"https://ipinfo.io/{ip}/json",
            headers=headers,
            timeout=5.0,
        )
        data = resp.json()
        loc = data.get("loc", "0,0").split(",")
        lat = float(loc[0]) if len(loc) >= 2 else 0.0
        lon = float(loc[1]) if len(loc) >= 2 else 0.0
        return GeoInfo(
            country=data.get("country", "XX"),
            country_code=data.get("country", "XX"),
            city=data.get("city", "Unknown"),
            lat=lat,
            lon=lon,
            asn=data.get("org", ""),
            org=data.get("org", ""),
        )
    except Exception as e:
        logger.warning(f"ipinfo lookup failed for {ip}: {e}")
    return None


# Shared HTTP client
_client: Optional[httpx.AsyncClient] = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient()
    return _client


async def close_client():
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None


async def enrich_ip(ip: str) -> GeoInfo:
    """Get geolocation for an IP, using cache when possible."""
    now = time.time()

    if ip in _cache:
        geo, cached_at = _cache[ip]
        if now - cached_at < settings.GEO_CACHE_TTL:
            return geo

    async with _semaphore:
        # Double-check cache after acquiring semaphore
        if ip in _cache:
            geo, cached_at = _cache[ip]
            if now - cached_at < settings.GEO_CACHE_TTL:
                return geo

        client = _get_client()

        if settings.GEO_PROVIDER == "ipinfo":
            geo = await _lookup_ipinfo(ip, client)
        else:
            geo = await _lookup_ip_api(ip, client)

        if geo is None:
            geo = GeoInfo()

        _cache[ip] = (geo, now)

        # Evict old entries if cache grows too large
        if len(_cache) > 50000:
            cutoff = now - settings.GEO_CACHE_TTL
            to_remove = [k for k, (_, t) in _cache.items() if t < cutoff]
            for k in to_remove[:10000]:
                del _cache[k]

        return geo
