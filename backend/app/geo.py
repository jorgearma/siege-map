import asyncio
import time
import logging
from typing import Optional
import httpx
from .models import GeoInfo
from .config import settings

logger = logging.getLogger(__name__)

# ── Network classification from the ASN / organisation name ──────────
# Used when the provider does not say it (mmdb, ipinfo) and to put a brand
# on hosting ranges ("AWS", "DigitalOcean"...).
CLOUD_BRANDS = [
    ("amazon", "AWS"), ("aws", "AWS"), ("google", "Google Cloud"),
    ("microsoft", "Azure"), ("azure", "Azure"), ("digitalocean", "DigitalOcean"),
    ("ovh", "OVH"), ("hetzner", "Hetzner"), ("alibaba", "Alibaba Cloud"),
    ("aliyun", "Alibaba Cloud"), ("tencent", "Tencent Cloud"),
    ("linode", "Akamai/Linode"), ("akamai", "Akamai/Linode"),
    ("vultr", "Vultr"), ("choopa", "Vultr"), ("constant company", "Vultr"),
    ("contabo", "Contabo"), ("oracle", "Oracle Cloud"), ("scaleway", "Scaleway"),
    ("online s.a.s", "Scaleway"), ("leaseweb", "Leaseweb"), ("huawei cloud", "Huawei Cloud"),
    ("cloudflare", "Cloudflare"), ("m247", "M247"), ("datacamp", "DataCamp/CDN77"),
    ("ionos", "IONOS"), ("godaddy", "GoDaddy"), ("hostinger", "Hostinger"),
    ("censys", "Censys"), ("shodan", "Shodan"), ("shadowserver", "Shadowserver"),
]
_HOSTING_WORDS = (
    "hosting", "host ", "cloud", "datacenter", "data center", "server", "vps",
    "colo", "dedicated", "llc hosting", "internet solutions",
)
_MOBILE_WORDS = ("mobile", "wireless", "cellular", "moviles", "movil ")


def cloud_brand(org: str) -> str:
    low = (org or "").lower()
    for needle, brand in CLOUD_BRANDS:
        if needle in low:
            return brand
    return ""


def guess_net_type(org: str) -> str:
    """Best-effort network type when the geo provider gives no flags."""
    low = (org or "").lower()
    if not low:
        return "unknown"
    if cloud_brand(low) or any(w in low for w in _HOSTING_WORDS):
        return "hosting"
    if any(w in low for w in _MOBILE_WORDS):
        return "mobile"
    return "residential"

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
            params={"fields": "status,country,countryCode,city,lat,lon,as,org,mobile,proxy,hosting"},
            timeout=5.0,
        )
        data = resp.json()
        if data.get("status") == "success":
            org = data.get("org", "") or data.get("as", "")
            if data.get("hosting"):
                net_type = "hosting"
            elif data.get("proxy"):
                net_type = "proxy"
            elif data.get("mobile"):
                net_type = "mobile"
            else:
                net_type = "residential"
            return GeoInfo(
                country=data.get("country", "Unknown"),
                country_code=data.get("countryCode", "XX"),
                city=data.get("city", "Unknown"),
                lat=data.get("lat", 0.0),
                lon=data.get("lon", 0.0),
                asn=data.get("as", ""),
                org=org,
                net_type=net_type,
                cloud=cloud_brand(f"{org} {data.get('as', '')}"),
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
            net_type=guess_net_type(data.get("org", "")),
            cloud=cloud_brand(data.get("org", "")),
        )
    except Exception as e:
        logger.warning(f"ipinfo lookup failed for {ip}: {e}")
    return None


# ── Local database (GEO_PROVIDER=mmdb) ───────────────────────────────
# No rate limit and no visitor IP ever leaves the server. Works with
# MaxMind GeoLite2 and DB-IP lite files (same schema).
_mmdb_city = None
_mmdb_asn = None
_mmdb_loaded = False


def _load_mmdb() -> bool:
    global _mmdb_city, _mmdb_asn, _mmdb_loaded
    if _mmdb_loaded:
        return _mmdb_city is not None
    _mmdb_loaded = True
    try:
        import maxminddb
    except ImportError:
        logger.error("GEO_PROVIDER=mmdb needs the 'maxminddb' package")
        return False
    try:
        _mmdb_city = maxminddb.open_database(settings.GEOIP_CITY_DB)
    except Exception as e:
        logger.error(f"Cannot open GeoIP city DB {settings.GEOIP_CITY_DB}: {e}")
        return False
    try:
        _mmdb_asn = maxminddb.open_database(settings.GEOIP_ASN_DB)
    except Exception as e:
        logger.warning(f"No GeoIP ASN DB ({settings.GEOIP_ASN_DB}): {e} — ASN/network type unavailable")
    return True


def geo_from_mmdb_records(city: Optional[dict], asn: Optional[dict]) -> GeoInfo:
    """Build a GeoInfo from raw mmdb records (separate so it can be tested)."""
    city = city or {}
    asn = asn or {}
    country = city.get("country") or city.get("registered_country") or {}
    location = city.get("location") or {}
    names = (city.get("city") or {}).get("names") or {}
    org = asn.get("autonomous_system_organization", "") or ""
    number = asn.get("autonomous_system_number")
    return GeoInfo(
        country=(country.get("names") or {}).get("en", "Unknown"),
        country_code=country.get("iso_code", "XX"),
        city=names.get("en", "Unknown"),
        lat=float(location.get("latitude", 0.0) or 0.0),
        lon=float(location.get("longitude", 0.0) or 0.0),
        asn=f"AS{number} {org}".strip() if number else org,
        org=org,
        net_type=guess_net_type(org),
        cloud=cloud_brand(org),
    )


def _lookup_mmdb(ip: str) -> Optional[GeoInfo]:
    if not _load_mmdb():
        return None
    try:
        city = _mmdb_city.get(ip)
        asn = _mmdb_asn.get(ip) if _mmdb_asn else None
    except Exception as e:
        logger.warning(f"mmdb lookup failed for {ip}: {e}")
        return None
    if not city and not asn:
        return None
    return geo_from_mmdb_records(city, asn)


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

        if settings.GEO_PROVIDER == "mmdb":
            geo = _lookup_mmdb(ip)
            # Fall back to ip-api only if the local DB could not be opened
            if geo is None and _mmdb_city is None:
                geo = await _lookup_ip_api(ip, client)
        elif settings.GEO_PROVIDER == "ipinfo":
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
