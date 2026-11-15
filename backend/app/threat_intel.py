import asyncio
import time
import logging
from typing import Optional

import httpx

from .cache import TTLCache
from .config import settings
from .store import store as _store

logger = logging.getLogger(__name__)

# ip → AbuseIPDB answer. Bounded: the keys are attacker addresses.
_cache = TTLCache(maxsize=20000, ttl=settings.ABUSE_CACHE_TTL)

_semaphore = asyncio.Semaphore(1)
_last_request_at: float = 0.0
_daily_count: int = 0
_daily_reset_at: float = 0.0


def _reset_daily_if_needed() -> None:
    global _daily_count, _daily_reset_at
    if time.time() - _daily_reset_at >= 86400:
        _daily_count = 0
        _daily_reset_at = time.time()


def get_cached_abuse(ip: str) -> dict:
    return _cache.get(ip, {}, allow_stale=True)


def should_check_ip(ip: str) -> bool:
    if not settings.THREAT_INTEL_ENABLED:
        return False
    if _cache.fresh(ip):
        return False
    # Only query IPs that appear more than once (avoid one-shot scanners)
    return _store.ip_event_count(ip) > 1


async def check_abuseipdb(ip: str) -> dict:
    global _daily_count, _last_request_at

    if not settings.ABUSEIPDB_API_KEY:
        return {}

    if _cache.fresh(ip):
        return _cache.get(ip)

    _reset_daily_if_needed()
    if _daily_count >= 900:
        logger.warning("AbuseIPDB daily limit (900) reached, skipping")
        return {}

    async with _semaphore:
        # Re-check after acquiring lock
        if _cache.fresh(ip):
            return _cache.get(ip)

        # Enforce 1 req/s
        elapsed = time.time() - _last_request_at
        if elapsed < 1.0:
            await asyncio.sleep(1.0 - elapsed)

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": settings.ABUSEIPDB_API_KEY,
                        "Accept": "application/json",
                    },
                    timeout=8.0,
                )
                _last_request_at = time.time()
                _daily_count += 1

                if resp.status_code == 200:
                    d = resp.json().get("data", {})
                    result = {
                        "abuse_confidence": d.get("abuseConfidenceScore", 0),
                        "total_reports": d.get("totalReports", 0),
                        "usage_type": d.get("usageType", ""),
                        "isp": d.get("isp", ""),
                    }
                    _cache.set(ip, result)
                    logger.debug(
                        f"AbuseIPDB {ip}: confidence={result['abuse_confidence']}%"
                        f" reports={result['total_reports']}"
                    )
                    return result
                else:
                    logger.warning(f"AbuseIPDB HTTP {resp.status_code} for {ip}")
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")

    return {}


async def check_shodan(ip: str) -> dict:
    if not settings.SHODAN_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.SHODAN_API_KEY},
                timeout=10.0,
            )
            if resp.status_code == 200:
                d = resp.json()
                return {
                    "ports": sorted(d.get("ports", []))[:20],
                    "os": d.get("os") or "",
                    "vulns": list(d.get("vulns", {}).keys())[:5],
                }
    except Exception as e:
        logger.warning(f"Shodan lookup failed for {ip}: {e}")
    return {}
