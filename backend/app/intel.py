"""
Extra labels for an address: Tor exit node, cloud brand, proxy/VPN,
and (optional, on demand) GreyNoise community classification.
"""
import asyncio
import logging
import time
from typing import Optional

import httpx

from .cache import TTLCache
from .config import settings
from .models import GeoInfo

logger = logging.getLogger(__name__)

TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_tor_exits: set[str] = set()
_tor_loaded_at: float = 0.0

_gn_cache = TTLCache(maxsize=5000, ttl=86400)
_gn_day_start: float = 0.0
_gn_count: int = 0


def parse_tor_list(text: str) -> set[str]:
    return {line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith("#")}


async def refresh_tor_exits() -> int:
    global _tor_exits, _tor_loaded_at
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(TOR_LIST_URL, timeout=15.0)
        if resp.status_code == 200:
            exits = parse_tor_list(resp.text)
            if exits:
                _tor_exits = exits
                _tor_loaded_at = time.time()
                logger.info(f"Tor exit list loaded: {len(exits)} addresses")
    except Exception as e:
        logger.warning(f"Could not download the Tor exit list: {e}")
    return len(_tor_exits)


async def tor_refresh_loop() -> None:
    """Reload the list once a day (it changes slowly)."""
    while True:
        await refresh_tor_exits()
        await asyncio.sleep(86400 if _tor_exits else 3600)


def is_tor_exit(ip: str) -> bool:
    return ip in _tor_exits


def tags_for(ip: str, geo: Optional[GeoInfo]) -> list[str]:
    tags = []
    if is_tor_exit(ip):
        tags.append("tor-exit")
    if geo:
        if geo.cloud:
            tags.append(geo.cloud)
        if geo.net_type in ("hosting", "proxy", "mobile"):
            tags.append(geo.net_type)
    return tags


async def check_greynoise(ip: str) -> dict:
    """
    GreyNoise community API. Tells mass internet scanners ("noise") and
    known-benign services ("riot") apart from targeted activity.
    Only called when someone opens a dossier, to stay inside the free quota.

    The caller must pass an address this sensor has really seen (main.py
    checks it): the quota is small and the endpoint is public.
    """
    global _gn_day_start, _gn_count
    if not settings.GREYNOISE_API_KEY:
        return {}
    now = time.time()
    if _gn_cache.fresh(ip):
        return _gn_cache.get(ip)
    if now - _gn_day_start >= 86400:
        _gn_day_start, _gn_count = now, 0
    if _gn_count >= settings.GREYNOISE_DAILY_LIMIT:
        return {}
    _gn_count += 1
    result: dict = {}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": settings.GREYNOISE_API_KEY, "Accept": "application/json"},
                timeout=8.0,
            )
        if resp.status_code == 200:
            d = resp.json()
            result = {
                "noise": bool(d.get("noise")),
                "riot": bool(d.get("riot")),
                "classification": d.get("classification", ""),
                "name": d.get("name", ""),
                "last_seen": d.get("last_seen", ""),
            }
        elif resp.status_code == 404:
            result = {"noise": False, "riot": False, "classification": "unseen", "name": ""}
        else:
            logger.warning(f"GreyNoise HTTP {resp.status_code} for {ip}")
            return {}
    except Exception as e:
        logger.warning(f"GreyNoise lookup failed for {ip}: {e}")
        return {}
    _gn_cache.set(ip, result)
    return result
