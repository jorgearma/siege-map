"""
Deliver alerts to the operator: Discord, Slack, Telegram or any JSON webhook.

Best effort and never in the way: a failed delivery is logged and dropped,
the alert itself is already in SQLite and on the dashboard.
"""
import logging
from typing import Optional
from urllib.parse import urlsplit

import httpx

from .alerts import SEVERITY_RANK
from .config import settings

logger = logging.getLogger(__name__)

_ICON = {"LOW": "🔵", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}


def enabled() -> bool:
    return bool(settings.ALERT_WEBHOOK_URL
                or (settings.ALERT_TELEGRAM_BOT_TOKEN and settings.ALERT_TELEGRAM_CHAT_ID))


def should_notify(alert: dict) -> bool:
    floor = SEVERITY_RANK.get(settings.ALERT_NOTIFY_MIN_SEVERITY, SEVERITY_RANK["HIGH"])
    return SEVERITY_RANK.get(alert["severity"], 0) >= floor


def render(alert: dict) -> str:
    lines = [
        f"{_ICON.get(alert['severity'], '')} [{alert['severity']}] {alert['title']}",
        alert.get("detail", ""),
    ]
    if alert.get("private"):
        lines.append(alert["private"])
    if alert.get("mitre"):
        lines.append("MITRE ATT&CK: " + ", ".join(alert["mitre"]))
    lines.append(f"sensor: {settings.VPS_LABEL} · {alert['ts']}")
    return "\n".join(line for line in lines if line)


def webhook_payload(url: str, alert: dict) -> dict:
    """Body in the shape each service expects."""
    host = (urlsplit(url).hostname or "").lower()
    text = render(alert)
    if host.endswith("discord.com") or host.endswith("discordapp.com"):
        return {"content": text[:1900]}
    if host.endswith("slack.com"):
        return {"text": text}
    return {"text": text, "alert": alert, "sensor": settings.VPS_LABEL}


async def send(alert: dict, client: Optional[httpx.AsyncClient] = None) -> int:
    """Send one alert to every configured destination. Returns how many accepted it."""
    if not enabled() or not should_notify(alert):
        return 0
    delivered = 0
    own = client is None
    client = client or httpx.AsyncClient(timeout=8.0)
    try:
        if settings.ALERT_WEBHOOK_URL:
            delivered += await _post(client, settings.ALERT_WEBHOOK_URL,
                                     webhook_payload(settings.ALERT_WEBHOOK_URL, alert), "webhook")
        if settings.ALERT_TELEGRAM_BOT_TOKEN and settings.ALERT_TELEGRAM_CHAT_ID:
            delivered += await _post(
                client,
                f"https://api.telegram.org/bot{settings.ALERT_TELEGRAM_BOT_TOKEN}/sendMessage",
                {"chat_id": settings.ALERT_TELEGRAM_CHAT_ID, "text": render(alert),
                 "disable_web_page_preview": True},
                "telegram",
            )
    finally:
        if own:
            await client.aclose()
    return delivered


async def _post(client: httpx.AsyncClient, url: str, body: dict, name: str) -> int:
    try:
        resp = await client.post(url, json=body)
        if resp.status_code < 300:
            return 1
        logger.warning(f"Alert {name} answered HTTP {resp.status_code}")
    except Exception as e:
        # Never log the URL: it carries the webhook secret / bot token
        logger.warning(f"Alert {name} failed: {type(e).__name__}")
    return 0
