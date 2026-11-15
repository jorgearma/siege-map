"""
Unique visitors per day and what kind of client each one is.

The key is the FULL address, held only in memory and dropped at midnight;
what gets written to disk are counters ("3 Android / Chrome today").

Classes, from most to least trusted:

  browser_verified  browser UA that also fetched static assets (css/js/img),
                    which is what a real browser does after loading a page
  browser           browser UA, page only. NOT proof of a bot: behind a CDN
                    (Cloudflare) cached assets never reach the origin
  crawler           declared bots (Googlebot, GPTBot...)
  tool              curl, python-requests, Go-http-client...
  fake_browser      headless / automation / impossible browser version
  scanner           probes, exploits, 4xx hunting
"""
from datetime import datetime
from typing import Optional

from .models import SSHEvent

_RANK = {
    "browser": 0, "browser_verified": 1, "crawler": 2,
    "tool": 3, "fake_browser": 4, "scanner": 5,
}
_FROM_PARSER = {"human": "browser"}
_MAX_TRACKED = 50000

Delta = tuple[str, str, int]


class VisitorTracker:
    def __init__(self):
        self._day = ""
        self._seen: dict[str, dict] = {}

    def _roll(self, day: str) -> None:
        if day != self._day:
            self._day = day
            self._seen.clear()

    @staticmethod
    def _profile(event: SSHEvent) -> list[tuple[str, str]]:
        """Dimensions that describe a person's visit (counted once per day)."""
        m = event.meta
        dims = [
            ("device", m.get("device", "")),
            ("os", m.get("os", "")),
            ("browser", m.get("browser", "")),
            ("lang", m.get("lang", "")),
            ("referrer", m.get("ref", "")),
            ("device_os", f"{m.get('device', '')} · {m.get('os', '')}"
             if m.get("device") and m.get("os") else ""),
        ]
        if event.geo:
            dims.append(("visit_country", event.geo.country))
            dims.append(("visit_net", event.geo.net_type))
        return [(d, k) for d, k in dims if k]

    def on_event(self, event: SSHEvent, full_ip: str) -> list[Delta]:
        """Counter deltas caused by this HTTP event."""
        self._roll(event.timestamp[:10])
        cls = event.meta.get("visitor", "scanner")
        cls = _FROM_PARSER.get(cls, cls)
        state = self._seen.get(full_ip)

        if state is None:
            if len(self._seen) >= _MAX_TRACKED:
                return []
            state = self._seen[full_ip] = {"cls": cls, "profile": []}
            deltas: list[Delta] = [("visitor", cls, 1)]
            if cls == "browser":
                state["profile"] = self._profile(event)
                deltas += [(d, k, 1) for d, k in state["profile"]]
            return deltas

        old = state["cls"]
        # A verified browser stays verified on later page views
        if cls == "browser" and old == "browser_verified":
            return []
        if _RANK.get(cls, 5) <= _RANK.get(old, 0):
            return []
        # Same address turned out to be something worse: move it
        state["cls"] = cls
        deltas = [("visitor", old, -1), ("visitor", cls, 1)]
        deltas += [(d, k, -1) for d, k in state["profile"]]
        state["profile"] = []
        return deltas

    def on_asset(self, full_ip: str, day: str) -> list[Delta]:
        """A static file was fetched: page-only browsers become verified."""
        self._roll(day)
        state = self._seen.get(full_ip)
        if state and state["cls"] == "browser":
            state["cls"] = "browser_verified"
            return [("visitor", "browser", -1), ("visitor", "browser_verified", 1)]
        return []


visitor_tracker = VisitorTracker()
