import time
from collections import deque, Counter
from typing import Optional
from .models import SSHEvent
from .config import settings


class EventStore:
    """In-memory store for SSH events with time-windowed queries."""

    def __init__(self, max_events: int = None):
        self.max_events = max_events or settings.MAX_EVENTS
        self.events: deque[SSHEvent] = deque(maxlen=self.max_events)
        self._seen: deque[str] = deque(maxlen=5000)  # dedup window
        self._total_count = 0

    def add(self, event: SSHEvent) -> bool:
        """Add event, returns False if duplicate."""
        # Simple dedup: same IP + username + event_type within a short window
        dedup_key = f"{event.ip}:{event.username}:{event.event_type}:{event.timestamp[:16]}"
        if dedup_key in self._seen:
            return False

        self._seen.append(dedup_key)
        self.events.append(event)
        self._total_count += 1
        return True

    def _filter_by_window(self, seconds: Optional[int] = None) -> list[SSHEvent]:
        if seconds is None:
            return list(self.events)

        from datetime import datetime, timedelta

        cutoff = datetime.now() - timedelta(seconds=seconds)
        cutoff_str = cutoff.isoformat()

        return [e for e in self.events if e.timestamp >= cutoff_str]

    def recent(self, limit: int = 50, window: Optional[int] = None) -> list[dict]:
        events = self._filter_by_window(window)
        return [e.to_dict() for e in reversed(events)][:limit]

    def top_countries(self, limit: int = 10, window: Optional[int] = None) -> list[dict]:
        events = self._filter_by_window(window)
        counter = Counter()
        for e in events:
            if e.geo:
                counter[e.geo.country] += 1
        return [{"country": k, "count": v} for k, v in counter.most_common(limit)]

    def top_ips(self, limit: int = 10, window: Optional[int] = None, source: Optional[str] = None) -> list[dict]:
        events = self._filter_by_window(window)
        if source == "ssh":
            events = [e for e in events if e.source == "ssh"]
        elif source == "http":
            events = [e for e in events if e.source == "http" and not e.event_type.startswith("visit_")]
        elif source == "visits":
            events = [e for e in events if e.event_type.startswith("visit_")]
        counter = Counter(e.ip for e in events)
        return [{"ip": k, "count": v} for k, v in counter.most_common(limit)]

    def top_usernames(self, limit: int = 10, window: Optional[int] = None) -> list[dict]:
        events = self._filter_by_window(window)
        counter = Counter(e.username for e in events)
        return [{"username": k, "count": v} for k, v in counter.most_common(limit)]

    def top_http_routes(self, limit: int = 10, window: Optional[int] = None) -> list[dict]:
        from collections import defaultdict
        events = self._filter_by_window(window)
        http_events = [e for e in events if e.source == "http"]
        routes: dict[str, dict] = defaultdict(lambda: {"count": 0, "statuses": Counter()})
        for e in http_events:
            routes[e.username]["count"] += 1
            if e.http_status:
                routes[e.username]["statuses"][e.http_status] += 1
        result = []
        for path, data in sorted(routes.items(), key=lambda x: -x[1]["count"])[:limit]:
            top = data["statuses"].most_common(1)
            result.append({
                "path": path,
                "count": data["count"],
                "status": top[0][0] if top else 0,
            })
        return result

    def events_per_minute(self, window: Optional[int] = None) -> list[dict]:
        events = self._filter_by_window(window)
        counter = Counter()
        for e in events:
            # Group by minute
            minute_key = e.timestamp[:16]  # "2024-01-15T14:30"
            counter[minute_key] += 1

        sorted_minutes = sorted(counter.items())[-60:]  # last 60 minutes max
        return [{"minute": k, "count": v} for k, v in sorted_minutes]

    def total_count(self, window: Optional[int] = None) -> int:
        if window is None:
            return self._total_count
        return len(self._filter_by_window(window))

    def events_for_ip(self, ip: str, window: Optional[int] = None) -> list[SSHEvent]:
        return [e for e in self._filter_by_window(window) if e.ip == ip]

    def events_for_username(self, username: str, window: Optional[int] = None) -> list[SSHEvent]:
        return [e for e in self._filter_by_window(window) if e.username == username]


# Global store instance
store = EventStore()
