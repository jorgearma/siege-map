"""
Small bounded TTL cache.

Every cache in the app is keyed by something an attacker controls (an IP, a
username...), so a plain dict grows for as long as the process lives. This
one forgets the oldest entry once it is full.
"""
import time
from collections import OrderedDict
from typing import Any, Optional


class TTLCache:
    def __init__(self, maxsize: int, ttl: float):
        self.maxsize = maxsize
        self.ttl = ttl
        self._data: OrderedDict[Any, tuple[Any, float]] = OrderedDict()

    def get(self, key, default=None, allow_stale: bool = False):
        item = self._data.get(key)
        if item is None:
            return default
        value, stored_at = item
        if not allow_stale and time.time() - stored_at >= self.ttl:
            return default
        return value

    def fresh(self, key) -> bool:
        item = self._data.get(key)
        return item is not None and time.time() - item[1] < self.ttl

    def set(self, key, value, now: Optional[float] = None) -> None:
        self._data[key] = (value, now if now is not None else time.time())
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)

    def clear(self) -> None:
        self._data.clear()

    def __contains__(self, key) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)
