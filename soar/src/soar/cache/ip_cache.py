from __future__ import annotations

import threading
import time
from typing import Optional


class IpCache:
    def __init__(self):
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, ip: str) -> Optional[int]:
        with self._lock:
            entry = self._data.get(ip)
            if entry is None:
                return None
            if time.monotonic() > entry["expires_at"]:
                del self._data[ip]
                return None
            return entry["score"]

    def set(self, ip: str, score: int, ttl_seconds: int) -> None:
        with self._lock:
            self._data[ip] = {
                "score": score,
                "expires_at": time.monotonic() + ttl_seconds,
            }

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    @property
    def size(self) -> int:
        with self._lock:
            self._evict_expired()
            return len(self._data)

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [ip for ip, entry in self._data.items() if now > entry["expires_at"]]
        for ip in expired:
            del self._data[ip]
