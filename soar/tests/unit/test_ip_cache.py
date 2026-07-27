import threading
import time

import pytest

from soar.cache import IpCache


@pytest.fixture
def cache():
    return IpCache()


class TestIpCache:
    def test_set_and_get(self, cache):
        cache.set("10.0.1.50", 85, ttl_seconds=60)
        assert cache.get("10.0.1.50") == 85

    def test_get_unknown_ip(self, cache):
        assert cache.get("10.0.1.99") is None

    def test_get_after_expiry(self, cache):
        cache.set("10.0.1.50", 85, ttl_seconds=0)
        time.sleep(0.01)
        assert cache.get("10.0.1.50") is None

    def test_multiple_ips(self, cache):
        cache.set("10.0.1.50", 85, ttl_seconds=60)
        cache.set("10.0.1.51", 30, ttl_seconds=60)
        assert cache.get("10.0.1.50") == 85
        assert cache.get("10.0.1.51") == 30

    def test_overwrite_existing(self, cache):
        cache.set("10.0.1.50", 85, ttl_seconds=60)
        cache.set("10.0.1.50", 95, ttl_seconds=60)
        assert cache.get("10.0.1.50") == 95

    def test_clear(self, cache):
        cache.set("10.0.1.50", 85, ttl_seconds=60)
        cache.clear()
        assert cache.get("10.0.1.50") is None

    def test_size(self, cache):
        assert cache.size == 0
        cache.set("10.0.1.50", 85, ttl_seconds=60)
        assert cache.size == 1

    def test_size_after_expiry(self, cache):
        cache.set("10.0.1.50", 85, ttl_seconds=0)
        time.sleep(0.01)
        assert cache.size == 0

    def test_concurrent_access(self, cache):
        errors = []

        def worker(ip: str, score: int):
            try:
                for _ in range(100):
                    cache.set(ip, score, ttl_seconds=60)
                    result = cache.get(ip)
                    assert result is not None
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=("10.0.1.50", 85)),
            threading.Thread(target=worker, args=("10.0.1.51", 30)),
            threading.Thread(target=worker, args=("10.0.1.52", 95)),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Erreurs concurrentes: {errors}"
