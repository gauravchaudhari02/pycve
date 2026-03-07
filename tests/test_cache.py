"""Tests for pycve.cache.manager."""

from __future__ import annotations

import time

import pytest

from pycve.cache.manager import CacheManager


@pytest.fixture
def cache(tmp_path):
    return CacheManager(db_path=tmp_path / "test_cache.db", default_ttl=3600)


class TestCacheManager:
    def test_set_and_get(self, cache):
        cache.set("key1", {"value": 42})
        result = cache.get("key1")
        assert result == {"value": 42}

    def test_get_missing_key(self, cache):
        assert cache.get("nonexistent") is None

    def test_ttl_expiry(self, cache):
        cache.set("short", "data", ttl=1)
        time.sleep(1.1)
        assert cache.get("short") is None

    def test_overwrite(self, cache):
        cache.set("key", "v1")
        cache.set("key", "v2")
        assert cache.get("key") == "v2"

    def test_clear(self, cache):
        cache.set("a", 1)
        cache.set("b", 2)
        rows = cache.clear()
        assert rows == 2
        assert cache.get("a") is None

    def test_stats(self, cache):
        cache.set("x", "y")
        cache.get("x")   # hit
        cache.get("z")   # miss
        stats = cache.stats()
        assert stats["entries"] == 1
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5
        assert "db_path" in stats

    def test_evict_expired(self, cache):
        cache.set("permanent", "data", ttl=3600)
        cache.set("expiring", "data", ttl=1)
        time.sleep(1.1)
        removed = cache.evict_expired()
        assert removed == 1
        assert cache.get("permanent") is not None

    def test_string_values(self, cache):
        cache.set("str_key", "hello")
        assert cache.get("str_key") == "hello"

    def test_list_values(self, cache):
        cache.set("list_key", [1, 2, 3])
        assert cache.get("list_key") == [1, 2, 3]

    def test_repr(self, cache, tmp_path):
        r = repr(cache)
        assert "CacheManager" in r
        assert "test_cache.db" in r
        assert "3600" in r

    def test_set_with_custom_ttl(self, cache):
        """set() with explicit ttl overrides the default TTL."""
        cache.set("custom_ttl_key", "value", ttl=7200)
        # Verify the row was stored (not expired immediately)
        assert cache.get("custom_ttl_key") == "value"

    def test_hit_rate_zero_on_fresh_cache(self, cache):
        stats = cache.stats()
        assert stats["hit_rate"] == 0.0
        assert stats["hits"] == 0
        assert stats["misses"] == 0

    def test_valid_vs_expired_entries_in_stats(self, cache):
        cache.set("live", "data", ttl=3600)
        cache.set("dead", "data", ttl=1)
        time.sleep(1.1)
        stats = cache.stats()
        assert stats["valid_entries"] == 1
        assert stats["expired_entries"] == 1
