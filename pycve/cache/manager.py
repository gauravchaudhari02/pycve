"""SQLite-based TTL cache for NVD API responses."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

_DEFAULT_CACHE_PATH = Path.home() / ".pycve" / "cache.db"
_HIT_TRACKING_WINDOW = 1000  # track last N accesses for hit-rate calc


class CacheManager:
    """Thread-safe SQLite cache with configurable TTL.

    Each entry stores a JSON-serialised value with a timestamp and TTL.
    Expired entries are lazily evicted on read and periodically pruned.
    """

    def __init__(self, db_path: str | Path | None = None, default_ttl: int = 86400):
        self._db_path = Path(db_path) if db_path else _DEFAULT_CACHE_PATH
        self._default_ttl = default_ttl
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._init_db()

    # ── DB Setup ─────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key       TEXT PRIMARY KEY,
                    value     TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    ttl       INTEGER NOT NULL
                )
            """)
            conn.execute("PRAGMA journal_mode=WAL")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), check_same_thread=False)

    # ── Public API ───────────────────────────────────────────────────────────

    def get(self, key: str) -> Any | None:
        """Return the cached value for *key*, or ``None`` if missing/expired."""
        with self._lock:
            try:
                with self._connect() as conn:
                    row = conn.execute(
                        "SELECT value, timestamp, ttl FROM cache WHERE key = ?", (key,)
                    ).fetchone()
                    if row is None:
                        self._misses += 1
                        return None
                    value_str, timestamp, ttl = row
                    if time.time() > timestamp + ttl:
                        conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                        self._misses += 1
                        return None
                    self._hits += 1
                    return json.loads(value_str)
            except Exception:
                self._misses += 1
                return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Store *value* under *key* with optional custom *ttl* (seconds)."""
        effective_ttl = ttl if ttl is not None else self._default_ttl
        value_str = json.dumps(value, default=str)
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO cache (key, value, timestamp, ttl)
                        VALUES (?, ?, ?, ?)
                        """,
                        (key, value_str, time.time(), effective_ttl),
                    )
            except Exception:
                pass  # Cache failures are non-fatal

    def clear(self) -> int:
        """Delete all entries from the cache. Returns the number of rows deleted."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM cache")
                self._hits = 0
                self._misses = 0
                return cursor.rowcount

    def evict_expired(self) -> int:
        """Remove all expired entries. Returns the number of rows deleted."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM cache WHERE (timestamp + ttl) < ?", (time.time(),)
                )
                return cursor.rowcount

    def stats(self) -> dict[str, Any]:
        """Return cache statistics: entry count, DB size, and hit rate."""
        with self._lock:
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
                valid = conn.execute(
                    "SELECT COUNT(*) FROM cache WHERE (timestamp + ttl) >= ?", (time.time(),)
                ).fetchone()[0]
            size_bytes = self._db_path.stat().st_size if self._db_path.exists() else 0
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0.0
            return {
                "entries": total,
                "valid_entries": valid,
                "expired_entries": total - valid,
                "size_mb": round(size_bytes / (1024 * 1024), 3),
                "hit_rate": round(hit_rate, 4),
                "hits": self._hits,
                "misses": self._misses,
                "db_path": str(self._db_path),
            }

    def __repr__(self) -> str:
        return f"CacheManager(db_path={self._db_path!r}, default_ttl={self._default_ttl}s)"
