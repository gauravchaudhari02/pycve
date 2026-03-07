"""CISA Known Exploited Vulnerabilities (KEV) catalog checker."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import requests

from pycve.models.kev import KEVEntry

logger = logging.getLogger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_CACHE_PATH = Path.home() / ".pycve" / "kev_catalog.json"
_KEV_CACHE_TTL = 86400  # 24 hours


class KEVChecker:
    """Checks CVE IDs against the CISA Known Exploited Vulnerabilities catalog.

    The catalog is downloaded once and cached locally for up to 24 hours.
    """

    def __init__(self, cache_ttl: int = _KEV_CACHE_TTL, cache_path: Path | None = None):
        self._cache_ttl = cache_ttl
        self._cache_path = cache_path or _KEV_CACHE_PATH
        self._catalog: dict[str, dict] = {}  # cve_id → entry
        self._loaded_at: float = 0.0

    # ── Catalog management ───────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        now = time.monotonic()
        if self._catalog and (now - self._loaded_at) < self._cache_ttl:
            return  # Still fresh in memory
        self._load_catalog()

    def _load_catalog(self) -> None:
        """Load KEV catalog from local cache or download fresh copy."""
        # Try local file cache first
        if self._cache_path.exists():
            age = time.time() - self._cache_path.stat().st_mtime
            if age < self._cache_ttl:
                try:
                    self._catalog = self._parse_json(self._cache_path.read_text())
                    self._loaded_at = time.monotonic()
                    logger.debug("Loaded KEV catalog from local cache (%d entries)", len(self._catalog))
                    return
                except Exception:
                    pass  # Fall through to download

        # Download fresh catalog
        try:
            resp = requests.get(_KEV_URL, timeout=30)
            resp.raise_for_status()
            raw = resp.text
            self._catalog = self._parse_json(raw)
            self._loaded_at = time.monotonic()
            # Persist to local cache
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(raw)
            logger.info("Downloaded CISA KEV catalog: %d entries", len(self._catalog))
        except Exception as exc:
            logger.warning("Failed to download CISA KEV catalog: %s. Using stale cache.", exc)
            # Use stale cache as offline fallback
            if self._cache_path.exists():
                try:
                    self._catalog = self._parse_json(self._cache_path.read_text())
                    self._loaded_at = time.monotonic()
                    logger.info("Using stale KEV catalog as offline fallback")
                except Exception:
                    self._catalog = {}

    @staticmethod
    def _parse_json(raw: str) -> dict[str, dict]:
        """Parse KEV JSON and index by CVE ID."""
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", [])
        return {v["cveID"]: v for v in vulns if "cveID" in v}

    # ── Public API ───────────────────────────────────────────────────────

    def check(self, cve_id: str) -> KEVEntry:
        """Return a :class:`~pycve.models.kev.KEVEntry` for the given CVE ID."""
        self._ensure_loaded()
        cve_upper = cve_id.upper()
        entry = self._catalog.get(cve_upper)
        if entry:
            return KEVEntry.from_kev_json(cve_upper, entry)
        return KEVEntry.not_in_catalog(cve_upper)

    def check_batch(self, cve_ids: list[str]) -> list[KEVEntry]:
        """Batch check multiple CVE IDs. Only downloads the catalog once."""
        self._ensure_loaded()
        return [self.check(cve_id) for cve_id in cve_ids]

    def catalog_size(self) -> int:
        """Return the number of entries in the currently loaded catalog."""
        self._ensure_loaded()
        return len(self._catalog)

    def refresh(self) -> None:
        """Force re-download of the CISA KEV catalog."""
        if self._cache_path.exists():
            self._cache_path.unlink(missing_ok=True)
        self._catalog = {}
        self._loaded_at = 0.0
        self._load_catalog()
