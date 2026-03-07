"""Tests for pycve.analysis.kev_checker."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pycve.analysis.kev_checker import KEVChecker

FIXTURES = Path(__file__).parent / "fixtures"
CATALOG = (FIXTURES / "sample_kev_catalog.json").read_text()


@pytest.fixture
def checker(tmp_path):
    """KEVChecker backed by the fixture catalog at a temp cache path."""
    c = KEVChecker(cache_ttl=86400, cache_path=tmp_path / "kev.json")
    c._catalog = c._parse_json(CATALOG)
    c._loaded_at = 9999999999.0  # force "fresh"
    return c


class TestKEVChecker:
    def test_found_in_catalog(self, checker):
        entry = checker.check("CVE-2021-44228")
        assert entry.in_kev_catalog is True
        assert entry.cve_id == "CVE-2021-44228"
        assert entry.vendor_project == "Apache"

    def test_not_found_in_catalog(self, checker):
        entry = checker.check("CVE-1999-00001")
        assert entry.in_kev_catalog is False
        assert entry.cve_id == "CVE-1999-00001"

    def test_case_insensitive(self, checker):
        entry = checker.check("cve-2021-44228")
        assert entry.in_kev_catalog is True

    def test_batch_check(self, checker):
        entries = checker.check_batch(["CVE-2021-44228", "CVE-2023-44487", "CVE-9999-00001"])
        assert len(entries) == 3
        assert entries[0].in_kev_catalog is True
        assert entries[1].in_kev_catalog is True
        assert entries[2].in_kev_catalog is False

    def test_catalog_size(self, checker):
        assert checker.catalog_size() == 2

    def test_to_dict(self, checker):
        entry = checker.check("CVE-2021-44228")
        d = entry.to_dict()
        assert d["cve_id"] == "CVE-2021-44228"
        assert d["in_kev_catalog"] is True
        assert "vendor_project" in d

    def test_not_in_catalog_dict(self, checker):
        entry = checker.check("CVE-2000-00001")
        d = entry.to_dict()
        assert d["in_kev_catalog"] is False

    def test_refresh_forces_reload(self, tmp_path):
        """refresh() clears the in-memory catalog and triggers a fresh _load_catalog."""
        c = KEVChecker(cache_ttl=86400, cache_path=tmp_path / "kev.json")
        c._catalog = c._parse_json(CATALOG)
        c._loaded_at = 9999999999.0
        assert c.catalog_size() == 2

        with patch.object(c, "_load_catalog") as mock_load:
            mock_load.side_effect = lambda: None  # no-op, don't actually download
            c.refresh()
        assert c._catalog == {}
        mock_load.assert_called_once()

    def test_load_from_local_file_cache(self, tmp_path):
        """When a fresh local file exists the catalog is loaded without an HTTP call."""
        cache_file = tmp_path / "kev.json"
        cache_file.write_text(CATALOG)
        # File mtime is "now" → age < ttl → should use local cache
        c = KEVChecker(cache_ttl=86400, cache_path=cache_file)

        with patch("requests.get") as mock_get:
            c._load_catalog()
        mock_get.assert_not_called()
        assert c.catalog_size() == 2

    def test_stale_cache_fallback_on_download_failure(self, tmp_path):
        """When download fails and a stale file exists, use the stale cache."""
        cache_file = tmp_path / "kev.json"
        cache_file.write_text(CATALOG)
        # Make file appear old (age > ttl=1s)
        import os, time
        old_time = time.time() - 10
        os.utime(cache_file, (old_time, old_time))

        c = KEVChecker(cache_ttl=1, cache_path=cache_file)

        with patch("requests.get", side_effect=Exception("network error")):
            c._load_catalog()

        assert c.catalog_size() == 2  # loaded from stale file
