"""Tests for pycve.api.client — NVD HTTP client (mocked with responses)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses as resp_lib

from pycve.api.client import NVDClient
from pycve.utils.exceptions import APIError, CVENotFoundError, RateLimitError

FIXTURES = Path(__file__).parent / "fixtures"
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"


def fixture_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def client():
    """Client without api_key (public rate limit)."""
    return NVDClient(api_key=None, cache=None, timeout=5)


class TestNVDClientGetCVE:
    @resp_lib.activate
    def test_get_cve_success(self, client):
        resp_lib.add(
            resp_lib.GET,
            CVE_URL,
            json=fixture_json("sample_cve_response.json"),
            status=200,
        )
        record = client.get_cve("CVE-2021-44228")
        assert record.id == "CVE-2021-44228"
        assert record.severity == "CRITICAL"

    @resp_lib.activate
    def test_get_cve_not_found(self, client):
        resp_lib.add(resp_lib.GET, CVE_URL, status=404)
        with pytest.raises(CVENotFoundError):
            client.get_cve("CVE-1999-99999")

    @resp_lib.activate
    def test_get_cve_server_error(self, client):
        # Disable retry to speed up test
        client._session.get_adapter("https://").max_retries.total = 0
        resp_lib.add(resp_lib.GET, CVE_URL, status=500)
        resp_lib.add(resp_lib.GET, CVE_URL, status=500)
        resp_lib.add(resp_lib.GET, CVE_URL, status=500)
        resp_lib.add(resp_lib.GET, CVE_URL, status=500)
        with pytest.raises(APIError):
            client.get_cve("CVE-2021-44228")

    @resp_lib.activate
    def test_get_cves_batch_skips_not_found(self, client):
        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_cve_response.json"),
            status=200,
        )
        resp_lib.add(resp_lib.GET, CVE_URL, status=404)
        results = client.get_cves(["CVE-2021-44228", "CVE-9999-00000"])
        assert len(results) == 1
        assert results[0].id == "CVE-2021-44228"

    @resp_lib.activate
    def test_get_cves_with_cache(self, tmp_path):
        from pycve.cache.manager import CacheManager
        cache = CacheManager(db_path=tmp_path / "c.db", default_ttl=3600)
        client_c = NVDClient(api_key=None, cache=cache, timeout=5)

        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_cve_response.json"),
            status=200,
        )
        r1 = client_c.get_cve("CVE-2021-44228")  # cache miss → API call
        r2 = client_c.get_cve("CVE-2021-44228")  # cache hit → no API call
        assert r1.id == r2.id
        # Only one HTTP call was made
        assert len(resp_lib.calls) == 1


class TestNVDClientSearch:
    @resp_lib.activate
    def test_search_by_keyword(self, client):
        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_search_response.json"),
            status=200,
        )
        results = client.search_cves(keyword="log4j")
        assert len(results) == 2

    @resp_lib.activate
    def test_search_with_limit(self, client):
        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_search_response.json"),
            status=200,
        )
        results = client.search_cves(keyword="test", limit=1)
        assert len(results) == 1


class TestNVDClientHistory:
    @resp_lib.activate
    def test_get_history(self, client):
        resp_lib.add(
            resp_lib.GET, HISTORY_URL,
            json=fixture_json("sample_history_response.json"),
            status=200,
        )
        events = client.get_cve_history("CVE-2021-44228")
        assert len(events) == 1
        assert events[0].cve_id == "CVE-2021-44228"
        assert events[0].event_name == "CVE Modified"
        assert len(events[0].details) == 1


class TestNVDClientAuth:
    @resp_lib.activate
    def test_401_raises_api_error(self, client):
        resp_lib.add(resp_lib.GET, CVE_URL, status=401)
        with pytest.raises(APIError) as exc_info:
            client.get_cve("CVE-2021-44228")
        assert exc_info.value.status_code == 401

    @resp_lib.activate
    def test_403_raises_api_error(self, client):
        resp_lib.add(resp_lib.GET, CVE_URL, status=403)
        with pytest.raises(APIError) as exc_info:
            client.get_cve("CVE-2021-44228")
        assert exc_info.value.status_code == 403

    def test_api_key_set_in_header(self):
        c = NVDClient(api_key="test-secret-key", cache=None, timeout=5)
        assert c._session.headers.get("apiKey") == "test-secret-key"

    def test_no_api_key_header_absent(self, client):
        assert "apiKey" not in client._session.headers


class TestNVDClientProgressCallback:
    @resp_lib.activate
    def test_progress_callback_called(self):
        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_cve_response.json"),
            status=200,
        )
        client = NVDClient(api_key=None, cache=None, timeout=5)
        calls = []
        client.get_cves(["CVE-2021-44228"], progress_callback=lambda done, total: calls.append((done, total)))
        assert len(calls) == 1
        assert calls[0] == (1, 1)
