"""NVD API v2 HTTP client with rate limiting, retry, and pagination."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Generator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pycve.models.cve import CVERecord
from pycve.models.history import ChangeHistoryEvent
from pycve.utils.exceptions import APIError, CVENotFoundError, RateLimitError

logger = logging.getLogger(__name__)

# NVD API v2 base URLs
_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

# Rate limits: requests per 30-second rolling window
_RATE_PUBLIC = 5
_RATE_WITH_KEY = 50
_RATE_WINDOW = 30.0  # seconds

# Pagination
_MAX_RESULTS_PER_PAGE = 2000


class _TokenBucket:
    """Token-bucket rate limiter for the NVD API rolling window."""

    def __init__(self, rate: int, window: float):
        self._rate = rate
        self._window = window
        self._tokens: list[float] = []

    def consume(self) -> None:
        """Block until a request token is available."""
        now = time.monotonic()
        # Drop tokens older than one window
        self._tokens = [t for t in self._tokens if now - t < self._window]
        if len(self._tokens) >= self._rate:
            # Wait until the oldest token expires
            sleep_for = self._window - (now - self._tokens[0]) + 0.05
            if sleep_for > 0:
                logger.debug("Rate limit: sleeping %.2fs", sleep_for)
                time.sleep(sleep_for)
            self._tokens = self._tokens[1:]
        self._tokens.append(time.monotonic())


class NVDClient:
    """NIST NVD API v2 client.

    Parameters
    ----------
    api_key:
        NVD API key. Falls back to the ``NVD_API_KEY`` env var if ``None``.
    cache:
        Optional :class:`pycve.cache.CacheManager` instance. When supplied,
        responses are cached transparently.
    timeout:
        HTTP request timeout in seconds (default 30).
    """

    def __init__(
        self,
        api_key: str | None = None,
        cache: Any | None = None,
        timeout: int = 30,
    ):
        self._api_key = api_key or os.environ.get("NVD_API_KEY")
        self._cache = cache
        self._timeout = timeout
        rate = _RATE_WITH_KEY if self._api_key else _RATE_PUBLIC
        self._limiter = _TokenBucket(rate, _RATE_WINDOW)
        self._session = self._build_session()

    # ── Session setup ────────────────────────────────────────────────────────

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        if self._api_key:
            session.headers.update({"apiKey": self._api_key})
        session.headers.update({"Accept": "application/json"})
        return session

    # ── Low-level request ────────────────────────────────────────────────────

    def _get(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a rate-limited GET request. Handles 429 with back-off."""
        for attempt in range(4):
            self._limiter.consume()
            try:
                resp = self._session.get(url, params=params, timeout=self._timeout)
            except requests.RequestException as exc:
                raise APIError(f"Network error: {exc}") from exc

            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError as exc:
                    raise APIError("Invalid JSON response from NVD API") from exc

            if resp.status_code == 404:
                raise CVENotFoundError(params.get("cveId", "unknown"))

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", _RATE_WINDOW))
                logger.warning("429 from NVD, sleeping %ss (attempt %d)", retry_after, attempt + 1)
                time.sleep(retry_after + 1)
                raise RateLimitError(retry_after=retry_after)

            if resp.status_code in (403, 401):
                raise APIError(
                    f"Authorization error (HTTP {resp.status_code}). "
                    "Check your NVD_API_KEY.",
                    status_code=resp.status_code,
                    url=url,
                )

            raise APIError(
                f"NVD API returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                url=url,
            )

        raise APIError("Max retries exceeded")

    # ── CVE fetching ─────────────────────────────────────────────────────────

    def get_cve(self, cve_id: str) -> CVERecord:
        """Fetch a single CVE by ID.

        Uses cache if available; falls back to live API.
        """
        cache_key = f"cve:{cve_id.upper()}"
        if self._cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                logger.debug("Cache hit for %s", cve_id)
                return CVERecord.from_nvd_json(cached)

        data = self._get(_CVE_URL, {"cveId": cve_id})
        vuln_list = data.get("vulnerabilities", [])
        if not vuln_list:
            raise CVENotFoundError(cve_id)

        raw = vuln_list[0]
        if self._cache:
            self._cache.set(cache_key, raw)
        return CVERecord.from_nvd_json(raw)

    def get_cves(
        self,
        cve_ids: list[str],
        progress_callback: Any | None = None,
    ) -> list[CVERecord]:
        """Fetch multiple CVEs by ID, with optional progress callback.

        Parameters
        ----------
        cve_ids:
            List of CVE-IDs to fetch.
        progress_callback:
            Optional callable ``(done, total)`` invoked after each fetch.
        """
        results: list[CVERecord] = []
        total = len(cve_ids)
        for i, cve_id in enumerate(cve_ids):
            try:
                results.append(self.get_cve(cve_id))
            except CVENotFoundError:
                logger.warning("CVE not found: %s — skipping", cve_id)
            if progress_callback:
                progress_callback(i + 1, total)
        return results

    def search_cves(
        self,
        *,
        keyword: str | None = None,
        keyword_exact: bool = False,
        cpe_name: str | None = None,
        cve_tag: str | None = None,
        cvss_v3_severity: str | None = None,
        cvss_v4_severity: str | None = None,
        cwe_id: str | None = None,
        has_kev: bool = False,
        has_cert_alerts: bool = False,
        pub_start_date: str | None = None,
        pub_end_date: str | None = None,
        mod_start_date: str | None = None,
        mod_end_date: str | None = None,
        is_vulnerable: bool = False,
        results_per_page: int = 100,
        limit: int | None = None,
    ) -> list[CVERecord]:
        """Search NVD for CVEs matching the given filters.

        All parameters are optional; at least one should be supplied.
        """
        params: dict[str, Any] = {"resultsPerPage": min(results_per_page, _MAX_RESULTS_PER_PAGE)}

        if keyword:
            params["keywordSearch"] = keyword
            if keyword_exact:
                params["keywordExactMatch"] = ""
        if cpe_name:
            params["cpeName"] = cpe_name
        if cve_tag:
            params["cveTag"] = cve_tag
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()
        if cvss_v4_severity:
            params["cvssV4Severity"] = cvss_v4_severity.upper()
        if cwe_id:
            params["cweId"] = cwe_id
        if has_kev:
            params["hasKev"] = ""
        if has_cert_alerts:
            params["hasCertAlerts"] = ""
        if pub_start_date:
            params["pubStartDate"] = self._format_date(pub_start_date)
        if pub_end_date:
            params["pubEndDate"] = self._format_date(pub_end_date)
        if mod_start_date:
            params["lastModStartDate"] = self._format_date(mod_start_date)
        if mod_end_date:
            params["lastModEndDate"] = self._format_date(mod_end_date)
        if is_vulnerable and cpe_name:
            params["isVulnerable"] = ""

        results: list[CVERecord] = []
        for page_data in self._paginate(_CVE_URL, params):
            for item in page_data.get("vulnerabilities", []):
                results.append(CVERecord.from_nvd_json(item))
                if limit and len(results) >= limit:
                    return results
        return results

    def get_cve_history(
        self,
        cve_id: str,
        change_start_date: str | None = None,
        change_end_date: str | None = None,
    ) -> list[ChangeHistoryEvent]:
        """Fetch the complete change history for a CVE."""
        params: dict[str, Any] = {"cveId": cve_id}
        if change_start_date:
            params["changeStartDate"] = self._format_date(change_start_date)
        if change_end_date:
            params["changeEndDate"] = self._format_date(change_end_date)

        events: list[ChangeHistoryEvent] = []
        for page_data in self._paginate(_HISTORY_URL, params):
            for item in page_data.get("cveChanges", []):
                events.append(ChangeHistoryEvent.from_nvd_json(item))
        return events

    # ── Pagination ───────────────────────────────────────────────────────────

    def _paginate(
        self, url: str, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, None]:
        """Yield successive pages from a paginated NVD endpoint."""
        start_index = 0
        results_per_page = int(params.get("resultsPerPage", 100))

        while True:
            page_params = {**params, "startIndex": start_index}
            data = self._get(url, page_params)
            yield data

            total_results = data.get("totalResults", 0)
            returned = len(data.get("vulnerabilities", data.get("cveChanges", [])))
            start_index += returned

            if returned == 0 or start_index >= total_results:
                break

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _format_date(date_str: str) -> str:
        """Ensure a date string is in NVD's required ISO-8601 format."""
        if "T" not in date_str:
            return date_str + "T00:00:00.000"
        return date_str
