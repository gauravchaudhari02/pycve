"""PyCVE facade — the primary public interface for the library."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pycve.analysis.kev_checker import KEVChecker
from pycve.analysis.patch_analyzer import PatchAnalyzer
from pycve.analysis.severity_stats import SeverityStatsCalculator
from pycve.api.client import NVDClient
from pycve.cache.manager import CacheManager
from pycve.config.settings import ConfigManager
from pycve.models.cve import CVERecord
from pycve.models.history import ChangeHistoryEvent
from pycve.models.kev import KEVEntry
from pycve.models.patch import PatchInfo
from pycve.models.stats import CVEStats
from pycve.notifications.base import BaseNotifier
from pycve.parsers.file_parser import parse_cve_file
from pycve.reports.generator import ReportGenerator
from pycve.utils.exceptions import ConfigError, NotificationError
from pycve.utils.validators import validate_and_normalize_cve_ids

logger = logging.getLogger(__name__)


class PyCVE:
    """High-level facade providing a single entry point to all pycve features.

    Parameters
    ----------
    api_key:
        NVD API key. Takes priority over env var and config file.
        If omitted the library falls back to ``NVD_API_KEY`` env var or
        the config file.
    config_path:
        Override path for the YAML configuration file
        (default: ``~/.pycve/config.yaml``).
    cache_path:
        Override path for the SQLite cache database
        (default: ``~/.pycve/cache.db``).
    cache_ttl:
        Cache time-to-live in seconds (default: 86 400 = 24 h).
    enable_cache:
        Set to ``False`` to disable caching entirely (default: ``True``).
    request_timeout:
        HTTP timeout for NVD API calls in seconds (default: 30).

    Examples
    --------
    >>> from pycve import PyCVE
    >>> cve = PyCVE(api_key="your-key")
    >>> result = cve.lookup("CVE-2021-44228")
    >>> print(result.severity, result.cvss_score)
    CRITICAL 10.0
    """

    def __init__(
        self,
        api_key: str | None = None,
        config_path: str | Path | None = None,
        cache_path: str | Path | None = None,
        cache_ttl: int | None = None,
        enable_cache: bool = True,
        request_timeout: int = 30,
    ):
        # Config (api_key is explicit override)
        self._config = ConfigManager(
            config_path=config_path,
            overrides={"api_key": api_key} if api_key else {},
        )

        # Resolve effective API key
        effective_api_key = self._config.get("api_key")
        effective_ttl = cache_ttl or int(self._config.get("cache_ttl") or 86400)

        # Cache
        if enable_cache:
            self._cache: CacheManager | None = CacheManager(
                db_path=cache_path, default_ttl=effective_ttl
            )
        else:
            self._cache = None

        # NVD client
        self._client = NVDClient(
            api_key=effective_api_key,
            cache=self._cache,
            timeout=request_timeout,
        )

        # Analysis helpers (lazy instantiation of KEV checker)
        self._patch_analyzer = PatchAnalyzer()
        self._stats_calc = SeverityStatsCalculator()
        self._kev_checker: KEVChecker | None = None
        self._report_gen = ReportGenerator()

    # ── Private helpers ──────────────────────────────────────────────────────

    def _kev(self) -> KEVChecker:
        """Lazily instantiate a :class:`KEVChecker`."""
        if self._kev_checker is None:
            self._kev_checker = KEVChecker(cache_ttl=int(self._config.get("cache_ttl") or 86400))
        return self._kev_checker

    # ── Lookup ───────────────────────────────────────────────────────────────

    def lookup(self, cve_ids: str | list[str]) -> CVERecord | list[CVERecord]:
        """Fetch one or more CVEs from NVD by ID.

        Parameters
        ----------
        cve_ids:
            A single CVE-ID string or a list of CVE-IDs.

        Returns
        -------
        :class:`~pycve.models.cve.CVERecord`
            When a single ID is passed.
        list[:class:`~pycve.models.cve.CVERecord`]
            When a list is passed.
        """
        single = isinstance(cve_ids, str)
        ids = validate_and_normalize_cve_ids(cve_ids)
        results = self._client.get_cves(ids)
        return results[0] if single and results else results

    def lookup_from_file(self, file_path: str | Path) -> list[CVERecord]:
        """Parse CVE IDs from a file and fetch them all from NVD.

        Supported formats: ``.txt``, ``.csv``, ``.json``, ``.xlsx``

        Parameters
        ----------
        file_path:
            Path to the input file.
        """
        ids = parse_cve_file(file_path)
        logger.info("Parsed %d CVE IDs from %s", len(ids), file_path)
        return self._client.get_cves(ids)

    # ── Search ───────────────────────────────────────────────────────────────

    def search(
        self,
        *,
        keyword: str | None = None,
        keyword_exact: bool = False,
        severity: str | None = None,
        severity_v4: str | None = None,
        cpe_name: str | None = None,
        cwe_id: str | None = None,
        cve_tag: str | None = None,
        has_kev: bool = False,
        has_cert_alerts: bool = False,
        is_vulnerable: bool = False,
        pub_start_date: str | None = None,
        pub_end_date: str | None = None,
        mod_start_date: str | None = None,
        mod_end_date: str | None = None,
        limit: int | None = None,
        results_per_page: int = 100,
    ) -> list[CVERecord]:
        """Search NVD for CVEs matching the given criteria.

        All parameters are optional — supply at least one filter.

        Parameters
        ----------
        keyword:
            Free-text keyword search.
        keyword_exact:
            If ``True``, match the keyword phrase exactly.
        severity:
            CVSS v3 severity filter: ``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``.
        severity_v4:
            CVSS v4 severity filter: ``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``.
        cpe_name:
            CPE 2.3 URI to filter applicable products.
        cwe_id:
            CWE identifier to filter by weakness type (e.g. ``CWE-79``).
        cve_tag:
            NVD CVE tag filter (e.g. ``"disputed"``, ``"unsupported-when-assigned"``).
        has_kev:
            If ``True``, only return CVEs present in CISA KEV catalog.
        has_cert_alerts:
            If ``True``, only return CVEs with US-CERT alerts.
        is_vulnerable:
            If ``True`` and *cpe_name* is set, only return CVEs where that CPE
            is marked as vulnerable (not just mentioned).
        pub_start_date / pub_end_date:
            Publication date range (ISO 8601 format).
        mod_start_date / mod_end_date:
            Last-modified date range.
        limit:
            Maximum number of results to return.
        results_per_page:
            NVD API page size (max 2 000).
        """
        return self._client.search_cves(
            keyword=keyword,
            keyword_exact=keyword_exact,
            cvss_v3_severity=severity,
            cvss_v4_severity=severity_v4,
            cpe_name=cpe_name,
            cwe_id=cwe_id,
            cve_tag=cve_tag,
            has_kev=has_kev,
            has_cert_alerts=has_cert_alerts,
            is_vulnerable=is_vulnerable,
            pub_start_date=pub_start_date,
            pub_end_date=pub_end_date,
            mod_start_date=mod_start_date,
            mod_end_date=mod_end_date,
            limit=limit,
            results_per_page=results_per_page,
        )

    # ── Patch Check ──────────────────────────────────────────────────────────

    def patch_check(
        self, cve_ids: str | list[str]
    ) -> PatchInfo | list[PatchInfo]:
        """Analyse patch availability for one or more CVE IDs.

        Fetches the records from NVD then runs :class:`~pycve.analysis.patch_analyzer.PatchAnalyzer`.
        """
        single = isinstance(cve_ids, str)
        cves = self.lookup(cve_ids) if single else self.lookup(cve_ids)
        if single:
            cves = [cves] if isinstance(cves, CVERecord) else cves
        results = self._patch_analyzer.analyze_batch(cves)
        return results[0] if single and results else results

    # ── Generate Patch File ───────────────────────────────────────────────────

    def generate_patch_file(
        self,
        cve_id: str,
        output: str | Path | None = None,
        *,
        combine: bool = False,
    ) -> "str | list[str] | None":
        """Fetch a CVE by ID, download its patch(es), and write ``.patch`` file(s) locally.

        For each patch-tagged GitHub commit or pull-request URL found in the
        CVE references, the function fetches the unified-diff content (by
        appending ``.patch`` to the URL) and writes it as a ``.patch`` file.
        When multiple patches are found you can either merge them into one file
        (``combine=True``) or keep them separate (``combine=False``, default).

        Parameters
        ----------
        cve_id:
            A single CVE identifier, e.g. ``"CVE-2021-44228"``.
        output:
            * ``combine=True`` — full file path for the combined patch
              (default: ``<output_dir>/<CVE_ID>.patch``).
            * ``combine=False`` — directory where individual patch files are
              written (default: ``output_dir`` or current working directory).
              Files are named ``<CVE_ID>_1.patch``, ``<CVE_ID>_2.patch``, …
        combine:
            If ``True`` and multiple patches are found, merge them into a
            single file.  Default is ``False`` (one file per patch).

        Returns
        -------
        str
            Absolute path when ``combine=True`` or only one patch is found.
        list[str]
            List of absolute paths when ``combine=False`` and multiple patches.
        None
            When no downloadable patch content is found for the CVE.

        Raises
        ------
        :exc:`~pycve.utils.exceptions.CVENotFoundError`
            If the CVE ID is not found in the NVD database.
        :exc:`~pycve.utils.exceptions.InvalidCVEIdError`
            If *cve_id* is not a valid CVE identifier.

        Examples
        --------
        >>> cve = PyCVE(api_key="your-key")

        >>> # Single patch — returns the path of the .patch file
        >>> path = cve.generate_patch_file("CVE-2021-44228", output="/tmp/patches")

        >>> # Multiple patches, combined into one file
        >>> path = cve.generate_patch_file("CVE-2021-44228", output="/tmp/all.patch", combine=True)

        >>> # Multiple patches, one file each (default)
        >>> paths = cve.generate_patch_file("CVE-2021-44228", output="/tmp/patches")

        >>> # No patch available
        >>> print(cve.generate_patch_file("CVE-2023-99999"))  # None
        """
        import re

        import requests as _requests

        from pycve.utils.validators import normalize_cve_id

        cve_id = normalize_cve_id(cve_id)

        # 1. Fetch CVE and analyse patch availability
        cve_record = self._client.get_cve(cve_id)
        patch_info = self._patch_analyzer.analyze(cve_record)

        if not patch_info.is_patched:
            logger.info(
                "No patch available for %s (status: %s)", cve_id, patch_info.status.value
            )
            return None

        # 2. Collect GitHub commit / PR URLs that can yield a downloadable .patch
        _gh_pattern = re.compile(
            r"github\.com/[^/]+/[^/]+/(commit|pull)/[a-f0-9]+",
            re.IGNORECASE,
        )
        seen: set[str] = set()
        candidate_urls: list[str] = []
        for url in patch_info.patch_urls + patch_info.commit_urls:
            if url not in seen and _gh_pattern.search(url):
                seen.add(url)
                candidate_urls.append(url)

        if not candidate_urls:
            logger.info("No downloadable patch URLs found for %s", cve_id)
            return None

        # 3. Fetch patch content (unified diff) for each candidate URL
        patches: list[tuple[str, str]] = []  # (source_url, diff_text)
        session = _requests.Session()
        session.headers["User-Agent"] = "pycve patch-fetcher"
        for url in candidate_urls:
            patch_url = url if url.endswith(".patch") else url + ".patch"
            try:
                resp = session.get(patch_url, timeout=30, allow_redirects=True)
                if resp.status_code == 200 and resp.text.strip():
                    patches.append((url, resp.text))
                    logger.debug("Fetched patch from %s", patch_url)
                else:
                    logger.warning(
                        "Could not fetch patch from %s (HTTP %s)", patch_url, resp.status_code
                    )
            except _requests.RequestException as exc:
                logger.warning("Failed to fetch %s: %s", patch_url, exc)

        if not patches:
            logger.info("No patch content could be downloaded for %s", cve_id)
            return None

        # 4. Write .patch file(s)
        safe_id = cve_id.replace("-", "_")
        out_base = Path(self._config.get("output_dir") or ".")

        if combine:
            out_file = Path(output) if output is not None else out_base / f"{safe_id}.patch"
            out_file.parent.mkdir(parents=True, exist_ok=True)
            combined = "\n\n".join(
                f"# Source: {url}\n{content}" for url, content in patches
            )
            out_file.write_text(combined, encoding="utf-8")
            logger.info("Wrote combined patch file: %s", out_file)
            return str(out_file.resolve())

        # Separate files — output is treated as a directory
        out_dir = Path(output) if output is not None else out_base
        out_dir.mkdir(parents=True, exist_ok=True)
        paths: list[str] = []
        for i, (url, content) in enumerate(patches, start=1):
            out_file = out_dir / f"{safe_id}_{i}.patch"
            out_file.write_text(content, encoding="utf-8")
            logger.info("Wrote patch file %d/%d: %s", i, len(patches), out_file)
            paths.append(str(out_file.resolve()))

        return paths[0] if len(paths) == 1 else paths

    # ── Stats ────────────────────────────────────────────────────────────────

    def stats(
        self,
        cves: list[CVERecord],
        include_patch_stats: bool = True,
    ) -> CVEStats:
        """Compute aggregated statistics over a list of CVE records.

        Parameters
        ----------
        cves:
            List of :class:`~pycve.models.cve.CVERecord` objects.
        include_patch_stats:
            If ``True`` (default), also compute patch coverage statistics.
        """
        patch_infos = self._patch_analyzer.analyze_batch(cves) if include_patch_stats else None
        return self._stats_calc.calculate(cves, patch_infos)

    # ── History ──────────────────────────────────────────────────────────────

    def history(
        self,
        cve_id: str,
        change_start_date: str | None = None,
        change_end_date: str | None = None,
    ) -> list[ChangeHistoryEvent]:
        """Return the NVD change history for a CVE.

        Parameters
        ----------
        cve_id:
            The CVE to look up.
        change_start_date / change_end_date:
            Optional date range for the history query (ISO 8601).
        """
        return self._client.get_cve_history(
            cve_id=cve_id,
            change_start_date=change_start_date,
            change_end_date=change_end_date,
        )

    # ── KEV Check ────────────────────────────────────────────────────────────

    def kev_check(
        self, cve_ids: str | list[str]
    ) -> KEVEntry | list[KEVEntry]:
        """Check one or more CVE IDs against the CISA KEV catalog.

        Downloads and caches the catalog on first call.
        """
        single = isinstance(cve_ids, str)
        ids = validate_and_normalize_cve_ids(cve_ids)
        results = self._kev().check_batch(ids)
        return results[0] if single and results else results

    # ── Report ───────────────────────────────────────────────────────────────

    def report(
        self,
        cves: list[CVERecord],
        format: str | None = None,
        output: str | Path | None = None,
    ) -> str:
        """Generate a report file from a list of CVE records.

        Parameters
        ----------
        cves:
            Vulnerability records to include.
        format:
            Output format: ``json``, ``html``, ``pdf``, ``excel``.
            Defaults to the ``default_report_format`` config setting.
        output:
            Destination file path.  If ``None``, auto-generates a name in
            the ``output_dir`` config directory.
        """
        fmt = format or self._config.get("default_report_format") or "json"
        ext = {"excel": "xlsx"}.get(fmt.lower(), fmt.lower())
        if output is None:
            out_dir = Path(self._config.get("output_dir") or ".")
            output = out_dir / f"pycve_report.{ext}"
        return self._report_gen.generate(cves, format=fmt, output_path=output)

    # ── Notify ───────────────────────────────────────────────────────────────

    def notify(
        self,
        cves: list[CVERecord],
        *,
        notifier: BaseNotifier | None = None,
        channel: str | None = None,
        template: str = "summary",
    ) -> bool:
        """Send a CVE notification to Slack or Teams.

        Parameters
        ----------
        cves:
            The CVE records to include in the notification.
        notifier:
            A pre-configured :class:`~pycve.notifications.base.BaseNotifier`
            instance (e.g. ``SlackNotifier(webhook_url="...")``).
        channel:
            ``"slack"`` or ``"teams"`` — uses the webhook URL stored in
            config.  Requires ``slack_webhook_url`` or ``teams_webhook_url``
            to be configured.
        template:
            Notification template: ``"critical_alert"``, ``"summary"``, ``"digest"``.

        Returns
        -------
        bool
            ``True`` if the notification was delivered successfully.

        Raises
        ------
        :exc:`~pycve.utils.exceptions.NotificationError`
            On delivery failure.
        :exc:`ValueError`
            If neither *notifier* nor *channel* is supplied, or a configured
            webhook URL is missing for the requested *channel*.
        """
        from pycve.notifications.slack import SlackNotifier
        from pycve.notifications.teams import TeamsNotifier

        # Resolve notifier
        _notifier = notifier
        if _notifier is None:
            if channel is None:
                raise ValueError("Supply either 'notifier' or 'channel' ('slack'/'teams').")
            channel_lower = channel.lower()
            if channel_lower == "slack":
                url = self._config.get("slack_webhook_url")
                if not url:
                    raise ConfigError(
                        "No Slack webhook URL configured. "
                        "Set it with: cve.config.set('slack_webhook_url', 'https://...')"
                    )
                _notifier = SlackNotifier(webhook_url=url)
            elif channel_lower == "teams":
                url = self._config.get("teams_webhook_url")
                if not url:
                    raise ConfigError(
                        "No Teams webhook URL configured. "
                        "Set it with: cve.config.set('teams_webhook_url', 'https://...')"
                    )
                _notifier = TeamsNotifier(webhook_url=url)
            else:
                raise ValueError(f"Unknown channel: '{channel}'. Choose 'slack' or 'teams'.")

        message = _notifier.format_cves(cves, template=template)
        return _notifier.send(message)

    # ── Config & Cache properties ─────────────────────────────────────────────

    @property
    def config(self) -> ConfigManager:
        """Access the :class:`~pycve.config.settings.ConfigManager` directly."""
        return self._config

    @property
    def cache(self) -> CacheManager | None:
        """Access the :class:`~pycve.cache.manager.CacheManager`, or ``None`` if disabled."""
        return self._cache

    def __repr__(self) -> str:
        api_key_set = bool(self._config.get("api_key"))
        cache_on = self._cache is not None
        return f"PyCVE(api_key={'set' if api_key_set else 'not set'}, cache={'on' if cache_on else 'off'})"
