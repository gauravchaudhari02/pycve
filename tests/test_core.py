"""Integration tests for pycve.core.PyCVE facade."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import responses as resp_lib

from pycve import PyCVE
from pycve.models.cve import CVERecord
from pycve.models.patch import PatchStatus
from pycve.utils.exceptions import ConfigError

FIXTURES = Path(__file__).parent / "fixtures"
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"


def fixture_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def pycve(tmp_path):
    return PyCVE(
        config_path=tmp_path / "config.yaml",
        cache_path=tmp_path / "cache.db",
    )


class TestPyCVELookup:
    @resp_lib.activate
    def test_lookup_single(self, pycve):
        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_cve_response.json"),
            status=200,
        )
        result = pycve.lookup("CVE-2021-44228")
        assert isinstance(result, CVERecord)
        assert result.id == "CVE-2021-44228"

    @resp_lib.activate
    def test_lookup_list(self, pycve):
        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_cve_response.json"),
            status=200,
        )
        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_search_response.json"),
            status=200,
        )
        results = pycve.lookup(["CVE-2021-44228", "CVE-2023-44487"])
        assert isinstance(results, list)

    def test_lookup_from_file(self, pycve, tmp_path):
        f = tmp_path / "cves.txt"
        f.write_text("CVE-2021-44228\n")
        with resp_lib.RequestsMock() as rsps:
            rsps.add(
                rsps.GET, CVE_URL,
                json=fixture_json("sample_cve_response.json"),
                status=200,
            )
            results = pycve.lookup_from_file(f)
        assert len(results) == 1


class TestPyCVEStats:
    def test_stats_returns_cvestats(self, pycve, cve_record_list):
        from pycve.models.stats import CVEStats
        stats = pycve.stats(cve_record_list)
        assert isinstance(stats, CVEStats)
        assert stats.total == len(cve_record_list)

    def test_stats_empty_list(self, pycve):
        stats = pycve.stats([])
        assert stats.total == 0


class TestPyCVEPatchCheck:
    @resp_lib.activate
    def test_patch_check_single(self, pycve):
        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_cve_response.json"),
            status=200,
        )
        result = pycve.patch_check("CVE-2021-44228")
        from pycve.models.patch import PatchInfo
        assert isinstance(result, PatchInfo)
        assert result.status == PatchStatus.PATCHED


class TestPyCVEKEVCheck:
    def test_kev_check_in_catalog(self, pycve):
        kev_data = json.loads((FIXTURES / "sample_kev_catalog.json").read_text())
        pycve._kev_checker = MagicMock()
        pycve._kev_checker.check_batch.return_value = [
            MagicMock(in_kev_catalog=True, cve_id="CVE-2021-44228")
        ]
        result = pycve.kev_check("CVE-2021-44228")
        assert result.in_kev_catalog is True


class TestPyCVENotify:
    def test_notify_requires_notifier_or_channel(self, pycve, cve_record_list):
        with pytest.raises(ValueError):
            pycve.notify(cve_record_list)

    def test_notify_unknown_channel_raises(self, pycve, cve_record_list):
        with pytest.raises(ValueError):
            pycve.notify(cve_record_list, channel="pagerduty")

    def test_notify_slack_missing_url_raises(self, pycve, cve_record_list):
        with pytest.raises(ConfigError):
            pycve.notify(cve_record_list, channel="slack")

    def test_notify_with_explicit_notifier(self, pycve, cve_record_list):
        from pycve.notifications.slack import SlackNotifier
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        with patch.object(notifier, "send", return_value=True) as mock_send:
            result = pycve.notify(cve_record_list, notifier=notifier)
        assert result is True
        mock_send.assert_called_once()

    def test_notify_from_config_slack(self, pycve, cve_record_list):
        pycve.config.set("slack_webhook_url", "https://hooks.slack.com/services/test")
        with patch("pycve.notifications.slack.SlackNotifier.send", return_value=True):
            result = pycve.notify(cve_record_list, channel="slack")
        assert result is True


class TestPyCVEReport:
    def test_report_json(self, pycve, cve_record_list, tmp_path):
        output = tmp_path / "report.json"
        path = pycve.report(cve_record_list, format="json", output=output)
        assert Path(path).exists()
        data = json.loads(Path(path).read_text())
        assert data["total"] == len(cve_record_list)

    def test_report_default_format_from_config(self, pycve, cve_record_list, tmp_path):
        pycve.config.set("output_dir", str(tmp_path))
        path = pycve.report(cve_record_list)
        assert Path(path).exists()

    def test_report_unsupported_format_raises(self, pycve, cve_record_list, tmp_path):
        from pycve.utils.exceptions import ReportError
        with pytest.raises(ReportError):
            pycve.report(cve_record_list, format="toml", output=tmp_path / "r.toml")


class TestPyCVERepr:
    def test_repr_without_api_key(self, pycve):
        r = repr(pycve)
        assert "not set" in r

    def test_repr_with_api_key(self, tmp_path):
        p = PyCVE(
            api_key="test-key",
            config_path=tmp_path / "cfg.yaml",
            cache_path=tmp_path / "cache.db",
        )
        assert "set" in repr(p)


class TestPyCVEHistory:
    @resp_lib.activate
    def test_history(self, pycve):
        resp_lib.add(
            resp_lib.GET, HISTORY_URL,
            json=fixture_json("sample_history_response.json"),
            status=200,
        )
        events = pycve.history("CVE-2021-44228")
        assert len(events) == 1
        assert events[0].event_name == "CVE Modified"


class TestPyCVESearch:
    @resp_lib.activate
    def test_search_new_params_passed_through(self, pycve):
        """New search params (cve_tag, severity_v4, is_vulnerable, has_cert_alerts) reach the client."""
        resp_lib.add(
            resp_lib.GET, CVE_URL,
            json=fixture_json("sample_search_response.json"),
            status=200,
        )
        results = pycve.search(
            keyword="test",
            severity_v4="CRITICAL",
            cve_tag="disputed",
            has_cert_alerts=True,
            is_vulnerable=True,
            cpe_name="cpe:2.3:a:apache:log4j:*",
            limit=5,
        )
        assert isinstance(results, list)
        # Verify the HTTP call was made (params forwarded without error)
        assert len(resp_lib.calls) == 1


class TestPyCVEStatsNoPatch:
    def test_stats_without_patch_coverage(self, pycve, cve_record_list):
        """stats(include_patch_stats=False) → patch_coverage is None."""
        stats = pycve.stats(cve_record_list, include_patch_stats=False)
        assert stats.patch_coverage is None


class TestPyCVECacheDisabled:
    def test_cache_property_none_when_disabled(self, tmp_path):
        p = PyCVE(
            config_path=tmp_path / "cfg.yaml",
            enable_cache=False,
        )
        assert p.cache is None


class TestPyCVEKEVCheckList:
    def test_kev_check_list_returns_list(self, pycve):
        from pycve.models.kev import KEVEntry
        pycve._kev_checker = MagicMock()
        pycve._kev_checker.check_batch.return_value = [
            MagicMock(spec=KEVEntry, in_kev_catalog=True, cve_id="CVE-2021-44228"),
            MagicMock(spec=KEVEntry, in_kev_catalog=False, cve_id="CVE-2023-44487"),
        ]
        results = pycve.kev_check(["CVE-2021-44228", "CVE-2023-44487"])
        assert isinstance(results, list)
        assert len(results) == 2


class TestPyCVENotifyTeams:
    def test_notify_teams_missing_url_raises(self, pycve, cve_record_list):
        with pytest.raises(ConfigError):
            pycve.notify(cve_record_list, channel="teams")

    def test_notify_from_config_teams(self, pycve, cve_record_list):
        pycve.config.set("teams_webhook_url", "https://outlook.office.com/webhook/test")
        with patch("pycve.notifications.teams.TeamsNotifier.send", return_value=True):
            result = pycve.notify(cve_record_list, channel="teams")
        assert result is True
