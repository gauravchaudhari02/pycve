"""Tests for pycve.cli — thin CLI layer."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pycve.cli import EXIT_ERROR, EXIT_NO_RESULTS, EXIT_OK, EXIT_INVALID_INPUT, build_parser, main
from pycve.models.cve import CVERecord
from pycve.models.patch import PatchInfo, PatchStatus
from pycve.models.kev import KEVEntry
from pycve.models.history import ChangeHistoryEvent, ChangeDetail
from pycve.models.stats import CVEStats

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_json(name: str) -> dict:
    import json as _json
    return _json.loads((FIXTURES / name).read_text())


# ── Helpers ────────────────────────────────────────────────────────────────────


def make_cve(cve_id="CVE-2021-44228", severity="CRITICAL", score=10.0) -> CVERecord:
    raw = fixture_json("sample_cve_response.json")["vulnerabilities"][0]
    record = CVERecord.from_nvd_json(raw)
    # Patch attributes for deterministic testing
    object.__setattr__(record, "id", cve_id) if False else None
    return record


def run_cli(*args: str) -> tuple[int, str]:
    """Run main() with given argv, capturing stdout."""
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


# ── Parser tests ──────────────────────────────────────────────────────────────


class TestParser:
    def test_lookup_positional_ids(self):
        parser = build_parser()
        args = parser.parse_args(["lookup", "CVE-2021-44228", "CVE-2023-44487"])
        assert args.command == "lookup"
        assert "CVE-2021-44228" in args.cve_ids

    def test_lookup_file_flag(self):
        parser = build_parser()
        args = parser.parse_args(["lookup", "--file", "cves.txt"])
        assert args.file == "cves.txt"

    def test_search_all_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "search", "--keyword", "log4j", "--severity", "CRITICAL",
            "--severity-v4", "HIGH", "--cpe", "cpe:2.3:a:apache:*",
            "--cwe", "CWE-502", "--cve-tag", "disputed",
            "--kev-only", "--cert-alerts", "--is-vulnerable",
            "--pub-start", "2021-01-01", "--pub-end", "2021-12-31",
            "--mod-start", "2022-01-01", "--mod-end", "2022-12-31",
            "--limit", "5",
        ])
        assert args.keyword == "log4j"
        assert args.severity == "CRITICAL"
        assert args.severity_v4 == "HIGH"
        assert args.cpe == "cpe:2.3:a:apache:*"
        assert args.cwe == "CWE-502"
        assert args.cve_tag == "disputed"
        assert args.kev_only is True
        assert args.cert_alerts is True
        assert args.is_vulnerable is True
        assert args.limit == 5

    def test_patch_command(self):
        parser = build_parser()
        args = parser.parse_args(["patch", "CVE-2021-44228"])
        assert args.command == "patch"
        assert "CVE-2021-44228" in args.cve_ids

    def test_kev_command(self):
        parser = build_parser()
        args = parser.parse_args(["kev", "CVE-2021-44228"])
        assert args.command == "kev"

    def test_history_command(self):
        parser = build_parser()
        args = parser.parse_args(["history", "CVE-2021-44228", "--start", "2022-01-01"])
        assert args.cve_id == "CVE-2021-44228"
        assert args.start == "2022-01-01"

    def test_report_command(self):
        parser = build_parser()
        args = parser.parse_args(["report", "--file", "cves.txt", "--format", "html", "--output", "out.html"])
        assert args.file == "cves.txt"
        assert args.format == "html"
        assert args.output == "out.html"

    def test_config_set(self):
        parser = build_parser()
        args = parser.parse_args(["config", "set", "api_key", "my-key"])
        assert args.config_cmd == "set"
        assert args.key == "api_key"
        assert args.value == "my-key"

    def test_config_get(self):
        parser = build_parser()
        args = parser.parse_args(["config", "get", "api_key"])
        assert args.config_cmd == "get"

    def test_config_list(self):
        parser = build_parser()
        args = parser.parse_args(["config", "list"])
        assert args.config_cmd == "list"

    def test_config_reset_all(self):
        parser = build_parser()
        args = parser.parse_args(["config", "reset"])
        assert args.config_cmd == "reset"

    def test_config_reset_key(self):
        parser = build_parser()
        args = parser.parse_args(["config", "reset", "api_key"])
        assert args.key == "api_key"

    def test_cache_stats(self):
        parser = build_parser()
        args = parser.parse_args(["cache", "stats"])
        assert args.cache_cmd == "stats"

    def test_cache_clear(self):
        parser = build_parser()
        args = parser.parse_args(["cache", "clear"])
        assert args.cache_cmd == "clear"

    def test_format_choices_valid(self):
        parser = build_parser()
        args = parser.parse_args(["lookup", "CVE-2021-44228", "--format", "json"])
        assert args.format == "json"

    def test_no_cache_flag(self):
        parser = build_parser()
        args = parser.parse_args(["lookup", "CVE-2021-44228", "--no-cache"])
        assert args.no_cache is True

    def test_api_key_flag(self):
        parser = build_parser()
        args = parser.parse_args(["lookup", "CVE-2021-44228", "--api-key", "test-key"])
        assert args.api_key == "test-key"

    def test_invalid_severity_rejected(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["search", "--severity", "EXTREME"])

    def test_missing_required_subcommand_exits(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["config"])


# ── lookup command ────────────────────────────────────────────────────────────


class TestLookupCommand:
    def _mock_client(self, cves):
        mock = MagicMock()
        mock.lookup.return_value = cves[0] if len(cves) == 1 else cves
        mock.lookup_from_file.return_value = cves
        return mock

    def test_lookup_single_table(self, cve_record):
        with patch("pycve.cli._make_client", return_value=self._mock_client([cve_record])):
            code, out = run_cli("lookup", "CVE-2021-44228")
        assert code == EXIT_OK
        assert "CVE-2021-44228" in out

    def test_lookup_single_json(self, cve_record):
        with patch("pycve.cli._make_client", return_value=self._mock_client([cve_record])):
            code, out = run_cli("lookup", "CVE-2021-44228", "--format", "json")
        assert code == EXIT_OK
        data = json.loads(out)
        assert isinstance(data, list)
        assert data[0]["id"] == "CVE-2021-44228"

    def test_lookup_minimal_format(self, cve_record):
        with patch("pycve.cli._make_client", return_value=self._mock_client([cve_record])):
            code, out = run_cli("lookup", "CVE-2021-44228", "--format", "minimal")
        assert code == EXIT_OK
        assert "CVE-2021-44228" in out
        assert "CRITICAL" in out

    def test_lookup_from_file(self, cve_record, tmp_path):
        f = tmp_path / "cves.txt"
        f.write_text("CVE-2021-44228\n")
        with patch("pycve.cli._make_client", return_value=self._mock_client([cve_record])):
            code, out = run_cli("lookup", "--file", str(f))
        assert code == EXIT_OK

    def test_lookup_no_ids_no_file_returns_error(self):
        code, _ = run_cli("lookup")
        assert code == EXIT_INVALID_INPUT

    def test_lookup_api_error_returns_error(self):
        from pycve.utils.exceptions import APIError
        mock = MagicMock()
        mock.lookup.side_effect = APIError("NVD unreachable")
        with patch("pycve.cli._make_client", return_value=mock):
            code, _ = run_cli("lookup", "CVE-2021-44228")
        assert code == EXIT_ERROR

    def test_lookup_no_results(self):
        mock = MagicMock()
        mock.lookup.return_value = []
        with patch("pycve.cli._make_client", return_value=mock):
            code, _ = run_cli("lookup", "CVE-2021-44228")
        assert code == EXIT_NO_RESULTS

    def test_lookup_writes_to_output_file(self, cve_record, tmp_path):
        out_file = tmp_path / "out.txt"
        with patch("pycve.cli._make_client", return_value=self._mock_client([cve_record])):
            code, out = run_cli("lookup", "CVE-2021-44228", "--output", str(out_file))
        assert code == EXIT_OK
        assert out_file.exists()


# ── search command ────────────────────────────────────────────────────────────


class TestSearchCommand:
    def test_search_returns_results(self, cve_record_list):
        mock = MagicMock()
        mock.search.return_value = cve_record_list
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("search", "--keyword", "log4j")
        assert code == EXIT_OK
        assert "CVE-2021-44228" in out

    def test_search_json_format(self, cve_record_list):
        mock = MagicMock()
        mock.search.return_value = cve_record_list
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("search", "--keyword", "log4j", "--format", "json")
        assert code == EXIT_OK
        data = json.loads(out)
        assert isinstance(data, list)

    def test_search_no_results(self):
        mock = MagicMock()
        mock.search.return_value = []
        with patch("pycve.cli._make_client", return_value=mock):
            code, _ = run_cli("search", "--keyword", "nonexistent")
        assert code == EXIT_NO_RESULTS

    def test_search_passes_all_filters(self, cve_record_list):
        mock = MagicMock()
        mock.search.return_value = cve_record_list
        with patch("pycve.cli._make_client", return_value=mock):
            run_cli(
                "search", "--keyword", "log4j",
                "--severity", "CRITICAL",
                "--kev-only",
                "--limit", "5",
            )
        mock.search.assert_called_once()
        call_kwargs = mock.search.call_args.kwargs
        assert call_kwargs["keyword"] == "log4j"
        assert call_kwargs["severity"] == "CRITICAL"
        assert call_kwargs["has_kev"] is True
        assert call_kwargs["limit"] == 5


# ── patch command ─────────────────────────────────────────────────────────────


class TestPatchCommand:
    def _patch_info(self, cve_id="CVE-2021-44228", status=PatchStatus.PATCHED):
        return PatchInfo(
            cve_id=cve_id,
            status=status,
            patch_urls=["https://github.com/org/repo/commit/abc"],
        )

    def test_patch_table(self):
        mock = MagicMock()
        mock.patch_check.return_value = self._patch_info()
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("patch", "CVE-2021-44228")
        assert code == EXIT_OK
        assert "PATCHED" in out

    def test_patch_json(self):
        mock = MagicMock()
        mock.patch_check.return_value = self._patch_info()
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("patch", "CVE-2021-44228", "--format", "json")
        assert code == EXIT_OK
        data = json.loads(out)
        assert data[0]["status"] == "PATCHED"

    def test_patch_multiple(self):
        mock = MagicMock()
        mock.patch_check.return_value = [
            self._patch_info("CVE-2021-44228", PatchStatus.PATCHED),
            self._patch_info("CVE-2023-44487", PatchStatus.UNPATCHED),
        ]
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("patch", "CVE-2021-44228", "CVE-2023-44487")
        assert code == EXIT_OK
        assert "CVE-2021-44228" in out

    def test_patch_api_error(self):
        from pycve.utils.exceptions import CVENotFoundError
        mock = MagicMock()
        mock.patch_check.side_effect = CVENotFoundError("CVE-9999-99999")
        with patch("pycve.cli._make_client", return_value=mock):
            code, _ = run_cli("patch", "CVE-9999-99999")
        assert code == EXIT_ERROR


# ── kev command ───────────────────────────────────────────────────────────────


class TestKEVCommand:
    def _kev_entry(self, cve_id="CVE-2021-44228", in_kev=True):
        if in_kev:
            from datetime import datetime
            return KEVEntry(
                cve_id=cve_id,
                in_kev_catalog=True,
                vendor_project="Apache",
                product="Log4j",
                due_date=datetime(2021, 12, 24),
            )
        return KEVEntry.not_in_catalog(cve_id)

    def test_kev_in_catalog_table(self):
        mock = MagicMock()
        mock.kev_check.return_value = self._kev_entry()
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("kev", "CVE-2021-44228")
        assert code == EXIT_OK
        assert "YES" in out
        assert "CVE-2021-44228" in out

    def test_kev_not_in_catalog(self):
        mock = MagicMock()
        mock.kev_check.return_value = self._kev_entry("CVE-9999-00001", in_kev=False)
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("kev", "CVE-9999-00001")
        assert code == EXIT_OK
        assert "NO" in out

    def test_kev_json_format(self):
        mock = MagicMock()
        mock.kev_check.return_value = self._kev_entry()
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("kev", "CVE-2021-44228", "--format", "json")
        assert code == EXIT_OK
        data = json.loads(out)
        assert data[0]["in_kev_catalog"] is True

    def test_kev_multiple(self):
        mock = MagicMock()
        mock.kev_check.return_value = [
            self._kev_entry("CVE-2021-44228", True),
            self._kev_entry("CVE-2023-44487", False),
        ]
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("kev", "CVE-2021-44228", "CVE-2023-44487")
        assert code == EXIT_OK
        assert "CVE-2021-44228" in out


# ── history command ───────────────────────────────────────────────────────────


class TestHistoryCommand:
    def _event(self):
        from datetime import datetime
        return ChangeHistoryEvent(
            cve_id="CVE-2021-44228",
            event_name="CVE Modified",
            created=datetime(2022, 3, 1, 10, 0),
            details=[ChangeDetail(action="Changed", type="CVSS V3 Severity",
                                  old_value="HIGH", new_value="CRITICAL")],
        )

    def test_history_table(self):
        mock = MagicMock()
        mock.history.return_value = [self._event()]
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("history", "CVE-2021-44228")
        assert code == EXIT_OK
        assert "CVE Modified" in out
        assert "CRITICAL" in out

    def test_history_json(self):
        mock = MagicMock()
        mock.history.return_value = [self._event()]
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("history", "CVE-2021-44228", "--format", "json")
        assert code == EXIT_OK
        data = json.loads(out)
        assert data[0]["event_name"] == "CVE Modified"

    def test_history_no_events(self):
        mock = MagicMock()
        mock.history.return_value = []
        with patch("pycve.cli._make_client", return_value=mock):
            code, _ = run_cli("history", "CVE-2021-44228")
        assert code == EXIT_NO_RESULTS

    def test_history_date_flags_passed(self):
        mock = MagicMock()
        mock.history.return_value = []
        with patch("pycve.cli._make_client", return_value=mock):
            run_cli("history", "CVE-2021-44228", "--start", "2022-01-01", "--end", "2023-01-01")
        mock.history.assert_called_once_with(
            "CVE-2021-44228",
            change_start_date="2022-01-01",
            change_end_date="2023-01-01",
        )


# ── report command ────────────────────────────────────────────────────────────


class TestReportCommand:
    def test_report_creates_file(self, cve_record_list, tmp_path):
        cve_file = tmp_path / "cves.txt"
        cve_file.write_text("CVE-2021-44228\n")
        out_file = tmp_path / "report.json"
        mock = MagicMock()
        mock.lookup_from_file.return_value = cve_record_list
        mock.report.return_value = str(out_file)
        with patch("pycve.cli._make_client", return_value=mock):
            code, out = run_cli("report", "--file", str(cve_file), "--output", str(out_file))
        assert code == EXIT_OK
        assert str(out_file) in out

    def test_report_no_cves_in_file(self, tmp_path):
        cve_file = tmp_path / "empty.txt"
        cve_file.write_text("")
        mock = MagicMock()
        mock.lookup_from_file.return_value = []
        with patch("pycve.cli._make_client", return_value=mock):
            code, _ = run_cli("report", "--file", str(cve_file))
        assert code == EXIT_NO_RESULTS

    def test_report_missing_dependency_error(self, tmp_path):
        from pycve.utils.exceptions import MissingDependencyError
        cve_file = tmp_path / "cves.txt"
        cve_file.write_text("CVE-2021-44228\n")
        mock = MagicMock()
        mock.lookup_from_file.return_value = [MagicMock()]
        mock.report.side_effect = MissingDependencyError("fpdf2", "PDF reports", "reports")
        with patch("pycve.cli._make_client", return_value=mock):
            code, _ = run_cli("report", "--file", str(cve_file), "--format", "pdf")
        assert code == EXIT_ERROR


# ── config command ────────────────────────────────────────────────────────────


class TestConfigCommand:
    def test_config_set(self, tmp_path):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            code, out = run_cli("config", "set", "api_key", "my-test-key")
        assert code == EXIT_OK
        instance.config.set.assert_called_once_with("api_key", "my-test-key")

    def test_config_get(self, tmp_path):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            instance.config.get.return_value = "stored-key"
            code, out = run_cli("config", "get", "api_key")
        assert code == EXIT_OK
        assert "stored-key" in out

    def test_config_get_not_set(self):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            instance.config.get.return_value = None
            code, out = run_cli("config", "get", "api_key")
        assert code == EXIT_OK
        assert "not set" in out

    def test_config_list_table(self):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            instance.config.list.return_value = {"api_key": None, "cache_ttl": 86400}
            code, out = run_cli("config", "list")
        assert code == EXIT_OK
        assert "api_key" in out
        assert "cache_ttl" in out

    def test_config_list_json(self):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            instance.config.list.return_value = {"api_key": None, "cache_ttl": 86400}
            code, out = run_cli("config", "list", "--format", "json")
        assert code == EXIT_OK
        data = json.loads(out)
        assert "api_key" in data

    def test_config_reset_all(self):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            code, out = run_cli("config", "reset")
        assert code == EXIT_OK
        instance.config.reset.assert_called_once()

    def test_config_reset_key(self):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            code, out = run_cli("config", "reset", "api_key")
        assert code == EXIT_OK
        instance.config.reset.assert_called_once_with("api_key")

    def test_config_error_propagated(self):
        from pycve.utils.exceptions import ConfigError
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            instance.config.set.side_effect = ConfigError("Unknown key")
            code, _ = run_cli("config", "set", "bad_key", "value")
        assert code == EXIT_ERROR


# ── cache command ─────────────────────────────────────────────────────────────


class TestCacheCommand:
    def test_cache_stats_table(self):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            instance.cache.stats.return_value = {
                "entries": 10, "valid_entries": 8, "expired_entries": 2,
                "size_mb": 0.5, "hit_rate": 0.85, "hits": 17, "misses": 3,
                "db_path": "/tmp/cache.db",
            }
            code, out = run_cli("cache", "stats")
        assert code == EXIT_OK
        assert "entries" in out

    def test_cache_stats_json(self):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            instance.cache.stats.return_value = {"entries": 5, "hit_rate": 0.9}
            code, out = run_cli("cache", "stats", "--format", "json")
        assert code == EXIT_OK
        data = json.loads(out)
        assert data["entries"] == 5

    def test_cache_clear(self):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            instance.cache.clear.return_value = 42
            code, out = run_cli("cache", "clear")
        assert code == EXIT_OK
        assert "42" in out

    def test_cache_disabled_returns_error(self):
        with patch("pycve.PyCVE") as MockPyCVE:
            instance = MockPyCVE.return_value
            instance.cache = None
            code, _ = run_cli("cache", "stats")
        assert code == EXIT_ERROR
