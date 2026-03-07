"""Tests for pycve.utils.validators."""

from __future__ import annotations

import pytest

from pycve.utils.exceptions import InvalidCVEIdError
from pycve.utils.validators import (
    extract_cve_ids_from_text,
    normalize_cve_id,
    validate_and_normalize_cve_ids,
    validate_cve_id,
    validate_date,
    validate_file_path,
    validate_severity,
)


class TestValidateCVEId:
    @pytest.mark.parametrize("cve_id", [
        "CVE-2021-44228",
        "CVE-2023-00001",
        "CVE-1999-12345",
        "cve-2021-44228",  # lowercase should be accepted
    ])
    def test_valid_ids(self, cve_id):
        assert validate_cve_id(cve_id) is True

    @pytest.mark.parametrize("cve_id", [
        "CVE-202-4422",     # year too short
        "2021-44228",       # missing CVE prefix
        "CVE-2021-123",     # sequence too short
        "",
        "not-a-cve",
        None,
    ])
    def test_invalid_ids(self, cve_id):
        assert validate_cve_id(cve_id) is False


class TestNormalizeCVEId:
    def test_returns_uppercase(self):
        assert normalize_cve_id("cve-2021-44228") == "CVE-2021-44228"

    def test_strips_whitespace(self):
        assert normalize_cve_id("  CVE-2021-44228  ") == "CVE-2021-44228"

    def test_raises_on_invalid(self):
        with pytest.raises(InvalidCVEIdError):
            normalize_cve_id("NOT-A-CVE")


class TestValidateAndNormalize:
    def test_single_string(self):
        result = validate_and_normalize_cve_ids("CVE-2021-44228")
        assert result == ["CVE-2021-44228"]

    def test_deduplication(self):
        result = validate_and_normalize_cve_ids(
            ["CVE-2021-44228", "cve-2021-44228", "CVE-2021-44228"]
        )
        assert result == ["CVE-2021-44228"]

    def test_raises_on_any_invalid(self):
        with pytest.raises(InvalidCVEIdError):
            validate_and_normalize_cve_ids(["CVE-2021-44228", "invalid"])


class TestValidateSeverity:
    @pytest.mark.parametrize("sev", ["LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "High"])
    def test_valid_severities(self, sev):
        assert validate_severity(sev) is True

    def test_invalid_severity(self):
        assert validate_severity("EXTREME") is False


class TestValidateDate:
    def test_valid_date(self):
        assert validate_date("2021-12-10") is True

    def test_valid_datetime(self):
        assert validate_date("2021-12-10T10:15:09") is True

    def test_invalid_date(self):
        assert validate_date("not-a-date") is False


class TestExtractCVEIds:
    def test_extracts_from_text(self):
        text = "Found CVE-2021-44228 and CVE-2023-44487 in the logs."
        result = extract_cve_ids_from_text(text)
        assert "CVE-2021-44228" in result
        assert "CVE-2023-44487" in result

    def test_deduplicates(self):
        text = "CVE-2021-44228 CVE-2021-44228 CVE-2021-44228"
        result = extract_cve_ids_from_text(text)
        assert result == ["CVE-2021-44228"]

    def test_empty_text(self):
        assert extract_cve_ids_from_text("no cves here") == []


class TestValidateFilePath:
    def test_existing_file_returns_true(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("CVE-2021-44228")
        assert validate_file_path(str(f)) is True

    def test_nonexistent_path_returns_false(self, tmp_path):
        assert validate_file_path(str(tmp_path / "ghost.txt")) is False

    def test_directory_returns_false(self, tmp_path):
        assert validate_file_path(str(tmp_path)) is False
