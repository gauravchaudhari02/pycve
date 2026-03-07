"""Tests for pycve.parsers.file_parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from pycve.parsers.file_parser import parse_cve_file
from pycve.utils.exceptions import ParserError

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseCVEFile:
    def test_parse_txt(self):
        ids = parse_cve_file(FIXTURES / "sample_cves.txt")
        assert "CVE-2021-44228" in ids
        assert "CVE-2023-44487" in ids
        assert "CVE-2023-00001" in ids
        assert len(ids) == 3  # comments should be ignored

    def test_parse_csv(self):
        ids = parse_cve_file(FIXTURES / "sample_cves.csv")
        assert "CVE-2021-44228" in ids
        assert "CVE-2023-44487" in ids
        assert len(ids) == 3

    def test_parse_json(self):
        ids = parse_cve_file(FIXTURES / "sample_cves.json")
        assert "CVE-2021-44228" in ids
        assert "CVE-2023-44487" in ids
        assert len(ids) == 3

    def test_file_not_found(self):
        with pytest.raises(ParserError, match="File not found"):
            parse_cve_file("/nonexistent/path/cves.txt")

    def test_unsupported_format(self, tmp_path):
        f = tmp_path / "cves.xyz"
        f.write_text("CVE-2021-44228")
        with pytest.raises(ParserError, match="Unsupported file format"):
            parse_cve_file(f)

    def test_deduplication(self, tmp_path):
        f = tmp_path / "cves.txt"
        f.write_text("CVE-2021-44228\nCVE-2021-44228\ncve-2021-44228\n")
        ids = parse_cve_file(f)
        assert ids.count("CVE-2021-44228") == 1

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        ids = parse_cve_file(f)
        assert ids == []

    def test_json_list_of_dicts(self, tmp_path):
        import json
        f = tmp_path / "cves.json"
        data = [
            {"cve_id": "CVE-2021-44228", "severity": "CRITICAL"},
            {"id": "CVE-2023-44487"},
        ]
        f.write_text(json.dumps(data))
        ids = parse_cve_file(f)
        assert "CVE-2021-44228" in ids
        assert "CVE-2023-44487" in ids

    def test_txt_comment_lines_ignored(self, tmp_path):
        """Lines starting with # should be skipped in TXT files."""
        f = tmp_path / "cves.txt"
        f.write_text("# This is a comment\nCVE-2021-44228\n# Another comment\nCVE-2023-44487\n")
        ids = parse_cve_file(f)
        assert "CVE-2021-44228" in ids
        assert "CVE-2023-44487" in ids
        assert len(ids) == 2

    def test_text_extension_parsed_same_as_txt(self, tmp_path):
        """.text extension should be treated the same as .txt."""
        f = tmp_path / "cves.text"
        f.write_text("CVE-2021-44228\n")
        ids = parse_cve_file(f)
        assert "CVE-2021-44228" in ids

    def test_invalid_json_raises_parser_error(self, tmp_path):
        """Malformed JSON file should raise ParserError."""
        f = tmp_path / "broken.json"
        f.write_text("{not valid json")
        with pytest.raises(ParserError):
            parse_cve_file(f)
