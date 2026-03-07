"""Tests for PyCVE.generate_patch_file()."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses as resp_lib

from pycve import PyCVE
from pycve.utils.exceptions import CVENotFoundError, InvalidCVEIdError

FIXTURES = Path(__file__).parent / "fixtures"
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

COMMIT_URL_1 = "https://github.com/apache/logging-log4j2/commit/abc123"
COMMIT_URL_2 = "https://github.com/apache/logging-log4j2/commit/def456"
PATCH_URL_1 = COMMIT_URL_1 + ".patch"
PATCH_URL_2 = COMMIT_URL_2 + ".patch"

FAKE_PATCH_1 = """\
From abc123 Mon Sep 17 00:00:00 2001
From: Dev <dev@example.com>
Subject: Fix JNDI lookup

diff --git a/Foo.java b/Foo.java
--- a/Foo.java
+++ b/Foo.java
@@ -1 +1 @@
-lookupJndi(input);
+// removed
"""

FAKE_PATCH_2 = """\
From def456 Mon Sep 17 00:00:00 2001
From: Dev <dev@example.com>
Subject: Additional hardening

diff --git a/Bar.java b/Bar.java
--- a/Bar.java
+++ b/Bar.java
@@ -1 +1 @@
-riskyCall();
+// removed
"""


def fixture_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _multi_patch_response() -> dict:
    """CVE response with two GitHub commit patch URLs."""
    return {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "sourceIdentifier": "security@apache.org",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2023-04-03T20:15:09.143",
                "vulnStatus": "Modified",
                "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [
                    {"url": COMMIT_URL_1, "source": "security@apache.org", "tags": ["Patch"]},
                    {"url": COMMIT_URL_2, "source": "security@apache.org", "tags": ["Patch"]},
                ],
                "cveTags": [],
            }
        }],
    }


def _no_github_patch_response() -> dict:
    """CVE that is PARTIAL (has vendor advisory) but has no GitHub commit URL."""
    return {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "sourceIdentifier": "security@apache.org",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2023-04-03T20:15:09.143",
                "vulnStatus": "Modified",
                "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [
                    {
                        "url": "https://logging.apache.org/log4j/2.x/security.html",
                        "source": "security@apache.org",
                        "tags": ["Vendor Advisory"],
                    },
                ],
                "cveTags": [],
            }
        }],
    }


@pytest.fixture
def pycve(tmp_path):
    return PyCVE(config_path=tmp_path / "cfg.yaml", cache_path=tmp_path / "cache.db")


class TestGeneratePatchFile:

    @resp_lib.activate
    def test_returns_path_for_single_patch(self, pycve, tmp_path):
        """One patch URL → returns str path of the written .patch file."""
        resp_lib.add(resp_lib.GET, CVE_URL, json=fixture_json("sample_cve_response.json"), status=200)
        resp_lib.add(resp_lib.GET, PATCH_URL_1, body=FAKE_PATCH_1, status=200)

        result = pycve.generate_patch_file("CVE-2021-44228", output=tmp_path)

        assert isinstance(result, str)
        p = Path(result)
        assert p.exists()
        assert p.suffix == ".patch"

    @resp_lib.activate
    def test_patch_file_contains_diff_content(self, pycve, tmp_path):
        """Written .patch file must contain the unified-diff text from GitHub."""
        resp_lib.add(resp_lib.GET, CVE_URL, json=fixture_json("sample_cve_response.json"), status=200)
        resp_lib.add(resp_lib.GET, PATCH_URL_1, body=FAKE_PATCH_1, status=200)

        result = pycve.generate_patch_file("CVE-2021-44228", output=tmp_path)

        content = Path(result).read_text()
        assert "diff --git" in content

    @resp_lib.activate
    def test_returns_none_when_no_patch_refs(self, pycve, tmp_path):
        """CVE with no patch-tagged references → None, no file written."""
        no_patch = {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-99999",
                    "sourceIdentifier": "test@test.com",
                    "published": None,
                    "lastModified": None,
                    "vulnStatus": "Reserved",
                    "descriptions": [{"lang": "en", "value": "No patch."}],
                    "metrics": {},
                    "weaknesses": [],
                    "configurations": [],
                    "references": [],
                    "cveTags": [],
                }
            }],
        }
        resp_lib.add(resp_lib.GET, CVE_URL, json=no_patch, status=200)

        result = pycve.generate_patch_file("CVE-2023-99999", output=tmp_path)

        assert result is None

    @resp_lib.activate
    def test_returns_none_when_no_github_url(self, pycve, tmp_path):
        """Patch is marked available (vendor advisory) but no GitHub URL → None."""
        resp_lib.add(resp_lib.GET, CVE_URL, json=_no_github_patch_response(), status=200)

        result = pycve.generate_patch_file("CVE-2021-44228", output=tmp_path)

        assert result is None

    @resp_lib.activate
    def test_separate_files_for_multiple_patches(self, pycve, tmp_path):
        """combine=False (default) → one .patch file per patch URL."""
        resp_lib.add(resp_lib.GET, CVE_URL, json=_multi_patch_response(), status=200)
        resp_lib.add(resp_lib.GET, PATCH_URL_1, body=FAKE_PATCH_1, status=200)
        resp_lib.add(resp_lib.GET, PATCH_URL_2, body=FAKE_PATCH_2, status=200)

        result = pycve.generate_patch_file("CVE-2021-44228", output=tmp_path, combine=False)

        assert isinstance(result, list)
        assert len(result) == 2
        for p in result:
            assert Path(p).exists()
            assert Path(p).suffix == ".patch"

    @resp_lib.activate
    def test_combined_file_for_multiple_patches(self, pycve, tmp_path):
        """combine=True → single file containing all patches."""
        resp_lib.add(resp_lib.GET, CVE_URL, json=_multi_patch_response(), status=200)
        resp_lib.add(resp_lib.GET, PATCH_URL_1, body=FAKE_PATCH_1, status=200)
        resp_lib.add(resp_lib.GET, PATCH_URL_2, body=FAKE_PATCH_2, status=200)

        out_file = tmp_path / "combined.patch"
        result = pycve.generate_patch_file("CVE-2021-44228", output=out_file, combine=True)

        assert isinstance(result, str)
        content = Path(result).read_text()
        # Both source markers must appear
        assert content.count("# Source:") == 2
        # Content from both patches
        assert "abc123" in content
        assert "def456" in content

    @resp_lib.activate
    def test_default_output_uses_cve_id_in_name(self, pycve, tmp_path):
        """Without explicit output, file name includes the CVE ID."""
        resp_lib.add(resp_lib.GET, CVE_URL, json=fixture_json("sample_cve_response.json"), status=200)
        resp_lib.add(resp_lib.GET, PATCH_URL_1, body=FAKE_PATCH_1, status=200)
        pycve.config.set("output_dir", str(tmp_path))

        result = pycve.generate_patch_file("CVE-2021-44228")

        assert result is not None
        name = Path(result).name if isinstance(result, str) else Path(result[0]).name
        assert "CVE_2021_44228" in name
        assert name.endswith(".patch")

    @resp_lib.activate
    def test_auto_creates_parent_dirs(self, pycve, tmp_path):
        """Missing parent directories must be created automatically."""
        resp_lib.add(resp_lib.GET, CVE_URL, json=fixture_json("sample_cve_response.json"), status=200)
        resp_lib.add(resp_lib.GET, PATCH_URL_1, body=FAKE_PATCH_1, status=200)

        deep = tmp_path / "a" / "b" / "c"
        result = pycve.generate_patch_file("CVE-2021-44228", output=deep)

        assert result is not None
        assert Path(result).exists()

    @resp_lib.activate
    def test_not_found_raises(self, pycve):
        """404 from NVD should surface as CVENotFoundError."""
        resp_lib.add(resp_lib.GET, CVE_URL, status=404)

        with pytest.raises(CVENotFoundError):
            pycve.generate_patch_file("CVE-1999-99999")

    def test_invalid_cve_id_raises(self, pycve):
        """Malformed CVE ID should raise InvalidCVEIdError before any HTTP call."""
        with pytest.raises(InvalidCVEIdError):
            pycve.generate_patch_file("NOT-A-CVE-ID")

    @resp_lib.activate
    def test_lowercase_cve_id_normalised(self, pycve, tmp_path):
        """Lowercase CVE IDs should be accepted and normalised."""
        resp_lib.add(resp_lib.GET, CVE_URL, json=fixture_json("sample_cve_response.json"), status=200)
        resp_lib.add(resp_lib.GET, PATCH_URL_1, body=FAKE_PATCH_1, status=200)

        result = pycve.generate_patch_file("cve-2021-44228", output=tmp_path)

        assert result is not None
