"""Tests for pycve.analysis.patch_analyzer."""

from __future__ import annotations

import pytest

from pycve.analysis.patch_analyzer import PatchAnalyzer
from pycve.models.cve import CVERecord
from pycve.models.patch import PatchStatus


@pytest.fixture
def analyzer():
    return PatchAnalyzer()


class TestPatchAnalyzer:
    def test_patched_status(self, analyzer, cve_record):
        """CVE-2021-44228 has a Patch-tagged reference → PATCHED."""
        result = analyzer.analyze(cve_record)
        assert result.cve_id == "CVE-2021-44228"
        assert result.status == PatchStatus.PATCHED
        assert len(result.patch_urls) >= 1

    def test_partial_advisory_only(self, analyzer):
        """CVE with only vendor advisory → PARTIAL."""
        raw = {
            "cve": {
                "id": "CVE-2000-99999",
                "sourceIdentifier": "test@test.com",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Test CVE."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [
                    {
                        "url": "https://vendor.com/advisory",
                        "source": "vendor@vendor.com",
                        "tags": ["Vendor Advisory"],
                    }
                ],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        result = analyzer.analyze(record)
        assert result.status == PatchStatus.PARTIAL

    def test_unpatched_with_refs(self, analyzer):
        """CVE with unrelated references → PARTIAL or UNPATCHED (heuristic may promote)."""
        raw = {
            "cve": {
                "id": "CVE-2000-11111",
                "sourceIdentifier": "test@test.com",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [
                    {"url": "https://example.com/blog", "source": "test", "tags": ["Third Party Advisory"]}
                ],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        result = analyzer.analyze(record)
        assert result.status in (PatchStatus.UNPATCHED, PatchStatus.PARTIAL)

    def test_unknown_no_refs(self, analyzer):
        """CVE with no references → UNKNOWN."""
        raw = {
            "cve": {
                "id": "CVE-2000-22222",
                "sourceIdentifier": "test@test.com",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Reserved",
                "descriptions": [{"lang": "en", "value": "Reserved."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        result = analyzer.analyze(record)
        assert result.status == PatchStatus.UNKNOWN

    def test_batch_analysis(self, analyzer, cve_record_list):
        results = analyzer.analyze_batch(cve_record_list)
        assert len(results) == len(cve_record_list)
        for r in results:
            assert r.cve_id is not None
            assert isinstance(r.status, PatchStatus)

    def test_github_commit_url_classified_as_commit(self, analyzer):
        """Patch URL from GitHub commit should appear in commit_urls."""
        raw = {
            "cve": {
                "id": "CVE-2000-33333",
                "sourceIdentifier": "test",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Modified",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [
                    {
                        "url": "https://github.com/org/repo/commit/abc1234def5678",
                        "source": "sec",
                        "tags": ["Patch"],
                    }
                ],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        result = analyzer.analyze(record)
        assert result.status == PatchStatus.PATCHED
        assert len(result.commit_urls) >= 1

    def test_mitigation_tag_yields_partial(self, analyzer):
        """Reference tagged 'Mitigation' (no Patch tag) → PARTIAL."""
        raw = {
            "cve": {
                "id": "CVE-2000-44444",
                "sourceIdentifier": "test",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [
                    {
                        "url": "https://vendor.com/mitigation",
                        "source": "test",
                        "tags": ["Mitigation"],
                    }
                ],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        result = analyzer.analyze(record)
        assert result.status == PatchStatus.PARTIAL
        assert "https://vendor.com/mitigation" in result.mitigation_urls

    def test_url_heuristic_known_host_yields_partial(self, analyzer):
        """URL matching a known patch host pattern (no tags) → PARTIAL via heuristic."""
        raw = {
            "cve": {
                "id": "CVE-2000-55555",
                "sourceIdentifier": "test",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [
                    {
                        "url": "https://access.redhat.com/security/cve/CVE-2000-55555",
                        "source": "test",
                        "tags": [],
                    }
                ],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        result = analyzer.analyze(record)
        assert result.status == PatchStatus.PARTIAL

    def test_untagged_github_commit_url_in_commit_urls(self, analyzer):
        """Untagged GitHub commit URL (no tags) should still appear in commit_urls."""
        raw = {
            "cve": {
                "id": "CVE-2000-66666",
                "sourceIdentifier": "test",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [
                    {
                        "url": "https://github.com/org/repo/commit/deadbeef1234abcd",
                        "source": "test",
                        "tags": [],
                    }
                ],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        result = analyzer.analyze(record)
        assert len(result.commit_urls) >= 1
        assert "https://github.com/org/repo/commit/deadbeef1234abcd" in result.commit_urls
