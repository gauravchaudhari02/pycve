"""Tests for pycve.analysis.severity_stats."""

from __future__ import annotations

import pytest

from pycve.analysis.severity_stats import SeverityStatsCalculator
from pycve.models.stats import CVEStats


@pytest.fixture
def calc():
    return SeverityStatsCalculator()


class TestSeverityStatsCalculator:
    def test_empty_list(self, calc):
        stats = calc.calculate([])
        assert stats.total == 0
        assert stats.severity_distribution == {}

    def test_total_count(self, calc, cve_record_list):
        stats = calc.calculate(cve_record_list)
        assert stats.total == len(cve_record_list)

    def test_severity_distribution(self, calc, cve_record_list):
        stats = calc.calculate(cve_record_list)
        assert "CRITICAL" in stats.severity_distribution or "HIGH" in stats.severity_distribution

    def test_avg_cvss(self, calc, cve_record_list):
        stats = calc.calculate(cve_record_list)
        if stats.avg_cvss_score is not None:
            assert 0.0 <= stats.avg_cvss_score <= 10.0

    def test_patch_coverage_with_infos(self, calc, cve_record_list):
        from pycve.analysis.patch_analyzer import PatchAnalyzer
        from pycve.models.patch import PatchStatus, PatchInfo

        patch_infos = [
            PatchInfo(cve_id=cve.id, status=PatchStatus.PATCHED)
            for cve in cve_record_list
        ]
        stats = calc.calculate(cve_record_list, patch_infos)
        assert stats.patch_coverage == 1.0
        assert stats.patched_count == len(cve_record_list)

    def test_age_distribution(self, calc, cve_record_list):
        stats = calc.calculate(cve_record_list)
        assert isinstance(stats.age_distribution, dict)

    def test_to_dict(self, calc, cve_record_list):
        stats = calc.calculate(cve_record_list)
        d = stats.to_dict()
        assert d["total"] == len(cve_record_list)
        assert "severity_distribution" in d

    def test_median_max_min_cvss(self, calc, cve_record_list):
        stats = calc.calculate(cve_record_list)
        if stats.avg_cvss_score is not None:
            assert stats.median_cvss_score is not None
            assert stats.max_cvss_score is not None
            assert stats.min_cvss_score is not None
            assert stats.min_cvss_score <= stats.avg_cvss_score <= stats.max_cvss_score

    def test_no_scores_all_none(self, calc):
        """CVEs with no CVSS metrics → all score aggregates are None."""
        from pycve.models.cve import CVERecord
        raw = {
            "cve": {
                "id": "CVE-2000-11111",
                "sourceIdentifier": "test",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Reserved",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        stats = calc.calculate([record])
        assert stats.avg_cvss_score is None
        assert stats.median_cvss_score is None
        assert stats.max_cvss_score is None
        assert stats.min_cvss_score is None

    def test_top_cwes(self, calc):
        """top_cwes is populated when CVEs have weaknesses."""
        from pycve.models.cve import CVERecord, Weakness
        raw = {
            "cve": {
                "id": "CVE-2000-22222",
                "sourceIdentifier": "test",
                "published": "2021-01-01T00:00:00",
                "lastModified": "2021-01-01T00:00:00",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {},
                "weaknesses": [
                    {
                        "source": "nvd",
                        "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-79"}],
                    }
                ],
                "configurations": [],
                "references": [],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        stats = calc.calculate([record, record])
        assert len(stats.top_cwes) >= 1
        assert stats.top_cwes[0][1] == 2  # CWE-79 appears twice

    def test_no_patch_infos_patch_coverage_none(self, calc, cve_record_list):
        """patch_coverage is None when no patch_infos are supplied."""
        stats = calc.calculate(cve_record_list, patch_infos=None)
        assert stats.patch_coverage is None

    def test_age_bucket_unknown_for_no_published_date(self, calc):
        """CVE with no published date falls into the 'unknown' age bucket."""
        from pycve.models.cve import CVERecord
        raw = {
            "cve": {
                "id": "CVE-2000-33333",
                "sourceIdentifier": "test",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Reserved",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        stats = calc.calculate([record])
        assert stats.age_distribution.get("unknown", 0) == 1
