"""Tests for pycve.models — CVERecord, Reference, CPEMatch, ConfigurationNode,
ChangeHistoryEvent, KEVEntry, PatchInfo serialisation."""

from __future__ import annotations

from datetime import datetime

import pytest

from pycve.models.cve import CPEMatch, ConfigurationNode, CVERecord, CVSSScore, Reference, Weakness
from pycve.models.history import ChangeDetail, ChangeHistoryEvent
from pycve.models.kev import KEVEntry
from pycve.models.patch import PatchInfo, PatchStatus


class TestCVSSScore:
    def test_from_nvd_json(self):
        entry = {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "baseScore": 10.0,
                "baseSeverity": "CRITICAL",
            },
            "exploitabilityScore": 3.9,
            "impactScore": 6.0,
        }
        score = CVSSScore.from_nvd_json(entry)
        assert score.version == "3.1"
        assert score.score == 10.0
        assert score.severity == "CRITICAL"
        assert score.type == "Primary"
        assert score.source == "nvd@nist.gov"


class TestCVERecord:
    def test_from_nvd_json(self, raw_cve_response):
        vuln = raw_cve_response["vulnerabilities"][0]
        record = CVERecord.from_nvd_json(vuln)

        assert record.id == "CVE-2021-44228"
        assert record.vuln_status == "Modified"
        assert "Log4j2" in record.description
        assert isinstance(record.published, datetime)
        assert isinstance(record.last_modified, datetime)

    def test_primary_cvss(self, cve_record):
        assert cve_record.primary_cvss is not None
        assert cve_record.primary_cvss.version == "3.1"
        assert cve_record.primary_cvss.score == 10.0

    def test_severity_property(self, cve_record):
        assert cve_record.severity == "CRITICAL"

    def test_cvss_score_property(self, cve_record):
        assert cve_record.cvss_score == 10.0

    def test_patch_references(self, cve_record):
        patch_refs = cve_record.patch_references
        assert len(patch_refs) >= 1
        assert any("Patch" in r.tags for r in patch_refs)

    def test_days_since_published(self, cve_record):
        days = cve_record.days_since_published
        assert isinstance(days, int)
        assert days > 0  # Log4Shell was published in 2021

    def test_weaknesses_parsed(self, cve_record):
        assert len(cve_record.weaknesses) >= 1
        assert cve_record.weaknesses[0].cwe_id == "CWE-502"

    def test_to_dict_keys(self, cve_record):
        d = cve_record.to_dict()
        for key in ("id", "severity", "cvss_score", "published", "description", "references"):
            assert key in d

    def test_to_dict_json_serialisable(self, cve_record):
        import json
        d = cve_record.to_dict()
        json_str = json.dumps(d)  # should not raise
        assert "CVE-2021-44228" in json_str

    def test_missing_description_fallback(self):
        """Test that records without English description use first available."""
        raw = {
            "cve": {
                "id": "CVE-2000-00001",
                "sourceIdentifier": "test@test.com",
                "published": "2000-01-01T00:00:00",
                "lastModified": "2000-01-01T00:00:00",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "fr", "value": "Description en français"}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        assert record.description == "Description en français"

    def test_empty_metrics(self):
        """Record with no CVSS data should return UNKNOWN severity."""
        raw = {
            "cve": {
                "id": "CVE-2000-00002",
                "sourceIdentifier": "test@test.com",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Reserved",
                "descriptions": [{"lang": "en", "value": "No metrics yet."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        assert record.severity == "UNKNOWN"
        assert record.cvss_score is None

    def test_days_since_published_none_when_no_date(self):
        """days_since_published returns None when published date is absent."""
        raw = {
            "cve": {
                "id": "CVE-2000-00003",
                "sourceIdentifier": "test@test.com",
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
        assert record.days_since_published is None

    def test_primary_cvss_fallback_to_secondary(self):
        """When no Primary-typed score exists, first available score is returned."""
        raw = {
            "cve": {
                "id": "CVE-2000-00004",
                "sourceIdentifier": "test",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "third-party",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                            },
                        }
                    ]
                },
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "cveTags": [],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        assert record.primary_cvss is not None
        assert record.primary_cvss.score == 7.5

    def test_cve_tags_parsed(self):
        """cveTags field is parsed into cve_tags list."""
        raw = {
            "cve": {
                "id": "CVE-2000-00005",
                "sourceIdentifier": "test",
                "published": None,
                "lastModified": None,
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Test."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "cveTags": ["disputed"],
            }
        }
        record = CVERecord.from_nvd_json(raw)
        assert "disputed" in record.cve_tags


class TestReference:
    def test_from_nvd_json(self):
        data = {"url": "https://example.com/patch", "source": "sec@test.com", "tags": ["Patch"]}
        ref = Reference.from_nvd_json(data)
        assert ref.url == "https://example.com/patch"
        assert ref.source == "sec@test.com"
        assert "Patch" in ref.tags

    def test_has_tag_case_insensitive(self):
        ref = Reference(url="https://x.com", tags=["Patch", "Third Party Advisory"])
        assert ref.has_tag("patch") is True
        assert ref.has_tag("PATCH") is True
        assert ref.has_tag("third party advisory") is True

    def test_has_tag_not_found(self):
        ref = Reference(url="https://x.com", tags=["Patch"])
        assert ref.has_tag("exploit") is False

    def test_has_tag_empty_tags(self):
        ref = Reference(url="https://x.com", tags=[])
        assert ref.has_tag("Patch") is False


class TestCPEMatch:
    def test_from_nvd_json(self):
        data = {
            "criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
            "vulnerable": True,
            "versionStartIncluding": "2.0",
            "versionEndExcluding": "2.15.0",
        }
        cpe = CPEMatch.from_nvd_json(data)
        assert cpe.cpe_name == "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"
        assert cpe.vulnerable is True
        assert cpe.version_start_including == "2.0"
        assert cpe.version_end_excluding == "2.15.0"
        assert cpe.version_start_excluding is None
        assert cpe.version_end_including is None

    def test_from_nvd_json_defaults(self):
        cpe = CPEMatch.from_nvd_json({})
        assert cpe.cpe_name == ""
        assert cpe.vulnerable is True


class TestConfigurationNode:
    def test_from_nvd_json_flat(self):
        data = {
            "operator": "OR",
            "negate": False,
            "cpeMatch": [
                {"criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "vulnerable": True}
            ],
        }
        node = ConfigurationNode.from_nvd_json(data)
        assert node.operator == "OR"
        assert node.negate is False
        assert len(node.cpe_matches) == 1
        assert node.children == []

    def test_from_nvd_json_nested(self):
        data = {
            "operator": "AND",
            "negate": False,
            "cpeMatch": [],
            "children": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:o:linux:linux_kernel:*", "vulnerable": False}
                    ],
                }
            ],
        }
        node = ConfigurationNode.from_nvd_json(data)
        assert node.operator == "AND"
        assert len(node.children) == 1
        assert node.children[0].operator == "OR"


class TestChangeDetail:
    def test_from_nvd_json(self):
        data = {
            "action": "Changed",
            "type": "CVSS V3 Severity",
            "oldValue": "HIGH",
            "newValue": "CRITICAL",
        }
        detail = ChangeDetail.from_nvd_json(data)
        assert detail.action == "Changed"
        assert detail.type == "CVSS V3 Severity"
        assert detail.old_value == "HIGH"
        assert detail.new_value == "CRITICAL"

    def test_to_dict(self):
        detail = ChangeDetail(action="Added", type="Reference", old_value="", new_value="https://x.com")
        d = detail.to_dict()
        assert d["action"] == "Added"
        assert d["new_value"] == "https://x.com"
        assert "old_value" in d


class TestChangeHistoryEvent:
    def test_from_nvd_json(self):
        data = {
            "change": {
                "cveId": "CVE-2021-44228",
                "eventName": "CVE Modified",
                "created": "2022-03-01T10:00:00.000",
                "sourceIdentifier": "nvd@nist.gov",
                "details": [
                    {"action": "Changed", "type": "CVSS V3 Severity", "oldValue": "HIGH", "newValue": "CRITICAL"}
                ],
            }
        }
        event = ChangeHistoryEvent.from_nvd_json(data)
        assert event.cve_id == "CVE-2021-44228"
        assert event.event_name == "CVE Modified"
        assert isinstance(event.created, datetime)
        assert len(event.details) == 1

    def test_to_dict(self):
        event = ChangeHistoryEvent(
            cve_id="CVE-2021-44228",
            event_name="CVE Modified",
            created=datetime(2022, 3, 1),
            source_identifier="nvd@nist.gov",
            details=[ChangeDetail(action="Changed", type="CVSS", old_value="HIGH", new_value="CRITICAL")],
        )
        d = event.to_dict()
        assert d["cve_id"] == "CVE-2021-44228"
        assert d["event_name"] == "CVE Modified"
        assert d["created"] == "2022-03-01T00:00:00"
        assert len(d["details"]) == 1

    def test_to_dict_no_created(self):
        event = ChangeHistoryEvent(cve_id="CVE-2021-44228", event_name="Test", created=None)
        d = event.to_dict()
        assert d["created"] is None


class TestKEVEntry:
    def test_from_kev_json(self):
        data = {
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Apache Log4j2 RCE",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "requiredAction": "Apply patch",
            "shortDescription": "Remote code execution",
            "notes": "See advisory",
            "knownRansomwareCampaignUse": "Known",
        }
        entry = KEVEntry.from_kev_json("CVE-2021-44228", data)
        assert entry.cve_id == "CVE-2021-44228"
        assert entry.in_kev_catalog is True
        assert entry.vendor_project == "Apache"
        assert entry.product == "Log4j"
        assert isinstance(entry.date_added, datetime)
        assert isinstance(entry.due_date, datetime)

    def test_not_in_catalog(self):
        entry = KEVEntry.not_in_catalog("CVE-2099-99999")
        assert entry.cve_id == "CVE-2099-99999"
        assert entry.in_kev_catalog is False
        assert entry.vendor_project == ""

    def test_to_dict(self):
        entry = KEVEntry.from_kev_json("CVE-2021-44228", {
            "vendorProject": "Apache", "product": "Log4j",
            "vulnerabilityName": "RCE", "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24", "requiredAction": "Patch",
            "shortDescription": "RCE vuln", "notes": "",
            "knownRansomwareCampaignUse": "Known",
        })
        d = entry.to_dict()
        assert d["cve_id"] == "CVE-2021-44228"
        assert d["in_kev_catalog"] is True
        assert d["vendor_project"] == "Apache"
        assert "date_added" in d
        assert "due_date" in d

    def test_to_dict_no_dates(self):
        entry = KEVEntry.not_in_catalog("CVE-2099-00001")
        d = entry.to_dict()
        assert d["date_added"] is None
        assert d["due_date"] is None


class TestPatchInfo:
    def test_is_patched_true_for_patched(self):
        info = PatchInfo(cve_id="CVE-2021-44228", status=PatchStatus.PATCHED)
        assert info.is_patched is True

    def test_is_patched_true_for_partial(self):
        info = PatchInfo(cve_id="CVE-2021-44228", status=PatchStatus.PARTIAL)
        assert info.is_patched is True

    def test_is_patched_false_for_unpatched(self):
        info = PatchInfo(cve_id="CVE-2021-44228", status=PatchStatus.UNPATCHED)
        assert info.is_patched is False

    def test_is_patched_false_for_unknown(self):
        info = PatchInfo(cve_id="CVE-2021-44228", status=PatchStatus.UNKNOWN)
        assert info.is_patched is False

    def test_to_dict(self):
        info = PatchInfo(
            cve_id="CVE-2021-44228",
            status=PatchStatus.PATCHED,
            patch_urls=["https://github.com/org/repo/commit/abc"],
            commit_urls=["https://github.com/org/repo/commit/abc"],
            vendor_advisories=[],
            mitigation_urls=[],
        )
        d = info.to_dict()
        assert d["cve_id"] == "CVE-2021-44228"
        assert d["status"] == "PATCHED"
        assert len(d["patch_urls"]) == 1
        assert d["vendor_advisories"] == []
