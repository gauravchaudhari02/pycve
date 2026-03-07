"""Core CVE data models mapping NVD API v2 JSON to typed Python dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def _parse_dt(value: str | None) -> datetime | None:
    """Parse an NVD ISO-8601 date string into a :class:`datetime`. Returns ``None`` if absent."""
    if not value:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


@dataclass
class CVSSScore:
    """CVSS score for a specific version (v2, v3.1, v4.0)."""

    version: str                    # "2.0", "3.0", "3.1", "4.0"
    score: float                    # 0.0 – 10.0
    severity: str                   # LOW / MEDIUM / HIGH / CRITICAL
    vector_string: str              # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    source: str = ""                # Submitting organisation
    type: str = "Primary"           # "Primary" | "Secondary"
    base_score: float | None = None
    exploitability_score: float | None = None
    impact_score: float | None = None

    @classmethod
    def from_nvd_json(cls, data: dict[str, Any]) -> "CVSSScore":
        """Parse a CVSS metric entry from NVD API v2 response."""
        # Detect version from the cvssData dict key
        cvss_data = (
            data.get("cvssMetricV40")
            or data.get("cvssMetricV31")
            or data.get("cvssMetricV30")
            or data.get("cvssMetricV2")
            or data
        )
        # If we received an individual metric record (not the wrapper)
        cvss_inner = cvss_data.get("cvssData", cvss_data)
        version = str(cvss_inner.get("version", ""))
        score = float(cvss_inner.get("baseScore", 0.0))
        severity = (
            cvss_inner.get("baseSeverity")
            or data.get("baseSeverity", "")
        ).upper()
        vector = cvss_inner.get("vectorString", "")
        return cls(
            version=version,
            score=score,
            severity=severity,
            vector_string=vector,
            source=data.get("source", ""),
            type=data.get("type", "Primary"),
            base_score=score,
            exploitability_score=data.get("exploitabilityScore"),
            impact_score=data.get("impactScore"),
        )


@dataclass
class Reference:
    """A URL reference associated with a CVE."""

    url: str
    source: str = ""
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_nvd_json(cls, data: dict[str, Any]) -> "Reference":
        return cls(
            url=data.get("url", ""),
            source=data.get("source", ""),
            tags=data.get("tags", []),
        )

    def has_tag(self, tag: str) -> bool:
        """Return True if *tag* is present in the reference's tag list (case-insensitive)."""
        return any(t.lower() == tag.lower() for t in self.tags)


@dataclass
class Weakness:
    """A CWE weakness entry associated with a CVE."""

    cwe_id: str
    description: str = ""
    source: str = ""
    type: str = "Primary"

    @classmethod
    def from_nvd_json(cls, data: dict[str, Any]) -> "Weakness":
        desc_list = data.get("description", [])
        description = desc_list[0].get("value", "") if desc_list else ""
        cwe_entries = data.get("weaknessTypes", data.get("description", []))
        cwe_id = cwe_entries[0].get("value", "") if cwe_entries else description
        return cls(
            cwe_id=cwe_id,
            description=description,
            source=data.get("source", ""),
            type=data.get("type", "Primary"),
        )


@dataclass
class CPEMatch:
    """A single CPE match criteria within a CVE configuration node."""

    cpe_name: str
    vulnerable: bool = True
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    @classmethod
    def from_nvd_json(cls, data: dict[str, Any]) -> "CPEMatch":
        return cls(
            cpe_name=data.get("criteria", data.get("cpeName", "")),
            vulnerable=data.get("vulnerable", True),
            version_start_including=data.get("versionStartIncluding"),
            version_start_excluding=data.get("versionStartExcluding"),
            version_end_including=data.get("versionEndIncluding"),
            version_end_excluding=data.get("versionEndExcluding"),
        )


@dataclass
class ConfigurationNode:
    """A node in a CVE's CPE applicability configuration."""

    operator: str = "OR"
    negate: bool = False
    cpe_matches: list[CPEMatch] = field(default_factory=list)
    children: list["ConfigurationNode"] = field(default_factory=list)

    @classmethod
    def from_nvd_json(cls, data: dict[str, Any]) -> "ConfigurationNode":
        cpe_matches = [CPEMatch.from_nvd_json(m) for m in data.get("cpeMatch", [])]
        children = [cls.from_nvd_json(c) for c in data.get("children", [])]
        return cls(
            operator=data.get("operator", "OR"),
            negate=data.get("negate", False),
            cpe_matches=cpe_matches,
            children=children,
        )


@dataclass
class CVERecord:
    """Full CVE record as returned by the NVD API v2."""

    id: str
    source_identifier: str
    published: datetime | None
    last_modified: datetime | None
    vuln_status: str
    description: str
    cvss_scores: list[CVSSScore] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    weaknesses: list[Weakness] = field(default_factory=list)
    configurations: list[ConfigurationNode] = field(default_factory=list)
    cve_tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    # ── Convenience properties ───────────────────────────────────────────────

    @property
    def primary_cvss(self) -> CVSSScore | None:
        """Return the primary (highest version, Primary type) CVSS score."""
        primary = [s for s in self.cvss_scores if s.type == "Primary"]
        if primary:
            # Prefer the highest standard version
            for version_prefix in ("4.", "3.", "2."):
                for s in primary:
                    if s.version.startswith(version_prefix):
                        return s
            return primary[0]
        return self.cvss_scores[0] if self.cvss_scores else None

    @property
    def severity(self) -> str:
        """Return severity of the primary CVSS score, or 'UNKNOWN'."""
        score = self.primary_cvss
        return score.severity if score else "UNKNOWN"

    @property
    def cvss_score(self) -> float | None:
        """Return the numeric score of the primary CVSS entry."""
        score = self.primary_cvss
        return score.score if score else None

    @property
    def patch_references(self) -> list[Reference]:
        """Return references tagged as 'Patch'."""
        return [r for r in self.references if r.has_tag("Patch")]

    @property
    def days_since_published(self) -> int | None:
        """Return number of days since the CVE was published."""
        if self.published is None:
            return None
        from datetime import timezone
        now = datetime.now(timezone.utc)
        pub = self.published
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)
        return (now - pub).days

    # ── Factory ─────────────────────────────────────────────────────────────

    @classmethod
    def from_nvd_json(cls, data: dict[str, Any]) -> "CVERecord":
        """Parse a CVE item from the NVD API v2 ``vulnerabilities`` list."""
        cve = data.get("cve", data)

        # Description (prefer English)
        descriptions = cve.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang", "").lower() in ("en", "en-us"):
                description = d.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS scores
        metrics = cve.get("metrics", {})
        cvss_scores: list[CVSSScore] = []
        for version_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for entry in metrics.get(version_key, []):
                try:
                    cvss_scores.append(CVSSScore.from_nvd_json(entry))
                except Exception:
                    pass

        # References
        references = [Reference.from_nvd_json(r) for r in cve.get("references", [])]

        # Weaknesses
        weaknesses = [Weakness.from_nvd_json(w) for w in cve.get("weaknesses", [])]

        # Configurations
        configurations = [
            ConfigurationNode.from_nvd_json(c) for c in cve.get("configurations", [])
        ]

        return cls(
            id=cve.get("id", ""),
            source_identifier=cve.get("sourceIdentifier", ""),
            published=_parse_dt(cve.get("published")),
            last_modified=_parse_dt(cve.get("lastModified")),
            vuln_status=cve.get("vulnStatus", ""),
            description=description,
            cvss_scores=cvss_scores,
            references=references,
            weaknesses=weaknesses,
            configurations=configurations,
            cve_tags=cve.get("cveTags", []),
            raw=data,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record to a JSON-serializable dictionary."""
        return {
            "id": self.id,
            "source_identifier": self.source_identifier,
            "published": self.published.isoformat() if self.published else None,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "vuln_status": self.vuln_status,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_scores": [
                {
                    "version": s.version,
                    "score": s.score,
                    "severity": s.severity,
                    "vector_string": s.vector_string,
                    "source": s.source,
                    "type": s.type,
                }
                for s in self.cvss_scores
            ],
            "references": [
                {"url": r.url, "source": r.source, "tags": r.tags}
                for r in self.references
            ],
            "weaknesses": [
                {"cwe_id": w.cwe_id, "description": w.description}
                for w in self.weaknesses
            ],
            "cve_tags": self.cve_tags,
            "days_since_published": self.days_since_published,
        }
