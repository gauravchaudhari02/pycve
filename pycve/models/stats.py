"""Aggregated CVE statistics model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CVEStats:
    """Aggregated statistical summary over a collection of CVE records."""

    total: int
    severity_distribution: dict[str, int] = field(default_factory=dict)
    avg_cvss_score: float | None = None
    median_cvss_score: float | None = None
    max_cvss_score: float | None = None
    min_cvss_score: float | None = None
    patch_coverage: float | None = None       # fraction 0.0–1.0
    patched_count: int = 0
    unpatched_count: int = 0
    in_kev_count: int = 0
    top_cwes: list[tuple[str, int]] = field(default_factory=list)
    age_distribution: dict[str, int] = field(default_factory=dict)
    # age buckets: "0-7d", "8-30d", "31-90d", "91-365d", ">365d"

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "severity_distribution": self.severity_distribution,
            "avg_cvss_score": self.avg_cvss_score,
            "median_cvss_score": self.median_cvss_score,
            "max_cvss_score": self.max_cvss_score,
            "min_cvss_score": self.min_cvss_score,
            "patch_coverage": self.patch_coverage,
            "patched_count": self.patched_count,
            "unpatched_count": self.unpatched_count,
            "in_kev_count": self.in_kev_count,
            "top_cwes": [{"cwe_id": c, "count": n} for c, n in self.top_cwes],
            "age_distribution": self.age_distribution,
        }
