"""Severity and CVSS statistical aggregation."""

from __future__ import annotations

from collections import Counter
from statistics import mean, median

from pycve.models.cve import CVERecord
from pycve.models.patch import PatchInfo, PatchStatus
from pycve.models.stats import CVEStats


class SeverityStatsCalculator:
    """Computes aggregated statistics over a collection of CVE records."""

    def calculate(
        self,
        cves: list[CVERecord],
        patch_infos: list[PatchInfo] | None = None,
    ) -> CVEStats:
        """Compute and return a :class:`~pycve.models.stats.CVEStats` aggregate.

        Parameters
        ----------
        cves:
            The CVE records to analyse.
        patch_infos:
            Optional pre-computed patch data (parallel list with *cves*).
            If supplied, patch coverage statistics are included.
        """
        if not cves:
            return CVEStats(total=0)

        total = len(cves)
        severity_dist: Counter[str] = Counter()
        scores: list[float] = []
        cwe_counter: Counter[str] = Counter()

        for cve in cves:
            # Severity
            severity_dist[cve.severity.upper()] += 1
            # CVSS score
            if cve.cvss_score is not None:
                scores.append(cve.cvss_score)
            # CWEs
            for weakness in cve.weaknesses:
                if weakness.cwe_id:
                    cwe_counter[weakness.cwe_id] += 1

        # Patch coverage
        patched_count = 0
        unpatched_count = 0
        if patch_infos:
            for pi in patch_infos:
                if pi.status in (PatchStatus.PATCHED, PatchStatus.PARTIAL):
                    patched_count += 1
                else:
                    unpatched_count += 1
            patch_coverage = patched_count / total if total > 0 else None
        else:
            patch_coverage = None

        # Age distribution
        age_dist: Counter[str] = Counter()
        for cve in cves:
            days = cve.days_since_published
            if days is None:
                age_dist["unknown"] += 1
            elif days <= 7:
                age_dist["0-7d"] += 1
            elif days <= 30:
                age_dist["8-30d"] += 1
            elif days <= 90:
                age_dist["31-90d"] += 1
            elif days <= 365:
                age_dist["91-365d"] += 1
            else:
                age_dist[">365d"] += 1

        return CVEStats(
            total=total,
            severity_distribution=dict(severity_dist),
            avg_cvss_score=round(mean(scores), 2) if scores else None,
            median_cvss_score=round(median(scores), 2) if scores else None,
            max_cvss_score=max(scores) if scores else None,
            min_cvss_score=min(scores) if scores else None,
            patch_coverage=round(patch_coverage, 4) if patch_coverage is not None else None,
            patched_count=patched_count,
            unpatched_count=unpatched_count,
            top_cwes=cwe_counter.most_common(10),
            age_distribution=dict(age_dist),
        )
