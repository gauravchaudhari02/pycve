"""Patch availability analysis for CVE records."""

from __future__ import annotations

import re

from pycve.models.cve import CVERecord, Reference
from pycve.models.patch import PatchInfo, PatchStatus

# Reference tag names that indicate a patch is available
_PATCH_TAGS = {"patch"}
_ADVISORY_TAGS = {"vendor advisory", "vendor-advisory"}
_MITIGATION_TAGS = {"mitigation"}
_EXPLOIT_TAGS = {"exploit"}

# URL patterns for GitHub commit and common patch-delivery hosts
_COMMIT_PATTERN = re.compile(
    r"github\.com/[^/]+/[^/]+/(commit|pull)/[a-f0-9]{6,40}",
    re.IGNORECASE,
)
_PATCH_HOSTS = re.compile(
    r"(github\.com.*(commit|pull|releases|advisory)|"
    r"security\.snyk\.io|"
    r"cve\.mitre\.org/cgi-bin/cvename|"
    r"huntr\.dev|"
    r"advisories\.mageia\.org|"
    r"errata\.(almalinux|rockylinux)|"
    r"access\.redhat\.com/security/cve|"
    r"ubuntu\.com/security/notices|"
    r"debian\.org/security|"
    r"nvd\.nist\.gov)",
    re.IGNORECASE,
)


class PatchAnalyzer:
    """Determines patch status for CVE records by inspecting their references."""

    def analyze(self, cve: CVERecord) -> PatchInfo:
        """Analyse a single :class:`~pycve.models.cve.CVERecord` and return a
        :class:`~pycve.models.patch.PatchInfo`.
        """
        patch_urls: list[str] = []
        vendor_advisories: list[str] = []
        commit_urls: list[str] = []
        mitigation_urls: list[str] = []

        for ref in cve.references:
            tag_lower = {t.lower() for t in ref.tags}

            if tag_lower & _PATCH_TAGS:
                patch_urls.append(ref.url)
                if _COMMIT_PATTERN.search(ref.url):
                    commit_urls.append(ref.url)

            if tag_lower & _ADVISORY_TAGS:
                vendor_advisories.append(ref.url)

            if tag_lower & _MITIGATION_TAGS:
                mitigation_urls.append(ref.url)

            # Even without tags, check URL patterns for commits
            if not tag_lower and _COMMIT_PATTERN.search(ref.url):
                commit_urls.append(ref.url)

        # Determine status
        status = self._classify(
            patch_urls=patch_urls,
            vendor_advisories=vendor_advisories,
            mitigation_urls=mitigation_urls,
            all_refs=cve.references,
        )

        return PatchInfo(
            cve_id=cve.id,
            status=status,
            patch_urls=list(dict.fromkeys(patch_urls)),       # dedup, preserve order
            vendor_advisories=list(dict.fromkeys(vendor_advisories)),
            commit_urls=list(dict.fromkeys(commit_urls)),
            mitigation_urls=list(dict.fromkeys(mitigation_urls)),
        )

    def analyze_batch(self, cves: list[CVERecord]) -> list[PatchInfo]:
        """Analyse a list of CVE records and return corresponding PatchInfo objects."""
        return [self.analyze(cve) for cve in cves]

    # ── Classification logic ──────────────────────────────────────────────

    @staticmethod
    def _classify(
        patch_urls: list[str],
        vendor_advisories: list[str],
        mitigation_urls: list[str],
        all_refs: list[Reference],
    ) -> PatchStatus:
        if patch_urls:
            return PatchStatus.PATCHED
        if vendor_advisories or mitigation_urls:
            return PatchStatus.PARTIAL
        if not all_refs:
            return PatchStatus.UNKNOWN
        # Check URL patterns as a heuristic
        for ref in all_refs:
            if _PATCH_HOSTS.search(ref.url):
                return PatchStatus.PARTIAL
        return PatchStatus.UNPATCHED
