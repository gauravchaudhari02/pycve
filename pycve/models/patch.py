"""Patch information models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PatchStatus(str, Enum):
    """Classification of patch availability for a CVE."""

    PATCHED = "PATCHED"
    """A confirmed patch or fix is available (reference tagged 'Patch')."""

    PARTIAL = "PARTIAL"
    """A vendor advisory or mitigation exists but no direct patch reference."""

    UNPATCHED = "UNPATCHED"
    """No patch-related references found at all."""

    UNKNOWN = "UNKNOWN"
    """Insufficient data to determine patch status."""


@dataclass
class PatchInfo:
    """Result of patch availability analysis for a single CVE."""

    cve_id: str
    status: PatchStatus
    patch_urls: list[str] = field(default_factory=list)
    vendor_advisories: list[str] = field(default_factory=list)
    commit_urls: list[str] = field(default_factory=list)
    mitigation_urls: list[str] = field(default_factory=list)
    fix_versions: list[str] = field(default_factory=list)

    @property
    def is_patched(self) -> bool:
        """Return True if the status is PATCHED or PARTIAL."""
        return self.status in (PatchStatus.PATCHED, PatchStatus.PARTIAL)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "status": self.status.value,
            "patch_urls": self.patch_urls,
            "vendor_advisories": self.vendor_advisories,
            "commit_urls": self.commit_urls,
            "mitigation_urls": self.mitigation_urls,
            "fix_versions": self.fix_versions,
        }
