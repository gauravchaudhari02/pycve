"""Notification message model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pycve.models.cve import CVERecord


@dataclass
class NotificationMessage:
    """An intermediate message object built from CVE records before sending."""

    title: str
    summary: str
    cves: list[CVERecord] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    template: str = "summary"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def highest_severity(self) -> str:
        """Return the most critical severity present in this message's CVEs."""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if self.severity_counts.get(sev, 0) > 0:
                return sev
        return "UNKNOWN"

    @property
    def total(self) -> int:
        return len(self.cves)
