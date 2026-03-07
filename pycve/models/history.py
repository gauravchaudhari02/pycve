"""CVE change history data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


@dataclass
class ChangeDetail:
    """A single field change within a CVE history event."""

    action: str      # "Added" | "Changed" | "Removed"
    type: str        # "CVSS V3 Severity" | "Reference" | "CWE" | etc.
    old_value: str = ""
    new_value: str = ""

    @classmethod
    def from_nvd_json(cls, data: dict[str, Any]) -> "ChangeDetail":
        return cls(
            action=data.get("action", ""),
            type=data.get("type", ""),
            old_value=data.get("oldValue", ""),
            new_value=data.get("newValue", ""),
        )

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "type": self.type,
            "old_value": self.old_value,
            "new_value": self.new_value,
        }


@dataclass
class ChangeHistoryEvent:
    """A single entry in a CVE's change history from NVD."""

    cve_id: str
    event_name: str
    created: datetime | None
    source_identifier: str = ""
    details: list[ChangeDetail] = field(default_factory=list)

    @classmethod
    def from_nvd_json(cls, data: dict[str, Any]) -> "ChangeHistoryEvent":
        """Parse a change history entry from the NVD ``/cvehistory/2.0`` response."""
        change = data.get("change", data)
        details = [
            ChangeDetail.from_nvd_json(d)
            for d in change.get("details", [])
        ]
        return cls(
            cve_id=change.get("cveId", ""),
            event_name=change.get("eventName", ""),
            created=_parse_dt(change.get("created")),
            source_identifier=change.get("sourceIdentifier", ""),
            details=details,
        )

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "event_name": self.event_name,
            "created": self.created.isoformat() if self.created else None,
            "source_identifier": self.source_identifier,
            "details": [d.to_dict() for d in self.details],
        }
