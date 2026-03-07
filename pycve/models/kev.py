"""CISA Known Exploited Vulnerabilities (KEV) data model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


@dataclass
class KEVEntry:
    """CISA KEV catalog entry for a single CVE ID."""

    cve_id: str
    in_kev_catalog: bool
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: datetime | None = None
    due_date: datetime | None = None
    required_action: str = ""
    short_description: str = ""
    notes: str = ""
    known_ransomware_campaign_use: str = ""

    @classmethod
    def from_kev_json(cls, cve_id: str, data: dict[str, Any]) -> "KEVEntry":
        """Build a KEVEntry from a CISA KEV catalog vulnerability object."""
        return cls(
            cve_id=cve_id,
            in_kev_catalog=True,
            vendor_project=data.get("vendorProject", ""),
            product=data.get("product", ""),
            vulnerability_name=data.get("vulnerabilityName", ""),
            date_added=_parse_date(data.get("dateAdded")),
            due_date=_parse_date(data.get("dueDate")),
            required_action=data.get("requiredAction", ""),
            short_description=data.get("shortDescription", ""),
            notes=data.get("notes", ""),
            known_ransomware_campaign_use=data.get("knownRansomwareCampaignUse", "Unknown"),
        )

    @classmethod
    def not_in_catalog(cls, cve_id: str) -> "KEVEntry":
        """Return a KEVEntry indicating the CVE is NOT in the CISA KEV catalog."""
        return cls(cve_id=cve_id, in_kev_catalog=False)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "in_kev_catalog": self.in_kev_catalog,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added.isoformat() if self.date_added else None,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "required_action": self.required_action,
            "short_description": self.short_description,
            "notes": self.notes,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
        }
