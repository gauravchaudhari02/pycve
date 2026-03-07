"""Input validation utilities for pycve."""

from __future__ import annotations

import re
from datetime import datetime

from pycve.utils.exceptions import InvalidCVEIdError

# CVE-ID pattern: CVE-YYYY-N{4,}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# Non-anchored version for scanning within larger text blobs
_CVE_SCAN_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Allowed CVSS v3/v4 severity values
_SEVERITY_V3 = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_SEVERITY_V2 = {"LOW", "MEDIUM", "HIGH"}
_SEVERITY_ALL = _SEVERITY_V3 | _SEVERITY_V2  # superset


def validate_cve_id(cve_id: str) -> bool:
    """Return True if *cve_id* matches the ``CVE-YYYY-NNNNN`` pattern."""
    if not isinstance(cve_id, str):
        return False
    return bool(_CVE_RE.match(cve_id.strip()))


def normalize_cve_id(cve_id: str) -> str:
    """Return *cve_id* uppercased and stripped. Raises :exc:`InvalidCVEIdError` if invalid."""
    normalized = cve_id.strip().upper()
    if not validate_cve_id(normalized):
        raise InvalidCVEIdError(cve_id)
    return normalized


def validate_and_normalize_cve_ids(cve_ids: str | list[str]) -> list[str]:
    """Accept a single CVE ID or a list and return a normalized, deduplicated list.

    Raises :exc:`InvalidCVEIdError` for any malformed ID.
    """
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    seen: set[str] = set()
    result: list[str] = []
    for cid in cve_ids:
        normalized = normalize_cve_id(cid)
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def validate_severity(severity: str) -> bool:
    """Return True if *severity* is a valid CVSS severity string."""
    return severity.upper() in _SEVERITY_ALL


def validate_date(date_str: str) -> bool:
    """Return True if *date_str* is a parseable date (ISO 8601 ``YYYY-MM-DD`` or full datetime)."""
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            datetime.strptime(date_str, fmt)
            return True
        except ValueError:
            continue
    return False


def validate_file_path(path: str) -> bool:
    """Return True if *path* points to an existing file."""
    from pathlib import Path
    return Path(path).is_file()


def extract_cve_ids_from_text(text: str) -> list[str]:
    """Extract and return all unique CVE IDs found in *text* (e.g. file contents)."""
    matches = _CVE_SCAN_RE.findall(text)
    seen: set[str] = set()
    result: list[str] = []
    for m in matches:
        m_upper = m.upper()
        if m_upper not in seen:
            seen.add(m_upper)
            result.append(m_upper)
    return result
