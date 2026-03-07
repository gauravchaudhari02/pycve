"""File parser for reading CVE IDs from CSV, Excel, JSON, and TXT files."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Sequence

from pycve.utils.exceptions import ParserError
from pycve.utils.validators import extract_cve_ids_from_text

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def parse_cve_file(path: str | Path) -> list[str]:
    """Parse a file and return a deduplicated list of valid CVE IDs.

    Supported formats: ``.txt``, ``.csv``, ``.json``, ``.xlsx``

    Parameters
    ----------
    path:
        Path to the input file.

    Returns
    -------
    list[str]
        Deduplicated, uppercase CVE IDs found in the file.

    Raises
    ------
    :exc:`~pycve.utils.exceptions.ParserError`
        If the file cannot be read or its format is unsupported.
    """
    path = Path(path)
    if not path.exists():
        raise ParserError(f"File not found: {path}", file_path=str(path))

    ext = path.suffix.lower()
    parsers = {
        ".txt":  _parse_txt,
        ".text": _parse_txt,
        ".csv":  _parse_csv,
        ".json": _parse_json,
        ".xlsx": _parse_xlsx,
        ".xls":  _parse_xlsx,
    }

    parser = parsers.get(ext)
    if parser is None:
        raise ParserError(
            f"Unsupported file format: '{ext}'. Supported: {', '.join(parsers)}",
            file_path=str(path),
        )

    try:
        ids = parser(path)
    except ParserError:
        raise
    except Exception as exc:
        raise ParserError(f"Failed to parse {path.name}: {exc}", file_path=str(path)) from exc

    return _deduplicate(ids)


# ── Format-specific parsers ────────────────────────────────────────────────


def _parse_txt(path: Path) -> list[str]:
    """Parse a plain-text file, one CVE-ID per line. Lines starting with ``#`` are ignored."""
    ids: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ids.extend(extract_cve_ids_from_text(line))
    return ids


def _parse_csv(path: Path) -> list[str]:
    """Parse a CSV file; scans ALL columns for CVE-ID patterns."""
    ids: list[str] = []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            for cell in row:
                ids.extend(extract_cve_ids_from_text(str(cell)))
    return ids


def _parse_json(path: Path) -> list[str]:
    """Parse a JSON file.

    Accepts:
    - Flat list: ``["CVE-2021-44228", ...]``
    - List of dicts with a CVE-ID key: ``[{"cve_id": "CVE-..."}]``
    - Any nested JSON (will be serialised back to text for regex scanning)
    """
    with path.open(encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid JSON in {path.name}: {exc}") from exc

    if isinstance(data, list):
        ids: list[str] = []
        for item in data:
            if isinstance(item, str):
                ids.extend(extract_cve_ids_from_text(item))
            elif isinstance(item, dict):
                # Try common key names first
                for key in ("cve_id", "cveId", "id", "CVE", "cve"):
                    if key in item:
                        ids.extend(extract_cve_ids_from_text(str(item[key])))
                        break
                else:
                    # Fall back to scanning all values
                    ids.extend(extract_cve_ids_from_text(json.dumps(item)))
        return ids

    # Any other structure: convert to text and scan
    return extract_cve_ids_from_text(json.dumps(data))


def _parse_xlsx(path: Path) -> list[str]:
    """Parse an Excel file (.xlsx); scans all sheets and columns."""
    try:
        import openpyxl
    except ImportError:
        raise ParserError(
            "openpyxl is required to read Excel files. "
            "Install it with: pip install 'pycve[reports]'  or  uv pip install 'pycve[reports]'"
        )

    ids: list[str] = []
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    for sheet in wb.worksheets:
        for row in sheet.iter_rows(values_only=True):
            for cell in row:
                if cell is not None:
                    ids.extend(extract_cve_ids_from_text(str(cell)))
    wb.close()
    return ids


# ── Helpers ────────────────────────────────────────────────────────────────


def _deduplicate(ids: Sequence[str]) -> list[str]:
    """Return deduplicated list preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for cid in ids:
        cid_upper = cid.upper()
        if cid_upper not in seen:
            seen.add(cid_upper)
            result.append(cid_upper)
    return result
