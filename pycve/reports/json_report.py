"""JSON report generator."""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from pycve.models.cve import CVERecord


def _default_serialiser(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def generate_json_report(cves: list[CVERecord], output_path: str | Path) -> str:
    """Write a pretty-printed JSON report to *output_path*.

    Returns the absolute path of the created file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(cves),
        "vulnerabilities": [cve.to_dict() for cve in cves],
    }

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=_default_serialiser, ensure_ascii=False)

    return str(output_path.resolve())
