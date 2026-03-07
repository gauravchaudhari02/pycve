"""HTML report generator using Jinja2."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from pycve.models.cve import CVERecord
from pycve.utils.exceptions import MissingDependencyError


def generate_html_report(cves: list[CVERecord], output_path: str | Path) -> str:
    """Render a dark-mode HTML report using the Jinja2 template.

    Returns the absolute path of the created file.
    """
    try:
        from jinja2 import Environment, FileSystemLoader
    except ImportError:
        raise MissingDependencyError("jinja2", "HTML reports", "reports")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    templates_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)
    template = env.get_template("report.html.j2")

    severity_counts = Counter(cve.severity for cve in cves)
    patched_count = sum(1 for cve in cves if cve.patch_references)
    unpatched_count = len(cves) - patched_count

    html = template.render(
        cves=cves,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        severity_counts=dict(severity_counts),
        patched_count=patched_count,
        unpatched_count=unpatched_count,
    )

    with output_path.open("w", encoding="utf-8") as f:
        f.write(html)

    return str(output_path.resolve())
