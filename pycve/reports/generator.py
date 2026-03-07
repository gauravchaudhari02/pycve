"""Report orchestrator — delegates to format-specific generators."""

from __future__ import annotations

from pathlib import Path

from pycve.models.cve import CVERecord
from pycve.utils.exceptions import ReportError

_SUPPORTED_FORMATS = ("json", "html", "pdf", "excel")


class ReportGenerator:
    """Generates CVE reports in multiple formats.

    Usage::

        gen = ReportGenerator()
        gen.generate(cves, format="html", output_path="report.html")
    """

    def generate(
        self,
        cves: list[CVERecord],
        format: str,
        output_path: str | Path,
    ) -> str:
        """Generate a report in the requested *format* and write to *output_path*.

        Parameters
        ----------
        cves:
            List of CVE records to include.
        format:
            One of ``json``, ``html``, ``pdf``, ``excel``.
        output_path:
            Destination file path.

        Returns
        -------
        str
            Absolute path of the generated file.

        Raises
        ------
        :exc:`~pycve.utils.exceptions.ReportError`
            For unsupported formats.
        :exc:`~pycve.utils.exceptions.MissingDependencyError`
            When optional dependencies are not installed.
        """
        fmt = format.lower().strip()

        if fmt == "json":
            from pycve.reports.json_report import generate_json_report
            return generate_json_report(cves, output_path)

        if fmt == "html":
            from pycve.reports.html_report import generate_html_report
            return generate_html_report(cves, output_path)

        if fmt == "pdf":
            from pycve.reports.pdf_report import generate_pdf_report
            return generate_pdf_report(cves, output_path)

        if fmt in ("excel", "xlsx"):
            from pycve.reports.excel_report import generate_excel_report
            return generate_excel_report(cves, output_path)

        raise ReportError(
            f"Unsupported report format: '{format}'. "
            f"Supported formats: {', '.join(_SUPPORTED_FORMATS)}",
            format=format,
        )
