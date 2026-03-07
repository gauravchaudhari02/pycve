"""Abstract base class for notification channels."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter

from pycve.models.cve import CVERecord
from pycve.notifications.message import NotificationMessage


class BaseNotifier(ABC):
    """Abstract base for all notification channels.

    Subclasses must implement :meth:`send`.
    """

    def __init__(self, webhook_url: str):
        if not webhook_url:
            raise ValueError("webhook_url must not be empty.")
        self.webhook_url = webhook_url

    @abstractmethod
    def send(self, message: NotificationMessage) -> bool:
        """Deliver *message* to the target channel.

        Returns ``True`` on success, ``False`` on failure (implementors should
        log the error and return ``False`` rather than raising).
        """

    def format_cves(
        self,
        cves: list[CVERecord],
        template: str = "summary",
    ) -> NotificationMessage:
        """Build a :class:`~pycve.notifications.message.NotificationMessage` from *cves*.

        Parameters
        ----------
        cves:
            List of CVE records to include.
        template:
            One of ``critical_alert``, ``summary``, ``digest``.
        """
        severity_counts = dict(Counter(cve.severity for cve in cves))
        title = self._build_title(cves, template, severity_counts)
        summary = self._build_summary(cves, template, severity_counts)
        return NotificationMessage(
            title=title,
            summary=summary,
            cves=cves,
            severity_counts=severity_counts,
            template=template,
        )

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _build_title(
        cves: list[CVERecord], template: str, severity_counts: dict[str, int]
    ) -> str:
        total = len(cves)
        critical = severity_counts.get("CRITICAL", 0)
        if template == "critical_alert":
            return f"🚨 CRITICAL Security Alert: {critical} Critical CVE(s) Found"
        if template == "digest":
            return f"📋 CVE Digest: {total} Vulnerabilit{'y' if total == 1 else 'ies'}"
        return f"🛡 PyCVE Security Report: {total} CVE(s)"

    @staticmethod
    def _build_summary(
        cves: list[CVERecord], template: str, severity_counts: dict[str, int]
    ) -> str:
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = severity_counts.get(sev, 0)
            if count:
                parts.append(f"{count} {sev}")
        dist_str = ", ".join(parts) or "No severity data"
        return f"Severity breakdown: {dist_str}"
