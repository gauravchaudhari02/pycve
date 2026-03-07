"""Microsoft Teams Incoming Webhook notifier using Adaptive Cards."""

from __future__ import annotations

import json
import logging

import requests

from pycve.notifications.base import BaseNotifier
from pycve.notifications.message import NotificationMessage
from pycve.utils.exceptions import NotificationError

logger = logging.getLogger(__name__)

_SEVERITY_COLOR = {
    "CRITICAL": "DC3545",
    "HIGH":     "FD7E14",
    "MEDIUM":   "FFC107",
    "LOW":      "198754",
    "UNKNOWN":  "6C757D",
}

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "UNKNOWN":  "⚪",
}


class TeamsNotifier(BaseNotifier):
    """Send CVE notifications to Microsoft Teams via Incoming Webhooks.

    Uses the ``application/json`` payload format accepted by Teams
    workflow webhooks and the legacy Office 365 connector format.

    Parameters
    ----------
    webhook_url:
        Teams Incoming Webhook URL.
    max_cves_in_message:
        Maximum number of individual CVE cards to include.
    """

    def __init__(
        self,
        webhook_url: str,
        max_cves_in_message: int = 10,
    ):
        super().__init__(webhook_url)
        self.max_cves_in_message = max_cves_in_message

    def send(self, message: NotificationMessage) -> bool:
        """Deliver *message* to Teams. Returns ``True`` on success."""
        payload = self._build_payload(message)
        try:
            resp = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            if resp.status_code in (200, 202):
                logger.debug("Teams notification sent successfully")
                return True
            logger.error("Teams webhook returned HTTP %d: %s", resp.status_code, resp.text)
            raise NotificationError(
                f"Teams webhook failed (HTTP {resp.status_code}): {resp.text}",
                channel="teams",
                status_code=resp.status_code,
            )
        except NotificationError:
            raise
        except Exception as exc:
            logger.exception("Failed to send Teams notification: %s", exc)
            raise NotificationError(f"Teams notification failed: {exc}", channel="teams") from exc

    # ── Payload builder ─────────────────────────────────────────────────

    def _build_payload(self, message: NotificationMessage) -> dict:
        """Build a legacy Office 365 MessageCard JSON payload."""
        color = _SEVERITY_COLOR.get(message.highest_severity, "6C757D")

        # Severity breakdown section
        severity_facts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = message.severity_counts.get(sev, 0)
            emoji = _SEVERITY_EMOJI[sev]
            severity_facts.append({"name": f"{emoji} {sev}", "value": str(count)})

        sections = [
            {
                "activityTitle": message.title,
                "activitySubtitle": message.summary,
                "facts": severity_facts,
                "markdown": True,
            }
        ]

        # Per-CVE sections
        cves_to_show = message.cves[:self.max_cves_in_message]
        for cve in cves_to_show:
            emoji = _SEVERITY_EMOJI.get(cve.severity, "⚪")
            desc_short = (cve.description[:200] + "…") if len(cve.description) > 200 else cve.description
            sections.append({
                "activityTitle": f"{emoji} [{cve.id}](https://nvd.nist.gov/vuln/detail/{cve.id})",
                "activitySubtitle": f"**{cve.severity}** | Score: {cve.cvss_score or '?'}",
                "activityText": desc_short,
                "markdown": True,
            })

        if len(message.cves) > self.max_cves_in_message:
            remaining = len(message.cves) - self.max_cves_in_message
            sections.append({
                "activityText": f"*… and {remaining} more CVEs not shown.*",
                "markdown": True,
            })

        # Action button: link to NVD search
        potential_actions = [
            {
                "@type": "OpenUri",
                "name": "Open NVD",
                "targets": [{"os": "default", "uri": "https://nvd.nist.gov/vuln/search"}],
            }
        ]

        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": message.title,
            "sections": sections,
            "potentialAction": potential_actions,
        }
