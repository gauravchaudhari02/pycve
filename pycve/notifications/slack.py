"""Slack Incoming Webhook notifier using Block Kit."""

from __future__ import annotations

import json
import logging

import requests

from pycve.models.cve import CVERecord
from pycve.notifications.base import BaseNotifier
from pycve.notifications.message import NotificationMessage
from pycve.utils.exceptions import NotificationError

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "UNKNOWN":  "⚪",
}
_SEVERITY_COLOR = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#198754",
    "UNKNOWN":  "#6c757d",
}


class SlackNotifier(BaseNotifier):
    """Send CVE notifications to Slack via Incoming Webhooks using Block Kit.

    Parameters
    ----------
    webhook_url:
        Slack Incoming Webhook URL beginning with
        ``https://hooks.slack.com/services/...``
    mention:
        Optional Slack user/group mention to prepend (e.g. ``@channel``).
    max_cves_in_message:
        Maximum number of individual CVEs to list (to stay within Slack limits).
    """

    def __init__(
        self,
        webhook_url: str,
        mention: str | None = None,
        max_cves_in_message: int = 15,
    ):
        super().__init__(webhook_url)
        self.mention = mention
        self.max_cves_in_message = max_cves_in_message

    def send(self, message: NotificationMessage) -> bool:
        """Deliver *message* to Slack. Returns ``True`` on HTTP 200."""
        payload = self._build_payload(message)
        try:
            resp = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            if resp.status_code == 200:
                logger.debug("Slack notification sent successfully")
                return True
            logger.error("Slack webhook returned HTTP %d: %s", resp.status_code, resp.text)
            raise NotificationError(
                f"Slack webhook failed (HTTP {resp.status_code}): {resp.text}",
                channel="slack",
                status_code=resp.status_code,
            )
        except NotificationError:
            raise
        except Exception as exc:
            logger.exception("Failed to send Slack notification: %s", exc)
            raise NotificationError(f"Slack notification failed: {exc}", channel="slack") from exc

    # ── Payload builders ────────────────────────────────────────────────

    def _build_payload(self, message: NotificationMessage) -> dict:
        blocks = []
        color = _SEVERITY_COLOR.get(message.highest_severity, "#6c757d")

        # Optional mention
        if self.mention:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": self.mention},
            })

        # Header
        blocks.append({
            "type": "header",
            "text": {"type": "plain_text", "text": message.title, "emoji": True},
        })

        # Divider
        blocks.append({"type": "divider"})

        # Summary
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{message.summary}*"},
        })

        # Severity breakdown fields
        sev_fields = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = message.severity_counts.get(sev, 0)
            emoji = _SEVERITY_EMOJI[sev]
            sev_fields.append({
                "type": "mrkdwn",
                "text": f"{emoji} *{sev}:* {count}",
            })
        if sev_fields:
            blocks.append({"type": "section", "fields": sev_fields})

        blocks.append({"type": "divider"})

        # Individual CVE blocks (limited)
        cves_to_show = message.cves[:self.max_cves_in_message]
        for cve in cves_to_show:
            emoji = _SEVERITY_EMOJI.get(cve.severity, "⚪")
            desc_short = (cve.description[:150] + "…") if len(cve.description) > 150 else cve.description
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *<https://nvd.nist.gov/vuln/detail/{cve.id}|{cve.id}>* "
                        f"— {cve.severity} ({cve.cvss_score or '?'})\n{desc_short}"
                    ),
                },
            })

        if len(message.cves) > self.max_cves_in_message:
            remaining = len(message.cves) - self.max_cves_in_message
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"… and {remaining} more CVEs not shown."}],
            })

        # Footer
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "Powered by *PyCVE* | Data: NIST NVD API v2"}],
        })

        return {
            "attachments": [{"color": color, "blocks": blocks}],
        }
