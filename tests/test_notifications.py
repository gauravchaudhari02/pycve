"""Tests for pycve.notifications — Slack and Teams notifiers."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from pycve.notifications.message import NotificationMessage
from pycve.notifications.slack import SlackNotifier
from pycve.notifications.teams import TeamsNotifier
from pycve.utils.exceptions import NotificationError


def make_message(cves, template="summary"):
    notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
    return notifier.format_cves(cves, template=template)


class TestNotificationMessage:
    def test_highest_severity_critical(self, cve_record):
        msg = make_message([cve_record], template="summary")
        assert msg.highest_severity == "CRITICAL"

    def test_highest_severity_unknown_empty(self):
        msg = NotificationMessage(
            title="Test", summary="Test", cves=[], severity_counts={}
        )
        assert msg.highest_severity == "UNKNOWN"

    def test_total(self, cve_record_list):
        msg = make_message(cve_record_list)
        assert msg.total == len(cve_record_list)

    def test_title_critical_alert_template(self, cve_record):
        msg = make_message([cve_record], template="critical_alert")
        assert "CRITICAL" in msg.title or "Alert" in msg.title

    def test_title_digest_template(self, cve_record_list):
        msg = make_message(cve_record_list, template="digest")
        assert "Digest" in msg.title or "CVE" in msg.title


class TestSlackNotifier:
    def test_init_empty_url_raises(self):
        with pytest.raises(ValueError):
            SlackNotifier(webhook_url="")

    def test_send_success(self, cve_record_list):
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/services/test")
        msg = notifier.format_cves(cve_record_list, template="summary")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"
        with patch("requests.post", return_value=mock_resp) as mock_post:
            result = notifier.send(msg)
        assert result is True
        mock_post.assert_called_once()

    def test_send_failure_raises(self, cve_record_list):
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/services/test")
        msg = notifier.format_cves(cve_record_list)
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "invalid_payload"
        with patch("requests.post", return_value=mock_resp):
            with pytest.raises(NotificationError) as exc_info:
                notifier.send(msg)
        assert exc_info.value.channel == "slack"

    def test_payload_contains_cve_ids(self, cve_record_list):
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/services/test")
        msg = notifier.format_cves(cve_record_list)
        payload = notifier._build_payload(msg)
        payload_str = json.dumps(payload)
        assert "CVE-2021-44228" in payload_str

    def test_mention_in_payload(self, cve_record):
        notifier = SlackNotifier(
            webhook_url="https://hooks.slack.com/services/test",
            mention="@channel",
        )
        msg = notifier.format_cves([cve_record])
        payload = notifier._build_payload(msg)
        payload_str = json.dumps(payload)
        assert "@channel" in payload_str

    def test_max_cves_truncated(self, cve_record_list):
        notifier = SlackNotifier(
            webhook_url="https://hooks.slack.com/services/test",
            max_cves_in_message=1,
        )
        # Use list with 2 CVEs but max=1 → should have "… and 1 more"
        msg = notifier.format_cves(cve_record_list)
        payload = notifier._build_payload(msg)
        payload_str = json.dumps(payload)
        assert "more" in payload_str


class TestTeamsNotifier:
    def test_init_empty_url_raises(self):
        with pytest.raises(ValueError):
            TeamsNotifier(webhook_url="")

    def test_send_success(self, cve_record_list):
        notifier = TeamsNotifier(webhook_url="https://outlook.office.com/webhook/test")
        msg = notifier.format_cves(cve_record_list, template="summary")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "1"
        with patch("requests.post", return_value=mock_resp) as mock_post:
            result = notifier.send(msg)
        assert result is True
        mock_post.assert_called_once()

    def test_send_failure_raises(self, cve_record_list):
        notifier = TeamsNotifier(webhook_url="https://outlook.office.com/webhook/test")
        msg = notifier.format_cves(cve_record_list)
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request"
        with patch("requests.post", return_value=mock_resp):
            with pytest.raises(NotificationError) as exc_info:
                notifier.send(msg)
        assert exc_info.value.channel == "teams"

    def test_payload_structure(self, cve_record_list):
        notifier = TeamsNotifier(webhook_url="https://outlook.office.com/webhook/test")
        msg = notifier.format_cves(cve_record_list)
        payload = notifier._build_payload(msg)
        assert payload["@type"] == "MessageCard"
        assert "sections" in payload
        assert "themeColor" in payload
        assert "potentialAction" in payload

    def test_payload_contains_cve_ids(self, cve_record_list):
        notifier = TeamsNotifier(webhook_url="https://outlook.office.com/webhook/test")
        msg = notifier.format_cves(cve_record_list)
        payload = notifier._build_payload(msg)
        payload_str = json.dumps(payload)
        assert "CVE-2021-44228" in payload_str

    def test_send_success_on_202(self, cve_record_list):
        """Teams webhooks may return 202 Accepted — should still return True."""
        notifier = TeamsNotifier(webhook_url="https://outlook.office.com/webhook/test")
        msg = notifier.format_cves(cve_record_list)
        mock_resp = MagicMock()
        mock_resp.status_code = 202
        mock_resp.text = ""
        with patch("requests.post", return_value=mock_resp):
            result = notifier.send(msg)
        assert result is True

    def test_max_cves_truncated(self, cve_record_list):
        """Teams notifier with max_cves_in_message=1 should include truncation text."""
        notifier = TeamsNotifier(
            webhook_url="https://outlook.office.com/webhook/test",
            max_cves_in_message=1,
        )
        msg = notifier.format_cves(cve_record_list)
        payload = notifier._build_payload(msg)
        payload_str = json.dumps(payload)
        assert "more" in payload_str


class TestFormatCves:
    def test_severity_counts_accurate(self, cve_record_list):
        """format_cves() builds severity_counts matching actual CVE severities."""
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        msg = notifier.format_cves(cve_record_list)
        total_from_counts = sum(msg.severity_counts.values())
        assert total_from_counts == len(cve_record_list)

    def test_summary_contains_severity_info(self, cve_record):
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        msg = notifier.format_cves([cve_record], template="summary")
        assert "CRITICAL" in msg.summary or "HIGH" in msg.summary or "breakdown" in msg.summary

    def test_digest_template_title(self, cve_record_list):
        notifier = SlackNotifier(webhook_url="https://hooks.slack.com/test")
        msg = notifier.format_cves(cve_record_list, template="digest")
        assert str(len(cve_record_list)) in msg.title
