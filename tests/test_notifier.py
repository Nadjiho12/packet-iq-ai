import logging
from unittest.mock import MagicMock, patch

import pytest

from backend.app import notifier

RESULT_OK = {
    "alert": {"rule_id": "RULE-001", "rule_name": "Port Scan", "src_ip": "198.51.100.77",
              "dst_ip": "192.0.2.10", "timestamp_iso": "2026-09-22T18:00:12+00:00",
              "summary": "198.51.100.77 contacted 21 unique ports on 192.0.2.10 within 10s"},
    "report": {"summary": "s", "observed_behavior": "o", "severity_recommendation": "high",
               "confidence_score": 0.9, "benign_explanations": ["scan"], "next_steps": ["block"]},
    "investigation_status": "ok", "investigation_error": None,
}
RESULT_FAIL = {**RESULT_OK, "report": None, "investigation_status": "failed",
               "investigation_error": "AITimeoutError: timed out"}


@pytest.fixture
def smtp_env(monkeypatch):
    for k, v in {"SMTP_HOST": "smtp.example.com", "SMTP_PORT": "587", "SMTP_USER": "u@example.com",
                 "SMTP_PASSWORD": "pw-DO-NOT-LEAK", "ALERT_EMAIL_TO": "me@example.com"}.items():
        monkeypatch.setenv(k, v)


def test_send_success_uses_starttls(smtp_env):
    with patch("smtplib.SMTP") as smtp:
        server = smtp.return_value.__enter__.return_value
        assert notifier.send_alert_email(RESULT_OK) is True
    server.starttls.assert_called_once()
    server.login.assert_called_once_with("u@example.com", "pw-DO-NOT-LEAK")
    msg = server.send_message.call_args.args[0]
    assert "[PacketIQ][HIGH]" in msg["Subject"]


def test_failed_investigation_still_notifies(smtp_env):
    with patch("smtplib.SMTP") as smtp:
        server = smtp.return_value.__enter__.return_value
        assert notifier.send_alert_email(RESULT_FAIL) is True
    assert "AI investigation unavailable" in server.send_message.call_args.args[0].get_content()


def test_skipped_without_config(monkeypatch):
    for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "ALERT_EMAIL_TO"):
        monkeypatch.delenv(k, raising=False)
    with patch("smtplib.SMTP") as smtp:
        assert notifier.send_alert_email(RESULT_OK) is False
    smtp.assert_not_called()


def test_smtp_error_contained_and_no_password_logged(smtp_env, caplog):
    caplog.set_level(logging.INFO)
    with patch("smtplib.SMTP", side_effect=OSError("auth failed pw-DO-NOT-LEAK")):
        assert notifier.send_alert_email(RESULT_OK) is False
    assert "pw-DO-NOT-LEAK" not in caplog.text
