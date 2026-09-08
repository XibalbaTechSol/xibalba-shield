from unittest.mock import MagicMock, patch

import pytest

from shield.backend.email_delivery import EmailDeliveryError, send_email

def test_email_uses_resend_with_configured_sender(monkeypatch):
    monkeypatch.setenv("SHIELD_EMAIL_FROM", "security@example.com")
    monkeypatch.setenv("RESEND_API_KEY", "re_test123")

    with patch("shield.backend.email_delivery.resend.Emails.send") as send_mock:
        send_email("operator@example.com", "Reset", "body")
        send_mock.assert_called_once_with({
            "from": "security@example.com",
            "to": "operator@example.com",
            "subject": "Reset",
            "text": "body"
        })

def test_email_warns_without_api_key(monkeypatch, capfd):
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    monkeypatch.setenv("SHIELD_EMAIL_FROM", "security@example.com")

    with patch("shield.backend.email_delivery.resend.Emails.send") as send_mock:
        send_email("operator@example.com", "Reset", "body")
        send_mock.assert_not_called()

    out, err = capfd.readouterr()
    assert "WARN: RESEND_API_KEY not set" in out
