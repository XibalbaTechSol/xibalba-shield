from unittest.mock import MagicMock, patch

import pytest

from shield.backend.email_delivery import EmailDeliveryError, send_email

def test_email_uses_starttls_with_configured_sender(monkeypatch):
    monkeypatch.setenv("SHIELD_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SHIELD_SMTP_PORT", "2525")
    monkeypatch.setenv("SHIELD_SMTP_FROM", "security@example.com")
    client = MagicMock()
    smtp = MagicMock()
    smtp.return_value.__enter__.return_value = client
    with patch("shield.backend.email_delivery.smtplib.SMTP", smtp):
        send_email("operator@example.com", "Reset", "body")
    smtp.assert_called_once_with("smtp.example.com", 2525, timeout=15)
    client.starttls.assert_called_once()
    client.send_message.assert_called_once()

def test_email_fails_without_smtp_configuration(monkeypatch):
    monkeypatch.delenv("SHIELD_SMTP_HOST", raising=False)
    monkeypatch.delenv("SHIELD_SMTP_FROM", raising=False)
    with pytest.raises(EmailDeliveryError, match="required"):
        send_email("operator@example.com", "Reset", "body")
