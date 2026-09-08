from unittest.mock import MagicMock, patch

import pytest

from shield.backend.email_delivery import EmailDeliveryError, send_email


def test_email_requires_explicit_production_configuration(monkeypatch):
    monkeypatch.delenv("SHIELD_SMTP_HOST", raising=False)
    monkeypatch.delenv("SHIELD_SMTP_FROM", raising=False)
    with pytest.raises(EmailDeliveryError):
        send_email("operator@example.com", "subject", "body")


@patch("shield.backend.email_delivery.smtplib.SMTP")
def test_email_uses_starttls_auth_and_configured_sender(smtp, monkeypatch):
    monkeypatch.setenv("SHIELD_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SHIELD_SMTP_FROM", "security@example.com")
    monkeypatch.setenv("SHIELD_SMTP_USERNAME", "user")
    monkeypatch.setenv("SHIELD_SMTP_PASSWORD", "secret")
    connection = MagicMock()
    smtp.return_value.__enter__.return_value = connection
    send_email("operator@example.com", "Reset", "body")
    smtp.assert_called_once_with("smtp.example.com", 587, timeout=10.0)
    connection.starttls.assert_called_once()
    connection.login.assert_called_once_with("user", "secret")
    message = connection.send_message.call_args.args[0]
    assert message["From"] == "security@example.com"
