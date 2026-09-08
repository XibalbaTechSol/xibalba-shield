import os
import smtplib
import ssl
from email.message import EmailMessage


class EmailDeliveryError(RuntimeError):
    pass


def send_email(to_email: str, subject: str, body: str) -> None:
    host = os.environ.get("SHIELD_SMTP_HOST", "").strip()
    sender = os.environ.get("SHIELD_SMTP_FROM", "").strip()
    if not host or not sender:
        raise EmailDeliveryError("SHIELD_SMTP_HOST and SHIELD_SMTP_FROM are required")
    try:
        port = int(os.environ.get("SHIELD_SMTP_PORT", "587"))
        timeout = float(os.environ.get("SHIELD_SMTP_TIMEOUT_SECONDS", "10"))
    except ValueError as exc:
        raise EmailDeliveryError("SMTP port and timeout must be numeric") from exc

    message = EmailMessage()
    message.set_content(body)
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to_email

    username = os.environ.get("SHIELD_SMTP_USERNAME", "").strip()
    password = os.environ.get("SHIELD_SMTP_PASSWORD", "")
    try:
        with smtplib.SMTP(host, port, timeout=timeout) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            if username:
                if not password:
                    raise EmailDeliveryError("SHIELD_SMTP_PASSWORD is required when username is set")
                server.login(username, password)
            server.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError(f"SMTP delivery failed: {exc}") from exc
