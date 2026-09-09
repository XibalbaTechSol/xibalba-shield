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
    except ValueError as exc:
        raise EmailDeliveryError("SHIELD_SMTP_PORT must be an integer") from exc
    username = os.environ.get("SHIELD_SMTP_USERNAME", "").strip()
    password = os.environ.get("SHIELD_SMTP_PASSWORD", "")
    if bool(username) != bool(password):
        raise EmailDeliveryError("SHIELD_SMTP_USERNAME and SHIELD_SMTP_PASSWORD must be configured together")

    message = EmailMessage()
    message["From"] = sender
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=15) as client:
            client.ehlo()
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
            if username:
                client.login(username, password)
            client.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError("SMTP delivery failed") from exc
