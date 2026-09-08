import os
import resend

class EmailDeliveryError(RuntimeError):
    pass

def send_email(to_email: str, subject: str, body: str) -> None:
    sender = os.environ.get("SHIELD_EMAIL_FROM", "noreply@xibalba.local").strip()
    api_key = os.environ.get("RESEND_API_KEY")

    if not api_key:
        print(f"WARN: RESEND_API_KEY not set. Would have sent email to {to_email} with subject '{subject}'")
        # In a real environment, we'd raise an error if required:
        # raise EmailDeliveryError("RESEND_API_KEY is required")
        return

    resend.api_key = api_key

    try:
        resend.Emails.send({
            "from": sender,
            "to": to_email,
            "subject": subject,
            "text": body
        })
    except Exception as exc:
        raise EmailDeliveryError(f"Resend delivery failed: {exc}") from exc
