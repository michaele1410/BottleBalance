import os
import ssl
import logging
from smtplib import SMTP, SMTP_SSL, SMTPException
from email.message import EmailMessage

# Konfiguration aus Umgebungsvariablen
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() in ("1", "true", "yes", "on")
SMTP_SSL_ON = os.getenv("SMTP_SSL", "false").lower() in ("1", "true", "yes", "on")
SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "10"))
FROM_EMAIL = os.getenv("FROM_EMAIL") or SMTP_USER or "no-reply@example.com"
SEND_TEST_MAIL = os.getenv("SEND_TEST_MAIL", "false").lower() in ("1", "true", "yes", "on")
APP_BASE_URL = os.getenv("APP_BASE_URL") or "http://localhost:5000"

logger = logging.getLogger(__name__)

def send_mail(to_email: str, subject: str, body: str) -> bool:
    if not SMTP_HOST:
        logger.warning("SMTP_HOST nicht gesetzt – Mailversand übersprungen (to=%s, subject=%s).", to_email, subject)
        return False

    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if SMTP_SSL_ON:
            context = ssl.create_default_context()
            with SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context) as s:
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as s:
                s.ehlo()
                if SMTP_TLS:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)

        logger.info("E-Mail erfolgreich gesendet (to=%s, subject=%s).", to_email, subject)
        return True
    except SMTPException as e:
        logger.error("SMTP-Fehler beim Mailversand (to=%s, subject=%s): %s", to_email, subject, e, exc_info=True)
        return False

def send_status_email(to_email: str, antrag_id: int, status: str):
    subject = f"Zahlungsantrag #{antrag_id} – Status: {status.capitalize()}"
    body = f"Ihr Zahlungsantrag #{antrag_id} wurde auf '{status}' gesetzt.\n\nLink: {APP_BASE_URL}/zahlungsfreigabe/{antrag_id}"
    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if SMTP_SSL_ON:
            context = ssl.create_default_context()
            with SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context) as s:
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as s:
                s.ehlo()
                if SMTP_TLS:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        logger.info("Status-E-Mail gesendet an %s für Antrag %s", to_email, antrag_id)
    except Exception as e:
        logger.error("Fehler beim Senden der Status-E-Mail: %s", e)