# -----------------------
# Mail
# -----------------------
import os
import ssl
import logging
from smtplib import SMTP, SMTP_SSL, SMTPException
from email.message import EmailMessage
from modules.core_utils import APP_BASE_URL, engine
from sqlalchemy import text
from flask_babel import _
from smtplib import SMTP, SMTP_SSL

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

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[SMTP Check] %(levelname)s: %(message)s")
handler.setFormatter(formatter)

# -----------------------
# SMTP Test Mail if paraam SEND_TEST_MAIL is set to true
# -----------------------
logger.info("ENV SEND_TEST_MAIL in .env  is set to %s", SEND_TEST_MAIL)

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


def send_status_email(to_email: str, antrag_id: int, status: str, cc_approvers: bool = False):
    subject = _('Zahlungsantrag #%(id)d – Status: %(status)s', id=antrag_id, status=status.capitalize())
    body = _(
        "Ihr Zahlungsantrag #%(id)d wurde auf '%(status)s' gesetzt.\n\n"
        "Link: %(link)s",
        id=antrag_id,
        status=status,
        link=f"{APP_BASE_URL}/zahlungsfreigabe/{antrag_id}"
    )

    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    # Optional CC to approvers
    if cc_approvers:
        try:
            with engine.begin() as conn:
                approver_emails = conn.execute(text("""
                    SELECT email FROM users
                    WHERE can_approve = TRUE AND active = TRUE AND email IS NOT NULL
                """)).scalars().all()
            if approver_emails:
                msg["Cc"] = ", ".join(approver_emails)
        except Exception as e:
            logger.warning("Fehler beim Abrufen der Approver-E-Mails: %s", e)

    # Send email
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

        logger.info("Status-E-Mail gesendet an %s für Antrag %s. CC: %s", to_email, antrag_id, msg.get("Cc", "—"))
    except Exception as e:
        logger.error("Fehler beim Senden der Status-E-Mail: %s", e)

# -----------------------
# BottleBalance
# -----------------------

def check_smtp_configuration():
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS]):
        logger.warning("SMTP-Konfiguration unvollständig – keine Verbindung möglich.")
        return

    try:
        if SMTP_SSL:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
            if SMTP_TLS:
                server.starttls()

        server.login(SMTP_USER, SMTP_PASS)

        # UTF-8-kodierte Test-E-Mail senden
        message = (
            "Subject: SMTP-Test von BottleBalance\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Dies ist eine automatische Testnachricht zum Überprüfen der SMTP-Konfiguration. Enthält Umlaute wie Ü, Ä, Ö und ß."
        ).encode("utf-8")

        server.sendmail(FROM_EMAIL, TO_EMAIL, message)
        server.quit()
        logger.info("SMTP-Verbindung erfolgreich und Test-E-Mail versendet.")
    except Exception as e:
        logger.warning(f"SMTP-Test fehlgeschlagen: {e}")