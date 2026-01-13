# -----------------------
# Mail
# -----------------------
import os
import ssl
import logging
from smtplib import SMTP, SMTP_SSL, SMTPException
from email.message import EmailMessage
from modules.core_utils import APP_BASE_URL, engine, get_setting
from sqlalchemy import text
from flask_babel import _

# Configuration from environment variables
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
if not logger.handlers:
    logger.addHandler(handler)

# -----------------------
# SMTP Test Mail if paraam SEND_TEST_MAIL is set to true
# -----------------------
logger.info("ENV SEND_TEST_MAIL in .env  is set to %s", SEND_TEST_MAIL)


def send_mail(to_email: str, subject: str, body: str) -> bool:
    if not SMTP_HOST:
        logger.warning("SMTP_HOST not set – mail delivery skipped (to=%s, subject=%s).", to_email, subject)
        return False

    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    # Branding header: App-Titel als X-Mailer
    msg["X-Mailer"] = get_setting('app_title', 'BottleBalance')
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

        logger.info("Email sent successfully (to=%s, subject=%s).", to_email, subject)
        return True
    except SMTPException as e:
        logger.error("SMTP error when sending mail (to=%s, subject=%s): %s", to_email, subject, e, exc_info=True)
        return False

def send_status_email(to_email: str, request_id: int, state: str, cc_approvers: bool = False):
    
    subject = _('Payment request #%(id)d – State: %(state)s', id=request_id, state=state.capitalize())
    body = _(
        "Your payment request #%(id)d was sent to '%(state)s'.\n\n"
        "Link: %(link)s",
        id=request_id,
        state=state,
        link=f"{APP_BASE_URL}/payment_requests/{request_id}"
    )

    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["X-Mailer"] = get_setting('app_title', 'BottleBalance')
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
            logger.warning("Error retrieving approver emails: %s", e)

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

        logger.info("Status email sent to %s for payment request %s. CC: %s", to_email, request_id, msg.get("Cc", "—"))
    except Exception as e:
        logger.error("Error sending status email: %s", e)

# -----------------------
# BottleBalance
# -----------------------
def check_smtp_configuration(to_email: str | None = None):
    """
    Lightweight SMTP connectivity check (+ optional test email).
    If to_email is provided, a UTF-8 test mail is sent.
    """
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS]):
        logger.warning("SMTP configuration incomplete – connection not possible.")
        return

    try:
        # Connect
        if SMTP_SSL_ON:
            context = ssl.create_default_context()
            server = SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context)
        else:
            server = SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
            if SMTP_TLS:
                server.starttls(context=ssl.create_default_context())

        server.login(SMTP_USER, SMTP_PASS)

        # Optional: send UTF-8 test message
        if to_email:
            subject = _("SMTP test by %(app)s", app=get_setting('app_title', 'BottleBalance'))
            body    = _("This is an automated test message to verify the SMTP configuration. "
                        "Includes special characters like Ü, Ä, Ö, and ß.")
            message = (
                f"Subject: {subject}\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "\r\n"
                f"{body}"
            ).encode("utf-8")
            server.sendmail(FROM_EMAIL, to_email, message)

        server.quit()
        logger.info("SMTP connection successful%s.",
                    " and test email sent" if to_email else "")
    except Exception as e:
        logger.warning("SMTP test failed: %s", e)
