import os
import ssl
from flask import session, abort, current_app
from sqlalchemy import text
from flask_babel import _
from email.message import EmailMessage
from smtplib import SMTP

from modules.core_utils import (
    engine
) 

from modules.auth_utils import (
    current_user
)

from modules.core_utils import get_setting

def _user_can_view_payment_request(request_id: int) -> bool:
    """Requestor or Approver can view."""
    user = current_user()
    if not user:
        return False
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT requestor_id FROM payment_requests WHERE id=:id
        """), {'id': request_id}).mappings().first()
    if not row:
        return False
    is_owner = (row['requestor_id'] == user['id'])
    is_approver = bool(user.get('can_approve'))
    return is_owner or is_approver

def _user_can_edit_payment_request(request_id: int) -> bool:
    """
    Upload/remove only if the request is not 'completed'
    AND (Applicant or Approver).
    """
    user = current_user()
    if not user:
        return False
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT requestor_id, state
            FROM payment_requests
            WHERE id=:id
        """), {'id': request_id}).mappings().first()
    if not row:
        return False
    if row['state'] == 'completed':
        return False
    is_owner = (row['requestor_id'] == user['id'])
    is_approver = bool(user.get('can_approve'))
    return is_owner or is_approver

def get_payment_request_email(request_id: int):
    with engine.begin() as conn:
        return conn.execute(text("""
            SELECT u.email FROM payment_requests z
            JOIN users u ON u.id = z.requestor_id
            WHERE z.id = :id
        """), {'id': request_id}).scalar_one_or_none()

def get_notes():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT text FROM notes WHERE active = TRUE ORDER BY text ASC")).scalars().all()
    return rows

def _approvals_total(conn) -> int:
    # Only active users with approval authorization count
    return conn.execute(text("""
        SELECT COUNT(*) FROM users WHERE can_approve = TRUE AND active = TRUE
    """)).scalar_one()

def _approvals_done(conn, request_id: int) -> int:
    # DISTINCT user_ids that have approved this request
    return conn.execute(text("""
        SELECT COUNT(DISTINCT user_id)
        FROM payment_requests_audit
        WHERE request_id = :aid AND action = 'approved'
    """), {'aid': request_id}).scalar_one()

def _approved_by_user(conn, request_id: int, user_id: int) -> bool:
    return bool(conn.execute(text("""
        SELECT 1
        FROM payment_requests_audit
        WHERE request_id = :aid AND action = 'approved' AND user_id = :uid
        LIMIT 1
    """), {'aid': request_id, 'uid': user_id}).scalar_one_or_none())

def _require_approver(user):
    if not user or not user.get('can_approve'):
        abort(403)

def send_new_request_notifications(request_id: int, approver_emails: list[str]) -> None:
    """
    Sends notification emails to all approver_emails for a new payment request.
    """
    if not approver_emails:
        current_app.logger.warning("No recipients found for request %s – no email sent.", request_id)
        return

    base_url = os.getenv("APP_BASE_URL", "http://localhost:5000")
    link = f"{base_url}/payment_requests/{request_id}"

    subject = _('New payment request #%(id)d', id=request_id)
    body = _(
        "Hello,\n\n"
        "A new payment request (#%(id)d) has just been created.\n"
        "For review/approval:\n%(link)s\n\n"
        "Best regards, %(app)s",
        id=request_id,
        link=link,
        app=_("AppTitle")
    )

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASS")
    use_tls = os.getenv("SMTP_TLS", "true").lower() == "true"
    from_email = os.getenv("FROM_EMAIL") or user

    if not host or not from_email:
        raise RuntimeError("SMTP_HOST and FROM_EMAIL/SMTP_USER must be configured.")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    # Individual shipping or collective TO (collective TO in this case):
    msg["To"] = ", ".join(approver_emails)
    msg.set_content(body)

    context = ssl.create_default_context()
    with SMTP(host, port, timeout=30) as smtp:
        if use_tls:
            smtp.starttls(context=context)
        if user and password:
            smtp.login(user, password)
        smtp.send_message(msg)

    current_app.logger.info(
        "Notifications for payment request %s sent to %s.",
        request_id, approver_emails
    )