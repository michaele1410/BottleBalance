import os
from flask import session, abort, current_app
from sqlalchemy import text
from email.message import EmailMessage
from smtplib import SMTP

from modules.core_utils import (
    log_action,
    ROLES,
    engine,
    APP_BASE_URL
    ) 
from modules.mail_utils import (
    send_status_email
)
from modules.auth_utils import (
    current_user
)

def _user_can_view_antrag(antrag_id: int) -> bool:
    """Antragsteller:in oder Approver dürfen ansehen."""
    user = current_user()
    if not user:
        return False
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT antragsteller_id FROM zahlungsantraege WHERE id=:id
        """), {'id': antrag_id}).mappings().first()
    if not row:
        return False
    is_owner = (row['antragsteller_id'] == user['id'])
    is_approver = bool(user.get('can_approve'))
    return is_owner or is_approver

def _user_can_edit_antrag(antrag_id: int) -> bool:
    """
    Upload/Entfernen nur, wenn Antrag nicht 'abgeschlossen' ist
    UND (Antragsteller:in oder Approver).
    """
    user = current_user()
    if not user:
        return False
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT antragsteller_id, status
            FROM zahlungsantraege
            WHERE id=:id
        """), {'id': antrag_id}).mappings().first()
    if not row:
        return False
    if row['status'] == 'abgeschlossen':
        return False
    is_owner = (row['antragsteller_id'] == user['id'])
    is_approver = bool(user.get('can_approve'))
    return is_owner or is_approver

def get_antrag_email(antrag_id: int):
    with engine.begin() as conn:
        return conn.execute(text("""
            SELECT u.email FROM zahlungsantraege z
            JOIN users u ON u.id = z.antragsteller_id
            WHERE z.id = :id
        """), {'id': antrag_id}).scalar_one_or_none()

def get_bemerkungsoptionen():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT text FROM bemerkungsoptionen WHERE active = TRUE ORDER BY text ASC")).scalars().all()
    return rows

def _approvals_total(conn) -> int:
    # Nur aktive, freigabeberechtigte Benutzer zählen
    return conn.execute(text("""
        SELECT COUNT(*) FROM users WHERE can_approve = TRUE AND active = TRUE
    """)).scalar_one()

def _approvals_done(conn, antrag_id: int) -> int:
    # DISTINCT user_id, die für diesen Antrag freigegeben haben
    return conn.execute(text("""
        SELECT COUNT(DISTINCT user_id)
        FROM zahlungsantrag_audit
        WHERE antrag_id = :aid AND action = 'freigegeben'
    """), {'aid': antrag_id}).scalar_one()

def _approved_by_user(conn, antrag_id: int, user_id: int) -> bool:
    return bool(conn.execute(text("""
        SELECT 1
        FROM zahlungsantrag_audit
        WHERE antrag_id = :aid AND action = 'freigegeben' AND user_id = :uid
        LIMIT 1
    """), {'aid': antrag_id, 'uid': user_id}).scalar_one_or_none())

def _require_approver(user):
    if not user or not user.get('can_approve'):
        abort(403)

def send_new_request_notifications(antrag_id: int, approver_emails: list[str]) -> None:
    """
    Sendet Benachrichtigungs-E-Mails an alle approver_emails für einen neuen Zahlungsfreigabe-Antrag.
    """
    if not approver_emails:
        current_app.logger.warning("Keine Empfänger für Antrag %s gefunden – keine Mail gesendet.", antrag_id)
        return

    base_url = os.getenv("APP_BASE_URL", "http://localhost:5000")
    link = f"{base_url}/zahlungsfreigabe/{antrag_id}"

    subject = f"Neuer Zahlungsfreigabe-Antrag #{antrag_id}"
    body = (
        f"Hallo,\n\n"
        f"es wurde soeben ein neuer Zahlungsfreigabe-Antrag (#{antrag_id}) erstellt.\n"
        f"Zur Prüfung/Freigabe:\n{link}\n\n"
        f"Viele Grüße\nBottleBalance"
    )

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASS")
    use_tls = os.getenv("SMTP_TLS", "true").lower() == "true"
    from_email = os.getenv("FROM_EMAIL") or user

    if not host or not from_email:
        raise RuntimeError("SMTP_HOST und FROM_EMAIL/SMTP_USER müssen konfiguriert sein.")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    # Einzelversand oder Sammel-TO (hier Sammel-TO):
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
        "Benachrichtigungen für Antrag %s an %s gesendet.",
        antrag_id, approver_emails
    )