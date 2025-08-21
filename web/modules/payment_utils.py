from flask import session, abort
from sqlalchemy import text
from app import engine, log_action, APP_BASE_URL
from modules.mail_utils import send_status_email

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