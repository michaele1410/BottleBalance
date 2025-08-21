import secrets
import json
from functools import wraps
from flask import session, redirect, url_for, request, abort, Blueprint, render_template, flash
from flask_babel import _
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from modules.mail_utils import send_mail  # falls du Mails aus dem Profil versendest
from modules.core_utils import (
    log_action,
    ROLES,
    engine
    ) 

# -----------------------
# Helpers: Current user, RBAC
# -----------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    with engine.begin() as conn:
        row = conn.execute(text("""
                    SELECT id, username, email, role, active, must_change_password, totp_enabled,
                        backup_codes, locale, timezone, theme_preference, can_approve, last_login_at
                    FROM users WHERE id=:id
                """), {'id': uid}).mappings().first()
    return dict(row) if row else None

def require_perms(*perms):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for('login'))
            allowed = ROLES.get(user['role'], set())
            if not all(p in allowed for p in perms):
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# --- CSRF Utils ---
def require_csrf(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Nur für state-changing requests
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            session_tok = session.get('_csrf_token') or ''
            sent_tok = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token') or ''
            if not (session_tok and sent_tok) or not secrets.compare_digest(session_tok, sent_tok):
                abort(403)
        return fn(*args, **kwargs)
    return wrapper

def csrf_token():
    # für Jinja: {{ csrf_token() }}
    return _ensure_csrf_token()

def _ensure_csrf_token():
    tok = session.get('_csrf_token')
    if not tok:
        tok = secrets.token_urlsafe(32)
        session['_csrf_token'] = tok
    return tok

# -----------------------
# Auth & 2FA & Session
# -----------------------
def _finalize_login(user_id: int, role: str):
    """Setzt Session, aktualisiert last_login_at und schreibt Audit-Log.
       Leitet NICHT um – nur Status setzen."""
    session.pop('pending_2fa_user_id', None)
    session['user_id'] = user_id
    session['role'] = role
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET last_login_at=NOW(), updated_at=NOW() WHERE id=:id"), {'id': user_id})
    log_action(user_id, 'login', None, None)

def generate_and_store_backup_codes(uid: int) -> list[str]:
    """Erzeugt 10 Backup-Codes, speichert nur Hashes in DB und liefert die Klartext-Codes zurück (einmalige Anzeige)."""
    codes = [secrets.token_hex(4).lower() for _ in range(10)]
    hashes = [generate_password_hash(c) for c in codes]
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET backup_codes=:bc WHERE id=:id"),
                     {'bc': json.dumps(hashes), 'id': uid})
    return codes