import json
import pyotp
import re

from flask_babel import gettext as _
from flask import render_template, request, redirect, url_for, session, flash, Blueprint
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from modules.core_utils import (
    engine,
    log_action
)
from modules.auth_utils import (
    login_required,
    require_csrf,
    _finalize_login,
    check_password_hash,
    generate_and_store_backup_codes
)


auth_routes = Blueprint('auth_routes', __name__)

# -----------------------
# Auth & 2FA
# -----------------------

@auth_routes.route('/login', methods=['GET', 'POST'])
@require_csrf
def login():

    # GET-Logik
    if request.method == 'GET':
        # Prüfe, ob sich noch niemand eingeloggt hat
        with engine.begin() as conn:
            first_login_admin = conn.execute(text("SELECT COUNT(*) FROM users WHERE last_login_at IS NOT NULL")).scalar_one() == 0

        if first_login_admin:
            flash(_('Standard-Login: Benutzername <strong>admin</strong> und Passwort <strong>admin</strong> – bitte sofort ändern!'), 'warning')

        return render_template('login.html')
    
    # POST-Logik
    
    username = (request.form.get('username') or '').strip()
    password = (request.form.get('password') or '').strip()
    with engine.begin() as conn:
        user = conn.execute(text("""
            SELECT id, username, password_hash, role, active, must_change_password, totp_enabled, last_login_at
            FROM users WHERE username=:u
        """), {'u': username}).mappings().first()

    if not user or not check_password_hash(user['password_hash'], password) or not user['active']:
        flash(_('Login fehlgeschlagen.'))
        return redirect(url_for('auth_routes.login'))

    # Falls Passwort geändert werden muss: Info + Flag für spätere Weiterleitung setzen
    force_profile = False
    if user['must_change_password'] and user['role'] != 'admin':
        flash(_('Bitte das Passwort <a href="{0}" class="alert-link">im Profil</a> ändern.')
              .format(url_for('profile')), 'warning')
        force_profile = True
        session['force_profile_after_login'] = True  # <<--- nur Flag, keine Session-Authentifizierung!

    if user['totp_enabled']:
        # 2FA-Flow starten; force_profile wird nach erfolgreicher 2FA ausgewertet
        session['pending_2fa_user_id'] = user['id']
        return redirect(url_for('auth_routes.login_2fa_get'))

    # Kein 2FA: direkt finalisieren
    _finalize_login(user['id'], user['role'])

   # Nach erfolgreichem Login ggf. erzwungen zum Profil umleiten
    if force_profile:
        session.pop('force_profile_after_login', None)
        return redirect(url_for('profile'))

    # Rollenbasierte Weiterleitung
    if user['role'] == 'Payment Viewer':
        return redirect(url_for('payment_routes.zahlungsfreigabe'))

    # Standard-Weiterleitung
    return redirect(url_for('bbalance_routes.index'))

@auth_routes.get('/2fa')
def login_2fa_get():
    if not session.get('pending_2fa_user_id'):
        return redirect(url_for('auth_routes.login'))
    return render_template('2fa.html')

@auth_routes.post('/2fa')
@require_csrf
def login_2fa_post():
    uid = session.get('pending_2fa_user_id')
    if not uid:
        return redirect(url_for('auth_routes.login'))

    raw = request.form.get('code') or ''
    code = re.sub(r'[\s\-]', '', raw).lower()

    with engine.begin() as conn:
        user = conn.execute(text("""
            SELECT id, role, totp_secret, backup_codes
            FROM users WHERE id=:id
        """), {'id': uid}).mappings().first()

    if not user or not user['totp_secret']:
        flash(_('2FA nicht aktiv.'))
        return redirect(url_for('auth_routes.login'))

    totp = pyotp.TOTP(user['totp_secret'])

    # Prüfe TOTP
    if totp.verify(code, valid_window=1):
        _finalize_login(user['id'], user['role'])
        # Flag auswerten
        if session.pop('force_profile_after_login', None):
            return redirect(url_for('profile'))
        return redirect(url_for('bbalance_routes.index'))

    # Prüfe Backup-Codes
    bc_raw = user.get('backup_codes') or '[]'
    try:
        hashes = json.loads(bc_raw)
        if not isinstance(hashes, list):
            hashes = []
    except Exception:
        hashes = []

    matched_idx = None
    for i, h in enumerate(hashes):
        if h and check_password_hash(h, code):
            matched_idx = i
            break

    if matched_idx is not None:
        # Neuen Satz Backup-Codes generieren
        new_codes = generate_and_store_backup_codes(uid)

        # Einmalige Anzeige im Profil
        session['new_backup_codes'] = new_codes

        _finalize_login(user['id'], user['role'])
        flash(_('Backup-Code verwendet. Es wurden automatisch neue Codes generiert. Bitte sicher aufbewahren.'), 'info')
        log_action(user['id'], '2fa:backup_used_regenerated', None, None)

        # Nach Backup-Code ggf. ebenfalls Flag auswerten
        if session.pop('force_profile_after_login', None):
            return redirect(url_for('profile'))
        return redirect(url_for('profile'))  # Hier willst du ohnehin ins Profil
                                             # (zeigt die neuen Codes einmalig an)

    flash(_('Ungültiger 2FA-Code oder Backup-Code.'))
    return redirect(url_for('auth_routes.login_2fa_get'))


@auth_routes.post('/profile/2fa/regen')
@login_required
@require_csrf
def regen_backup_codes():
    uid = session['user_id']
    codes = generate_and_store_backup_codes(uid)
    # Einmalige Anzeige im Profil
    session['new_backup_codes'] = codes
    flash(_('Neue Backup-Codes wurden generiert. Bitte sicher aufbewahren.'))
    return redirect(url_for('profile'))

@auth_routes.post('/logout')
@login_required
@require_csrf
def logout():
    uid = session.get('user_id')
    log_action(uid, 'logout', None, None)
    session.clear()
    return redirect(url_for('auth_routes.login'))

# Reset-Formular (Token-only)
@auth_routes.get('/reset')
def reset_form():
    return render_template('reset.html')

@auth_routes.post('/reset')
@require_csrf
def reset_post():
    token = (request.form.get('token') or '').strip()
    pwd   = (request.form.get('password')  or '').strip()
    pwd2  = (request.form.get('password2') or '').strip()
    if not token:
        flash(_('Reset‑Token fehlt.'))
        return redirect(url_for('reset_form'))
    if len(pwd) < 8 or pwd != pwd2:
        flash(_('Passwortanforderungen nicht erfüllt oder stimmen nicht überein.'))
        return redirect(url_for('reset_form'))
    with engine.begin() as conn:
        trow = conn.execute(
            text("SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token=:t"),
            {'t': token}
        ).mappings().first()
        if not trow or trow['used'] or trow['expires_at'] < datetime.utcnow():
            flash(_('Link ungültig oder abgelaufen.'))
            return redirect(url_for('auth_routes.login'))
        conn.execute(text("UPDATE users SET password_hash=:ph, must_change_password=FALSE, updated_at=NOW() WHERE id=:id"),
                     {'ph': generate_password_hash(pwd), 'id': trow['user_id']})
        conn.execute(text("UPDATE password_reset_tokens SET used=TRUE WHERE user_id=:uid AND used=FALSE"), {"uid": trow['user_id']})
    flash(_('Passwort aktualisiert. Bitte einloggen.'))
    return redirect(url_for('auth_routes.login'))