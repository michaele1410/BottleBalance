
import json
import pyotp
import re
import secrets

from flask_babel import gettext as _
from flask import render_template, request, redirect, url_for, session, flash, Blueprint

from flask import current_app
from flask_mail import Message

from markupsafe import Markup
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

from modules.core_utils import (
    engine,
    log_action,
    APP_BASE_URL
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
    # Rollenbezeichnung konsistent zur DB ('Admin', nicht 'admin')
    if user['must_change_password'] and user['role'] != 'Admin':
        message = _(
            'Bitte das Passwort <a href="%(link)s" class="alert-link">im Profil</a> ändern.',
        ) % {'link': url_for('profile')}  # Babel-style substitution
        flash(Markup(message), 'warning')  # Mark message as safe HTML

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

#@auth_routes.post('/reset')
#@require_csrf
#def reset_post():
#    token = (request.form.get('token') or '').strip()
#    pwd   = (request.form.get('password')  or '').strip()
#    pwd2  = (request.form.get('password2') or '').strip()
#    if not token:
#        flash(_('Reset‑Token fehlt.'))
#        return redirect(url_for('reset_form'))
#    if len(pwd) < 8 or pwd != pwd2:
#        flash(_('Passwortanforderungen nicht erfüllt oder stimmen nicht überein.'))
#        return redirect(url_for('reset_form'))
#    with engine.begin() as conn:
#        trow = conn.execute(
#            text("SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token=:t"),
#            {'t': token}
#        ).mappings().first()
#        if not trow or trow['used'] or trow['expires_at'] < datetime.utcnow():
#            flash(_('Link ungültig oder abgelaufen.'))
#            return redirect(url_for('auth_routes.login'))
#        conn.execute(text("UPDATE users SET password_hash=:ph, must_change_password=FALSE, updated_at=NOW() WHERE id=:id"),
#                     {'ph': generate_password_hash(pwd), 'id': trow['user_id']})
#        conn.execute(text("UPDATE password_reset_tokens SET used=TRUE WHERE user_id=:uid AND used=FALSE"), {"uid": trow['user_id']})
#    flash(_('Passwort aktualisiert. Bitte einloggen.'))
#    return redirect(url_for('auth_routes.login'))

@auth_routes.get('/reset/<token>')
def reset_get(token: str):
    # Token prüfen
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, user_id, expires_at, used
            FROM password_reset_tokens
            WHERE token=:t
        """), {'t': token}).mappings().first()

    if not row or row['used'] or (row['expires_at'] and row['expires_at'] < datetime.utcnow()):
        flash(_('Reset-Link ist ungültig oder abgelaufen.'), 'danger')
        return redirect(url_for('auth_routes.login'))

    return render_template('reset.html', token=token)

@auth_routes.post('/reset/<token>')
@require_csrf
def reset_post(token: str):
    pwd  = (request.form.get('password')  or '').strip()
    pwd2 = (request.form.get('password2') or '').strip()

    if len(pwd) < 8:
        flash(_('Passwort muss mindestens 8 Zeichen haben.') + '.', 'danger')
        return redirect(url_for('auth_routes.reset_get', token=token))
    if pwd != pwd2:
        flash(_('Passwörter stimmen nicht überein.') + '.', 'danger')
        return redirect(url_for('auth_routes.reset_get', token=token))
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, user_id, expires_at, used
            FROM password_reset_tokens
            WHERE token=:t
            FOR UPDATE
        """), {'t': token}).mappings().first()

        if not row or row['used'] or (row['expires_at'] and row['expires_at'] < datetime.utcnow()):
            flash(_('Reset-Link ist ungültig oder abgelaufen.'), 'danger')
            return redirect(url_for('auth_routes.login'))

        # Passwort setzen
        conn.execute(text("""
            UPDATE users
            SET password_hash=:ph, must_change_password=FALSE, updated_at=NOW()
            WHERE id=:uid
        """), {'ph': generate_password_hash(pwd), 'uid': row['user_id']})

        # Token als verwendet markieren
        conn.execute(text("""
            UPDATE password_reset_tokens
            SET used=TRUE
            WHERE id=:id
        """), {'id': row['id']})

    flash(_('Passwort wurde zurückgesetzt.') + '.', 'success')
    return redirect(url_for('auth_routes.login'))

@auth_routes.post('/forgot')
@require_csrf
def request_reset():
    username = (request.form.get('username') or '').strip()
    # generische Antwort – verhindert Nutzer-Enumeration
    generic_msg = _('Wenn die Angaben korrekt sind, wurde ein Reset-Link gesendet.')

    if not username:
        flash(_('Bitte Benutzername angeben') + '.', 'danger')
        return redirect(url_for('auth_routes.login'))

    # Nutzer laden
    with engine.begin() as conn:
        user = conn.execute(text("""
            SELECT id, email FROM users
            WHERE username=:u AND active=TRUE
        """), {'u': username}).mappings().first()

    # Wenn nicht vorhanden oder keine E-Mail -> generische Meldung
    if not user or not (user.get('email') or '').strip():
        flash(generic_msg, 'info')
        return redirect(url_for('auth_routes.login'))

    # Token erzeugen + speichern
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO password_reset_tokens (user_id, token, expires_at, used)
            VALUES (:uid, :tok, :exp, FALSE)
        """), {'uid': user['id'], 'tok': token, 'exp': expires_at})

    # Reset-URL konstruieren
    # Nutze APP_BASE_URL (falls gesetzt) für absolute URL
    reset_path = url_for('auth_routes.reset_get', token=token)
    reset_url = (APP_BASE_URL.rstrip('/') + reset_path) if (APP_BASE_URL or '').strip() else url_for('reset_get', token=token, _external=True)

    # E-Mail senden
    try:
        msg = Message(
            subject=_('Passwort zurücksetzen'),
            recipients=[user['email']],
            body=_('Bitte klicke auf den folgenden Link, um dein Passwort zurückzusetzen:\n\n%(url)s\n\nDer Link ist 1 Stunde gültig.', url=reset_url)
        )
        # bestehende Mail-Extension aus app.py nutzen:
        current_app.extensions['mail'].send(msg)
    except Exception as e:
        # Keine Details leaken – trotzdem generische Antwort
        flash(generic_msg, 'info')
        return redirect(url_for('auth_routes.login'))

    flash(generic_msg, 'info')
    return redirect(url_for('auth_routes.login'))
