from flask import Blueprint, request, session, redirect, url_for, render_template, flash
from sqlalchemy import text
from app import engine

from modules.auth_utils import (
    login_required,
    current_user,
    require_csrf,
    _finalize_login,
    check_password_hash
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
        return redirect(url_for('login'))

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
        return redirect(url_for('login_2fa_get'))

    # Kein 2FA: direkt finalisieren
    _finalize_login(user['id'], user['role'])

    # Nach erfolgreichem Login ggf. erzwungen zum Profil umleiten
    if force_profile:
        session.pop('force_profile_after_login', None)
        return redirect(url_for('profile'))

    return redirect(url_for('index'))