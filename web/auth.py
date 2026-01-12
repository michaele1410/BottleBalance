
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

    # Get Logic
    if request.method == 'GET':
        # Check whether anyone has logged in yet.
        with engine.begin() as conn:
            first_login_admin = conn.execute(text("SELECT COUNT(*) FROM users WHERE last_login_at IS NOT NULL")).scalar_one() == 0

        if first_login_admin:
            flash(_('Default login: Username <strong>admin</strong> and password <strong>admin</strong> – please change immediately!'), 'warning')

        return render_template('login.html')
    
    # POST logic
    username = (request.form.get('username') or '').strip()
    password = (request.form.get('password') or '').strip()
    with engine.begin() as conn:
        user = conn.execute(text("""
            SELECT id, username, password_hash, role, active, must_change_password, totp_enabled, last_login_at
            FROM users WHERE username=:u
        """), {'u': username}).mappings().first()

    if not user or not check_password_hash(user['password_hash'], password) or not user['active']:
        flash(_('Login failed.'))
        return redirect(url_for('auth_routes.login'))

    # If password needs to be changed: Set info + flag for later forwarding
    force_profile = False
    # Role name consistent with the database ('Admin', not 'admin')
    if user['must_change_password'] and user['role'] != 'Admin':
        message = _(
            'Please change the password <a href="%(link)s" class="alert-link">on profile</a>.',
        ) % {'link': url_for('profile')}  # Babel-style substitution
        flash(Markup(message), 'warning')  # Mark message as safe HTML

        force_profile = True
        session['force_profile_after_login'] = True  # <<--- flag only, no session authentication!


    if user['totp_enabled']:
        # Start 2FA flow; force_profile is evaluated after successful 2FA
        session['pending_2fa_user_id'] = user['id']
        return redirect(url_for('auth_routes.login_2fa_get'))

    # No 2FA: finalize directly
    _finalize_login(user['id'], user['role'])

   # After successful login, redirect to profile if necessary
    if force_profile:
        session.pop('force_profile_after_login', None)
        return redirect(url_for('profile'))

    # Role-based forwarding
    if user['role'] == 'Payment Viewer':
        return redirect(url_for('payment_routes.payment_requests'))

    # Standard forwarding
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
        flash(_('2FA not active.'))
        return redirect(url_for('auth_routes.login'))

    totp = pyotp.TOTP(user['totp_secret'])

    # Check TOTP
    if totp.verify(code, valid_window=1):
        _finalize_login(user['id'], user['role'])
        # Evaluate flag
        if session.pop('force_profile_after_login', None):
            return redirect(url_for('profile'))
        return redirect(url_for('bbalance_routes.index'))

    # Check backup codes
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
        # Generate new set of backup codes
        new_codes = generate_and_store_backup_codes(uid)

        # One-time display in profile
        session['new_backup_codes'] = new_codes

        _finalize_login(user['id'], user['role'])
        flash(_('Backup code used. New codes were generated automatically. Please keep them safe.'), 'info')
        log_action(user['id'], '2fa:backup_used_regenerated', None, None)

        # If necessary, also evaluate flag after backup code
        if session.pop('force_profile_after_login', None):
            return redirect(url_for('profile'))
        return redirect(url_for('profile'))

    flash(_('Invalid 2FA code or backup code.'))
    return redirect(url_for('auth_routes.login_2fa_get'))

@auth_routes.post('/profile/2fa/regen')
@login_required
@require_csrf
def regen_backup_codes():
    uid = session['user_id']
    codes = generate_and_store_backup_codes(uid)
    # One-time display in profile
    session['new_backup_codes'] = codes
    flash(_('New backup codes have been generated. Please keep them safe.'))
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

@auth_routes.get('/reset/<token>')
def reset_get(token: str):
    # Check token
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, user_id, expires_at, used
            FROM password_reset_tokens
            WHERE token=:t
        """), {'t': token}).mappings().first()

    if not row or row['used'] or (row['expires_at'] and row['expires_at'] < datetime.utcnow()):
        flash(_('Reset link is invalid or expired.'), 'danger')
        return redirect(url_for('auth_routes.login'))

    return render_template('reset.html', token=token)

@auth_routes.post('/reset/<token>')
@require_csrf
def reset_post(token: str):
    pwd  = (request.form.get('password')  or '').strip()
    pwd2 = (request.form.get('password2') or '').strip()

    if len(pwd) < 8:
        flash(_('Password must be at least 8 characters long.') + '.', 'danger')
        return redirect(url_for('auth_routes.reset_get', token=token))
    if pwd != pwd2:
        flash(_('Passwords do not match.'), 'danger')
        return redirect(url_for('auth_routes.reset_get', token=token))
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, user_id, expires_at, used
            FROM password_reset_tokens
            WHERE token=:t
            FOR UPDATE
        """), {'t': token}).mappings().first()

        if not row or row['used'] or (row['expires_at'] and row['expires_at'] < datetime.utcnow()):
            flash(_('Reset link is invalid or has expired.'), 'danger')
            return redirect(url_for('auth_routes.login'))

        # Set password
        conn.execute(text("""
            UPDATE users
            SET password_hash=:ph, must_change_password=FALSE, updated_at=NOW()
            WHERE id=:uid
        """), {'ph': generate_password_hash(pwd), 'uid': row['user_id']})

        # Mark token as used
        conn.execute(text("""
            UPDATE password_reset_tokens
            SET used=TRUE
            WHERE id=:id
        """), {'id': row['id']})

    flash(_('Password has been reset.'), 'success')
    return redirect(url_for('auth_routes.login'))

@auth_routes.post('/forgot')
@require_csrf
def request_reset():
    username = (request.form.get('username') or '').strip()
    # Generic response – prevents user enumeration
    generic_msg = _('If the information is correct, a reset link has been sent.')

    if not username:
        flash(_('Please enter your username.'), 'danger')
        return redirect(url_for('auth_routes.login'))

    # Load user
    with engine.begin() as conn:
        user = conn.execute(text("""
            SELECT id, email FROM users
            WHERE username=:u AND active=TRUE
        """), {'u': username}).mappings().first()

    # If not available or no email -> generic message
    if not user or not (user.get('email') or '').strip():
        flash(generic_msg, 'info')
        return redirect(url_for('auth_routes.login'))

    # Generate + save tokens
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO password_reset_tokens (user_id, token, expires_at, used)
            VALUES (:uid, :tok, :exp, FALSE)
        """), {'uid': user['id'], 'tok': token, 'exp': expires_at})

    # Construct reset URL
    # Use APP_BASE_URL (if set) for absolute URL
    reset_path = url_for('auth_routes.reset_get', token=token)
    reset_url = (APP_BASE_URL.rstrip('/') + reset_path) if (APP_BASE_URL or '').strip() else url_for('reset_get', token=token, _external=True)

    # Send email
    try:
        msg = Message(
            subject=_('Reset password'),
            recipients=[user['email']],
            body=_('Please click on the following link to reset your password:\n\n%(url)s\n\nThe link is valid for 1 hour.', url=reset_url)
        )
        # Use existing mail extension from app.py:
        current_app.extensions['mail'].send(msg)
    except Exception as e:
        # No details leaked – generic response nonetheless
        flash(generic_msg, 'info')
        return redirect(url_for('auth_routes.login'))

    flash(generic_msg, 'info')
    return redirect(url_for('auth_routes.login'))