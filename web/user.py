# -----------------------
# Admin: Users & Audit
# -----------------------
import secrets
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, session, flash, abort, Blueprint
from flask_babel import gettext as _
from markupsafe import escape
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from modules.auth_utils import (
    login_required,
    require_perms,
    require_csrf,
    current_user
)

from modules.core_utils import (
    engine,
    log_action
)

from modules.core_utils import (
    log_action,
    ROLES,
    engine,
    build_base_url,
    APP_BASE_URL
)

from modules.mail_utils import (
    SMTP_HOST,
    logger
)

from modules.mail_utils import (
    send_mail
)

user_routes = Blueprint('user_routes', __name__)

@user_routes.get('/admin/users')
@login_required
@require_perms('users:manage')
def users_list():
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, username, email, role, active, must_change_password, can_approve, created_at, updated_at
            FROM users
            ORDER BY username ASC
        """)).mappings().all()

    # rows = db.session.execute(stmt).mappings().all()  # delivers RowMapping objects
    return render_template('users.html', users=rows, user=current_user())

@user_routes.post('/admin/users/add')
@login_required
@require_perms('users:manage')
@require_csrf
def users_add():    
    username = (request.form.get('username') or '').strip()
    email = (request.form.get('email') or '').strip() or None
    role = (request.form.get('role') or 'Viewer').strip()
    pwd = (request.form.get('password') or '').strip()
    if not username:
        flash(_('Username cannot be empty.'), 'warning')
        return redirect(url_for('user_routes.users_list'))
    if role not in ROLES:
        flash(_('Invalid role.'), 'danger')
        return redirect(url_for('user_routes.users_list'))
    if len(pwd) < 8:
        flash(_('Password must be at least 8 characters long.'), 'danger')
        return redirect(url_for('user_routes.users_list'))
    
    
    try:
        with engine.begin() as conn:
            # Username-Kollision (case-insensitive)?
            exists_username = conn.execute(text("""
                SELECT 1 FROM users WHERE LOWER(username) = LOWER(:u)
            """), {'u': username}).scalar_one_or_none()
            if exists_username:
                flash(_('Username already exists.'), 'danger')
                return redirect(url_for('user_routes.users_list'))

            # Only check for email collision if email is available
            if email:
                exists_email = conn.execute(text("""
                    SELECT 1 FROM users
                    WHERE email IS NOT NULL AND email <> '' AND LOWER(email) = LOWER(:e)
                """), {'e': email}).scalar_one_or_none()
                if exists_email:
                    flash(_('Email already in use.'), 'danger')
                    return redirect(url_for('user_routes.users_list'))

            # Now create users
            conn.execute(text("""
                INSERT INTO users (username, email, password_hash, role, active, must_change_password, theme_preference)
                VALUES (:u, :e, :ph, :r, TRUE, TRUE, 'system')
            """), {'u': username, 'e': email, 'ph': generate_password_hash(pwd), 'r': role})

        flash(_('User created.'), 'success')
    except Exception as e:
        flash(_('Error: %(error)s', error=escape(str(e))), 'danger')

    return redirect(url_for('user_routes.users_list'))

@user_routes.route('/admin/users/<int:uid>/edit', methods=['GET', 'POST'])
@login_required
@require_perms('users:manage')
def edit_user(uid):
    if request.method == 'POST':
        role = request.form.get('role')
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip() or None

        # Checkboxes -> bool (checkbox only sends when checked)
        active = request.form.get('active') is not None
        can_approve = request.form.get('can_approve') is not None

        # Optional password
        password = (request.form.get('password') or '').strip()

        if role not in ROLES.keys():
            flash(_('Invalid role.'), 'danger')
            return redirect(url_for('edit_user', uid=uid))

        with engine.begin() as conn:
                # Username collision (excluding own data record)
                if username:
                    exists_username = conn.execute(text("""
                        SELECT 1 FROM users
                        WHERE id <> :id AND LOWER(username) = LOWER(:u)
                    """), {'id': uid, 'u': username}).scalar_one_or_none()
                    if exists_username:
                        flash(_('Username already exists.'), 'danger')
                        return redirect(url_for('edit_user', uid=uid))

                if email:
                    exists_email = conn.execute(text("""
                        SELECT 1 FROM users
                        WHERE id <> :id
                        AND email IS NOT NULL AND email <> ''
                        AND LOWER(email) = LOWER(:e)
                    """), {'id': uid, 'e': email}).scalar_one_or_none()
                    if exists_email:
                        flash(_('Email already in use.'), 'danger')
                        return redirect(url_for('edit_user', uid=uid))

                # Update including username
                base_stmt = """
                    UPDATE users
                    SET username=:username,
                        email=:email,
                        role=:role,
                        active=:active,
                        can_approve=:can_approve,
                        {pwd_clause}
                        updated_at=NOW()
                    WHERE id=:id
                """
                if password:
                    hashed = generate_password_hash(password)
                    stmt = text(base_stmt.format(pwd_clause="password_hash=:pwd,"))
                    params = {'username': username, 'email': email, 'role': role,
                            'active': active, 'can_approve': can_approve,
                            'pwd': hashed, 'id': uid}
                else:
                    stmt = text(base_stmt.format(pwd_clause=""))
                    params = {'username': username, 'email': email, 'role': role,
                            'active': active, 'can_approve': can_approve, 'id': uid}
                # You can keep bindparam(Boolean) if you need it.
                conn.execute(stmt, params)

        flash(_('User updated.'), 'success')
        return redirect(url_for('user_routes.users_list'))

    # GET part
    with engine.begin() as conn:
        user = conn.execute(text("""
            SELECT id, username, email, role, active, can_approve
            FROM users
            WHERE id=:id
        """), {'id': uid}).mappings().first()
    if not user:
        abort(404)
    roles = ROLES.keys()
    return render_template('edit_user.html', user=user, roles=roles)

@user_routes.post('/admin/users/<int:uid>/delete')
@login_required
@require_perms('users:manage')
@require_csrf
def users_delete(uid: int):
    current_uid = session.get('user_id')
    if uid == current_uid:
        flash(_('You cannot delete yourself.'), 'warning')
        return redirect(url_for('user_routes.users_list'))

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id=:id"), {'id': uid})
    log_action(current_uid, 'users:delete', None, f"user_id={uid}")
    flash(_('User deleted.'), 'success')
    return redirect(url_for('user_routes.users_list'))

@user_routes.post('/admin/users/<int:uid>/resetpw')
@login_required
@require_perms('users:manage')
@require_csrf
def users_reset_pw(uid: int):
    newpw = (request.form.get('password') or '').strip()
    if len(newpw) < 8:
        flash(_('New password must be at least 8 characters long.'), 'danger')
        return redirect(url_for('user_routes.users_list'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET password_hash=:ph, must_change_password=FALSE, updated_at=NOW() WHERE id=:id"),
                     {'ph': generate_password_hash(newpw), 'id': uid})
    flash(_('New password set.'), 'success')
    return redirect(url_for('user_routes.users_list'))

@user_routes.post('/admin/users/<int:uid>/resetlink')
@login_required
@require_perms('users:manage')
@require_csrf
def users_reset_link(uid: int):
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(minutes=30)
    base = build_base_url()  # ends with /
    reset_url = f"{base}reset/{token}"

    with engine.begin() as conn:
        conn.execute(text("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (:u,:t,:e)"),
                     {'u': uid, 't': token, 'e': expires})
        email = conn.execute(text("SELECT email FROM users WHERE id=:id"), {'id': uid}).scalar_one()

    body = _(
        "Your password reset token is:\n\n"
        "%(token)s\n\n"
        "This token is valid for 30 minutes.\n"
        "Please use the following link: %(url)s",
        token=token,
        url=reset_url
    )

    if email and SMTP_HOST:
        sent = send_mail(email, _("Reset password"), body)
        if sent:
            flash(_('Reset link sent by email.'), 'success')
        else:
            flash(_('Reset-Link: %(url)s', url=escape(reset_url)), 'info')
            logger.warning("Email delivery failed – token displayed in UI (user_id=%s).", uid)
    else:
        flash(_('Reset-Link: %(url)s', url=escape(reset_url)), 'info')
        logger.warning("No email address or SMTP_HOST token displayed in the UI (user_id=%s).", uid)

    return redirect(url_for('user_routes.users_list'))

@user_routes.post('/admin/users/<int:uid>/toggle')
@login_required
@require_perms('users:manage')
@require_csrf
def users_toggle(uid: int):
    current_uid = session.get('user_id')
    if uid == current_uid:
        flash(_('You cannot deactivate yourself.'), 'warning')
        return redirect(url_for('user_routes.users_list'))

    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET active = NOT active, updated_at=NOW() WHERE id=:id"), {'id': uid})
    return redirect(url_for('user_routes.users_list'))

@user_routes.post('/admin/users/<int:uid>/role')
@login_required
@require_perms('users:manage')
@require_csrf
def users_change_role(uid: int):
    role = (request.form.get('role') or 'Viewer').strip()
    if role not in ROLES:
        flash(_('Invalid role.'), 'danger')
        return redirect(url_for('user_routes.users_list'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET role=:r, updated_at=NOW() WHERE id=:id"), {'r': role, 'id': uid})
    return redirect(url_for('user_routes.users_list'))