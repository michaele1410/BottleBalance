# -----------------------
# Admin: Users & Audit
# -----------------------

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

    # rows = db.session.execute(stmt).mappings().all()  # liefert RowMapping-Objekte
    return render_template('users.html', users=rows)

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
        flash(_('Benutzername darf nicht leer sein.'))
        return redirect(url_for('users_list'))
    if role not in ROLES:
        flash(_('Ungültige Rolle.'))
        return redirect(url_for('users_list'))
    if len(pwd) < 8:
        flash(_('Passwort muss mindestens 8 Zeichen haben.'))
        return redirect(url_for('users_list'))
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO users (username, email, password_hash, role, active, must_change_password, theme_preference)
                VALUES (:u, :e, :ph, :r, TRUE, TRUE, 'system')
            """), {'u': username, 'e': email, 'ph': generate_password_hash(pwd), 'r': role})
        flash(_('Benutzer angelegt.'))
    except Exception as e:
        flash(f"{_('Fehler:')} {e}")
    return redirect(url_for('users_list'))

@user_routes.route('/admin/users/<int:uid>/edit', methods=['GET', 'POST'])
@login_required
@require_perms('users:manage')
def edit_user(uid):
    if request.method == 'POST':
        role = request.form.get('role')
        email = (request.form.get('email') or '').strip() or None

        # Checkboxen -> bool (Checkbox sendet nur, wenn angehakt)
        active = request.form.get('active') is not None
        can_approve = request.form.get('can_approve') is not None

        # Optionales Passwort
        password = (request.form.get('password') or '').strip()

        if role not in ROLES.keys():
            flash('Ungültige Rolle.')
            return redirect(url_for('edit_user', uid=uid))

        with engine.begin() as conn:
            if password:
                hashed = generate_password_hash(password)
                stmt = text("""
                    UPDATE users
                    SET email=:email,
                        role=:role,
                        active=:active,
                        can_approve=:can_approve,
                        password_hash=:pwd,
                        updated_at=NOW()
                    WHERE id=:id
                """).bindparams(
                    bindparam('active', type_=Boolean()),
                    bindparam('can_approve', type_=Boolean()),
                )
                conn.execute(stmt, {
                    'email': email,
                    'role': role,
                    'active': active,
                    'can_approve': can_approve,
                    'pwd': hashed,
                    'id': uid
                })
            else:
                stmt = text("""
                    UPDATE users
                    SET email=:email,
                        role=:role,
                        active=:active,
                        can_approve=:can_approve,
                        updated_at=NOW()
                    WHERE id=:id
                """).bindparams(
                    bindparam('active', type_=Boolean()),
                    bindparam('can_approve', type_=Boolean()),
                )
                conn.execute(stmt, {
                    'email': email,
                    'role': role,
                    'active': active,
                    'can_approve': can_approve,
                    'id': uid
                })

        flash('Benutzer aktualisiert.')
        return redirect(url_for('users_list'))

    # GET-Teil
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
        flash(_('Du kannst dich nicht selbst löschen.'))
        return redirect(url_for('users_list'))

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id=:id"), {'id': uid})
    log_action(current_uid, 'users:delete', None, f"user_id={uid}")
    flash(_('Benutzer gelöscht.'))
    return redirect(url_for('users_list'))

@user_routes.post('/admin/users/<int:uid>/resetpw')
@login_required
@require_perms('users:manage')
@require_csrf
def users_reset_pw(uid: int):
    newpw = (request.form.get('password') or '').strip()
    if len(newpw) < 8:
        flash(_('Neues Passwort muss mindestens 8 Zeichen haben.'))
        return redirect(url_for('users_list'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET password_hash=:ph, must_change_password=FALSE, updated_at=NOW() WHERE id=:id"),
                     {'ph': generate_password_hash(newpw), 'id': uid})
    flash(_('Passwort gesetzt.'))
    return redirect(url_for('users_list'))

@user_routes.post('/admin/users/<int:uid>/resetlink')
@login_required
@require_perms('users:manage')
@require_csrf
def users_reset_link(uid: int):
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(minutes=30)
    base = build_base_url()
    reset_url = f"{base}reset/{token}"
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (:u,:t,:e)"),
                     {'u': uid, 't': token, 'e': expires})
        email = conn.execute(text("SELECT email FROM users WHERE id=:id"), {'id': uid}).scalar_one()
    body = f"""
    Dein Passwort-Reset-Token lautet:

    {token}

    Dieser Token ist 30 Minuten gültig.
    Bitte gib ihn auf der Reset-Seite ein: {APP_BASE_URL}/reset
    """
    if email and SMTP_HOST:
        sent = send_mail(email, 'Passwort zurücksetzen', body)
        if sent:
            flash(_('Reset-Link per E-Mail versendet.'))
        else:
            flash(f"{_('Reset-Link:')} {reset_url}")
            logger.warning("E-Mail-Versand fehlgeschlagen – Token im UI angezeigt (user_id=%s).", uid)
    else:
        flash(f"{_('Reset-Link:')} {reset_url}")
        logger.warning("Keine E-Mail-Adresse oder kein SMTP_HOST – Token im UI angezeigt (user_id=%s).", uid)
    return redirect(url_for('users_list'))

@user_routes.post('/admin/users/<int:uid>/toggle')
@login_required
@require_perms('users:manage')
@require_csrf
def users_toggle(uid: int):
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET active = NOT active, updated_at=NOW() WHERE id=:id"), {'id': uid})
    return redirect(url_for('users_list'))

@user_routes.post('/admin/users/<int:uid>/role')
@login_required
@require_perms('users:manage')
@require_csrf
def users_change_role(uid: int):
    role = (request.form.get('role') or 'Viewer').strip()
    if role not in ROLES:
        flash(_('Ungültige Rolle.'))
        return redirect(url_for('users_list'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET role=:r, updated_at=NOW() WHERE id=:id"), {'r': role, 'id': uid})
    return redirect(url_for('users_list'))