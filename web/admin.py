# -----------------------
# DB Export url/admin/export-db
# -----------------------
from flask import render_template, redirect, url_for, session, send_file, flash, Blueprint

import os
import subprocess
from modules.core_utils import (
    DB_HOST,
    DB_NAME,
    DB_USER,
    DB_PASS
)
from modules.core_utils import (
    log_action
)
from modules.auth_utils import (
    login_required,
    require_perms,
    require_csrf
)

admin_routes = Blueprint('admin_routes', __name__)

@admin_routes.get('/admin/export-db')
@login_required
@require_perms('export:db')
def admin_export_page():
    return render_template('admin_export.html')

@admin_routes.post('/admin/export-db')
@login_required
@require_perms('export:db')
@require_csrf
def admin_export_dump():
    dump_file = "/tmp/bottlebalance_dump.sql"
    db_user = DB_USER
    db_name = DB_NAME
    db_host = DB_HOST
    db_pass = DB_PASS

    # Set password for pg_dump
    env = os.environ.copy()
    env["PGPASSWORD"] = db_pass

    try:
        with open(dump_file, "w") as f:
            subprocess.run([
                "pg_dump",
                "-U", db_user,
                "-h", db_host,
                db_name
            ], stdout=f, env=env, check=True)

        # audit log entry
        log_action(session.get('user_id'), 'db:export', None, f'Dump von {db_name} erzeugt')

        flash(_('Database dump successfully created.'), 'success')
        return send_file(dump_file, as_attachment=True, download_name="bottlebalance_dump.sql")

    except subprocess.CalledProcessError as e:
        flash(_('Error during database dump: %(error)s', error=str(e)), 'danger')
        log_action(session.get('user_id'), 'db:export:error', None, f'Dump fehlgeschlagen: {e}')
        return redirect(url_for('admin_export_page'))

@admin_routes.post('/settings/app_title')
@login_required
@require_perms('admin:tools')
@require_csrf
def set_app_title():
    new_title = (request.form.get('app_title') or '').strip()
    if not new_title:
        flash(_("App title cannot be empty."), "danger")
        return redirect(request.referrer)

    set_setting('app_title', new_title)
    flash(_("Application title updated."), "success")
    return redirect(request.referrer)
