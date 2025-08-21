# -----------------------
# DB Export url/admin/export-db
# -----------------------

from modules.core_utils import (
    DB_HOST,
    DB_NAME,
    DB_USER,
    DB_PASS
)
from modules.core_utils import log_action

admin_tools_routes = Blueprint('admin_tools_routes', __name__)

@admin_tools_routes.get('/admin/export-db')
@login_required
@require_perms('users:manage')  # oder eigene Permission wie 'db:export'
def admin_export_page():
    return render_template('admin_export.html')

@admin_tools_routes.post('/admin/export-db')
@login_required
@require_perms('users:manage')
@require_csrf
def admin_export_dump():
    dump_file = "/tmp/bottlebalance_dump.sql"
    db_user = DB_USER
    db_name = DB_NAME
    db_host = DB_HOST
    db_pass = DB_PASS

    # Passwort für pg_dump setzen
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

        # Audit-Log-Eintrag
        log_action(session.get('user_id'), 'db:export', None, f'Dump von {db_name} erzeugt')

        flash(_('Datenbank-Dump erfolgreich erzeugt.'))
        return send_file(dump_file, as_attachment=True, download_name="bottlebalance_dump.sql")

    except subprocess.CalledProcessError as e:
        flash(_('Fehler beim Datenbank-Dump: ') + str(e))
        log_action(session.get('user_id'), 'db:export:error', None, f'Dump fehlgeschlagen: {e}')
        return redirect(url_for('admin_export_page'))