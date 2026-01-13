# -----------------------
# Document uploads for entries
# -----------------------
import os
from flask_babel import gettext as _
from flask import request, redirect, url_for, session, send_file, flash, abort, jsonify, Blueprint
from sqlalchemy import text

from modules.core_utils import (
    engine, 
    ROLES, 
    log_action, 
    allowed_file, 
    _entry_dir, 
    _temp_dir, 
    _require_temp_token
)
from modules.bbalance_utils import (
    _user_can_edit_entry, 
    _user_can_view_entry
)

# Document Upload
from werkzeug.utils import secure_filename
from uuid import uuid4
import mimetypes

from modules.auth_utils import (
    login_required,
    require_csrf,
    require_perms
)

attachments_routes = Blueprint('attachments_routes', __name__)

#Upload
@attachments_routes.post('/attachments/<int:entry_id>/upload')
@login_required
@require_csrf
def attachments_upload(entry_id: int):
    if not _user_can_edit_entry(entry_id):
        abort(403)

    files = request.files.getlist('files')  # name="files" (multiple)
    if not files:
        flash(_('Please select files.'), 'info')
        return redirect(request.referrer or url_for('bbalance_routes.edit', entry_id=entry_id))

    saved = 0
    target_dir = _entry_dir(entry_id)

    with engine.begin() as conn:
        for f in files:
            if not f or not f.filename:
                continue
            if not allowed_file(f.filename):
                flash(_('Invalid file type: %(filename)s', filename=f.filename), 'danger')
                continue
   
            name = f.filename or ''
            ext = name.rsplit('.', 1)[1].lower() if '.' in name else 'bin'
            stored_name = f"{uuid4().hex}.{ext}"
            original_name = secure_filename(f.filename) or f"file.{ext}"
            path = os.path.join(target_dir, stored_name)
            
            f.save(path)
            size = os.path.getsize(path)
            ctype = f.mimetype or mimetypes.guess_type(original_name)[0] or 'application/octet-stream'

            conn.execute(text("""
                INSERT INTO attachments (entry_id, stored_name, original_name, content_type, size_bytes, uploaded_by)
                VALUES (:e,:sn,:on,:ct,:sz,:ub)
            """), {'e': entry_id, 'sn': stored_name, 'on': original_name, 'ct': ctype, 'sz': size, 'ub': session.get('user_id')})
            saved += 1

    if saved:
        log_action(session.get('user_id'), 'attachments:upload', entry_id, f'files={saved}')
        flash(_('%(num)d Files uploaded.', num=saved), 'success')
    else:
        flash(_('No files uploaded.'), 'warning')

    return redirect(request.referrer or url_for('bbalance_routes.edit', entry_id=entry_id))

@attachments_routes.get('/attachments/<int:entry_id>/list')
@login_required
def attachments_list(entry_id: int):
    if not _user_can_view_entry(entry_id):
        abort(403)
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, original_name, content_type, size_bytes, created_at
            FROM attachments WHERE entry_id=:e ORDER BY created_at DESC, id DESC
        """), {'e': entry_id}).mappings().all()

    data = [{
        'id': r['id'],
        'name': r['original_name'],
        'size': r['size_bytes'],
        'content_type': r['content_type'],
        'url': url_for('attachments_routes.attachments_download', att_id=r['id']),
        'view_url': url_for('attachments_view', att_id=r['id'])
    } for r in rows]
    return jsonify(data), 200

#Download
@attachments_routes.get('/attachments/<int:att_id>/download')
@login_required
def attachments_download(att_id: int):
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT a.id, a.entry_id, a.stored_name, a.original_name, a.content_type
            FROM attachments a WHERE a.id=:id
        """), {'id': att_id}).mappings().first()
    if not r:
        abort(404)
    if not _user_can_view_entry(r['entry_id']):
        abort(403)

    path = os.path.join(_entry_dir(r['entry_id']), r['stored_name'])
    if not os.path.exists(path):
        abort(404)

    log_action(session.get('user_id'), 'attachments:download', r['entry_id'], f"att_id={att_id}")
    return send_file(path, as_attachment=True, download_name=r['original_name'],
                     mimetype=r.get('content_type') or 'application/octet-stream')

#Delete
@attachments_routes.post('/attachments/<int:att_id>/delete')
@login_required
@require_csrf
def attachments_delete(att_id: int):
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT id, entry_id, stored_name, original_name FROM attachments WHERE id=:id
        """), {'id': att_id}).mappings().first()
    if not r:
        abort(404)
    if not _user_can_edit_entry(r['entry_id']):
        abort(403)

    path = os.path.join(_entry_dir(r['entry_id']), r['stored_name'])
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM attachments WHERE id=:id"), {'id': att_id})
    log_action(session.get('user_id'), 'attachments:delete', r['entry_id'], f"att_id={att_id}")
    flash(_('Attachment deleted.'), 'success')
    return redirect(request.referrer or url_for('bbalance_routes.edit', entry_id=r['entry_id']))

# -----------------------
# Temporary attachments for "Add record"
# -----------------------
@attachments_routes.post('/attachments/temp/<token>/upload')
@login_required
@require_csrf
def attachments_temp_upload(token: str):
    _require_temp_token(token)

    files = request.files.getlist('files') or []
    if not files:
        return ('No file transmitted.', 400)

    saved = 0
    tdir = _temp_dir(token)

    with engine.begin() as conn:
        for f in files:
            if not f or not f.filename:
                continue
            if not allowed_file(f.filename):
                continue

            ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else 'bin'
            stored_name = f"{uuid4().hex}.{ext}"
            original_name = secure_filename(f.filename) or f"file.{ext}"

            path = os.path.join(tdir, stored_name)
            f.save(path)
            size = os.path.getsize(path)
            ctype = f.mimetype or mimetypes.guess_type(original_name)[0] or 'application/octet-stream'

            conn.execute(text("""
                INSERT INTO attachments_temp (temp_token, stored_name, original_name, content_type, size_bytes, uploaded_by)
                VALUES (:t,:sn,:on,:ct,:sz,:ub)
            """), {'t': token, 'sn': stored_name, 'on': original_name, 'ct': ctype, 'sz': size, 'ub': session.get('user_id')})
            saved += 1

    if saved == 0:
        return ('No files accepted.', 400)
    return jsonify({'ok': True, 'saved': saved}), 200

@attachments_routes.get('/attachments/temp/<token>/open/<path:stored_name>')
@login_required
def attachments_temp_open(token: str, stored_name: str):
    _require_temp_token(token)
    tdir = _temp_dir(token)
    path = os.path.join(tdir, stored_name)
    if not os.path.exists(path):
        abort(404)
    # Note: No "as_attachment" here, for direct viewing
    guessed = mimetypes.guess_type(stored_name)[0] or 'application/octet-stream'
    return send_file(path, as_attachment=False, mimetype=guessed)

@attachments_routes.get('/attachments/temp/<token>/list')
@login_required
def attachments_temp_list(token: str):
    _require_temp_token(token)
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, stored_name, original_name, size_bytes, content_type, created_at
            FROM attachments_temp
            WHERE temp_token=:t AND uploaded_by=:u
            ORDER BY created_at ASC, id ASC
        """), {'t': token, 'u': session.get('user_id')}).mappings().all()

    data = [{
        'id': r['id'],
        'name': r['original_name'],
        'size': r['size_bytes'],
        'content_type': r['content_type'],
        'url': url_for('attachments_routes.attachments_temp_open', token=token, stored_name=r['stored_name'])
    } for r in rows]
    return jsonify(data), 200

@attachments_routes.post('/attachments/temp/<int:att_id>/delete')
@login_required
@require_csrf
def attachments_temp_delete(att_id: int):
    # Get record + check owner
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT id, temp_token, stored_name, uploaded_by
            FROM attachments_temp WHERE id=:id
        """), {'id': att_id}).mappings().first()
    if not r or r['uploaded_by'] != session.get('user_id'):
        abort(404)

    tdir = _temp_dir(r['temp_token'])
    path = os.path.join(tdir, r['stored_name'])
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM attachments_temp WHERE id=:id"), {'id': att_id})

    # Try deleting any empty folders
    try:
        if os.path.isdir(tdir) and not os.listdir(tdir):
            os.rmdir(tdir)
    except Exception:
        pass

    return ('', 204)