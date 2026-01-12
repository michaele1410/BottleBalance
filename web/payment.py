# -----------------------
# Payment approval
# -----------------------
import io
import os
import json
from datetime import date, datetime
from decimal import Decimal
from flask_babel import gettext as _
from flask import render_template, request, redirect, url_for, session, send_file, flash, abort, Blueprint, current_app, jsonify
from markupsafe import escape
from flask_babel import ngettext
from sqlalchemy import text

# PDF (ReportLab)
from reportlab.lib.pagesizes import A4
from reportlab.platypus import Image, SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib import colors  # Import colors locally only

# Document Upload
from werkzeug.utils import secure_filename
from uuid import uuid4
import mimetypes

from modules.core_utils import (
    engine
)
from modules.auth_utils import (
    current_user,
    login_required,
    require_perms,
    require_csrf
)
from modules.core_utils import (
    engine,
    allowed_file,
    UPLOAD_FOLDER,
    log_action
)
from modules.payment_utils import (
    _approvals_total,
    _approved_by_user,
    _require_approver,
    _approvals_done,
    _user_can_edit_payment_requests,
    _user_can_view_payment_requests,
    get_payment_requests_email,
    send_new_request_notifications    
)
from modules.mail_utils import (
    send_status_email
)
from modules.pdf_utils import (
    build_audit_table, 
    standard_table_style, 
    footer,
    embed_pdf_attachments
)

payment_routes = Blueprint('payment_routes', __name__)

@payment_routes.route('/payment_requests')
@login_required
@require_perms('payment:view')
def payment_requests():
    today = date.today()
    user = current_user()
    is_approver = bool(user and user.get('can_approve'))

    with engine.begin() as conn:
        approvals_total = _approvals_total(conn)

        # Requests + approvals already granted (from audit, DISTINCT user_id)
        rows = conn.execute(text("""
            WITH agg AS (
              SELECT request_id, COUNT(DISTINCT user_id) AS approvals_done
              FROM payment_requests_audit
              WHERE action='approved'
              GROUP BY request_id
            )
            SELECT z.id, z.requestor_id, u.username AS requestor,
            z.date, z.paragraph, z.purpose, z.amount,
            z.supplier, z.justification, z.state, z.read_only,
            z.created_at, z.updated_at,
            z.approver_snapshot,
            COALESCE(a.approvals_done, 0) AS approvals_done

            FROM payment_requests z
            LEFT JOIN users u ON u.id = z.requestor_id
            LEFT JOIN agg a   ON a.request_id = z.id
            ORDER BY z.created_at DESC
        """)).mappings().all()

        payment_requests = []
        for r in rows:
            done = int(r['approvals_done'] or 0)

            snap = r.get('approver_snapshot')
            if snap:
                if isinstance(snap, str):
                    try:
                        approver_list = json.loads(snap)
                    except Exception:
                        approver_list = []
                else:
                    approver_list = snap
                total = len(approver_list)
            else:
                total = int(approvals_total or 0)

            percent = int(done * 100 / total) if total > 0 else 0

            approved_by_me = False
            if is_approver:
                approved_by_me = _approved_by_user(conn, r['id'], user['id'])

            payment_requests.append({
                'id': r['id'],
                'requestor': r['requestor'],
                'date': r['date'].strftime('%d.%m.%Y') if r['date'] else '',
                'today': date.today(),
                'paragraph': r['paragraph'],
                'purpose': r['purpose'],
                'amount': str(r['amount']),
                'supplier': r['supplier'],
                'justification': r['justification'],
                'state': r['state'],
                'read_only': r['read_only'],
                'created_at': r['created_at'],
                'updated_at': r['updated_at'],
                'approvals_count': done,
                'approvals_total': total,
                'approvals_percent': percent,
                'approved_by_me': approved_by_me,
                'can_approve': is_approver and r['state'] == 'pending' and not approved_by_me,
                'can_withdraw_approval': is_approver and r['state'] in ('pending','approved') and approved_by_me,
                'can_on_hold': is_approver and r['state'] == 'pending',
                'can_continue': is_approver and r['state'] == 'on_hold',
                'can_complete': is_approver and r['state'] == 'approved',
                'can_delete': is_approver,
                'can_reject': is_approver and r['state'] in ('pending', 'on_hold'),
                'can_withdraw': (user and user['id'] == r['requestor_id']
                                    and r['state'] in ('pending', 'on_hold')),
            })

    return render_template('payment_authorization.html', payment_request=payment_requests, today=today)

@payment_routes.post('/approve/<int:request_id>')
@login_required
@require_csrf
def approve_payment_request(request_id):
    user = current_user()
    _require_approver(user)
    with engine.begin() as conn:
        # Only pending requests can be approved.
        state = conn.execute(
            text("SELECT state FROM payment_requests WHERE id=:id"),
            {'id': request_id}
        ).scalar_one_or_none()
        if state != 'pending':
            flash(_('Only pending requests can be approved.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))

        # Already released? -> idempotent
        if _approved_by_user(conn, request_id, user['id']):
            flash(_('You have already approved this request.'), 'info')
            return redirect(url_for('payment_routes.payment_requests'))

        # 1) Audit entry "approved"
        conn.execute(
            text("""
                INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp)
                VALUES (:aid, :uid, 'approved', NOW())
            """),
            {'aid': request_id, 'uid': user['id']}
        )

        # 2) Check progress
        done = _approvals_done(conn, request_id)
        total = _approvals_total(conn)

        # 3) Completeness -> state change + audit + email functionality
        if total > 0 and done >= total:
            # Set state
            conn.execute(
                text("""
                    UPDATE payment_requests SET state='approved', updated_at=NOW()
                    WHERE id=:id
                """),
                {'id': request_id}
            )
            # Approver-Snapshot nur setzen, wenn noch nicht vorhanden
            snap = conn.execute(
                text("SELECT approver_snapshot FROM payment_requests WHERE id=:id"),
                {'id': request_id}
            ).scalar_one_or_none()
            if not snap:
                approvers = conn.execute(
                    text("SELECT id, username FROM users WHERE can_approve=TRUE AND active=TRUE")
                ).mappings().all()
                conn.execute(
                    text("UPDATE payment_requests SET approver_snapshot=:snap WHERE id=:id"),
                    {'snap': json.dumps([dict(a) for a in approvers]), 'id': request_id}
                )

            conn.execute(
                text("""
                    INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp, detail)
                    VALUES (:aid, :uid, 'approval_complete', NOW(), :det)
                """),
                {'aid': request_id, 'uid': user['id'], 'det': f'{done}/{total} Approvals'}
            )
            if (email := get_payment_request_email(request_id)):
                send_status_email(email, request_id, 'approved', cc_approvers=True)
            flash(_('All necessary approvals have been received – the payment request has now been approved.'), 'success')
        else:
            flash(_('Partial approval recorded: %(done)d/%(total)d.', done=done, total=total), 'info')
    return redirect(url_for('payment_routes.payment_requests'))

@payment_routes.post('/on_hold/<int:request_id>')
@login_required
@require_csrf
def on_hold_payment_request(request_id):
    user = current_user()
    _require_approver(user)
    with engine.begin() as conn:
        curr = conn.execute(text("SELECT state FROM payment_requests WHERE id=:id"), {'id': request_id}).scalar_one_or_none()
        if curr != 'pending':
            flash(_('Only pending payment requests can be placed on hold.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))
        conn.execute(text("UPDATE payment_requests SET state='on_hold', updated_at=NOW() WHERE id=:id"), {'id': request_id})
        conn.execute(text("INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp) VALUES (:aid, :uid, 'on_hold', NOW())"),
                     {'aid': request_id, 'uid': user['id']})
    if (email := get_payment_request_email(request_id)):
                send_status_email(email, request_id, 'on_hold', cc_approvers=True)
    flash(_('The payment request was placed on hold.'), 'info')
    return redirect(url_for('payment_routes.payment_requests'))

@payment_routes.post('/complete/<int:request_id>')
@login_required
@require_csrf
def acomplete_payment_request(request_id):
    user = current_user()
    _require_approver(user)
    with engine.begin() as conn:
        curr = conn.execute(text("SELECT state FROM payment_requests WHERE id=:id"), {'id': request_id}).scalar_one_or_none()
        if curr != 'approved':
            flash(_('The payment request can only be completed after approval.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))
        conn.execute(text("UPDATE payment_requests SET state='completed', updated_at=NOW() WHERE id=:id"), {'id': request_id})
        conn.execute(text("INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp) VALUES (:aid, :uid, 'completed', NOW())"),
                     {'aid': request_id, 'uid': user['id']})
    if (email := get_payment_request_email(request_id)):
        send_status_email(email, request_id, 'completed', cc_approvers=True)
    flash(_('Payment request has been completed.'), 'success')
    return redirect(url_for('payment_routes.payment_requests'))

@payment_routes.post('/delete/<int:request_id>')
@login_required
@require_csrf
def delete_payment_request(request_id: int):
    user = current_user()
    _require_approver(user)

    with engine.begin() as conn:
        # Check state
        state = conn.execute(
            text("SELECT state FROM payment_requests WHERE id=:id"),
            {'id': request_id}
        ).scalar_one_or_none()

        if state is None:
            abort(404)
        
        # Only delete if NOT completed/rejected/approved
        if state in ('completed', 'rejected', 'approved'):
            flash(_('Rejected, approved, or completed payment requests cannot be deleted.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))

        # Perform deletion
        conn.execute(text("DELETE FROM payment_requests WHERE id=:id"), {'id': request_id})
        conn.execute(text("""
            INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp)
            VALUES (:aid, :uid, 'geloescht', NOW())
        """), {'aid': request_id, 'uid': user['id']})

        if (email := get_payment_request_email(request_id)):
            send_status_email(email, request_id, 'geloescht')

    flash(_('Payment request was deleted.'), 'danger')
    return redirect(url_for('payment_routes.payment_requests'))

@payment_routes.post('/reject/<int:request_id>')
@login_required
@require_csrf
def reject_payment_request(request_id):
    user = current_user()
    _require_approver(user)
    justification = (request.form.get('justification') or '').strip()

    with engine.begin() as conn:
        curr = conn.execute(text("SELECT state FROM payment_requests WHERE id=:id"), {'id': request_id}).scalar_one_or_none()
        if curr not in ('pending', 'on_hold'):
            flash(_('Only pending or paused payment requests can be rejected.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))
        if not justification:
            flash(_('Please specify a reason for rejection.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))
        conn.execute(text("UPDATE payment_requests SET state='rejected', updated_at=NOW() WHERE id=:id"), {'id': request_id})
        conn.execute(text("""
            INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp, detail)
            VALUES (:aid, :uid, 'rejected', NOW(), :detail)
        """), {'aid': request_id, 'uid': user['id'], 'detail': justification})

    if (email := get_payment_request_email(request_id)):
        send_status_email(email, request_id, 'rejected', cc_approvers=True)

    flash(_('Payment request was rejected.'), 'danger')
    return redirect(url_for('payment_routes.payment_requests'))

# Request withdraw by the requestor
@payment_routes.post('/withdraw/<int:request_id>', endpoint='withdraw_payment_request')
@login_required
@require_csrf
def withdraw_payment_request(request_id):
    user = current_user()
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT requestor_id, state
            FROM payment_requests
            WHERE id=:id
        """), {'id': request_id}).mappings().first()

        if not row:
            abort(404)

        # Only the requestor and only in 'pending' or 'on_hold' mode.
        if row['requestor_id'] != user['id'] or row['state'] not in ('pending', 'on_hold'):
            flash(_('You can only withdraw your own, pending, or paused payment requests.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))

        # Set state to 'withdrawn'
        conn.execute(text("""
            UPDATE payment_requests
            SET state='withdrawn', updated_at=NOW()
            WHERE id=:id
        """), {'id': request_id})

        # Audit entry
        conn.execute(text("""
            INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp)
            VALUES (:aid, :uid, 'withdrawn', NOW())
        """), {'aid': request_id, 'uid': user['id']})

    # Mail (best effort)
    if (email := get_payment_request_email(request_id)):
        send_status_email(email, request_id, 'withdrawn', cc_approvers=True)

    flash(_('Payment request was withdrawn.'), 'info')
    return redirect(url_for('payment_routes.payment_requests'))

@payment_routes.post('/fortsetzen/<int:request_id>')
@login_required
@require_csrf
def continue_payment_request(request_id: int):
    user = current_user()
    _require_approver(user)

    with engine.begin() as conn:
        curr = conn.execute(
            text("SELECT state FROM payment_requests WHERE id=:id"),
            {'id': request_id}
        ).scalar_one_or_none()

        if curr != 'on_hold':
            flash(_('Only paused payment requests can be resumed.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))

        # Set back to 'open'
        conn.execute(
            text("UPDATE payment_requests SET state='pending', updated_at=NOW() WHERE id=:id"),
            {'id': request_id}
        )

        # Audit: continued
        conn.execute(
            text("""INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp, detail)
                    VALUES (:aid, :uid, 'fortgesetzt', NOW(), NULL)"""),
            {'aid': request_id, 'uid': user['id']}
        )

        # Best-effort Mail
        if (email := get_payment_request_email(request_id)):
            send_status_email(email, request_id, 'fortgesetzt', cc_approvers=True)

    flash(_('The payment request was continued and is pending again.'), 'info')
    return redirect(url_for('payment_routes.payment_requests'))

@payment_routes.route('/payment_requests/audit')
@login_required
@require_perms('audit:view')
def payment_requests_audit():
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT a.id, a.request_id, a.user_id, u.username, a.action, a.timestamp, a.detail
            FROM payment_requests_audit a
            LEFT JOIN users u ON u.id = a.user_id
            ORDER BY a.timestamp DESC, a.id DESC
        """)).mappings().all()
    return render_template('payment_authorization_audit.html', logs=rows)

@payment_routes.get('/payment_requests/<int:request_id>/export/pdf')
@login_required
def export_single_request_pdf(request_id: int):
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT z.*, u.username AS requestor
            FROM payment_requests z
            LEFT JOIN users u ON u.id = z.requestor_id
            WHERE z.id = :id
        """), {'id': request_id}).mappings().first()

        audits = conn.execute(text("""
            SELECT a.timestamp, a.action, a.detail, u.username
            FROM payment_requests_audit a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.request_id = :id
            ORDER BY a.timestamp ASC
        """), {'id': request_id}).mappings().all()

        attachments = conn.execute(text("""
            SELECT original_name, stored_name, content_type
            FROM payment_requests_attachments
            WHERE request_id = :id
            ORDER BY created_at ASC
        """), {'id': request_id}).mappings().all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    story = []

    def P(text, style='Normal'):
        return Paragraph((text or '').replace('\n', '<br/>'), styles[style])

    logo_path = os.path.join("static", "logo.png")
    if os.path.exists(logo_path):
        story.append(Image(logo_path, width=40*mm))
        story.append(Spacer(1, 6))

    story.append(Paragraph(f"{_('Payment request')} #{request_id}", styles['Title']))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"{_('Created on')} {datetime.now().strftime('%d.%m.%Y %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 12))

    details_data = [
        [_("Requestor:"), P(r['requestor'])],
        [_("Date:"), P(r['date'].strftime('%d.%m.%Y') if r['date'] else '')],
        [_("Paragraph:"), P(r['paragraph'])],
        [_("Purpose:"), P(r['purpose'])],
        [_("Amount:"), P(f"{r['amount']} {_('currency')}")],
        [_("Supplier:"), P(r['supplier'])],
        [_("Justification:"), P(r['justification'])],
        [_("State:"), P(r['state'])],
    ]
    details_table = Table(details_data, colWidths=[42*mm, None])
    details_table.setStyle(standard_table_style())
    story.append(details_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph(_("Audit History"), styles['Heading3']))
    story.append(Spacer(1, 4))
    story.append(build_audit_table(audits, styles))
    story.append(Spacer(1, 10))
    
    # Attachments including PDF pages
    story = embed_pdf_attachments(request_id, attachments, story, styles)

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f'payment_request_{request_id}.pdf',
                     mimetype='application/pdf')

# ============= Payment request attachments =============
@payment_routes.post('/payment_requests/<int:request_id>/attachments/upload')
@login_required
@require_csrf
def upload_payment_requests_attachment(request_id: int):
    user = current_user()

    # Check state
        with engine.begin() as conn:
                state = conn.execute(
                Check state
    with engine.begin() as conn:
        state = conn.execute(
            text("SELECT state FROM payment_requests WHERE id=:id"),
            {'id': request_id}
        ).scalar_one_or_none()
        if state is None:
            abort(404)

    # Block upload only if completed (optionally also rejected)
    if state in ('completed', 'rejected'):
        flash(_('Attachments can no longer be uploaded because the request has been completed or rejected.'), 'warning')
        return redirect(url_for('payment_routes.payment_request_detail', request_id=request_id))

    # Authorization: Applicant or approver may upload
    if not _user_can_view_payment_request(request_id):
        abort(403)

    files = request.files.getlist('files') or []
    if not files:
        flash(_('Please select file(s).'), 'warning')
        return redirect(url_for('payment_routes.payment_request_detail', request_id=request_id))

    target_dir = _payment_request_dir(request_id)
    saved = 0

    with engine.begin() as conn:
        for f in files:
            if not f or not f.filename:
                continue
            if not allowed_file(f.filename):
                flash(_('Invalid file type: %(filename)s', filename=escape(f.filename)), 'danger')
                continue

            ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else 'bin'
            stored_name = f"{uuid4().hex}.{ext}"
            original_name = secure_filename(f.filename) or f"file.{ext}"
            path = os.path.join(target_dir, stored_name)
            f.save(path)
            size = os.path.getsize(path)
            ctype = f.mimetype or mimetypes.guess_type(original_name)[0] or 'application/octet-stream'

            conn.execute(text("""
                INSERT INTO payment_requests_attachments
                    (request_id, stored_name, original_name, content_type, size_bytes, uploaded_by)
                VALUES (:aid, :sn, :on, :ct, :sz, :ub)
            """), {'aid': request_id, 'sn': stored_name, 'on': original_name,
                   'ct': ctype, 'sz': size, 'ub': user['id']})
            saved += 1

        # Audit trail in the payment request audit
        if saved:
            conn.execute(text("""
                INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp, detail)
                VALUES (:aid, :uid, 'anhang_hochgeladen', NOW(), :det)
            """), {'aid': request_id, 'uid': user['id'], 'det': f'files={saved}'})

    if saved:
        flash(ngettext(
            '%(count)d Files uploaded.',
            '%(count)d Files uploaded.',
            saved,
            count=saved
        ), 'success')
    else:
        flash(_('No files uploaded.'), 'warning')

    return redirect(url_for('payment_routes.payment_request_detail', request_id=request_id))

@payment_routes.get('/payment_requests/attachments/<int:att_id>/view')
@login_required
def view_payment_requests_attachment(att_id: int):
    """
    Displays an request attachment (inline) – including RBAC check.
    """
    # Load data set
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT id, request_id, stored_name, original_name, content_type
            FROM payment_requests_attachments
            WHERE id = :id
        """), {'id': att_id}).mappings().first()

    if not r:
        abort(404)
    # Authorization: Requestor or Approver
    if not _user_can_view_payment_request(r['request_id']):
        abort(403)

    # Check path & existence
    path = os.path.join(_payment_request_dir(r['request_id']), r['stored_name'])
    if not os.path.exists(path):
        abort(404)

    # Determine the Mime type (DB preferred)
    mimetype = r.get('content_type') or (
        mimetypes.guess_type(r['original_name'])[0] or 'application/octet-stream'
    )

    # Audit (optional in the general log)
    log_action(session.get('user_id'), 'payment_requests_attachments:view', r['request_id'],
               f"att_id={att_id}")

    # Deliver inline + security header
    resp = send_file(
        path,
        as_attachment=False,
        mimetype=mimetype,
        download_name=r['original_name']
    )
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    # resp.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:;"
    return resp

@payment_routes.get('/payment_requests/attachments/<int:att_id>/download')
@login_required
def download_payment_requests_attachment(att_id: int):
    # att + load request
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT id, request_id, stored_name, original_name, content_type
            FROM payment_requests_attachments
            WHERE id=:id
        """), {'id': att_id}).mappings().first()
    if not r:
        abort(404)
    if not _user_can_view_payment_request(r['request_id']):
        abort(403)

    path = os.path.join(_payment_request_dir(r['request_id']), r['stored_name'])
    if not os.path.exists(path):
        abort(404)

    # Optional: Audit in the general log
    log_action(session.get('user_id'), 'payment_requests_attachments:download', r['request_id'],
               f"att_id={att_id}")

    return send_file(
        path,
        as_attachment=True,
        download_name=r['original_name'],
        mimetype=r.get('content_type') or 'application/octet-stream'
    )

@payment_routes.post('/payment_requests/attachments/<int:att_id>/delete')
@login_required
@require_csrf
def delete_payment_requests_attachment(att_id: int):
    # att + load request
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT id, request_id, stored_name, original_name
            FROM payment_requests_attachments
            WHERE id=:id
        """), {'id': att_id}).mappings().first()
    if not r:
        abort(404)

    # Edit-Rights & state != 'completed'
    if not _user_can_edit_payment_request(r['request_id']):
        abort(403)

    path = os.path.join(_payment_request_dir(r['request_id']), r['stored_name'])
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM payment_requests_attachments WHERE id=:id"), {'id': att_id})
        conn.execute(text("""
            INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp, detail)
            VALUES (:aid, :uid, 'anhang_geloescht', NOW(), :det)
        """), {'aid': r['request_id'], 'uid': session.get('user_id'),
               'det': f"att_id={att_id}, name={r['original_name']}"})
    flash(_('Attachment deleted.'), 'info')
    return redirect(url_for('payment_routes.payment_request_detail', request_id=r['request_id']))


@payment_routes.post('/payment_requests/<int:request_id>/edit')
@login_required
@require_csrf
def edit_payment_request(request_id):
    user = current_user()

    # Load old values + Check permissions
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT purpose, amount, supplier, justification, paragraph, date,
                   requestor_id, state
            FROM payment_requests
            WHERE id=:id
        """), {'id': request_id}).mappings().first()

        if not row:
            abort(404)
        if row['state'] in ('approved', 'completed', 'rejected', 'withdrawn'):
            flash(_('Bearbeitung nicht mehr möglich.'), 'warning')
            return redirect(url_for('payment_routes.payment_request_detail', request_id=request_id))
        if user['id'] != row['requestor_id'] and not user.get('can_approve'):
            abort(403)

    # Form values
    purpose = (request.form.get('purpose') or '').strip()
    amount_str       = (request.form.get('amount') or '').strip()
    supplier        = (request.form.get('supplier') or '').strip()
    justification      = (request.form.get('justification') or '').strip()
    paragraph        = (request.form.get('paragraph') or '').strip()
    date_str        = (request.form.get('date') or '').strip()

    # Parse amount + date
    try:
        from decimal import Decimal, InvalidOperation
        amount_decimal = Decimal(amount_str.replace(',', '.'))

        def parse_date_flexible(s: str | None):
            if not s:
                return None
            for fmt in ('%Y-%m-%d', '%d.%m.%Y'):
                try:
                    return datetime.strptime(s, fmt).date()
                except ValueError:
                    continue
            return None

        date_obj = parse_date_flexible(date_str)

    except InvalidOperation:
        flash(_('Invalid amount') + '.', 'danger')
        return redirect(url_for('payment_routes.payment_request_detail', request_id=request_id))
    except Exception as e:
        flash(_('Invalid input: %(error)s', error=escape(str(e))), 'danger')
        return redirect(url_for('payment_routes.payment_request_detail', request_id=request_id))

    # Record changes (for audit text)
    def _q2(v):
        if v is None: return None
        return Decimal(str(v)).quantize(Decimal('0.01'))
    def _fmt_money(v):
        v = _q2(v); return "" if v is None else f"{v:.2f}"
    def _fmt_date(d):
        if not d: return ""
        if isinstance(d, datetime): d = d.date()
        return d.strftime('%d.%m.%Y')

    old_purpose         = row['purpose']
    old_amount          = row['amount']
    old_supplier        = row['supplier']
    old_justification   = row['justification']
    old_paragraph       = row['paragraph']
    old_date_norm       = row['date'].date() if isinstance(row['date'], datetime) else row['date']

    changes = []
    if (old_purpose or '') != purpose:
        changes.append(("purpose", "Purpose", (old_purpose or ''), purpose))
    if _q2(old_amount) != _q2(amount_decimal):
        changes.append(("amount", "Amount", _fmt_money(old_amount), _fmt_money(amount_decimal)))
    if (old_supplier or '') != supplier:
        changes.append(("supplier", "Supplier", (old_supplier or ''), supplier))
    if (old_justification or '') != justification:
        changes.append(("justification", "Justification", (old_justification or ''), justification))
    if (old_paragraph or '') != paragraph:
        changes.append(("paragraph", "Paragraph", (old_paragraph or ''), paragraph))
    if old_date_norm != (date_obj or old_date_norm):
        changes.append(("date", "Date", _fmt_date(old_date_norm), _fmt_date(date_obj or old_date_norm)))

    # --- Update: Never write zero on a date. ---
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE payment_requests
            SET purpose=:zweck,
                amount=:amount,
                supplier=:supplier,
                justification=:justification,
                paragraph=:paragraph,
                -- behalte alten Wert, wenn :date NULL kommt
                date=COALESCE(:date, date),
                updated_at=NOW()
            WHERE id=:id
        """), {
            'zweck': purpose,
            'amount': str(amount_decimal),
            'supplier': supplier,
            'justification': justification,
            'paragraph': paragraph,
            'date': date_obj,  # can be None; COALESCE intercepts it
            'id': request_id
        })

        now_str = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        if changes:
            summary = "\n".join([f"- {label}: {old} → {new}" for _, label, old, new in changes])
            detail_text = f"Edited on {now_str}\n{summary}"
        else:
            detail_text = f"Edited on {now_str} (no field changes)"

        conn.execute(text("""
            INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp, detail)
            VALUES (:aid, :uid, 'edit', NOW(), :detail)
        """), {'aid': request_id, 'uid': user['id'], 'detail': detail_text})

    flash(_('Payment request saved.'), 'success')
    return redirect(url_for('payment_routes.payment_request_detail', request_id=request_id))

@payment_routes.get('/payment_requests/export/pdf')
@login_required
def export_all_payment_requests_pdf():
    with engine.begin() as conn:
        payment_requests = conn.execute(text("""
            SELECT z.*, u.username AS requestor
            FROM payment_requests z
            LEFT JOIN users u ON u.id = z.requestor_id
            ORDER BY z.created_at ASC
        """)).mappings().all()

        audit_by_payment_request = {}
        for a in payment_requests:
            audits = conn.execute(text("""
                SELECT a.timestamp, a.action, a.detail, u.username
                FROM payment_requests_audit a
                LEFT JOIN users u ON u.id = a.user_id
                WHERE a.request_id = :id
                ORDER BY a.timestamp ASC
            """), {'id': a['id']}).mappings().all()
            audit_by_payment_request[a['id']] = audits

        attachments_by_payment_request = {}
        for a in payment_requests:
            attachments = conn.execute(text("""
                SELECT original_name, stored_name, content_type
                FROM payment_requests_attachments
                WHERE request_id = :id
                ORDER BY created_at ASC
            """), {'id': a['id']}).mappings().all()
            attachments_by_payment_request[a['id']] = attachments

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    story = []

    def P(text, style='Normal'):
        return Paragraph((text or '').replace('\n', '<br/>'), styles[style])

    logo_path = os.path.join("static", "logo.png")
    if os.path.exists(logo_path):
        story.append(Image(logo_path, width=40*mm))
        story.append(Spacer(1, 6))

    story.append(Paragraph(f"{_('Payment request - Overall document')}", styles['Title']))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"{_('Created at')} {datetime.now().strftime('%d.%m.%Y %H:%M')} – {_('Number of requests')}: {len(payment_requests)}", styles['Normal']))
    story.append(Spacer(1, 12))

    for idx, r in enumerate(payment_requests):
        blocks = []

        if os.path.exists(logo_path):
            blocks.append(Image(logo_path, width=40*mm))
            blocks.append(Spacer(1, 6))

        blocks.append(Paragraph(f"<b>{_('Payment request')} #{r['id']}</b>", styles['Heading2']))
        blocks.append(Spacer(1, 6))

        details_data = [
                [_("Requestor:"), P(r['requestor'])],
                [_("Date:"), P(r['date'].strftime('%d.%m.%Y') if r['date'] else '')],
                [_("Paragraph:"), P(r['paragraph'])],
                [_("Purpose:"), P(r['purpose'])],
                [_("Amount:"), P(f"{r['amount']} {_('currency')}")],
                [_("Supplier:"), P(r['supplier'])],
                [_("Justification:"), P(r['justification'])],
                [_("State:"), P(r['state'])],
            ]

        details_table = Table(details_data, colWidths=[42*mm, None])
        details_table.setStyle(standard_table_style())
        blocks.append(details_table)
        blocks.append(Spacer(1, 10))

        blocks.append(Paragraph(_("Audit history"), styles['Heading3']))
        blocks.append(build_audit_table(audit_by_payment_requests.get(r['id'], []), styles))
        blocks.append(Spacer(1, 10))

        # Attachments including PDF pages
        blocks = embed_pdf_attachments(r['id'], attachments_by_payment_requests.get(r['id'], []), blocks, styles)

        story.append(KeepTogether(blocks))
        if idx < len(payment_requests) - 1:
            story.append(PageBreak())

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    buffer.seek(0)
    filename = _('all_payment_requests.pdf')
    return send_file(buffer, as_attachment=True,
                     download_name=filename,
                     mimetype='application/pdf')

# Payment requests
def _payment_request_dir(request_id: int) -> str:
    p = os.path.join(UPLOAD_FOLDER, f"payment_request_{request_id}")
    os.makedirs(p, exist_ok=True)
    return p

@payment_routes.post('/payment_requests/request')
@login_required
@require_csrf
def payment_requests_request():
    user = current_user()
    if not user:
        abort(403)

    paragraph = (request.form.get('paragraph') or '').strip()
    purpose = (request.form.get('zweck') or '').strip()
    date_str = (request.form.get('date') or '').strip()
    amount_str = (request.form.get('amount') or '').strip()
    supplier = (request.form.get('supplier') or '').strip()
    justification = (request.form.get('justification') or '').strip()

    # Validate entries
    if not date_str:
        flash(_('Please enter a valid date.'), 'danger')
        return redirect(url_for('payment_routes.payment_requests'))

    if not amount_str:
        flash(_('Please enter a valid amount.'), 'danger')
        return redirect(url_for('payment_routes.payment_requests'))

    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        flash(_('Invalid date format. Please enter in YYYY-MM-DD format.'), 'danger')
        return redirect(url_for('payment_routes.payment_requests'))

    try:
        amount = Decimal(amount_str.replace(',', '.'))
    except Exception:
        flash(_('Invalid amount. Please enter a number.'), 'danger')
        return redirect(url_for('payment_routes.payment_requests'))


    # Save payment request
    with engine.begin() as conn:
        res = conn.execute(text("""
            INSERT INTO payment_requests (
                requestor_id, date, paragraph, purpose, amount,
                supplier, justification, state, read_only, created_at, updated_at
            ) VALUES (
                :uid, :date, :para, :zweck, :amount,
                :supplier, :justification, 'pending', TRUE, NOW(), NOW()
            ) RETURNING id
        """), {
            'uid': user['id'],
            'date': date,
            'para': paragraph,
            'zweck': purpose,
            'amount': str(amount),
            'supplier': supplier,
            'justification': justification
        })
        request_id = res.scalar_one()

        # Audit entry
        conn.execute(text("""
            INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp, detail)
            VALUES (:aid, :uid, 'erstellt', NOW(), NULL)
        """), {'aid': request_id, 'uid': user['id']})

    # Notification to approver (best effort)
    try:
        with engine.begin() as conn:
            approver_emails = conn.execute(text("""
                SELECT email FROM users
                WHERE can_approve = TRUE AND active = TRUE AND email IS NOT NULL
            """)).scalars().all()

        if approver_emails:
            send_new_request_notifications(request_id, approver_emails)
        else:
            current_app.logger.warning("No approver emails found for payment request %s", request_id)

    except Exception:
        current_app.logger.exception("Error sending notifications for new payment request %s", request_id)

    flash(_('Payment request created successfully.'), 'success')
    return redirect(url_for('payment_routes.payment_requests'))

# Withdraw your own approval (as approver)
@payment_routes.post('/withdraw_approval/<int:request_id>', endpoint='withdraw_approval')
@login_required
@require_csrf
def withdraw_approval(request_id):
    user = current_user()
    _require_approver(user)

    with engine.begin() as conn:
        # Check state (completed -> no returns)
        curr = conn.execute(text("""
            SELECT state FROM payment_requests WHERE id=:id
        """), {'id': request_id}).scalar_one_or_none()
        if curr is None:
            abort(404)
        if curr == 'completed':
            flash(_('Completed payment requests can not longer be changed.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))

        # Delete your own request (if available)
        deleted = conn.execute(text("""
            DELETE FROM payment_requests_audit
            WHERE request_id = :aid AND user_id = :uid AND action = 'approved'
        """), {'aid': request_id, 'uid': user['id']}).rowcount

        if deleted == 0:
            flash(_('No approval found for withdrawal.'), 'warning')
            return redirect(url_for('payment_routes.payment_requests'))

        # Log audit entry
        conn.execute(text("""
            INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp)
            VALUES (:aid, :uid, 'approval_withdrawn', NOW())
        """), {'aid': request_id, 'uid': user['id']})

        # State if necessary, back to 'pending', if no longer complete
        done  = _approvals_done(conn, request_id)
        total = _approvals_total(conn)
        if curr == 'approved' and (total == 0 or done < total):
            conn.execute(text("""
                UPDATE payment_requests SET state='pending', updated_at=NOW()
                WHERE id=:id
            """), {'id': request_id})
            conn.execute(text("""
                INSERT INTO payment_requests_audit (request_id, user_id, action, timestamp, detail)
                VALUES (:aid, :uid, 'approval_no_longer_complete', NOW(), :det)
            """), {'aid': request_id, 'uid': user['id'], 'det': f'{done}/{total} Approvals'})

    flash(_('Your approval has been withdrawn.'), 'info')
    return redirect(url_for('payment_routes.payment_requests'))

@payment_routes.get('/payment_requests/<int:request_id>/attachments/list')
@login_required
def list_payment_requests_attachments(request_id: int):
    if not _user_can_view_payment_request(request_id):
        abort(403)
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, original_name, content_type, size_bytes, created_at
            FROM payment_requests_attachments
            WHERE request_id = :aid
            ORDER BY created_at DESC, id DESC
        """), {'aid': request_id}).mappings().all()
    data = [{
        'id': r['id'],
        'name': r['original_name'],
        'size': r['size_bytes'],
        'content_type': r['content_type'],
        'created_at': r['created_at'].isoformat() if r['created_at'] else None,
        'url': url_for('payment_routes.download_payment_requests_attachment', att_id=r['id']),
    } for r in rows]
    return jsonify(data), 200

@payment_routes.route('/payment_requests/<int:request_id>')
@login_required
def payment_request_detail(request_id):
    user = current_user()
    is_approver = bool(user and user.get('can_approve'))

    payment_request_row = None
    audit = []
    approvers = []

    with engine.begin() as conn:
        # Download request including approver_snapshot
        payment_request_row = conn.execute(
            text("""
                SELECT z.*, u.username AS requestor
                FROM payment_requests z
                LEFT JOIN users u ON u.id = z.requestor_id
                WHERE z.id = :id
            """), {'id': request_id}
        ).mappings().first()
        if not payment_request_row:
            abort(404)

        # Load audit
        audit = conn.execute(text("""
            SELECT a.id, a.user_id, u.username, a.action, a.timestamp, a.detail
            FROM payment_requests_audit a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.request_id = :id
            ORDER BY a.timestamp ASC, a.id ASC
        """), {'id': request_id}).mappings().all()

        # Approver list: If snapshot is available, use it! Including approved flag
        if payment_request_row.get('approver_snapshot'):
            snap = payment_request_row['approver_snapshot']
            if isinstance(snap, str):
                approver_list = json.loads(snap)
            else:
                approver_list = snap  # Already as a list (e.g., in PostgreSQL JSONB)
            approved_ids = set(
                a['user_id'] for a in audit if a['action'] == 'approved'
            )
            approvers = [
                {
                    'id': ap['id'],
                    'username': ap['username'],
                    'approved': ap['id'] in approved_ids
                }
                for ap in approver_list
            ]
        else:
            # Fallback: current list from DB
            approvers = conn.execute(
                text("""
                    SELECT u.id, u.username,
                    EXISTS (
                        SELECT 1 FROM payment_requests_audit a
                        WHERE a.request_id=:aid AND a.action='approved' AND a.user_id=u.id
                    ) AS approved
                    FROM users u
                    WHERE u.can_approve=TRUE AND u.active=TRUE
                    ORDER BY u.username ASC
                """), {'aid': request_id}
            ).mappings().all()

        attachments = conn.execute(text("""    
            SELECT id, original_name, size_bytes, content_type, created_at
            FROM payment_requests_attachments
            WHERE request_id=:aid
            ORDER BY created_at DESC
        """), {'aid': request_id}).mappings().all()

    # ---- Access the result NOW outside the with block ----
    done = sum(1 for a in approvers if a['approved'])
    total = len(approvers)
    percent = int(done * 100 / total) if total > 0 else 0

    state = payment_request_row.get('state') or ''
    can_continue = is_approver and state == 'on_hold'
    can_on_hold    = is_approver and state == 'pending'

    return render_template(
        'payment_authorization_detail.html',
        payment_request=payment_request_row,
        audit=audit,
        approvers=approvers,
        approvals_done=done,
        approvals_total=total,
        approval_percent=percent,
        can_continue=can_continue,
        can_on_hold=can_on_hold,
        attachments=attachments
    )