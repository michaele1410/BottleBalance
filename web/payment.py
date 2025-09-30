# -----------------------
# Zahlungsfreigabe
# -----------------------
import io
import os
import json
from datetime import date, datetime
from decimal import Decimal
from flask_babel import gettext as _
from flask import render_template, request, redirect, url_for, session, send_file, flash, abort, Blueprint, current_app, jsonify
from sqlalchemy import text

# PDF (ReportLab)
from reportlab.lib.pagesizes import A4
from reportlab.platypus import Image, SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib import colors  # nur colors lokal importieren


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
    _user_can_edit_antrag,
    _user_can_view_antrag,
    get_antrag_email,
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

@payment_routes.route('/zahlungsfreigabe')
@login_required
@require_perms('payment:view')
def zahlungsfreigabe():
    today = date.today()
    user = current_user()
    is_approver = bool(user and user.get('can_approve'))

    with engine.begin() as conn:
        approvals_total = _approvals_total(conn)

        # Anträge + bereits erteilte Freigaben (aus Audit, DISTINCT user_id)
        rows = conn.execute(text("""
            WITH agg AS (
              SELECT antrag_id, COUNT(DISTINCT user_id) AS approvals_done
              FROM zahlungsantrag_audit
              WHERE action='freigegeben'
              GROUP BY antrag_id
            )
            SELECT z.id, z.antragsteller_id, u.username AS antragsteller,
            z.datum, z.paragraph, z.verwendungszweck, z.betrag,
            z.lieferant, z.begruendung, z.status, z.read_only,
            z.created_at, z.updated_at,
            z.approver_snapshot,
            COALESCE(a.approvals_done, 0) AS approvals_done

            FROM zahlungsantraege z
            LEFT JOIN users u ON u.id = z.antragsteller_id
            LEFT JOIN agg a   ON a.antrag_id = z.id
            ORDER BY z.created_at DESC
        """)).mappings().all()

        antraege = []
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

            antraege.append({
                'id': r['id'],
                'antragsteller': r['antragsteller'],
                'datum': r['datum'].strftime('%d.%m.%Y') if r['datum'] else '',
                'today': date.today(),
                'paragraph': r['paragraph'],
                'verwendungszweck': r['verwendungszweck'],
                'betrag': str(r['betrag']),
                'lieferant': r['lieferant'],
                'begruendung': r['begruendung'],
                'status': r['status'],
                'read_only': r['read_only'],
                'created_at': r['created_at'],
                'updated_at': r['updated_at'],
                'freigaben_count': done,
                'freigaben_gesamt': total,
                'freigabe_prozent': percent,
                'approved_by_me': approved_by_me,
                'can_freigeben': is_approver and r['status'] == 'offen' and not approved_by_me,
                'can_freigabe_zurueckziehen': is_approver and r['status'] in ('offen','freigegeben') and approved_by_me,
                'can_on_hold': is_approver and r['status'] == 'offen',
                'can_fortsetzen': is_approver and r['status'] == 'on_hold',
                'can_abschliessen': is_approver and r['status'] == 'freigegeben',
                'can_loeschen': is_approver,
                'can_ablehnen': is_approver and r['status'] in ('offen', 'on_hold'),
                'can_zurueckziehen': (user and user['id'] == r['antragsteller_id']
                                    and r['status'] in ('offen', 'on_hold')),
            })

    return render_template('payment_authorization.html', antraege=antraege, today=today)

@payment_routes.post('/freigeben/<int:antrag_id>')
@login_required
@require_csrf
def freigeben_antrag(antrag_id):
    user = current_user()
    _require_approver(user)
    with engine.begin() as conn:
        # Nur offene Anträge können freigegeben werden
        status = conn.execute(
            text("SELECT status FROM zahlungsantraege WHERE id=:id"),
            {'id': antrag_id}
        ).scalar_one_or_none()
        if status != 'offen':
            flash(_('Nur offene Anträge können freigegeben werden.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # Schon freigegeben? -> idempotent
        if _approved_by_user(conn, antrag_id, user['id']):
            flash(_('Du hast diesen Antrag bereits freigegeben.'), 'info')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # 1) Audit-Eintrag "freigegeben"
        conn.execute(
            text("""
                INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp)
                VALUES (:aid, :uid, 'freigegeben', NOW())
            """),
            {'aid': antrag_id, 'uid': user['id']}
        )

        # 2) Fortschritt prüfen
        done = _approvals_done(conn, antrag_id)
        total = _approvals_total(conn)

        # 3) Vollständigkeit -> Statuswechsel + Audit + Mail
        if total > 0 and done >= total:
            # Status setzen
            conn.execute(
                text("""
                    UPDATE zahlungsantraege SET status='freigegeben', updated_at=NOW()
                    WHERE id=:id
                """),
                {'id': antrag_id}
            )
            # Approver-Snapshot nur setzen, wenn noch nicht vorhanden
            snap = conn.execute(
                text("SELECT approver_snapshot FROM zahlungsantraege WHERE id=:id"),
                {'id': antrag_id}
            ).scalar_one_or_none()
            if not snap:
                approvers = conn.execute(
                    text("SELECT id, username FROM users WHERE can_approve=TRUE AND active=TRUE")
                ).mappings().all()
                conn.execute(
                    text("UPDATE zahlungsantraege SET approver_snapshot=:snap WHERE id=:id"),
                    {'snap': json.dumps([dict(a) for a in approvers]), 'id': antrag_id}
                )

            conn.execute(
                text("""
                    INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
                    VALUES (:aid, :uid, 'freigabe_vollständig', NOW(), :det)
                """),
                {'aid': antrag_id, 'uid': user['id'], 'det': f'{done}/{total} Freigaben'}
            )
            if (email := get_antrag_email(antrag_id)):
                send_status_email(email, antrag_id, 'freigegeben', cc_approvers=True)
            flash(_('Alle erforderlichen Freigaben liegen vor – Antrag ist jetzt freigegeben.'), 'success')
        else:
            flash(f'Teilfreigabe erfasst ({done}/{total}).', 'info')
    return redirect(url_for('payment_routes.zahlungsfreigabe'))

@payment_routes.post('/on_hold/<int:antrag_id>')
@login_required
@require_csrf
def on_hold_antrag(antrag_id):
    user = current_user()
    _require_approver(user)
    with engine.begin() as conn:
        curr = conn.execute(text("SELECT status FROM zahlungsantraege WHERE id=:id"), {'id': antrag_id}).scalar_one_or_none()
        if curr != 'offen':
            flash(_('Nur offene Anträge können auf On Hold gesetzt werden.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))
        conn.execute(text("UPDATE zahlungsantraege SET status='on_hold', updated_at=NOW() WHERE id=:id"), {'id': antrag_id})
        conn.execute(text("INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp) VALUES (:aid, :uid, 'on_hold', NOW())"),
                     {'aid': antrag_id, 'uid': user['id']})
    if (email := get_antrag_email(antrag_id)):
                send_status_email(email, antrag_id, 'on_hold', cc_approvers=True)
    flash(_('Antrag wurde auf On Hold gesetzt.'), 'info')
    return redirect(url_for('payment_routes.zahlungsfreigabe'))

@payment_routes.post('/abschliessen/<int:antrag_id>')
@login_required
@require_csrf
def abschliessen_antrag(antrag_id):
    user = current_user()
    _require_approver(user)
    with engine.begin() as conn:
        curr = conn.execute(text("SELECT status FROM zahlungsantraege WHERE id=:id"), {'id': antrag_id}).scalar_one_or_none()
        if curr != 'freigegeben':
            flash(_('Antrag kann nur nach Freigabe abgeschlossen werden.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))
        conn.execute(text("UPDATE zahlungsantraege SET status='abgeschlossen', updated_at=NOW() WHERE id=:id"), {'id': antrag_id})
        conn.execute(text("INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp) VALUES (:aid, :uid, 'abgeschlossen', NOW())"),
                     {'aid': antrag_id, 'uid': user['id']})
    if (email := get_antrag_email(antrag_id)):
        send_status_email(email, antrag_id, 'abgeschlossen', cc_approvers=True)
    flash(_('Antrag wurde abgeschlossen.'), 'success')
    return redirect(url_for('payment_routes.zahlungsfreigabe'))

@payment_routes.post('/loeschen/<int:antrag_id>')
@login_required
@require_csrf
def loeschen_antrag(antrag_id: int):
    user = current_user()
    _require_approver(user)

    with engine.begin() as conn:
        # Status prüfen
        status = conn.execute(
            text("SELECT status FROM zahlungsantraege WHERE id=:id"),
            {'id': antrag_id}
        ).scalar_one_or_none()

        if status is None:
            abort(404)
        
        # Nur löschen, wenn NICHT abgeschlossen/abgelehnt/freigegeben
        if status in ('abgeschlossen', 'abgelehnt', 'freigegeben'):
            flash(_('Abgelehnte, freigegebene oder abgeschlossene Anträge können nicht gelöscht werden.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # Löschen durchführen
        conn.execute(text("DELETE FROM zahlungsantraege WHERE id=:id"), {'id': antrag_id})
        conn.execute(text("""
            INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp)
            VALUES (:aid, :uid, 'geloescht', NOW())
        """), {'aid': antrag_id, 'uid': user['id']})

        if (email := get_antrag_email(antrag_id)):
            send_status_email(email, antrag_id, 'geloescht')

    flash(_('Antrag wurde gelöscht.'), 'danger')
    return redirect(url_for('payment_routes.zahlungsfreigabe'))

@payment_routes.post('/ablehnen/<int:antrag_id>')
@login_required
@require_csrf
def ablehnen_antrag(antrag_id):
    user = current_user()
    _require_approver(user)
    grund = (request.form.get('grund') or '').strip()

    with engine.begin() as conn:
        curr = conn.execute(text("SELECT status FROM zahlungsantraege WHERE id=:id"), {'id': antrag_id}).scalar_one_or_none()
        if curr not in ('offen', 'on_hold'):
            flash(_('Nur offene oder pausierte Anträge können abgelehnt werden.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))
        if not grund:
            flash(_('Bitte einen Ablehnungsgrund angeben.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))
        conn.execute(text("UPDATE zahlungsantraege SET status='abgelehnt', updated_at=NOW() WHERE id=:id"), {'id': antrag_id})
        conn.execute(text("""
            INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
            VALUES (:aid, :uid, 'abgelehnt', NOW(), :detail)
        """), {'aid': antrag_id, 'uid': user['id'], 'detail': grund})

    if (email := get_antrag_email(antrag_id)):
        send_status_email(email, antrag_id, 'abgelehnt', cc_approvers=True)

    flash(_('Antrag wurde abgelehnt.'), 'danger')
    return redirect(url_for('payment_routes.zahlungsfreigabe'))

# Antrag durch den Antragsteller zurückziehen
@payment_routes.post('/zurueckziehen/<int:antrag_id>', endpoint='zurueckziehen_antrag')
@login_required
@require_csrf
def zurueckziehen_antrag(antrag_id):
    user = current_user()
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT antragsteller_id, status
            FROM zahlungsantraege
            WHERE id=:id
        """), {'id': antrag_id}).mappings().first()

        if not row:
            abort(404)

        # Nur der Antragsteller und nur in 'offen' oder 'on_hold'
        if row['antragsteller_id'] != user['id'] or row['status'] not in ('offen', 'on_hold'):
            flash(_('Du kannst nur eigene, offene oder pausierte Anträge zurückziehen.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # Status auf 'zurueckgezogen' setzen
        conn.execute(text("""
            UPDATE zahlungsantraege
            SET status='zurueckgezogen', updated_at=NOW()
            WHERE id=:id
        """), {'id': antrag_id})

        # Audit-Eintrag
        conn.execute(text("""
            INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp)
            VALUES (:aid, :uid, 'zurueckgezogen', NOW())
        """), {'aid': antrag_id, 'uid': user['id']})

    # Mail (best effort)
    if (email := get_antrag_email(antrag_id)):
        send_status_email(email, antrag_id, 'zurückgezogen', cc_approvers=True)

    flash(_('Antrag wurde zurückgezogen.'), 'info')
    return redirect(url_for('payment_routes.zahlungsfreigabe'))

@payment_routes.post('/fortsetzen/<int:antrag_id>')
@login_required
@require_csrf
def fortsetzen_antrag(antrag_id: int):
    user = current_user()
    _require_approver(user)

    with engine.begin() as conn:
        curr = conn.execute(
            text("SELECT status FROM zahlungsantraege WHERE id=:id"),
            {'id': antrag_id}
        ).scalar_one_or_none()

        if curr != 'on_hold':
            flash(_('Nur pausierte Anträge können fortgesetzt werden.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # Status zurück auf 'offen'
        conn.execute(
            text("UPDATE zahlungsantraege SET status='offen', updated_at=NOW() WHERE id=:id"),
            {'id': antrag_id}
        )

        # Audit: fortgesetzt
        conn.execute(
            text("""INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
                    VALUES (:aid, :uid, 'fortgesetzt', NOW(), NULL)"""),
            {'aid': antrag_id, 'uid': user['id']}
        )

        # Best-effort Mail
        if (email := get_antrag_email(antrag_id)):
            send_status_email(email, antrag_id, 'fortgesetzt', cc_approvers=True)

    flash(_('Antrag wurde fortgesetzt und ist wieder offen.'), 'info')
    return redirect(url_for('payment_routes.zahlungsfreigabe'))

@payment_routes.route('/zahlungsfreigabe/audit')
@login_required
@require_perms('audit:view')
def zahlungsfreigabe_audit():
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT a.id, a.antrag_id, a.user_id, u.username, a.action, a.timestamp, a.detail
            FROM zahlungsantrag_audit a
            LEFT JOIN users u ON u.id = a.user_id
            ORDER BY a.timestamp DESC, a.id DESC
        """)).mappings().all()
    return render_template('payment_authorization_audit.html', logs=rows)

@payment_routes.get('/zahlungsfreigabe/<int:antrag_id>/export/pdf')
@login_required
def export_einzelantrag_pdf(antrag_id: int):
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT z.*, u.username AS antragsteller
            FROM zahlungsantraege z
            LEFT JOIN users u ON u.id = z.antragsteller_id
            WHERE z.id = :id
        """), {'id': antrag_id}).mappings().first()

        audits = conn.execute(text("""
            SELECT a.timestamp, a.action, a.detail, u.username
            FROM zahlungsantrag_audit a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.antrag_id = :id
            ORDER BY a.timestamp ASC
        """), {'id': antrag_id}).mappings().all()

        attachments = conn.execute(text("""
            SELECT original_name, stored_name, content_type
            FROM antrag_attachments
            WHERE antrag_id = :id
            ORDER BY created_at ASC
        """), {'id': antrag_id}).mappings().all()

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

    story.append(Paragraph(f"{_('Zahlungsantrag')} #{antrag_id}", styles['Title']))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"{_('Erstellt am')} {datetime.now().strftime('%d.%m.%Y %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 12))

    details_data = [
        [_("Antragsteller/in:"), P(r['antragsteller'])],
        [_("Datum:"), P(r['datum'].strftime('%d.%m.%Y') if r['datum'] else '')],
        [_("Paragraph:"), P(r['paragraph'])],
        [_("Verwendungszweck:"), P(r['verwendungszweck'])],
        [_("Betrag:"), P(f"{r['betrag']} {_('waehrung')}")],
        [_("Lieferant:"), P(r['lieferant'])],
        [_("Begründung:"), P(r['begruendung'])],
        [_("Status:"), P(r['status'])],
    ]
    details_table = Table(details_data, colWidths=[42*mm, None])
    details_table.setStyle(standard_table_style())
    story.append(details_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph(_("Audit-Historie"), styles['Heading3']))
    story.append(Spacer(1, 4))
    story.append(build_audit_table(audits, styles))
    story.append(Spacer(1, 10))
    
    # Anhänge inkl. PDF-Seiten
    story = embed_pdf_attachments(antrag_id, attachments, story, styles)

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f'antrag_{antrag_id}.pdf',
                     mimetype='application/pdf')

# ============= Zahlungsantrag-Anhänge =============
@payment_routes.post('/zahlungsfreigabe/<int:antrag_id>/attachments/upload')
@login_required
@require_csrf
def upload_antrag_attachment(antrag_id: int):
    user = current_user()

    # Status prüfen
    with engine.begin() as conn:
        status = conn.execute(
            text("SELECT status FROM zahlungsantraege WHERE id=:id"),
            {'id': antrag_id}
        ).scalar_one_or_none()
        if status is None:
            abort(404)

    # Upload nur sperren, wenn abgeschlossen (optional auch abgelehnt)
    if status in ('abgeschlossen', 'abgelehnt'):
        flash(_('Anhänge können nicht mehr hochgeladen werden, da der Antrag abgeschlossen oder abgelehnt ist.'), 'warning')
        return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

    # Berechtigung: Antragsteller oder Approver darf hochladen
    if not _user_can_view_antrag(antrag_id):
        abort(403)

    files = request.files.getlist('files') or []
    if not files:
        flash(_('Bitte Datei(en) auswählen.'), 'warning')
        return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

    target_dir = _antrag_dir(antrag_id)
    saved = 0

    with engine.begin() as conn:
        for f in files:
            if not f or not f.filename:
                continue
            if not allowed_file(f.filename):
                flash(f'Ungültiger Dateityp: {f.filename}', 'danger')
                continue

            ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else 'bin'
            stored_name = f"{uuid4().hex}.{ext}"
            original_name = secure_filename(f.filename) or f"file.{ext}"
            path = os.path.join(target_dir, stored_name)
            f.save(path)
            size = os.path.getsize(path)
            ctype = mimetypes.guess_type(original_name)[0] or 'application/octet-stream'

            conn.execute(text("""
                INSERT INTO antrag_attachments
                    (antrag_id, stored_name, original_name, content_type, size_bytes, uploaded_by)
                VALUES (:aid, :sn, :on, :ct, :sz, :ub)
            """), {'aid': antrag_id, 'sn': stored_name, 'on': original_name,
                   'ct': ctype, 'sz': size, 'ub': user['id']})
            saved += 1

        # Audit trail im Zahlungsantrags-Audit
        if saved:
            conn.execute(text("""
                INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
                VALUES (:aid, :uid, 'anhang_hochgeladen', NOW(), :det)
            """), {'aid': antrag_id, 'uid': user['id'], 'det': f'files={saved}'})

    if saved:
        flash(f'{saved} Datei(en) hochgeladen.', 'success')
    else:
        flash(_('Keine Dateien hochgeladen.'), 'warning')

    return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

@payment_routes.get('/zahlungsfreigabe/attachments/<int:att_id>/view')
@login_required
def view_antrag_attachment(att_id: int):
    """
    Zeigt einen Antrags-Anhang (inline) an – inkl. RBAC-Check.
    """
    # Datensatz laden
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT id, antrag_id, stored_name, original_name, content_type
            FROM antrag_attachments
            WHERE id = :id
        """), {'id': att_id}).mappings().first()

    if not r:
        abort(404)
    # Berechtigung: Antragsteller:in oder Approver
    if not _user_can_view_antrag(r['antrag_id']):
        abort(403)

    # Pfad & Existenz prüfen
    path = os.path.join(_antrag_dir(r['antrag_id']), r['stored_name'])
    if not os.path.exists(path):
        abort(404)

    # Mimetype bestimmen (DB bevorzugt)
    mimetype = r.get('content_type') or (
        mimetypes.guess_type(r['original_name'])[0] or 'application/octet-stream'
    )

    # Audit (optional im allgemeinen Log)
    log_action(session.get('user_id'), 'antrag_attachments:view', r['antrag_id'],
               f"att_id={att_id}")

    # Inline ausliefern + Sicherheitsheader
    resp = send_file(
        path,
        as_attachment=False,
        mimetype=mimetype,
        download_name=r['original_name']
    )
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    # resp.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:;"
    return resp

@payment_routes.get('/zahlungsfreigabe/attachments/<int:att_id>/download')
@login_required
def download_antrag_attachment(att_id: int):
    # att + antrag laden
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT id, antrag_id, stored_name, original_name, content_type
            FROM antrag_attachments
            WHERE id=:id
        """), {'id': att_id}).mappings().first()
    if not r:
        abort(404)
    if not _user_can_view_antrag(r['antrag_id']):
        abort(403)

    path = os.path.join(_antrag_dir(r['antrag_id']), r['stored_name'])
    if not os.path.exists(path):
        abort(404)

    # Optional: Audit im allgemeinen Log
    log_action(session.get('user_id'), 'antrag_attachments:download', r['antrag_id'],
               f"att_id={att_id}")

    return send_file(
        path,
        as_attachment=True,
        download_name=r['original_name'],
        mimetype=r.get('content_type') or 'application/octet-stream'
    )

@payment_routes.post('/zahlungsfreigabe/attachments/<int:att_id>/delete')
@login_required
@require_csrf
def delete_antrag_attachment(att_id: int):
    # att + antrag laden
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT id, antrag_id, stored_name, original_name
            FROM antrag_attachments
            WHERE id=:id
        """), {'id': att_id}).mappings().first()
    if not r:
        abort(404)

    # Edit-Rechte & Status != 'abgeschlossen'
    if not _user_can_edit_antrag(r['antrag_id']):
        abort(403)

    path = os.path.join(_antrag_dir(r['antrag_id']), r['stored_name'])
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM antrag_attachments WHERE id=:id"), {'id': att_id})
        conn.execute(text("""
            INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
            VALUES (:aid, :uid, 'anhang_geloescht', NOW(), :det)
        """), {'aid': r['antrag_id'], 'uid': session.get('user_id'),
               'det': f"att_id={att_id}, name={r['original_name']}"})
    flash(_('Anhang gelöscht.'), 'info')
    return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=r['antrag_id']))

@payment_routes.post('/zahlungsfreigabe/<int:antrag_id>/edit')
@login_required
@require_csrf
def edit_antrag(antrag_id):
    user = current_user()

    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT verwendungszweck, betrag, lieferant, begruendung, paragraph, datum,
                   antragsteller_id, status
            FROM zahlungsantraege
            WHERE id=:id
        """), {'id': antrag_id}).mappings().first()

        if not row:
            abort(404)

        if row['status'] in ('freigegeben', 'abgeschlossen', 'abgelehnt', 'zurueckgezogen'):
            flash(_('Bearbeitung nicht mehr möglich.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

        if user['id'] != row['antragsteller_id'] and not user.get('can_approve'):
            abort(403)

    # Neue Werte aus dem Formular
    verwendungszweck = (request.form.get('verwendungszweck') or '').strip()
    betrag_str       = (request.form.get('betrag') or '').strip()
    lieferant        = (request.form.get('lieferant') or '').strip()
    begruendung      = (request.form.get('begruendung') or '').strip()
    paragraph        = (request.form.get('paragraph') or '').strip()
    datum_str        = (request.form.get('datum') or '').strip()

    # Validierung/Parsing
    try:
        from decimal import Decimal
        betrag_decimal = Decimal(betrag_str.replace(',', '.'))
        datum_obj      = datetime.strptime(datum_str, '%Y-%m-%d').date()
    except Exception as e:
        flash(f'Ungültige Eingabe: {e}', 'danger')
        return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

    
# Änderungen erkennen – NUR für die Zusammenfassung (identisch zur Logik in entries/edit.html)
    from decimal import Decimal  # falls oben noch nicht im Scope
    def _q2(v):
        if v is None:
            return None
        return Decimal(str(v)).quantize(Decimal('0.01'))

    def _fmt_money(v):
        v = _q2(v)
        return "" if v is None else f"{v:.2f}"

    def _fmt_date(d):
        if not d:
            return ""
        if isinstance(d, datetime):
            d = d.date()
        return d.strftime('%d.%m.%Y')

    # Alte Werte (bereits oben aus DB geladen)
    old_verwendungszweck = row['verwendungszweck']
    old_betrag           = row['betrag']
    old_lieferant        = row['lieferant']
    old_begruendung      = row['begruendung']
    old_paragraph        = row['paragraph']
    old_datum            = row['datum']

    # NEU: 4‑Tuples wie in entries/edit.html: (feld_key, label, old_str, new_str)
    changes: list[tuple[str, str, str, str]] = []

    if (old_verwendungszweck or '') != verwendungszweck:
        changes.append(("verwendungszweck", "Verwendungszweck",
                        (old_verwendungszweck or ''), verwendungszweck))

    if _q2(old_betrag) != _q2(betrag_decimal):
        changes.append(("betrag", "Betrag",
                        _fmt_money(old_betrag), _fmt_money(betrag_decimal)))

    if (old_lieferant or '') != lieferant:
        changes.append(("lieferant", "Lieferant",
                        (old_lieferant or ''), lieferant))

    if (old_begruendung or '') != begruendung:
        changes.append(("begruendung", "Begründung",
                        (old_begruendung or ''), begruendung))

    if (old_paragraph or '') != paragraph:
        changes.append(("paragraph", "Paragraph",
                        (old_paragraph or ''), paragraph))

    old_datum_norm = old_datum.date() if isinstance(old_datum, datetime) else old_datum
    if old_datum_norm != datum_obj:
        changes.append(("datum", "Datum",
                        _fmt_date(old_datum_norm), _fmt_date(datum_obj)))

    # Zusammenfassung wie in entries/edit.html (kann unverändert bleiben)
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE zahlungsantraege
            SET verwendungszweck=:zweck,
                betrag=:betrag,
                lieferant=:lieferant,
                begruendung=:begruendung,
                paragraph=:paragraph,
                datum=:datum,
                updated_at=NOW()
            WHERE id=:id
        """), {
            'zweck': verwendungszweck,
            'betrag': str(betrag_decimal),
            'lieferant': lieferant,
            'begruendung': begruendung,
            'paragraph': paragraph,
            'datum': datum_obj,
            'id': antrag_id
        })

        now_str = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        if changes:
            summary = "\n".join([f"- {label}: {old} → {new}" for _, label, old, new in changes])
            detail_text = f"Bearbeitet am {now_str}\n{summary}"
        else:
            detail_text = f"Bearbeitet am {now_str} (keine Feldänderungen)"

        conn.execute(text("""
            INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
            VALUES (:aid, :uid, 'edit', NOW(), :detail)
        """), {
            'aid': antrag_id,
            'uid': user['id'],
            'detail': detail_text
        })

        # Neu laden für Darstellung
        antrag = conn.execute(text("""
            SELECT z.*, u.username AS antragsteller
            FROM zahlungsantraege z
            LEFT JOIN users u ON u.id = z.antragsteller_id
            WHERE z.id = :id
        """), {'id': antrag_id}).mappings().first()

        audit = conn.execute(text("""
            SELECT a.id, a.user_id, u.username, a.action, a.timestamp, a.detail
            FROM zahlungsantrag_audit a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.antrag_id = :id
            ORDER BY a.timestamp ASC, a.id ASC
        """), {'id': antrag_id}).mappings().all()

    flash(_('Antrag gespeichert.'), 'success')
    return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

@payment_routes.get('/zahlungsfreigabe/export/pdf')
@login_required
def export_alle_antraege_pdf():
    with engine.begin() as conn:
        antraege = conn.execute(text("""
            SELECT z.*, u.username AS antragsteller
            FROM zahlungsantraege z
            LEFT JOIN users u ON u.id = z.antragsteller_id
            ORDER BY z.created_at ASC
        """)).mappings().all()

        audit_by_antrag = {}
        for a in antraege:
            audits = conn.execute(text("""
                SELECT a.timestamp, a.action, a.detail, u.username
                FROM zahlungsantrag_audit a
                LEFT JOIN users u ON u.id = a.user_id
                WHERE a.antrag_id = :id
                ORDER BY a.timestamp ASC
            """), {'id': a['id']}).mappings().all()
            audit_by_antrag[a['id']] = audits

        attachments_by_antrag = {}
        for a in antraege:
            attachments = conn.execute(text("""
                SELECT original_name, stored_name, content_type
                FROM antrag_attachments
                WHERE antrag_id = :id
                ORDER BY created_at ASC
            """), {'id': a['id']}).mappings().all()
            attachments_by_antrag[a['id']] = attachments

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

    story.append(Paragraph(f"{_('Zahlungsantrag - Gesamtdokument')}", styles['Title']))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"{_('Erstellt am')} {datetime.now().strftime('%d.%m.%Y %H:%M')} – {_('Anzahl Anträge')}: {len(antraege)}", styles['Normal']))
    story.append(Spacer(1, 12))

    for idx, r in enumerate(antraege):
        blocks = []

        if os.path.exists(logo_path):
            blocks.append(Image(logo_path, width=40*mm))
            blocks.append(Spacer(1, 6))

        blocks.append(Paragraph(f"<b>{_('Zahlungsantrag')} #{r['id']}</b>", styles['Heading2']))
        blocks.append(Spacer(1, 6))

        details_data = [
                [_("Antragsteller/in:"), P(r['antragsteller'])],
                [_("Datum:"), P(r['datum'].strftime('%d.%m.%Y') if r['datum'] else '')],
                [_("Paragraph:"), P(r['paragraph'])],
                [_("Verwendungszweck:"), P(r['verwendungszweck'])],
                [_("Betrag:"), P(f"{r['betrag']} {_('waehrung')}")],
                [_("Lieferant:"), P(r['lieferant'])],
                [_("Begründung:"), P(r['begruendung'])],
                [_("Status:"), P(r['status'])],
            ]

        details_table = Table(details_data, colWidths=[42*mm, None])
        details_table.setStyle(standard_table_style())
        blocks.append(details_table)
        blocks.append(Spacer(1, 10))

        blocks.append(Paragraph(_("Audit-Historie"), styles['Heading3']))
        blocks.append(build_audit_table(audit_by_antrag.get(r['id'], []), styles))
        blocks.append(Spacer(1, 10))

        # Anhänge inkl. PDF-Seiten
        blocks = embed_pdf_attachments(r['id'], attachments_by_antrag.get(r['id'], []), blocks, styles)

        story.append(KeepTogether(blocks))
        if idx < len(antraege) - 1:
            story.append(PageBreak())

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name='alle_antraege.pdf',
                     mimetype='application/pdf')

# Zahlungsfreigabe
def _antrag_dir(antrag_id: int) -> str:
    p = os.path.join(UPLOAD_FOLDER, f"antrag_{antrag_id}")
    os.makedirs(p, exist_ok=True)
    return p

@payment_routes.post('/zahlungsfreigabe/antrag')
@login_required
@require_csrf
def zahlungsfreigabe_antrag():
    user = current_user()
    if not user:
        abort(403)

    paragraph = (request.form.get('paragraph') or '').strip()
    verwendungszweck = (request.form.get('zweck') or '').strip()
    datum_str = (request.form.get('datum') or '').strip()
    betrag_str = (request.form.get('betrag') or '').strip()
    lieferant = (request.form.get('lieferant') or '').strip()
    begruendung = (request.form.get('begruendung') or '').strip()

    # Eingaben validieren
    if not datum_str:
        flash(_('Bitte ein gültiges Datum angeben.'), 'danger')
        return redirect(url_for('payment_routes.zahlungsfreigabe'))

    if not betrag_str:
        flash(_('Bitte einen gültigen Betrag angeben.'), 'danger')
        return redirect(url_for('payment_routes.zahlungsfreigabe'))

    try:
        datum = datetime.strptime(datum_str, '%Y-%m-%d').date()
    except ValueError:
        flash(_('Ungültiges Datumsformat. Bitte im Format YYYY-MM-DD eingeben.'), 'danger')
        return redirect(url_for('payment_routes.zahlungsfreigabe'))

    try:
        betrag = Decimal(betrag_str.replace(',', '.'))
    except Exception:
        flash(_('Ungültiger Betrag. Bitte eine Zahl eingeben.'), 'danger')
        return redirect(url_for('payment_routes.zahlungsfreigabe'))


    # Antrag speichern
    with engine.begin() as conn:
        res = conn.execute(text("""
            INSERT INTO zahlungsantraege (
                antragsteller_id, datum, paragraph, verwendungszweck, betrag,
                lieferant, begruendung, status, read_only, created_at, updated_at
            ) VALUES (
                :uid, :datum, :para, :zweck, :betrag,
                :lieferant, :begruendung, 'offen', TRUE, NOW(), NOW()
            ) RETURNING id
        """), {
            'uid': user['id'],
            'datum': datum,
            'para': paragraph,
            'zweck': verwendungszweck,
            'betrag': str(betrag),
            'lieferant': lieferant,
            'begruendung': begruendung
        })
        antrag_id = res.scalar_one()

        # Audit-Eintrag
        conn.execute(text("""
            INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
            VALUES (:aid, :uid, 'erstellt', NOW(), NULL)
        """), {'aid': antrag_id, 'uid': user['id']})

    # Benachrichtigung an Approver (Best-Effort)
    try:
        with engine.begin() as conn:
            approver_emails = conn.execute(text("""
                SELECT email FROM users
                WHERE can_approve = TRUE AND active = TRUE AND email IS NOT NULL
            """)).scalars().all()

        if approver_emails:
            send_new_request_notifications(antrag_id, approver_emails)
        else:
            current_app.logger.warning("Keine Approver-E-Mails gefunden für Antrag %s", antrag_id)

    except Exception:
        current_app.logger.exception("Fehler beim Senden der Benachrichtigungen für neuen Antrag %s", antrag_id)

    flash(_('Zahlungsantrag erfolgreich erstellt.'), 'success')
    return redirect(url_for('payment_routes.zahlungsfreigabe'))

# Eigene Freigabe (des Approvers) zurückziehen
@payment_routes.post('/freigabe_zurueckziehen/<int:antrag_id>', endpoint='freigabe_zurueckziehen')
@login_required
@require_csrf
def freigabe_zurueckziehen(antrag_id):
    user = current_user()
    _require_approver(user)

    with engine.begin() as conn:
        # Status prüfen (abgeschlossen -> keine Rücknahme mehr)
        curr = conn.execute(text("""
            SELECT status FROM zahlungsantraege WHERE id=:id
        """), {'id': antrag_id}).scalar_one_or_none()
        if curr is None:
            abort(404)
        if curr == 'abgeschlossen':
            flash(_('Abgeschlossene Anträge können nicht mehr geändert werden.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # Eigene Freigabe löschen (falls vorhanden)
        deleted = conn.execute(text("""
            DELETE FROM zahlungsantrag_audit
            WHERE antrag_id = :aid AND user_id = :uid AND action = 'freigegeben'
        """), {'aid': antrag_id, 'uid': user['id']}).rowcount

        if deleted == 0:
            flash(_('Keine Freigabe zum Zurückziehen gefunden.'), 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # Audit-Eintrag protokollieren
        conn.execute(text("""
            INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp)
            VALUES (:aid, :uid, 'freigabe_zurueckgezogen', NOW())
        """), {'aid': antrag_id, 'uid': user['id']})

        # Status ggf. zurück auf 'offen', wenn nicht mehr vollständig
        done  = _approvals_done(conn, antrag_id)
        total = _approvals_total(conn)
        if curr == 'freigegeben' and (total == 0 or done < total):
            conn.execute(text("""
                UPDATE zahlungsantraege SET status='offen', updated_at=NOW()
                WHERE id=:id
            """), {'id': antrag_id})
            conn.execute(text("""
                INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
                VALUES (:aid, :uid, 'freigabe_nicht_mehr_vollständig', NOW(), :det)
            """), {'aid': antrag_id, 'uid': user['id'], 'det': f'{done}/{total} Freigaben'})

    flash(_('Deine Freigabe wurde zurückgezogen.'), 'info')
    return redirect(url_for('payment_routes.zahlungsfreigabe'))

@payment_routes.get('/zahlungsfreigabe/<int:antrag_id>/attachments/list')
@login_required
def list_antrag_attachments(antrag_id: int):
    if not _user_can_view_antrag(antrag_id):
        abort(403)
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, original_name, content_type, size_bytes, created_at
            FROM antrag_attachments
            WHERE antrag_id = :aid
            ORDER BY created_at DESC, id DESC
        """), {'aid': antrag_id}).mappings().all()
    data = [{
        'id': r['id'],
        'name': r['original_name'],
        'size': r['size_bytes'],
        'content_type': r['content_type'],
        'created_at': r['created_at'].isoformat() if r['created_at'] else None,
        'url': url_for('payment_routes.download_antrag_attachment', att_id=r['id']),
    } for r in rows]
    return jsonify(data), 200

@payment_routes.route('/zahlungsfreigabe/<int:antrag_id>')
@login_required
def zahlungsfreigabe_detail(antrag_id):
    user = current_user()
    is_approver = bool(user and user.get('can_approve'))

    antrag_row = None
    audit = []
    approvers = []

    with engine.begin() as conn:
        # Antrag inkl. approver_snapshot laden
        antrag_row = conn.execute(
            text("""
                SELECT z.*, u.username AS antragsteller
                FROM zahlungsantraege z
                LEFT JOIN users u ON u.id = z.antragsteller_id
                WHERE z.id = :id
            """), {'id': antrag_id}
        ).mappings().first()
        if not antrag_row:
            abort(404)

        # Audit laden
        audit = conn.execute(text("""
            SELECT a.id, a.user_id, u.username, a.action, a.timestamp, a.detail
            FROM zahlungsantrag_audit a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.antrag_id = :id
            ORDER BY a.timestamp ASC, a.id ASC
        """), {'id': antrag_id}).mappings().all()

        # Approver-Liste: Wenn Snapshot vorhanden, diesen verwenden! inkl. approved-Flag
        if antrag_row.get('approver_snapshot'):
            snap = antrag_row['approver_snapshot']
            if isinstance(snap, str):
                approver_list = json.loads(snap)
            else:
                approver_list = snap  # Bereits als Liste (z.B. bei PostgreSQL JSONB)
            approved_ids = set(
                a['user_id'] for a in audit if a['action'] == 'freigegeben'
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
            # Fallback: aktuelle Liste aus DB
            approvers = conn.execute(
                text("""
                    SELECT u.id, u.username,
                    EXISTS (
                        SELECT 1 FROM zahlungsantrag_audit a
                        WHERE a.antrag_id=:aid AND a.action='freigegeben' AND a.user_id=u.id
                    ) AS approved
                    FROM users u
                    WHERE u.can_approve=TRUE AND u.active=TRUE
                    ORDER BY u.username ASC
                """), {'aid': antrag_id}
            ).mappings().all()

        attachments = conn.execute(text("""    
            SELECT id, original_name, size_bytes, content_type, created_at
            FROM antrag_attachments
            WHERE antrag_id=:aid
            ORDER BY created_at DESC
        """), {'aid': antrag_id}).mappings().all()

    # ---- JETZT ausserhalb des with-Blocks auf das Ergebnis zugreifen ----
    done = sum(1 for a in approvers if a['approved'])
    total = len(approvers)
    percent = int(done * 100 / total) if total > 0 else 0

    status = antrag_row.get('status') or ''
    can_fortsetzen = is_approver and status == 'on_hold'
    can_on_hold    = is_approver and status == 'offen'

    return render_template(
        'payment_authorization_detail.html',
        antrag=antrag_row,
        audit=audit,
        approvers=approvers,
        approvals_done=done,
        approvals_total=total,
        approval_percent=percent,
        can_fortsetzen=can_fortsetzen,
        can_on_hold=can_on_hold,
        attachments=attachments
    )