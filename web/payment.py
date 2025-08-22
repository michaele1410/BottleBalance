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
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, KeepTogether



# PDF (ReportLab)
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
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
payment_routes = Blueprint('payment_routes', __name__)

@payment_routes.route('/zahlungsfreigabe')
@login_required
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
            flash('Nur offene Anträge können freigegeben werden.', 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # Schon freigegeben? -> idempotent
        if _approved_by_user(conn, antrag_id, user['id']):
            flash('Du hast diesen Antrag bereits freigegeben.', 'info')
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
                send_status_email(email, antrag_id, 'freigegeben')
            flash('Alle erforderlichen Freigaben liegen vor – Antrag ist jetzt freigegeben.', 'success')
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
            flash('Nur offene Anträge können auf On Hold gesetzt werden.', 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))
        conn.execute(text("UPDATE zahlungsantraege SET status='on_hold', updated_at=NOW() WHERE id=:id"), {'id': antrag_id})
        conn.execute(text("INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp) VALUES (:aid, :uid, 'on_hold', NOW())"),
                     {'aid': antrag_id, 'uid': user['id']})
    if (email := get_antrag_email(antrag_id)):
        send_status_email(email, antrag_id, 'on_hold')
    flash('Antrag wurde auf On Hold gesetzt.', 'info')
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
            flash('Antrag kann nur nach Freigabe abgeschlossen werden.', 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))
        conn.execute(text("UPDATE zahlungsantraege SET status='abgeschlossen', updated_at=NOW() WHERE id=:id"), {'id': antrag_id})
        conn.execute(text("INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp) VALUES (:aid, :uid, 'abgeschlossen', NOW())"),
                     {'aid': antrag_id, 'uid': user['id']})
    if (email := get_antrag_email(antrag_id)):
        send_status_email(email, antrag_id, 'abgeschlossen')
    flash('Antrag wurde abgeschlossen.', 'success')
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
            flash('Abgelehnte, freigegebene oder abgeschlossene Anträge können nicht gelöscht werden.', 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # Löschen durchführen
        conn.execute(text("DELETE FROM zahlungsantraege WHERE id=:id"), {'id': antrag_id})
        conn.execute(text("""
            INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp)
            VALUES (:aid, :uid, 'geloescht', NOW())
        """), {'aid': antrag_id, 'uid': user['id']})

        if (email := get_antrag_email(antrag_id)):
            send_status_email(email, antrag_id, 'geloescht')

    flash('Antrag wurde gelöscht.', 'danger')
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
            flash('Nur offene oder pausierte Anträge können abgelehnt werden.', 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))
        if not grund:
            flash('Bitte einen Ablehnungsgrund angeben.', 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))
        conn.execute(text("UPDATE zahlungsantraege SET status='abgelehnt', updated_at=NOW() WHERE id=:id"), {'id': antrag_id})
        conn.execute(text("""
            INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
            VALUES (:aid, :uid, 'abgelehnt', NOW(), :detail)
        """), {'aid': antrag_id, 'uid': user['id'], 'detail': grund})

    if (email := get_antrag_email(antrag_id)):
        send_status_email(email, antrag_id, 'abgelehnt')

    flash('Antrag wurde abgelehnt.', 'danger')
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
            flash('Du kannst nur eigene, offene oder pausierte Anträge zurückziehen.', 'warning')
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
        send_status_email(email, antrag_id, 'zurückgezogen')

    flash('Antrag wurde zurückgezogen.', 'info')
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
            flash('Nur pausierte Anträge können fortgesetzt werden.', 'warning')
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
            send_status_email(email, antrag_id, 'fortgesetzt')

    flash('Antrag wurde fortgesetzt und ist wieder offen.', 'info')
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
            SELECT z.id,
                   u.username AS antragsteller,
                   z.datum,
                   z.paragraph,
                   z.verwendungszweck,
                   z.betrag,
                   z.lieferant,
                   z.begruendung,
                   z.status
            FROM zahlungsantraege z
            LEFT JOIN users u ON u.id = z.antragsteller_id
            WHERE z.id=:id
        """), {'id': antrag_id}).mappings().first()

        if not r:
            abort(404)

        audits = conn.execute(text("""
            SELECT a.timestamp, a.action, a.detail, COALESCE(u.username, 'Unbekannt') AS username
            FROM zahlungsantrag_audit a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.antrag_id = :id
            ORDER BY a.timestamp ASC, a.id ASC
        """), {'id': antrag_id}).mappings().all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Titel
    story.append(Paragraph(f"Zahlungsantrag #{r['id']}", styles['Title']))
    story.append(Spacer(1, 10))

    # Stammdaten
    fields = [
        ('Antragsteller', r['antragsteller']),
        ('Datum', r['datum'].strftime('%d.%m.%Y') if r['datum'] else ''),
        ('Paragraph', f"§ {r['paragraph']}" if r['paragraph'] else ''),
        ('Verwendungszweck', r['verwendungszweck'] or ''),
        ('Betrag', f"{r['betrag']} EUR" if r['betrag'] is not None else ''),
        ('Lieferant', r['lieferant'] or ''),
        ('Begründung', r['begruendung'] or ''),
        ('Status', r['status'] or ''),
    ]
    for label, value in fields:
        story.append(Paragraph(f"<b>{label}:</b> {value}", styles['Normal']))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Audit‑Historie", styles['Heading3']))
    story.append(Spacer(1, 4))

    # Audit-Tabelle
    audit_data = [[
        Paragraph("<b>Zeitpunkt</b>", styles['Normal']),
        Paragraph("<b>Aktion</b>", styles['Normal']),
        Paragraph("<b>Benutzer</b>", styles['Normal']),
        Paragraph("<b>Details</b>", styles['Normal']),
    ]]

    if audits:
        for a in audits:
            audit_data.append([
                a['timestamp'].strftime('%d.%m.%Y %H:%M:%S') if a['timestamp'] else '',
                a['action'] or '',
                a['username'] or 'Unbekannt',
                Paragraph((a['detail'] or '').replace('\n', '<br/>'), styles['Normal'])
            ])
    else:
        audit_data.append(['–', '–', '–', 'Keine Audit‑Einträge vorhanden.'])

    table = Table(audit_data, colWidths=[80, 80, 90, None], repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f3f5')),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.HexColor('#212529')),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 9.5),
        ('VALIGN',     (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fcfcfd')]),
        ('GRID',       (0,0), (-1,-1), 0.25, colors.HexColor('#dee2e6')),
        ('LEFTPADDING',(0,0), (-1,-1), 4),
        ('RIGHTPADDING',(0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING',(0,0), (-1,-1), 3),
    ]))
    story.append(table)

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f'antrag_{antrag_id}.pdf',
                     mimetype='application/pdf')

# ============= Zahlungsantrag-Anhänge =============
@payment_routes.post('/zahlungsfreigabe/<int:antrag_id>/attachments/upload')
@login_required
@require_csrf
def upload_antrag_attachment(antrag_id: int):
    if not _user_can_edit_antrag(antrag_id):
        current_app.logger.warning(f"403 bei Antrag {antrag_id} für Benutzer {user['id']}")
        abort(403)

    files = request.files.getlist('files') or []
    if not files:
        flash('Bitte Datei(en) auswählen.', 'warning')
        return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

    target_dir = _antrag_dir(antrag_id)
    saved = 0
    user = current_user()

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
        flash('Keine Dateien hochgeladen.', 'warning')

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
    flash('Anhang gelöscht.', 'info')
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

        if row['status'] in ('freigegeben', 'abgeschlossen', 'abgelehnt'):
            flash('Bearbeitung nicht mehr möglich.', 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

        if user['id'] != row['antragsteller_id'] and not user.get('can_approve'):
            abort(403)

        # Neue Werte aus dem Formular
        verwendungszweck = (request.form.get('verwendungszweck') or '').strip()
        betrag_str = (request.form.get('betrag') or '').strip()
        lieferant = (request.form.get('lieferant') or '').strip()
        begruendung = (request.form.get('begruendung') or '').strip()
        paragraph = (request.form.get('paragraph') or '').strip()
        datum_str = (request.form.get('datum') or '').strip()

        # Validierung
        try:
            betrag_decimal = Decimal(betrag_str.replace(',', '.'))
            datum_obj = datetime.strptime(datum_str, '%Y-%m-%d').date()
        except Exception as e:
            flash(f'Ungültige Eingabe: {e}', 'danger')
            return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

        # Änderungen erkennen und einzeln protokollieren
        for field, new_value, old_value in [
            ('verwendungszweck', verwendungszweck, row['verwendungszweck']),
            ('betrag', betrag_decimal, row['betrag']),
            ('lieferant', lieferant, row['lieferant']),
            ('begruendung', begruendung, row['begruendung']),
            ('paragraph', paragraph, row['paragraph']),
            ('datum', datum_obj, row['datum']),
        ]:
            if new_value != old_value:
                conn.execute(text("""
                    INSERT INTO zahlungsantrag_audit (antrag_id, user_id, action, timestamp, detail)
                    VALUES (:aid, :uid, 'feld_geaendert', NOW(), :detail)
                """), {
                    'aid': antrag_id,
                    'uid': user['id'],
                    'detail': f"Feld: {field}\nAlt: {old_value}\nNeu: {new_value}"
                })

        # Update durchführen
        conn.execute(text("""
            UPDATE zahlungsantraege
            SET verwendungszweck=:zweck, betrag=:betrag, lieferant=:lieferant,
                begruendung=:begruendung, paragraph=:paragraph, datum=:datum, updated_at=NOW()
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

        flash('Antrag gespeichert.', 'success')
    return redirect(url_for('payment_routes.zahlungsfreigabe_detail', antrag_id=antrag_id))

@payment_routes.get('/zahlungsfreigabe/export/pdf')
@login_required
def export_alle_antraege_pdf():
    # ---- 1) Daten laden: Anträge + Audit ----
    with engine.begin() as conn:
        antraege = conn.execute(text("""
            SELECT z.id,
                   u.username AS antragsteller,
                   z.datum,
                   z.paragraph,
                   z.verwendungszweck,
                   z.betrag,
                   z.lieferant,
                   z.begruendung,
                   z.status,
                   z.created_at
            FROM zahlungsantraege z
            LEFT JOIN users u ON u.id = z.antragsteller_id
            ORDER BY z.created_at DESC, z.id DESC
        """)).mappings().all()

        audits = conn.execute(text("""
            SELECT a.antrag_id,
                   a.timestamp,
                   a.action,
                   a.detail,
                   u.username
            FROM zahlungsantrag_audit a
            LEFT JOIN users u ON u.id = a.user_id
            ORDER BY a.antrag_id ASC, a.timestamp ASC, a.id ASC
        """)).mappings().all()

    # Map: antrag_id -> Liste der Audit-Einträge
    audit_by_antrag: dict[int, list] = {}
    for row in audits:
        aid = row['antrag_id']
        audit_by_antrag.setdefault(aid, []).append(row)

    # ---- 2) PDF-Dokument vorbereiten ----
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm
    )
    styles = getSampleStyleSheet()
    story = []

    # Titel / Meta
    story.append(Paragraph("Zahlungsanträge – Gesamtdokument", styles['Title']))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Erstellt am {datetime.now().strftime('%d.%m.%Y %H:%M')} – Anzahl Anträge: {len(antraege)}",
        styles['Normal']
    ))
    story.append(Spacer(1, 12))

    # Hilfsfunktion: Text -> Paragraph (mit Zeilenumbruch-Unterstützung)
    def P(text: str | None, style='Normal'):
        txt = (text or '').replace('\n', '<br/>')
        return Paragraph(txt, styles[style])

    # ---- 3) Pro Antrag: Details + Audit ----
    for idx, r in enumerate(antraege):
        blocks = []

        # Kopf je Antrag
        blocks.append(Paragraph(f"<b>Zahlungsantrag #{r['id']}</b>", styles['Heading2']))
        blocks.append(Spacer(1, 6))

        # Details (2-Spalten-Tabelle: Label / Wert)
        details_data = [
            ["Antragsteller/in:", P(r['antragsteller'])],
            ["Datum:", P(r['datum'].strftime('%d.%m.%Y') if r['datum'] else '')],
            ["Paragraph:", P(f"§ {r['paragraph']}" if r['paragraph'] else '')],
            ["Verwendungszweck:", P(r['verwendungszweck'])],
            ["Betrag:", P(f"{r['betrag']} EUR" if r['betrag'] is not None else '')],
            ["Lieferant:", P(r['lieferant'])],
            ["Begründung:", P(r['begruendung'])],
            ["Status:", P(r['status'])],
        ]
        details_table = Table(details_data, colWidths=[42*mm, None], hAlign='LEFT')
        details_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#212529')),
            ('TEXTCOLOR', (1,0), (1,-1), colors.HexColor('#212529')),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LINEBELOW', (0,0), (-1,-1), 0.25, colors.HexColor('#e9ecef')),
        ]))
        blocks.append(details_table)
        blocks.append(Spacer(1, 10))

        # Audit-Sektion
        blocks.append(Paragraph("Audit-Historie", styles['Heading3']))
        rows = audit_by_antrag.get(r['id'], [])
        if rows:
            audit_data = [[
                Paragraph("<b>Zeitpunkt</b>", styles['Normal']),
                Paragraph("<b>Aktion</b>", styles['Normal']),
                Paragraph("<b>Benutzer</b>", styles['Normal']),
                Paragraph("<b>Details</b>", styles['Normal']),
            ]]
            for a in rows:
                audit_data.append([
                    a['timestamp'].strftime('%d.%m.%Y %H:%M:%S') if a['timestamp'] else '',
                    a['action'] or '',
                    a['username'] or 'Unbekannt',
                    P(a['detail']),
                ])
            audit_table = Table(audit_data, colWidths=[36*mm, 32*mm, 35*mm, None], repeatRows=1)
            audit_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f3f5')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#212529')),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9.5),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fcfcfd')]),
                ('GRID', (0,0), (-1,-1), 0.25, colors.HexColor('#dee2e6')),
                ('LEFTPADDING', (0,0), (-1,-1), 4),
                ('RIGHTPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ]))
            blocks.append(audit_table)
        else:
            blocks.append(Paragraph("<i>Keine Audit‑Einträge vorhanden.</i>", styles['Normal']))

        # Alles zusammen (falls Blockseitenumbruch zu unschönen Split führt, zusammenhalten)
        story.append(KeepTogether(blocks))

        # Seitenumbruch zwischen Anträgen
        if idx < len(antraege) - 1:
            story.append(PageBreak())

    # ---- 4) Seitenzahlen im Footer ----
    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        page_txt = f"Seite {doc_.page}"
        canvas.drawRightString(doc_.pagesize[0] - 18*mm, 12, page_txt)
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='alle_antraege.pdf', mimetype='application/pdf')

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
        flash('Bitte ein gültiges Datum angeben.', 'danger')
        return redirect(url_for('payment_routes.zahlungsfreigabe'))

    if not betrag_str:
        flash('Bitte einen gültigen Betrag angeben.', 'danger')
        return redirect(url_for('payment_routes.zahlungsfreigabe'))

    try:
        datum = datetime.strptime(datum_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Ungültiges Datumsformat. Bitte im Format YYYY-MM-DD eingeben.', 'danger')
        return redirect(url_for('payment_routes.zahlungsfreigabe'))

    try:
        betrag = Decimal(betrag_str.replace(',', '.'))
    except Exception:
        flash('Ungültiger Betrag. Bitte eine Zahl eingeben.', 'danger')
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
        logger.exception("Fehler beim Senden der Benachrichtigungen für neuen Antrag %s", antrag_id)

    flash('Zahlungsantrag erfolgreich erstellt.', 'success')
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
            flash('Abgeschlossene Anträge können nicht mehr geändert werden.', 'warning')
            return redirect(url_for('payment_routes.zahlungsfreigabe'))

        # Eigene Freigabe löschen (falls vorhanden)
        deleted = conn.execute(text("""
            DELETE FROM zahlungsantrag_audit
            WHERE antrag_id = :aid AND user_id = :uid AND action = 'freigegeben'
        """), {'aid': antrag_id, 'uid': user['id']}).rowcount

        if deleted == 0:
            flash('Keine Freigabe zum Zurückziehen gefunden.', 'warning')
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

    flash('Deine Freigabe wurde zurückgezogen.', 'info')
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