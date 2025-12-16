# -----------------------
# BottleBalance
# -----------------------
import os
import io
from flask import render_template, request, redirect, url_for, session, send_file, flash, abort, Blueprint
from flask_babel import gettext as _
from flask_babel import ngettext
from markupsafe import escape
from sqlalchemy import text, func, asc
from datetime import datetime, date
import csv

from decimal import Decimal, InvalidOperation

from modules.utils import (
    parse_money
)
from modules.core_utils import (
    _entry_dir, 
    _temp_dir,
    log_action,
    ROLES,
    engine
)
from modules.auth_utils import (
    login_required,
    require_csrf,
    require_perms,
    current_user
) 
from modules.bbalance_utils import (
    _build_index_context,
    fetch_entries
) 

from modules.csv_utils import (
    today_ddmmyyyy,
    parse_date_de_or_none
)

from modules.payment_utils import (
    get_bemerkungsoptionen
)

from modules.csv_utils import (
    parse_date_de_or_today,
    format_date_de
)

bbalance_routes = Blueprint('bbalance_routes', __name__)

@bbalance_routes.get('/')
@login_required
def index():
    ctx = _build_index_context(default_date=today_ddmmyyyy())
    ctx['bemerkungsoptionen'] = get_bemerkungsoptionen()
    role = session.get('role')
    if role == 'Payment Viewer':
        return redirect(url_for('payment_routes.zahlungsfreigabe')) 
    return render_template('index.html', **ctx)

@bbalance_routes.post('/add')
@login_required
@require_csrf
@require_perms('entries:add')
def add():
    user = current_user()

    # Rohwerte für sauberes Re-Render bei Fehlern merken
    datum_s   = (request.form.get('datum') or '').strip()
    temp_token = (request.form.get('temp_token') or '').strip()

    try:
        datum    = parse_date_de_or_today(datum_s)
        # Alternativ stricte Parser: parse_int_strict(...) or 0
        vollgut  = int((request.form.get('vollgut') or '0').strip() or '0')
        leergut  = int((request.form.get('leergut') or '0').strip() or '0')
        einnahme = parse_money(request.form.get('einnahme') or '0')
        ausgabe  = parse_money(request.form.get('ausgabe') or '0')
        bemerkung = (request.form.get('bemerkung') or '').strip()
    except Exception as e:
        flash(_("Eingabefehler: %(error)s", error=str(e)), "danger")
        # ⬇️ bei Fehler: gleiche Seite rendern, temp_token beibehalten
        ctx = _build_index_context(default_date=(datum_s or today_ddmmyyyy()),
                                   temp_token=temp_token)
        return render_template('index.html', **ctx), 400

    # 🔐 Optional: Härtung gegen DevTools-Manipulation (Front-End min=0 serverseitig durchsetzen)
    vollgut  = max(0, vollgut)
    leergut  = max(0, leergut)
    if einnahme < 0:
        einnahme = Decimal('0')
    if ausgabe < 0:
        ausgabe = Decimal('0')

    # Mindestbedingung: mind. eines der Felder > 0
    any_filled = any([
        (einnahme is not None and einnahme != 0),
        (ausgabe  is not None and ausgabe  != 0),
        vollgut > 0,
        leergut > 0
    ])
    if not any_filled:
        flash(_('Bitte mindestens einen Wert bei Einnahme, Ausgabe, Vollgut oder Leergut angeben.'), 'danger')
        # ⬇️ KEIN redirect – render mit identischem temp_token, sonst gehen Tempfiles verloren
        ctx = _build_index_context(default_date=(datum_s or today_ddmmyyyy()),
                                   temp_token=temp_token)
        return render_template('index.html', **ctx), 400

    # Datensatz speichern
    with engine.begin() as conn:
        res = conn.execute(text("""
            INSERT INTO entries (datum, vollgut, leergut, einnahme, ausgabe, bemerkung, created_by)
            VALUES (:datum,:vollgut,:leergut,:einnahme,:ausgabe,:bemerkung,:cb)
            RETURNING id
        """), {
            'datum': datum,
            'vollgut': vollgut,
            'leergut': leergut,
            'einnahme': str(einnahme),
            'ausgabe': str(ausgabe),
            'bemerkung': bemerkung,
            'cb': user['id']
        })
        new_id = res.scalar_one()

    # Temporäre Anhänge übernehmen (nur wenn Session-Token passt)
    moved = 0
    if temp_token and session.get('add_temp_token') == temp_token:
        target_dir = _entry_dir(new_id)
        tdir = _temp_dir(temp_token)
        with engine.begin() as conn:
            rows = conn.execute(text("""
                SELECT id, stored_name, original_name, content_type, size_bytes
                FROM attachments_temp
                WHERE temp_token=:t AND uploaded_by=:u
                ORDER BY created_at ASC, id ASC
            """), {'t': temp_token, 'u': session.get('user_id')}).mappings().all()

        for r in rows:
            src = os.path.join(tdir, r['stored_name'])
            dst = os.path.join(target_dir, r['stored_name'])
            try:
                os.replace(src, dst)  # atomar
                moved += 1
            except Exception:
                # Falls move fehlschlägt → diesen Datensatz überspringen
                continue

            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO attachments (entry_id, stored_name, original_name, content_type, size_bytes, uploaded_by)
                    VALUES (:e,:sn,:on,:ct,:sz,:ub)
                """), {
                    'e': new_id,
                    'sn': r['stored_name'],
                    'on': r['original_name'],
                    'ct': r['content_type'],
                    'sz': r['size_bytes'],
                    'ub': session.get('user_id')
                })
                conn.execute(text("DELETE FROM attachments_temp WHERE id=:id"), {'id': r['id']})

        # Temp-Ordner evtl. aufräumen
        try:
            if os.path.isdir(tdir) and not os.listdir(tdir):
                os.rmdir(tdir)
        except Exception:
            pass

    log_action(user['id'], 'entries:add', new_id, f'attachments_moved={moved}')
    if moved:
        flash(_('Datensatz gespeichert, {count} Datei(en) übernommen.').format(count=moved), 'success')
    else:
        flash(_('Datensatz wurde gespeichert.'), 'success')

    # Token für diese Seite invalidieren (One-shot)
    session.pop('add_temp_token', None)

    return redirect(url_for('bbalance_routes.index'))

@bbalance_routes.get('/edit/<int:entry_id>')
@login_required
def edit(entry_id: int):
    with engine.begin() as conn:
        # Lade den Eintrag
        row = conn.execute(text("""
            SELECT id, datum, vollgut, leergut, einnahme, ausgabe, bemerkung, created_by
            FROM entries
            WHERE id = :id
        """), {'id': entry_id}).mappings().first()

        # Lade die Anhänge
        attachments = conn.execute(text("""
            SELECT id, original_name, content_type, size_bytes, created_at
            FROM attachments
            WHERE entry_id = :id
            ORDER BY created_at DESC
        """), {'id': entry_id}).mappings().all()

        # Lade die Audit-Daten
        audit = conn.execute(text("""
            SELECT a.id, a.user_id, u.username, a.action, a.created_at, a.detail
            FROM audit_log a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.entry_id = :id
            ORDER BY a.created_at ASC, a.id ASC
        """), {'id': entry_id}).mappings().all()

    if not row:
        flash(_('Eintrag nicht gefunden.'))
        return redirect(url_for('bbalance_routes.index'))

    # Eintragsdaten für das Formular
    data = {
        'id': row['id'],
        'datum': row['datum'],
        'vollgut': row['vollgut'],
        'leergut': row['leergut'],
        'einnahme': row['einnahme'],
        'ausgabe': row['ausgabe'],
        'bemerkung': row['bemerkung']
    }

    # Anhänge für die Anzeige
    att_data = [{
        'id': r['id'],
        'name': r['original_name'],
        'size': r['size_bytes'],
        'content_type': r['content_type'],
        'url': url_for('attachments_routes.attachments_download', att_id=r['id']),
        'view_url': url_for('attachments_view', att_id=r['id'])
    } for r in attachments]

    bemerkungsoptionen = get_bemerkungsoptionen()
    
    return render_template('edit.html', data=data, attachments=att_data, audit=audit, bemerkungsoptionen=bemerkungsoptionen)


@bbalance_routes.post('/edit/<int:entry_id>')
@login_required
@require_perms('entries:edit:any')
@require_csrf
def edit_post(entry_id: int):
    # 1) Altwerte laden
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, datum, vollgut, leergut, einnahme, ausgabe, bemerkung, created_by
            FROM entries
            WHERE id=:id
        """), {'id': entry_id}).mappings().first()
    if not row:
        abort(404)

    # 2) RBAC wie gehabt
    allowed = ROLES.get(session.get('role'), set())
    if 'entries:edit:any' not in allowed:
        user = current_user()
        if not user or row['created_by'] != user['id'] or 'entries:edit:own' not in allowed:
            abort(403)

    # 3) Neue Werte parsen
    try:
        # Datum nur übernehmen, wenn gültig – sonst Altwert behalten
        parsed_date = parse_date_de_or_none(request.form.get('datum'))
        if parsed_date:
            datum = parsed_date
        else:
            # row['datum'] kann date oder datetime sein
            od = row['datum']
            datum = od.date() if isinstance(od, datetime) else od

        vollgut = int((request.form.get('vollgut') or '0').strip() or '0')
        leergut = int((request.form.get('leergut') or '0').strip() or '0')
        einnahme = parse_money(request.form.get('einnahme') or '0')
        ausgabe  = parse_money(request.form.get('ausgabe')  or '0')
        bemerkung = (request.form.get('bemerkung') or '').strip()
    except Exception as e:
        flash(f"{_('Eingabefehler:')} {e}", 'danger')
        return redirect(url_for('bbalance_routes.edit', entry_id=entry_id))

    # 4) Änderungen (Diff) ermitteln – identisch zur Philosophie in payment.py
    def _q2(v: Decimal | None) -> Decimal | None:
        """Geldwerte auf 2 Nachkommastellen normalisieren (oder None)."""
        if v is None:
            return None
        return Decimal(str(v)).quantize(Decimal('0.01'))

    def _fmt_money(v: Decimal | None) -> str:
        v = _q2(v)
        return "" if v is None else f"{v:.2f}"

    def _fmt_date(d) -> str:
        if not d:
            return ""
        if isinstance(d, datetime):
            d = d.date()
        return d.strftime('%d.%m.%Y')

    changes: list[tuple[str, str, str, str]] = []  # (feld_key, label, old_str, new_str)

    # Datum
    old_datum = row['datum'].date() if isinstance(row['datum'], datetime) else row['datum']
    if old_datum != datum:
        changes.append(("datum", "Datum", _fmt_date(old_datum), _fmt_date(datum)))

    # Vollgut
    old_vollgut = int(row['vollgut'] or 0)
    if old_vollgut != vollgut:
        changes.append(("vollgut", "Vollgut", str(old_vollgut), str(vollgut)))

    # Leergut
    old_leergut = int(row['leergut'] or 0)
    if old_leergut != leergut:
        changes.append(("leergut", "Leergut", str(old_leergut), str(leergut)))

    # Einnahme
    old_einnahme = _q2(row['einnahme'])
    new_einnahme = _q2(einnahme)
    if old_einnahme != new_einnahme:
        changes.append(("einnahme", "Einnahme", _fmt_money(old_einnahme), _fmt_money(new_einnahme)))

    # Ausgabe
    old_ausgabe = _q2(row['ausgabe'])
    new_ausgabe = _q2(ausgabe)
    if old_ausgabe != new_ausgabe:
        changes.append(("ausgabe", "Ausgabe", _fmt_money(old_ausgabe), _fmt_money(new_ausgabe)))

    # Bemerkung (trim vergleichen)
    old_bemerkung = (row['bemerkung'] or '').strip()
    if old_bemerkung != bemerkung:
        changes.append(("bemerkung", "Bemerkung", old_bemerkung, bemerkung))

    # 5) Speichern + Audit (analog zu payment.py: pro Feldänderung eigener Audit-Eintrag)
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE entries
            SET datum=:datum,
                vollgut=:vollgut,
                leergut=:leergut,
                einnahme=:einnahme,
                ausgabe=:ausgabe,
                bemerkung=:bemerkung,
                updated_at=NOW()
            WHERE id=:id
        """), {
            'id': entry_id,
            'datum': datum,
            'vollgut': vollgut,
            'leergut': leergut,
            'einnahme': str(einnahme) if einnahme is not None else None,
            'ausgabe':  str(ausgabe)  if ausgabe  is not None else None,
            'bemerkung': bemerkung
        })

        # a) Einzelne Feldänderungen wie in payment.py
        #for _key, label, old, new in changes:
        #    conn.execute(text("""
        #        INSERT INTO audit_log (user_id, action, entry_id, detail)
        #        VALUES (:uid, :action, :eid, :detail)
        #    """), {
        #        'uid': session.get('user_id'),
        #        'action': 'feld_geaendert',
        #        'eid': entry_id,
        #        'detail': f"Feld: {label}\nAlt: {old}\nNeu: {new}"
        #    })

        # b) Zusammenfassender Edit-Eintrag
        now_str = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        if changes:
            summary = "\n".join([f"- {lbl}: {old} → {new}" for _, lbl, old, new in changes])
            detail_text = f"Bearbeitet am {now_str}\n{summary}"
        else:
            detail_text = f"Bearbeitet am {now_str} (keine Feldänderungen)"

        conn.execute(text("""
            INSERT INTO audit_log (user_id, action, entry_id, detail)
            VALUES (:uid, 'edit', :eid, :detail)
        """), {
            'uid': session.get('user_id'),
            'eid': entry_id,
            'detail': detail_text
        })

    # log_action(session.get('user_id'), 'entries:edit', entry_id, None)
    flash(_('Eintrag wurde gespeichert.'), 'success')

    return redirect(url_for('bbalance_routes.index'))

@bbalance_routes.post('/delete/<int:entry_id>')
@login_required
@require_csrf
def delete(entry_id: int):
    with engine.begin() as conn:
        row = conn.execute(text('SELECT created_by FROM entries WHERE id=:id'), {'id': entry_id}).mappings().first()
    if not row:
        abort(404)
    allowed = ROLES.get(session.get('role'), set())
    if 'entries:delete:any' not in allowed:
        user = current_user()
        if not user or row['created_by'] != user['id'] or 'entries:delete:own' not in allowed:
            abort(403)
    with engine.begin() as conn:
        conn.execute(text('DELETE FROM entries WHERE id=:id'), {'id': entry_id})
    log_action(session.get('user_id'), 'entries:delete', entry_id, None)
    return redirect(url_for('bbalance_routes.index'))

# -----------------------
# Export/Import
# -----------------------
@bbalance_routes.get('/export')
@login_required
@require_perms('export:csv')
def export_csv():
    q = (request.args.get('q') or '').strip()
    df = request.args.get('from')
    dt = request.args.get('to')
    attachments_filter = request.args.get('attachments')  # 'only' | 'none' | None

    date_from = datetime.strptime(df, '%Y-%m-%d').date() if df else None
    date_to   = datetime.strptime(dt, '%Y-%m-%d').date() if dt else None

    entries = fetch_entries(q or None, date_from, date_to, attachments_filter=attachments_filter)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', lineterminator='\n')
    writer.writerow(['Datum','Vollgut','Leergut','Inventar','Einnahme','Ausgabe','Kassenbestand','Bemerkung'])
    for e in entries:
        writer.writerow([
            format_date_de(e['datum']), e['vollgut'], e['leergut'], e['inventar'],
            str(e['einnahme']).replace('.', ','), str(e['ausgabe']).replace('.', ','),
            str(e['kassenbestand']).replace('.', ','), e['bemerkung']
        ])
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))
    mem.seek(0)
    filename = f"bottlebalance_export_{date.today().strftime('%Y%m%d')}.csv"
    return send_file(mem, as_attachment=True, download_name=filename, mimetype='text/csv')

@bbalance_routes.post('/import')
@login_required
@require_perms('import:csv')
@require_csrf
def import_csv():
    file = request.files.get('file')
    replace_all = request.form.get('replace_all') == 'on'
    if not file or file.filename == '':
        flash(_('Bitte eine CSV-Datei auswählen.'))
        return redirect(url_for('bbalance_routes.index'))
    try:
        content = file.read().decode('utf-8-sig')
        reader = csv.reader(io.StringIO(content), delimiter=';')
        headers = next(reader, None)
        # Robustheit: Header-Zeile prüfen und ggf. splitten
        if headers and len(headers) == 1 and ';' in headers[0]:
            headers = headers[0].split(';')
        # Validierung
        validation_errors = []

        if len(set(headers)) != len(headers):
            validation_errors.append("Doppelte Spaltennamen in CSV.")

        if any(h.strip() == "" for h in headers):
            validation_errors.append("Leere Spaltennamen in CSV.")

        required_fields = {"Datum", "Vollgut", "Leergut"}
        if not required_fields.issubset(set(headers)):
            validation_errors.append("Pflichtfelder fehlen: Datum, Vollgut, Leergut.")

        if validation_errors:
            for err in validation_errors:
                flash(err)
            return redirect(url_for('bbalance_routes.index'))
        expected = ['Datum','Vollgut','Leergut','Inventar','Einnahme','Ausgabe','Kassenbestand','Bemerkung']
        alt_expected = ['Datum','Vollgut','Leergut','Einnahme','Ausgabe','Bemerkung']
        if headers is None or [h.strip() for h in headers] not in (expected, alt_expected):
            raise ValueError('CSV-Header entspricht nicht dem erwarteten Format.')
        rows_to_insert = []
        for row in reader:
            if len(row) == 8:
                datum_s, voll_s, leer_s, _inv, ein_s, aus_s, _kas, bem = row
            else:
                datum_s, voll_s, leer_s, ein_s, aus_s, bem = row
            datum = parse_date_de_or_today(datum_s)
            vollgut = int((voll_s or '0').strip() or 0)
            leergut = int((leer_s or '0').strip() or 0)
            einnahme = parse_money(ein_s or '0')
            ausgabe = parse_money(aus_s or '0')
            bemerkung = (bem or '').strip()
            rows_to_insert.append({'datum': datum, 'vollgut': vollgut, 'leergut': leergut,
                                   'einnahme': str(einnahme), 'ausgabe': str(ausgabe), 'bemerkung': bemerkung})
        with engine.begin() as conn:
            if replace_all:
                conn.execute(text('DELETE FROM entries'))
            for r in rows_to_insert:
                conn.execute(text("""
                    INSERT INTO entries (datum, vollgut, leergut, einnahme, ausgabe, bemerkung)
                    VALUES (:datum,:vollgut,:leergut,:einnahme,:ausgabe,:bemerkung)
                """), r)

        # Success message with pluralization
        flash(ngettext(
            'Import erfolgreich: %(count)d Zeile übernommen.',
            'Import erfolgreich: %(count)d Zeilen übernommen.',
            len(rows_to_insert),
            count=len(rows_to_insert)
        ), "success")

    except Exception as e:
        flash(_('Import fehlgeschlagen: %(error)s', error=escape(str(e))), "danger")

    return redirect(url_for('bbalance_routes.index'))
