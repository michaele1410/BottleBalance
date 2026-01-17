# -----------------------
# BottleBalance
# -----------------------
import os
import io
import json
import csv

from flask import render_template, request, redirect, url_for, session, send_file, flash, abort, Blueprint, current_app
from flask_babel import gettext as _
from flask_babel import ngettext
from markupsafe import escape
from sqlalchemy import text
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from time import time
from flask_socketio import emit
from uuid import uuid4

from modules.csv_utils import (
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
    get_categories
)

from modules.csv_utils import (
    parse_date_de_or_today,
    format_date_de
)

from modules.core_utils import get_setting

bbalance_routes = Blueprint('bbalance_routes', __name__)

@bbalance_routes.get('/')
@login_required
def index():
    # Basic context
    temp_token = session.get('temp_token')
    if not temp_token:
        temp_token = uuid4().hex
        session['temp_token'] = temp_token

    ctx = _build_index_context(default_date=today_ddmmyyyy())
    ctx['categories'] = get_categories()
    ctx['temp_token'] = temp_token

    # Role Redirect
    role = session.get('role')
    if role == 'Payment Viewer':
        return redirect(url_for('payment_routes.payment_requests'))

    return render_template('index.html', **ctx, now=int(time()))

@bbalance_routes.get('/api/table')
@login_required
def api_table():
    ctx = _build_index_context()
    # Only the values required for the table
    table_ctx = {
        'entries': ctx['entries'],
        'format_eur_de': ctx['format_eur_de'],
        'format_date_de': ctx['format_date_de'],
    }
    return render_template('table_partial.html', **table_ctx)

@bbalance_routes.post('/add')
@login_required
@require_csrf
@require_perms('entries:add')
def add():
    user = current_user()

    # Save raw values for clean re-rendering in case of errors
    date_s = (request.form.get('date') or '').strip()

    # Read specific fields from the form
    temp_token = (request.form.get('attachments_token') or '').strip()
    ids_json   = request.form.get('temp_attachment_ids') or '[]'
    try:
        temp_ids = [int(x) for x in (json.loads(ids_json) if ids_json else [])]
    except Exception:
        temp_ids = []

    try:
        date    = parse_date_de_or_today(date_s)
        full    = int((request.form.get('full') or '0').strip() or '0')
        empty   = int((request.form.get('empty') or '0').strip() or '0')
        revenue = parse_money(request.form.get('revenue') or '0')
        expense = parse_money(request.form.get('expense') or '0')
        category    = (request.form.get('category') or '').strip()
        comment  = (request.form.get('comment') or '').strip()
    except Exception as e:
        flash(_("Input error: %(error)s", error=str(e)), "danger")
        ctx = _build_index_context(default_date=(date_s or today_ddmmyyyy()))
        ctx['temp_token'] = temp_token
        return render_template('index.html', **ctx, now=int(time())), 400

    full  = max(0, full)
    empty = max(0, empty)
    if revenue < 0: revenue = Decimal('0')
    if expense < 0: expense = Decimal('0')

    any_filled = any([
        (revenue is not None and revenue != 0),
        (expense  is not None and expense  != 0),
        full > 0,
        empty > 0
    ])
    if not any_filled:
        flash(_('Please enter at least one value for revenue, expenditure, full or empty.'), 'danger')
        ctx = _build_index_context(default_date=(date_s or today_ddmmyyyy()))
        ctx['temp_token'] = temp_token
        return render_template('index.html', **ctx, now=int(time())), 400

    # Create data record
    with engine.begin() as conn:
        res = conn.execute(text("""
            INSERT INTO entries (date, "full", "empty", revenue, expense, category, comment, created_by)
            VALUES (:date,:full,:empty,:revenue,:expense,:category,:comment,:cb)
            RETURNING id
        """), {
            'date': date,
            'full': full,
            'empty': empty,
            'revenue': str(revenue),
            'expense': str(expense),
            'category': category,
            'comment': comment,
            'cb': user['id']
        })
        new_id = res.scalar_one()

    # Live-Update
    emit('entry_changed', {'message': 'New entry added'}, namespace='/', broadcast=True)

    # Claim temp attachments (without incorrect session comparison)
    moved = 0
    if temp_token:
        tdir = _temp_dir(temp_token)
        edir = _entry_dir(new_id)
        os.makedirs(edir, exist_ok=True)

        # Select candidates: only the specified IDs (if available),
        # otherwise all for tokens+users
        with engine.begin() as conn:
            if temp_ids:
                rows = conn.execute(text("""
                    SELECT id, stored_name, original_name, content_type, size_bytes
                    FROM attachments_temp
                    WHERE id = ANY(:ids)
                    AND temp_token = :t
                    AND (uploaded_by = :u OR uploaded_by IS NULL)
                    ORDER BY id
                """), {'ids': temp_ids, 't': temp_token, 'u': session.get('user_id')}).mappings().all()
            else:
                rows = conn.execute(text("""
                    SELECT id, stored_name, original_name, content_type, size_bytes
                    FROM attachments_temp
                    WHERE temp_token = :t
                    AND (uploaded_by = :u OR uploaded_by IS NULL)
                    ORDER BY id
                """), {'t': temp_token, 'u': session.get('user_id')}).mappings().all()

        if not rows:
            current_app.logger.info(
                "No temp attachments found for token=%s user_id=%s (ids=%s)",
                temp_token, session.get('user_id'), temp_ids
            )

        for r in rows:
            src = os.path.join(tdir, r['stored_name'])
            dst = os.path.join(edir, r['stored_name'])
            try:
                if os.path.exists(src):
                    os.replace(src, dst)  # atomar verschieben
                else:
                    # Datei fehlt? überspringen
                    continue
            except Exception:
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
            moved += 1

        # Temp-Verzeichnis ggf. leeren
        try:
            if os.path.isdir(tdir) and not os.listdir(tdir):
                os.rmdir(tdir)
        except Exception:
            pass

    log_action(user['id'], 'entries:add', new_id, f'attachments_moved={moved}')
    if moved:
        flash(_('Record saved, %(count)d file(s) transferred.', count=moved), 'success')
    else:
        flash(_('Record saved.'), 'success')

    return redirect(url_for('bbalance_routes.index'))

@bbalance_routes.get('/edit/<int:entry_id>')
@login_required
def edit(entry_id: int):
    with engine.begin() as conn:
        # Load the entry
        row = conn.execute(text("""
            SELECT id, date, "full", "empty", revenue, expense, category, comment, created_by
            FROM entries
            WHERE id = :id
        """), {'id': entry_id}).mappings().first()

        # Download the attachments
        attachments = conn.execute(text("""
            SELECT id, original_name, content_type, size_bytes, created_at
            FROM attachments
            WHERE entry_id = :id
            ORDER BY created_at DESC
        """), {'id': entry_id}).mappings().all()

        # Download the audit data
        audit = conn.execute(text("""
            SELECT a.id, a.user_id, u.username, a.action, a.created_at, a.detail
            FROM audit_log a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.entry_id = :id
            ORDER BY a.created_at ASC, a.id ASC
        """), {'id': entry_id}).mappings().all()

    if not row:
        flash(_('Entry not found.'), 'danger')
        return redirect(url_for('bbalance_routes.index'))

    # Entry data for the form
    data = {
        'id': row['id'],
        'date': row['date'],
        'full': row['full'],
        'empty': row['empty'],
        'revenue': row['revenue'],
        'expense': row['expense'],
        'category': row['category'],
        'comment': row['comment'] or ''
    }

    # Attachments for display
    att_data = [{
        'id': r['id'],
        'name': r['original_name'],
        'size': r['size_bytes'],
        'content_type': r['content_type'],
        'url': url_for('attachments_routes.attachments_download', att_id=r['id']),
        'view_url': url_for('attachments_view', att_id=r['id'])
    } for r in attachments]

    categories = get_categories()
    
    return render_template('edit.html', data=data, attachments=att_data, audit=audit, categories=categories)

@bbalance_routes.post('/edit/<int:entry_id>')
@login_required
@require_perms('entries:edit:any')
@require_csrf
def edit_post(entry_id: int):
    # 1) Load old values
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, date, "full", "empty", revenue, expense, category, comment, created_by
            FROM entries
            WHERE id=:id
        """), {'id': entry_id}).mappings().first()
    if not row:
        abort(404)

    # 2) RBAC as usual
    allowed = ROLES.get(session.get('role'), set())
    if 'entries:edit:any' not in allowed:
        user = current_user()
        if not user or row['created_by'] != user['id'] or 'entries:edit:own' not in allowed:
            abort(403)

    # 3) Parse new values
    try:
        # Only accept the date if it's valid – otherwise keep the old value
        parsed_date = parse_date_de_or_none(request.form.get('date'))
        if parsed_date:
            date = parsed_date
        else:
            # row['date'] could be date or datetime
            od = row['date']
            date = od.date() if isinstance(od, datetime) else od

        full = int((request.form.get('full') or '0').strip() or '0')
        empty = int((request.form.get('empty') or '0').strip() or '0')
        revenue = parse_money(request.form.get('revenue') or '0')
        expense  = parse_money(request.form.get('expense')  or '0')
        category = (request.form.get('category') or '').strip()
        comment  = (request.form.get('comment') or '').strip()
    except Exception as e:
        flash(f"{_('Input error:')} {e}", 'danger')
        return redirect(url_for('bbalance_routes.edit', entry_id=entry_id))

    # 4) Determine changes (diff) – identical to the philosophy in payment.py
    def _q2(v: Decimal | None) -> Decimal | None:
        """Normalize monetary values to 2 decimal places (or None)."""
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

    # Date
    old_date = row['date'].date() if isinstance(row['date'], datetime) else row['date']
    if old_date != date:
        changes.append(("date", "Date", _fmt_date(old_date), _fmt_date(date)))

    # Full bottles
    old_full = int(row['full'] or 0)
    if old_full != full:
        changes.append(("full", "Full", str(old_full), str(full)))

    # Empty bottles
    old_empty = int(row['empty'] or 0)
    if old_empty != empty:
        changes.append(("empty", "Empty", str(old_empty), str(empty)))

    # Revenue
    old_revenue = _q2(row['revenue'])
    new_revenue = _q2(revenue)
    if old_revenue != new_revenue:
        changes.append(("revenue", "Revenue", _fmt_money(old_revenue), _fmt_money(new_revenue)))

    # Expense
    old_expense = _q2(row['expense'])
    new_expense = _q2(expense)
    if old_expense != new_expense:
        changes.append(("expense", "Expense", _fmt_money(old_expense), _fmt_money(new_expense)))

    # Category (compare trim)
    old_category = (row['category'] or '').strip()
    if old_category != category:
        changes.append(("category", "Category", old_category, category))

    # Comment
    old_comment = (row.get('comment') or '').strip()
    if old_comment != comment:
        changes.append(("comment", "Comment", old_comment, comment))

    # 5) Save + Audit (similar to payment.py: separate audit entry for each field change)
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE entries
            SET date=:date,
                "full"=:full,
                "empty"=:empty,
                revenue=:revenue,
                expense=:expense,
                category=:category,
                comment=:comment,
                updated_at=NOW()
            WHERE id=:id
        """), {
            'id': entry_id,
            'date': date,
            'full': full,
            'empty': empty,
            'revenue': str(revenue) if revenue is not None else None,
            'expense':  str(expense)  if expense  is not None else None,
            'category': category,
            'comment': comment
        })

        # b) Summary edit entry
        now_str = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        if changes:
            summary = "\n".join([f"- {lbl}: {old} → {new}" for _, lbl, old, new in changes])
            detail_text = f"Edited on {now_str}\n{summary}"
        else:
            detail_text = f"Edited on {now_str} (no field changes)"

        conn.execute(text("""
            INSERT INTO audit_log (user_id, action, entry_id, detail)
            VALUES (:uid, 'edit', :eid, :detail)
        """), {
            'uid': session.get('user_id'),
            'eid': entry_id,
            'detail': detail_text
        })

    # Emit event for live updates
    emit('entry_changed', {'message': 'Entry edited'}, namespace='/', broadcast=True)

    # log_action(session.get('user_id'), 'entries:edit', entry_id, None)
    flash(_('Entry saved.'), 'success')

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

    # Emit event for live updates
    emit('entry_changed', {'message': 'Entry deleted'}, namespace='/', broadcast=True)

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
    writer.writerow(['Date','Full','Empty','Inventory','Revenue','Expense','Cash balance','Category'])
    for e in entries:
        writer.writerow([
            format_date_de(e['date']), e['full'], e['empty'], e['inventory'],
            str(e['revenue']).replace('.', ','), str(e['expense']).replace('.', ','),
            str(e['cashBalance']).replace('.', ','), e['category']
        ])
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))
    mem.seek(0)
    filename = f"{get_setting('app_title', 'BottleBalance')}_{_('export')}_{date.today().strftime('%Y%m%d')}.csv"
    return send_file(mem, as_attachment=True, download_name=filename, mimetype='text/csv')

@bbalance_routes.post('/import')
@login_required
@require_perms('import:csv')
@require_csrf
def import_csv():
    file = request.files.get('file')
    replace_all = request.form.get('replace_all') == 'on'
    if not file or file.filename == '':
        flash(_('Please select a CSV file.'), 'info')
        return redirect(url_for('bbalance_routes.index'))
    try:
        content = file.read().decode('utf-8-sig')
        reader = csv.reader(io.StringIO(content), delimiter=';')
        headers = next(reader, None)
        # Robustness: Check header row and split if necessary
        if headers and len(headers) == 1 and ';' in headers[0]:
            headers = headers[0].split(';')
        # Validation
        validation_errors = []

        if len(set(headers)) != len(headers):
            validation_errors.append("Duplicate column names in CSV.")

        if any(h.strip() == "" for h in headers):
            validation_errors.append("Empty column names in CSV.")

        required_fields = {"Date", "Full", "Empty"}
        if not required_fields.issubset(set(headers)):
            validation_errors.append("Required fields missing: Date, Full, Empty.")

        if validation_errors:
            for err in validation_errors:
                flash(err)
            return redirect(url_for('bbalance_routes.index'))
        expected = ['Date','Full','Empty','Inventory','Revenue','Expense','Cash balance','Category']
        alt_expected = ['Date','Full','Empty','Revenue','Expense','Category']
        if headers is None or [h.strip() for h in headers] not in (expected, alt_expected):
            raise ValueError('CSV header does not match the expected format.')
        rows_to_insert = []
        for row in reader:
            if len(row) == 8:
                date_s, full_s, empty_s, _inv, revenue_s, expense_s, _kas, category = row
            else:
                date_s, full_s, empty_s, revenue_s, expense_s, category = row
            date = parse_date_de_or_today(date_s)
            full = int((full_s or '0').strip() or 0)
            empty = int((empty_s or '0').strip() or 0)
            revenue = parse_money(revenue_s or '0')
            expense = parse_money(expense_s or '0')
            category = (category or '').strip()
            rows_to_insert.append({'date': date, 'full': full, 'empty': empty,
                                   'revenue': str(revenue), 'expense': str(expense), 'category': category})
        with engine.begin() as conn:
            if replace_all:
                conn.execute(text('DELETE FROM entries'))
            for r in rows_to_insert:
                conn.execute(text("""
                    INSERT INTO entries (date, "full", "empty", revenue, expense, category)
                    VALUES (:date,:full,:empty,:revenue,:expense,:category)
                """), r)

        # Success message with pluralization
        flash(ngettext(
            'Import successful: %(count)d lines transferred.',
            len(rows_to_insert),
            count=len(rows_to_insert)
        ), "success")

    except Exception as e:
        flash(_('Import failed: %(error)s', error=escape(str(e))), "danger")

    return redirect(url_for('bbalance_routes.index'))