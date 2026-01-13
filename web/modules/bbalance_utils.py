# -----------------------
# Data Access
# ----------------------
from decimal import Decimal
from flask import request, session
from sqlalchemy import text
from datetime import datetime, date
from uuid import uuid4

from modules.core_utils import engine, ROLES
from modules.csv_utils import today_ddmmyyyy, format_eur_de, format_date_de
from modules.auth_utils import current_user

def fetch_entries(
    search=None,
    date_from=None,
    date_to=None,
    attachments_filter=None,
    year=None,
    force_order_dir: str | None = None
):
    where = []
    params = {}

    # Filter (external, alias "ar")
    if search:
        where.append("(ar.note ILIKE :q OR to_char(ar.date, 'DD.MM.YYYY') ILIKE :q)")
        params['q'] = f"%{search}%"
    if date_from:
        where.append("ar.date >= :df")
        params['df'] = date_from
    if date_to:
        where.append("ar.date <= :dt")
        params['dt'] = date_to
    if year is not None:
        where.append("EXTRACT(YEAR FROM ar.date) = :year")
        params['year'] = year
    if attachments_filter == 'only':
        where.append("COALESCE(a.cnt, 0) > 0")
    elif attachments_filter == 'none':
        where.append("COALESCE(a.cnt, 0) = 0")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    # Sorting (profile) + override
    user = current_user()
    sort_order_desc = bool(user.get('sort_order_desc')) if user else False
    order_dir = 'DESC' if sort_order_desc else 'ASC'
    if force_order_dir:
        od = str(force_order_dir).upper()
        order_dir = 'ASC' if od == 'ASC' else 'DESC'

    # CTE: Window functions over *all* rows (no WHERE here!)
    sql = f"""
        WITH att AS (
            SELECT entry_id, COUNT(*) AS cnt
            FROM attachments
            GROUP BY entry_id
        ),
        all_rows AS (
            SELECT
                e.id,
                e.date,
                e.full,
                e.empty,
                e.revenue,
                e.expense,
                e.note,
                e.created_by,
                SUM(e.revenue - e.expense)
                    OVER (ORDER BY e.date, e.id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS "cashBalance",
                SUM(e."full" - e."empty")
                    OVER (ORDER BY e.date, e.id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS inventory

            FROM entries e
        )
        SELECT
            ar.id,
            ar.date,
            ar.full,
            ar.empty,
            ar.revenue,
            ar.expense,
            ar.note,
            ar.created_by,
            ar."cashBalance",
            ar.inventory,
            COALESCE(a.cnt, 0) AS attachment_count
        FROM all_rows ar
        LEFT JOIN att a ON a.entry_id = ar.id
        {where_sql}
        ORDER BY ar.date {order_dir}, ar.id {order_dir}
    """

    with engine.begin() as conn:
        rows = conn.execute(text(sql), params).mappings().all()

    result = []
    for r in rows:
        result.append({
            'id': r['id'],
            'date': r['date'],
            'full': int(r['full'] or 0),
            'empty': int(r['empty'] or 0),
            'revenue': Decimal(r['revenue'] or 0),
            'expense': Decimal(r['expense'] or 0),
            'note': r['note'] or '',
            'inventory': int(r['inventory'] or 0),  # Inventory in bottles
            'cashBalance': Decimal(r['cashBalance'] or 0).quantize(Decimal('0.01')),
            'created_by': r['created_by'],
            'attachment_count': int(r['attachment_count'] or 0),
        })
    return result

def get_global_totals():
    """Calculates inventory and cash balance from the entire history."""
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT
                COALESCE(SUM("full") - SUM("empty"), 0) AS inventory,
                COALESCE(SUM(revenue) - SUM(expense), 0) AS "cashBalance"
            FROM entries
        """)).mappings().first()

    return row['inventory'], row['cashBalance']

def get_delta_for_filter(date_from=None, date_to=None):
    """Calculates the change in the selected period (optional for display)."""
    query = """
        SELECT
            COALESCE(SUM("full") - SUM("empty"), 0) AS delta_inv,
            COALESCE(SUM(revenue) - SUM(expense), 0) AS "delta_cashbalance"
        FROM entries
        WHERE 1=1
    """
    params = {}
    if date_from:
        query += " AND date >= :df"
        params['df'] = date_from
    if date_to:
        query += " AND date <= :dt"
        params['dt'] = date_to
    with engine.begin() as conn:
        row = conn.execute(text(query), params).mappings().first()
    return row['delta_inv'], row['delta_cashbalance']

def _user_can_edit_entry(entry_id: int) -> bool:
    """RBAC-Check: edit:any oder edit:own wenn created_by = current_user."""
    allowed = ROLES.get(session.get('role'), set())
    if 'entries:edit:any' in allowed:
        return True
    if 'entries:edit:own' in allowed:
        user = current_user()
        if not user:
            return False
        with engine.begin() as conn:
            owner = conn.execute(
                text("SELECT created_by FROM entries WHERE id=:id"),
                {'id': entry_id}
            ).scalar_one_or_none()
        return owner == user['id']
    return False

def _user_can_view_entry(entry_id: int) -> bool:
    allowed = ROLES.get(session.get('role'), set())
    return 'entries:view' in allowed

def _build_index_context(default_date: str | None = None, temp_token: str | None = None):
    q = (request.args.get('q') or '').strip()
    date_from_s = request.args.get('from')
    date_to_s = request.args.get('to')
    df = datetime.strptime(date_from_s, '%Y-%m-%d').date() if date_from_s else None
    dt = datetime.strptime(date_to_s, '%Y-%m-%d').date() if date_to_s else None

    filter_attachments = request.args.get('attachments')

    # Annual filter from URL
    year_raw = (request.args.get('year') or '').strip().lower()
    year_val: int | None = None
    if year_raw not in ('', 'all'):
        try:
            year_val = int(year_raw)
        except ValueError:
            year_val = None
    
    #Only apply default if the user has NOT passed 'year'
    year_param_present = 'year' in request.args
    if (not year_param_present) and (not df) and (not dt):
        user = current_user()
        # TRUE = Show all, FALSE = Current year
        if user and user.get('default_filter'):
            year_val = None  # All
        else:
            year_val = date.today().year

    # Entries for table (with profile sorting)
    entries = fetch_entries(
        q or None, df, dt,
        attachments_filter=filter_attachments,
        year=year_val
    )

    years = get_available_years()
    inv_current, kas_current = get_global_totals()
    delta_inv, delta_cashbalance = get_delta_for_filter(df, dt)

    # Sparklines: Consider the year, but always chronologically (ASC)
    entries_for_chart = fetch_entries(
        None,
        None if year_val is not None else df,
        None if year_val is not None else dt,
        attachments_filter=None,
        year=year_val,
        force_order_dir='ASC'
    )
    entries_for_chart.sort(key=lambda e: (e['date'] or date.min, e['id']))

    series_inv = [e['inventory'] for e in entries_for_chart]
    series_cashbalance = [float(e['cashBalance']) for e in entries_for_chart]
    labels_all = [e['date'].isoformat() if e['date'] else '' for e in entries_for_chart]

    if entries:
        last = max(entries, key=lambda e: (e['date'], e['id']))
        finv = last['inventory']
        fcashbalance = last['cashBalance']
    else:
        finv, fcashbalance = 0, Decimal('0')

    role = session.get('role')
    allowed = ROLES.get(role, set())

    token = temp_token or session.get('add_temp_token') or uuid4().hex
    session['add_temp_token'] = token

    return {
        'entries': entries,
        'inv_current': inv_current,
        'kas_current': kas_current,
        'delta_inv': delta_inv,
        'delta_cashbalance': delta_cashbalance,
        'filter_inv': finv,
        'filter_cashbalance': fcashbalance,
        'default_date': default_date or today_ddmmyyyy(),
        'format_eur_de': format_eur_de,
        'format_date_de': format_date_de,
        'can_add': ('entries:add' in allowed),
        'can_export_csv': ('export:csv' in allowed),
        'can_export_pdf': ('export:pdf' in allowed),
        'can_import_csv': ('import:csv' in allowed),
        'role': role,
        'series_inv': series_inv,
        'series_cashbalance': series_cashbalance,
        'labels_all': labels_all,
        'temp_token': token,
        'years': years,
        'selected_year': str(year_val) if year_val is not None else 'all',
        'from': date_from_s or '',
        'to': date_to_s or '',
    }

def get_available_years() -> list[int]:
    """Returns all existing years from entries.date sorted in ascending order."""
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT DISTINCT EXTRACT(YEAR FROM date)::int AS year
            FROM entries
            WHERE date IS NOT NULL
            ORDER BY year ASC
        """)).mappings().all()
    return [r['year'] for r in rows]