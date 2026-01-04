# -----------------------
# Data Access
# -----------------------

# modules/bbalance_utils.py
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

    # Filter (außen, Alias "ar")
    if search:
        where.append("(ar.bemerkung ILIKE :q OR to_char(ar.datum, 'DD.MM.YYYY') ILIKE :q)")
        params['q'] = f"%{search}%"
    if date_from:
        where.append("ar.datum >= :df")
        params['df'] = date_from
    if date_to:
        where.append("ar.datum <= :dt")
        params['dt'] = date_to
    if year is not None:
        where.append("EXTRACT(YEAR FROM ar.datum) = :year")
        params['year'] = year
    if attachments_filter == 'only':
        where.append("COALESCE(a.cnt, 0) > 0")
    elif attachments_filter == 'none':
        where.append("COALESCE(a.cnt, 0) = 0")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    # Sortierung (Profil) + Override
    user = current_user()
    sort_order_desc = bool(user.get('sort_order_desc')) if user else False
    order_dir = 'DESC' if sort_order_desc else 'ASC'
    if force_order_dir:
        od = str(force_order_dir).upper()
        order_dir = 'ASC' if od == 'ASC' else 'DESC'

    # CTE: Window-Functions über *alle* Zeilen (kein WHERE hier!)
    sql = f"""
        WITH att AS (
            SELECT entry_id, COUNT(*) AS cnt
            FROM attachments
            GROUP BY entry_id
        ),
        all_rows AS (
            SELECT
                e.id,
                e.datum,
                e.vollgut,
                e.leergut,
                e.einnahme,
                e.ausgabe,
                e.bemerkung,
                e.created_by,
                SUM(e.einnahme - e.ausgabe)
                    OVER (ORDER BY e.datum, e.id
                          ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS kassenbestand,
                SUM(e.vollgut - e.leergut)
                    OVER (ORDER BY e.datum, e.id
                          ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS inventar
            FROM entries e
        )
        SELECT
            ar.id,
            ar.datum,
            ar.vollgut,
            ar.leergut,
            ar.einnahme,
            ar.ausgabe,
            ar.bemerkung,
            ar.created_by,
            ar.kassenbestand,
            ar.inventar,
            COALESCE(a.cnt, 0) AS attachment_count
        FROM all_rows ar
        LEFT JOIN att a ON a.entry_id = ar.id
        {where_sql}
        ORDER BY ar.datum {order_dir}, ar.id {order_dir}
    """

    with engine.begin() as conn:
        rows = conn.execute(text(sql), params).mappings().all()

    result = []
    for r in rows:
        result.append({
            'id': r['id'],
            'datum': r['datum'],
            'vollgut': int(r['vollgut'] or 0),
            'leergut': int(r['leergut'] or 0),
            'einnahme': Decimal(r['einnahme'] or 0),
            'ausgabe': Decimal(r['ausgabe'] or 0),
            'bemerkung': r['bemerkung'] or '',
            'inventar': int(r['inventar'] or 0),  # Inventar in Flaschen
            'kassenbestand': Decimal(r['kassenbestand'] or 0).quantize(Decimal('0.01')),
            'created_by': r['created_by'],
            'attachment_count': int(r['attachment_count'] or 0),
        })
    return result


def get_global_totals():
    """Berechnet Inventar und Kassenbestand aus der gesamten Historie."""
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT
                COALESCE(SUM(vollgut) - SUM(leergut), 0) AS inventar,
                COALESCE(SUM(einnahme) - SUM(ausgabe), 0) AS kassenbestand
            FROM entries
        """)).mappings().first()
    return row['inventar'], row['kassenbestand']


def get_delta_for_filter(date_from=None, date_to=None):
    """Berechnet die Veränderung im gewählten Zeitraum (optional für Anzeige)."""
    query = """
        SELECT
            COALESCE(SUM(vollgut) - SUM(leergut), 0) AS delta_inv,
            COALESCE(SUM(einnahme) - SUM(ausgabe), 0) AS delta_kas
        FROM entries
        WHERE 1=1
    """
    params = {}
    if date_from:
        query += " AND datum >= :df"
        params['df'] = date_from
    if date_to:
        query += " AND datum <= :dt"
        params['dt'] = date_to
    with engine.begin() as conn:
        row = conn.execute(text(query), params).mappings().first()
    return row['delta_inv'], row['delta_kas']


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

    # Jahresfilter
    year_raw = (request.args.get('year') or '').strip().lower()
    year_val: int | None = None
    if year_raw not in ('', 'all'):
        try:
            year_val = int(year_raw)
        except ValueError:
            year_val = None

    # Einträge für Tabelle (mit Profil-Sortierung)
    entries = fetch_entries(
        q or None, df, dt,
        attachments_filter=filter_attachments,
        year=year_val
    )

    years = get_available_years()

    # Gesamtwerte unabhängig vom Filter
    inv_aktuell, kas_aktuell = get_global_totals()

    # Veränderung im Filterbereich (nur by date-range)
    delta_inv, delta_kas = get_delta_for_filter(df, dt)

    # Sparklines: Jahr berücksichtigen, aber immer chronologisch (ASC)
    entries_for_chart = fetch_entries(
        None,
        None if year_val is not None else df,
        None if year_val is not None else dt,
        attachments_filter=None,
        year=year_val,
        force_order_dir='ASC'
    )
    entries_for_chart.sort(key=lambda e: (e['datum'] or date.min, e['id']))

    series_inv = [e['inventar'] for e in entries_for_chart]
    series_kas = [float(e['kassenbestand']) for e in entries_for_chart]
    labels_all = [e['datum'].isoformat() if e['datum'] else '' for e in entries_for_chart]

    # Filterstände (chronologisch letzter Eintrag)
    if entries:
        last = max(entries, key=lambda e: (e['datum'], e['id']))
        finv = last['inventar']
        fkas = last['kassenbestand']
    else:
        finv, fkas = 0, Decimal('0')

    role = session.get('role')
    allowed = ROLES.get(role, set())

    token = temp_token or session.get('add_temp_token') or uuid4().hex
    session['add_temp_token'] = token

    return {
        'entries': entries,
        'inv_aktuell': inv_aktuell,
        'kas_aktuell': kas_aktuell,
        'delta_inv': delta_inv,
        'delta_kas': delta_kas,
        'filter_inv': finv,
        'filter_kas': fkas,
        'default_date': default_date or today_ddmmyyyy(),
        'format_eur_de': format_eur_de,
        'format_date_de': format_date_de,
        'can_add': ('entries:add' in allowed),
        'can_export_csv': ('export:csv' in allowed),
        'can_export_pdf': ('export:pdf' in allowed),
        'can_import_csv': ('import:csv' in allowed),
        'role': role,
        'series_inv': series_inv,
        'series_kas': series_kas,
        'labels_all': labels_all,
        'temp_token': token,
        'years': years,
        'selected_year': str(year_val) if year_val is not None else '',
        'from': date_from_s or '',
        'to': date_to_s or '',
    }


def get_available_years() -> list[int]:
    """Liefert alle vorhandenen Jahre aus entries.datum aufsteigend sortiert."""
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT DISTINCT EXTRACT(YEAR FROM datum)::int AS year
            FROM entries
            WHERE datum IS NOT NULL
            ORDER BY year ASC
        """)).mappings().all()
    return [r['year'] for r in rows]
