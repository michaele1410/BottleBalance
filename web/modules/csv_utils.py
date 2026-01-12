# -----------------------
# Utils: Formatting
# -----------------------
import re
import os
import csv
import io
from flask_babel import Babel, gettext as _
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from sqlalchemy import text

from modules.core_utils import (
    engine,
    localize_dt_str
)

# -----------------------
# Feature Switches (ENV)
# -----------------------
IMPORT_ALLOW_MAPPING = os.getenv("IMPORT_ALLOW_MAPPING", "true").lower() in ("1", "true", "yes", "on")

# Canonical target fields
CANONICAL_FIELDS = ['Date', 'Full', 'Empty', 'Revenue', 'Expense', 'Note']

# Synonyms (freely expandable)
HEADER_SYNONYMS = {
    'Date':     {'date', 'datum', 'ttmmjjjj', 'tt.mm.jjjj', 'day', 'tag'},
    'Full':   {'full bottles', 'full', 'plus', 'revenue', 'inventoryin', 'bottlesin'},
    'Empty':   {'empty', 'leer', 'out', 'ausgang', 'bestandsabgang', 'bottlesout', 'pfand'},
    'Revenue':  {'revenue', 'einzahlung', 'revenue', 'revenue', 'cashin'},
    'Expense':   {'expense', 'auszahlung', 'expense', 'cost', 'cashout'},
    'Note': {'note', 'notiz', 'kommentar', 'comment', 'note', 'description', 'desc'},
}

_money_re = re.compile(r'^\s*[+-]?\d{1,3}([.,]\d{3})*([.,]\d{1,2})?\s*(€)?\s*$')

# -----------------------
# Helpers
# -----------------------
def _norm(h: str) -> str:
    return re.sub(r'[^a-z0-9]', '', (h or '').strip().lower())

def today_ddmmyyyy():
    return date.today().strftime('%d.%m.%Y')

def format_date_de(d: date) -> str:
    return d.strftime('%d.%m.%Y')

def format_eur_de(value: Decimal | float | int) -> str:
    d = Decimal(value).quantize(Decimal('0.01'))
    sign = '-' if d < 0 else ''
    d = abs(d)
    whole, frac = divmod(int(d * 100), 100)
    whole_str = f"{whole:,}".replace(',', '.')
    return f"{sign}{whole_str},{frac:02d} {_('currency')}"

def parse_date_de_strict(s: str) -> date:
    s = (s or '').strip()
    if not s:
        raise ValueError(_('Date missing.'))
    try:
        return datetime.strptime(s, '%d.%m.%Y').date()
    except Exception:
        raise ValueError(_('Invalid date (expected DD.MM.YYYY): ') + s)

def parse_date_de_or_none(s: str | None) -> date | None:
    if not s or not s.strip():
        return None
    try:
        return datetime.strptime(s.strip(), '%d.%m.%Y').date()
    except ValueError:
        return None

def parse_date_de_or_today(s: str | None) -> date:
    return parse_date_de_or_none(s) or date.today()

def is_valid_money_str(s: str) -> bool:
    if s is None or s.strip() == '':
        return True
    return bool(_money_re.match(s.strip()))

def try_int_strict(s: str, field: str) -> int:
    ss = (s or '').strip()
    if ss == '':
        return 0
    if not re.fullmatch(r'[+-]?\d+', ss):
        raise ValueError(_(f'Invalid integer for {field}: ') + ss)
    return int(ss)

def parse_money(value: str | None) -> Decimal:
    currency_variants = [_("currency"), "€", "EUR", "USD"]
    if value is None:
        return Decimal('0')

    s = str(value).strip()
    if s == '':
        return Decimal('0')

    for w in currency_variants:
        s = s.replace(w, '')

    s = re.sub(r'[\s\u00A0\u202F]', '', s)

    if s.startswith('+'):
        s = s[1:]

    has_comma = ',' in s
    has_dot = '.' in s

    if has_comma and has_dot:
        dec_pos = max(s.rfind(','), s.rfind('.'))
        int_part = s[:dec_pos].replace(',', '').replace('.', '')
        frac_part = s[dec_pos+1:]
        s = f"{int_part}.{frac_part}"
    elif has_comma:
        if s.count(',') > 1:
            dec_pos = s.rfind(',')
            int_part = s[:dec_pos].replace(',', '').replace('.', '')
            frac_part = s[dec_pos+1:]
            s = f"{int_part}.{frac_part}"
        else:
            s = s.replace('.', '').replace(',', '.')
    elif has_dot and s.count('.') > 1:
        dec_pos = s.rfind('.')
        int_part = s[:dec_pos].replace('.', '').replace(',', '')
        frac_part = s[dec_pos+1:]
        s = f"{int_part}.{frac_part}"

    try:
        return Decimal(s)
    except InvalidOperation:
        return Decimal('0')

def _signature(row: dict) -> tuple:
    return (
        row['date'],
        int(row['full']),
        int(row['empty']),
        str(Decimal(row['revenue'] or 0).quantize(Decimal('0.01'))),
        str(Decimal(row['expense'] or 0).quantize(Decimal('0.01'))),
        (row['note'] or '').strip().lower()
    )

def _fetch_existing_signature_set(conn) -> set[tuple]:
    existing = conn.execute(text("""
        SELECT date, COALESCE(full,0), COALESCE(empty,0),
               COALESCE(revenue,0), COALESCE(expense,0), COALESCE(note,'')
        FROM entries
    """)).fetchall()

    result = set()
    for d, voll, leer, ein, aus, bem in existing:
        result.add((
            d,
            int(voll),
            int(leer),
            str(Decimal(ein or 0).quantize(Decimal('0.01'))),
            str(Decimal(aus or 0).quantize(Decimal('0.01'))),
            (bem or '').strip().lower()
        ))
    return result

def compute_auto_mapping(headers: list[str]) -> dict:
    mapping = {}
    norm_headers = [_norm(h) for h in headers]
    for canon in CANONICAL_FIELDS:
        candidates = { _norm(c) for c in HEADER_SYNONYMS.get(canon, set()) } | {_norm(canon)}
        idx = next((i for i, nh in enumerate(norm_headers) if nh in candidates), None)
        if idx is None:
            if canon in ('Revenue', 'Expense', 'Note'):
                mapping[canon] = None
                continue
            return {}
        mapping[canon] = idx
    return mapping

def _parse_csv_with_mapping(content: str, replace_all: bool, mapping: dict | None) -> tuple[list, list, int]:
    reader = csv.reader(io.StringIO(content), delimiter=';')
    headers = next(reader, None)
    if not headers:
        raise ValueError(_('Empty CSV or missing header.'))

    if mapping is None:
        auto_map = compute_auto_mapping(headers) if IMPORT_ALLOW_MAPPING else {}
        mapping = auto_map if auto_map else {}

    idx_date     = mapping.get('Date')
    idx_full   = mapping.get('Full')
    idx_empty   = mapping.get('Empty')
    idx_revenue  = mapping.get('Revenue')
    idx_expense   = mapping.get('Expense')
    idx_note = mapping.get('Note')

    preview_rows = []
    dup_count = 0

    with engine.begin() as conn:
        existing = set()
        if not replace_all:
            existing = _fetch_existing_signature_set(conn)

    line_no = 1
    for raw in reader:
        line_no += 1
        if not raw or all(not (c or '').strip() for c in raw):
            continue
        errors = []

        v_date     = raw[idx_date]     if idx_date     is not None and idx_date     < len(raw) else ''
        v_full   = raw[idx_full]   if idx_full   is not None and idx_full   < len(raw) else ''
        v_empty   = raw[idx_empty]   if idx_empty   is not None and idx_empty   < len(raw) else ''
        v_revenue  = raw[idx_revenue]  if idx_revenue  is not None and idx_revenue  < len(raw) else ''
        v_expense   = raw[idx_expense]   if idx_expense   is not None and idx_expense   < len(raw) else ''
        v_note = raw[idx_note] if idx_note is not None and idx_note < len(raw) else ''

        try:
            date = parse_date_de_strict(v_date)
        except ValueError as e:
            errors.append(str(e))
            date = None

        try:
            full = try_int_strict(v_full, 'Full')
        except ValueError as e:
            errors.append(str(e))
            full = 0

        try:
            empty = try_int_strict(v_empty, 'Empty')
        except ValueError as e:
            errors.append(str(e))
            empty = 0

        if not is_valid_money_str(v_revenue):
            errors.append(_('Invalid money format for revenue: ') + (v_revenue or ''))
        if not is_valid_money_str(v_expense):
            errors.append(_('Invalid money format for expense: ') + (v_expense or ''))

        revenue = parse_money(v_revenue or '0')
        expense  = parse_money(v_expense or '0')
        note = (v_note or '').strip()

        row_obj = {
            'date': date,
            'full': full,
            'empty': empty,
            'revenue': str(revenue),
            'expense': str(expense),
            'note': note,
            'line_no': line_no,
            'errors': errors,
            'is_duplicate': False
        }

        if not errors and not replace_all:
            sig = _signature(row_obj)
            if sig in existing:
                row_obj['is_duplicate'] = True
                dup_count += 1

        preview_rows.append(row_obj)

    return preview_rows, headers, dup_count

def export_audit_entries_to_csv(audit_entries: list[dict], tz_name: str = 'Europe/Berlin') -> str:
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(['Timestamp', 'Action', 'User', 'Details'])

    for entry in audit_entries:
        formatted_time = localize_dt_str(entry.get('timestamp'), tz_name, '%d.%m.%Y %H:%M:%S')
        writer.writerow([
            formatted_time,
            entry.get('action', ''),
            entry.get('username', 'Unknown'),
            (entry.get('detail') or '').replace('\n', ' ')
        ])

    return output.getvalue()