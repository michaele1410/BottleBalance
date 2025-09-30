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

# Kanonische Zielfelder
CANONICAL_FIELDS = ['Datum', 'Vollgut', 'Leergut', 'Einnahme', 'Ausgabe', 'Bemerkung']

# Synonyme (frei erweiterbar)
HEADER_SYNONYMS = {
    'Datum':     {'datum', 'date', 'ttmmjjjj', 'tt.mm.jjjj', 'day', 'tag'},
    'Vollgut':   {'vollgut', 'voll', 'in', 'eingang', 'bestandszugang', 'bottlesin'},
    'Leergut':   {'leergut', 'leer', 'out', 'ausgang', 'bestandsabgang', 'bottlesout', 'pfand'},
    'Einnahme':  {'einnahme', 'einzahlung', 'revenue', 'income', 'cashin'},
    'Ausgabe':   {'ausgabe', 'auszahlung', 'expense', 'cost', 'cashout'},
    'Bemerkung': {'bemerkung', 'notiz', 'kommentar', 'comment', 'note', 'description', 'desc'},
}

_money_re = re.compile(r'^\s*[+-]?\d{1,3}([.,]\d{3})*([.,]\d{1,2})?\s*(€)?\s*$')

# -----------------------
# Hilfsfunktionen
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
    return f"{sign}{whole_str},{frac:02d} {_('waehrung')}"

def parse_date_de_strict(s: str) -> date:
    s = (s or '').strip()
    if not s:
        raise ValueError(_('Datum fehlt'))
    try:
        return datetime.strptime(s, '%d.%m.%Y').date()
    except Exception:
        raise ValueError(_('Ungültiges Datum (erwartet TT.MM.JJJJ): ') + s)

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
        raise ValueError(_(f'Ungültige Ganzzahl für {field}: ') + ss)
    return int(ss)

def parse_money(value: str | None) -> Decimal:
    waehrung_variants = [_("waehrung"), "€", "EUR", "USD"]
    if value is None:
        return Decimal('0')

    s = str(value).strip()
    if s == '':
        return Decimal('0')

    for w in waehrung_variants:
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
        row['datum'],
        int(row['vollgut']),
        int(row['leergut']),
        str(Decimal(row['einnahme'] or 0).quantize(Decimal('0.01'))),
        str(Decimal(row['ausgabe'] or 0).quantize(Decimal('0.01'))),
        (row['bemerkung'] or '').strip().lower()
    )

def _fetch_existing_signature_set(conn) -> set[tuple]:
    existing = conn.execute(text("""
        SELECT datum, COALESCE(vollgut,0), COALESCE(leergut,0),
               COALESCE(einnahme,0), COALESCE(ausgabe,0), COALESCE(bemerkung,'')
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
            if canon in ('Einnahme', 'Ausgabe', 'Bemerkung'):
                mapping[canon] = None
                continue
            return {}
        mapping[canon] = idx
    return mapping

def _parse_csv_with_mapping(content: str, replace_all: bool, mapping: dict | None) -> tuple[list, list, int]:
    reader = csv.reader(io.StringIO(content), delimiter=';')
    headers = next(reader, None)
    if not headers:
        raise ValueError(_('Leere CSV oder fehlender Header.'))

    if mapping is None:
        auto_map = compute_auto_mapping(headers) if IMPORT_ALLOW_MAPPING else {}
        mapping = auto_map if auto_map else {}

    idx_datum     = mapping.get('Datum')
    idx_vollgut   = mapping.get('Vollgut')
    idx_leergut   = mapping.get('Leergut')
    idx_einnahme  = mapping.get('Einnahme')
    idx_ausgabe   = mapping.get('Ausgabe')
    idx_bemerkung = mapping.get('Bemerkung')

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

        v_datum     = raw[idx_datum]     if idx_datum     is not None and idx_datum     < len(raw) else ''
        v_vollgut   = raw[idx_vollgut]   if idx_vollgut   is not None and idx_vollgut   < len(raw) else ''
        v_leergut   = raw[idx_leergut]   if idx_leergut   is not None and idx_leergut   < len(raw) else ''
        v_einnahme  = raw[idx_einnahme]  if idx_einnahme  is not None and idx_einnahme  < len(raw) else ''
        v_ausgabe   = raw[idx_ausgabe]   if idx_ausgabe   is not None and idx_ausgabe   < len(raw) else ''
        v_bemerkung = raw[idx_bemerkung] if idx_bemerkung is not None and idx_bemerkung < len(raw) else ''

        try:
            datum = parse_date_de_strict(v_datum)
        except ValueError as e:
            errors.append(str(e))
            datum = None

        try:
            vollgut = try_int_strict(v_vollgut, 'Vollgut')
        except ValueError as e:
            errors.append(str(e))
            vollgut = 0

        try:
            leergut = try_int_strict(v_leergut, 'Leergut')
        except ValueError as e:
            errors.append(str(e))
            leergut = 0

        if not is_valid_money_str(v_einnahme):
            errors.append(_('Ungültiges Geldformat für Einnahme: ') + (v_einnahme or ''))
        if not is_valid_money_str(v_ausgabe):
            errors.append(_('Ungültiges Geldformat für Ausgabe: ') + (v_ausgabe or ''))

        einnahme = parse_money(v_einnahme or '0')
        ausgabe  = parse_money(v_ausgabe or '0')
        bemerkung = (v_bemerkung or '').strip()

        row_obj = {
            'datum': datum,
            'vollgut': vollgut,
            'leergut': leergut,
            'einnahme': str(einnahme),
            'ausgabe': str(ausgabe),
            'bemerkung': bemerkung,
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
    writer.writerow(['Zeitpunkt', 'Aktion', 'Benutzer', 'Details'])

    for entry in audit_entries:
        formatted_time = localize_dt_str(entry.get('timestamp'), tz_name, '%d.%m.%Y %H:%M:%S')
        writer.writerow([
            formatted_time,
            entry.get('action', ''),
            entry.get('username', 'Unbekannt'),
            (entry.get('detail') or '').replace('\n', ' ')
        ])

    return output.getvalue()