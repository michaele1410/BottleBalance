# -----------------------
# Utils: Formatting
# -----------------------
def today_ddmmyyyy():
    return date.today().strftime('%d.%m.%Y')

def parse_date_de_or_today(s: str | None) -> date:
    if not s or not s.strip():
        return date.today()
    return datetime.strptime(s.strip(), '%d.%m.%Y').date()

def format_date_de(d: date) -> str:
    return d.strftime('%d.%m.%Y')

def format_eur_de(value: Decimal | float | int) -> str:
    d = Decimal(value).quantize(Decimal('0.01'))
    sign = '-' if d < 0 else ''
    d = abs(d)
    whole, frac = divmod(int(d * 100), 100)
    whole_str = f"{whole:,}".replace(',', '.')
    return f"{sign}{whole_str},{frac:02d} {_('waehrung')}"

# Money parsing utility
def parse_money(value: str | None) -> Decimal:
    """
    Akzeptiert: '12,50', '12.50', '1.234,56', '1,234.56',
                '  -1 234,56 € ', '', None
    Liefert: Decimal (Default 0)
    """
    if value is None:
        return Decimal('0')

    s = str(value).strip()
    if s == '':
        return Decimal('0')

    # Währung/Spaces entfernen (inkl. NBSP/NNBSP/Narrow NBSP)
    s = s.replace("{{ _('waehrung') }}", "").replace("{{ _('(waehrungEURUSD)') }}", "")
    s = re.sub(r'[\s\u00A0\u202F]', '', s)

    # Optionales führendes '+'
    if s.startswith('+'):
        s = s[1:]

    has_comma = ',' in s
    has_dot = '.' in s

    if has_comma and has_dot:
        # Rechtester Separator (',' oder '.') ist Dezimaltrennzeichen
        last_comma = s.rfind(',')
        last_dot = s.rfind('.')
        dec_pos = max(last_comma, last_dot)

        int_part = s[:dec_pos]
        frac_part = s[dec_pos+1:]

        # Tausenderzeichen aus dem Ganzzahlteil entfernen
        int_part = int_part.replace(',', '').replace('.', '')

        # Dezimalpunkt vereinheitlichen auf '.'
        s = f"{int_part}.{frac_part}"

    elif has_comma:
        # Nur Kommas vorhanden
        if s.count(',') > 1:
            # Letztes Komma als Dezimaltrenner interpretieren
            dec_pos = s.rfind(',')
            int_part = s[:dec_pos].replace(',', '').replace('.', '')
            frac_part = s[dec_pos+1:]
            s = f"{int_part}.{frac_part}"
        else:
            # Einfach: Komma = Dezimal, Punkte (falls vorhanden) = Tausender
            s = s.replace('.', '')
            s = s.replace(',', '.')

    elif has_dot:
        # Nur Punkte vorhanden
        if s.count('.') > 1:
            # Letzter Punkt als Dezimaltrenner
            dec_pos = s.rfind('.')
            int_part = s[:dec_pos].replace('.', '').replace(',', '')
            frac_part = s[dec_pos+1:]
            s = f"{int_part}.{frac_part}"
        # Bei genau einem Punkt: ist bereits Dezimalpunkt

    # Sonst: keine Separatoren → unverändert

    try:
        return Decimal(s)
    except InvalidOperation:
        return Decimal('0')
    
# -----------------------
# CSV Import – Vorschau, Mapping, Commit (Erweitert)
# -----------------------
def _parse_csv_with_mapping(content: str, replace_all: bool, mapping: dict | None) -> tuple[list, list, int]:
    """
    Liefert (preview_rows, headers, dup_count)
    - preview_rows: Liste von Dicts mit Feldern + Flags: is_duplicate, errors (list[str])
    - headers: Original-Header für UI/Mapping
    - dup_count: Anzahl potentieller Duplikate
    """
    reader = csv.reader(io.StringIO(content), delimiter=';')
    headers = next(reader, None)
    if not headers:
        raise ValueError(_('Leere CSV oder fehlender Header.'))

    # Mapping bestimmen
    if mapping is None:
        auto_map = compute_auto_mapping(headers) if IMPORT_ALLOW_MAPPING else {}
        if not auto_map and IMPORT_ALLOW_MAPPING:
            # Kein Auto-Mapping möglich → Benutzer muss manuell mappen
            mapping = {}
        else:
            mapping = auto_map

    # Felderzuordnung (Index oder None)
    idx_datum     = mapping.get('Datum')
    idx_vollgut   = mapping.get('Vollgut')
    idx_leergut   = mapping.get('Leergut')
    idx_einnahme  = mapping.get('Einnahme')
    idx_ausgabe   = mapping.get('Ausgabe')
    idx_bemerkung = mapping.get('Bemerkung')

    # Falls Mapping leer -> nur Header/Mapping anzeigen, keine Zeilen parsen
    preview_rows = []
    dup_count = 0

    # Duplikate in DB
    with engine.begin() as conn:
        existing = set()
        if not replace_all:
            existing = _fetch_existing_signature_set(conn)

    line_no = 1  # Header = 1
    for raw in reader:
        line_no += 1
        if not raw or all(not (c or '').strip() for c in raw):
            continue
        errors = []

        # Rohwerte nach Mapping
        v_datum     = raw[idx_datum]     if idx_datum     is not None and idx_datum     < len(raw) else ''
        v_vollgut   = raw[idx_vollgut]   if idx_vollgut   is not None and idx_vollgut   < len(raw) else ''
        v_leergut   = raw[idx_leergut]   if idx_leergut   is not None and idx_leergut   < len(raw) else ''
        v_einnahme  = raw[idx_einnahme]  if idx_einnahme  is not None and idx_einnahme  < len(raw) else ''
        v_ausgabe   = raw[idx_ausgabe]   if idx_ausgabe   is not None and idx_ausgabe   < len(raw) else ''
        v_bemerkung = raw[idx_bemerkung] if idx_bemerkung is not None and idx_bemerkung < len(raw) else ''

        # Validierung/Parsing
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

        # Duplikatprüfung nur, wenn keine Fehler vorliegen & nicht replace_all
        if not errors and not replace_all:
            sig = _signature(row_obj)
            if sig in existing:
                row_obj['is_duplicate'] = True
                dup_count += 1

        preview_rows.append(row_obj)

    return preview_rows, headers, dup_count

def compute_auto_mapping(headers: list[str]) -> dict:
    """Gibt Mapping {Kanonisch -> Index} zurück oder {} wenn nicht möglich."""
    mapping = {}
    norm_headers = [_norm(h) for h in headers]
    for canon in CANONICAL_FIELDS:
        candidates = { _norm(c) for c in HEADER_SYNONYMS.get(canon, set()) } | {_norm(canon)}
        idx = next((i for i, nh in enumerate(norm_headers) if nh in candidates), None)
        if idx is None:
            # Feld optional: Einnahme/Ausgabe/Bemerkung dürfen fehlen -> None heißt: als leer behandeln
            if canon in ('Einnahme','Ausgabe','Bemerkung'):
                mapping[canon] = None
                continue
            # Pflichtfelder Datum/Vollgut/Leergut fehlen -> Auto-Mapping scheitert
            return {}
        mapping[canon] = idx
    return mapping

def is_valid_money_str(s: str) -> bool:
    if s is None:
        return True  # leer = 0 ist ok
    if s.strip() == '':
        return True
    return bool(_money_re.match(s.strip()))

def try_int_strict(s: str, field: str) -> int:
    ss = (s or '').strip()
    if ss == '':
        return 0
    if not re.fullmatch(r'[+-]?\d+', ss):
        raise ValueError(_(f'Ungültige Ganzzahl für {field}: ') + ss)
    return int(ss)