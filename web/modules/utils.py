from decimal import Decimal, InvalidOperation
import re
from flask_babel import gettext as _

def parse_money(s: str | None) -> Decimal:
    if s is None:
        return Decimal('0')
    s = s.strip()
    if not s:
        return Decimal('0')

    # Dynamisch übersetztes Währungssymbol entfernen
    currency_symbol = _('waehrung')
    s = s.replace(currency_symbol, '')

    # Weitere bekannte Symbole entfernen (optional)
    s = s.replace('€', '').replace('EUR', '')

    # Whitespace entfernen (inkl. NBSP, NNBSP, Narrow NBSP)
    s = re.sub(r'[\s\u00A0\u202F]', '', s)

    # Optionales führendes '+'
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
        raise ValueError(f'Ungültige Zahl: {s}')
