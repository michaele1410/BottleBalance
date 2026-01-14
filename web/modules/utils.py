from decimal import Decimal, InvalidOperation
import re
from flask_babel import gettext as _

def parse_money(s: str | None) -> Decimal:
    if s is None:
        return Decimal('0')
    s = s.strip()
    if not s:
        return Decimal('0')

    # Remove dynamically translated currency symbol
    currency_symbol = _('currency')
    s = s.replace(currency_symbol, '')

    # Remove other known symbols (optional)
    s = s.replace("_('currency')", '').replace("_('currency')", '')

    # Remove whitespace (including NBSP, NNBSP, Narrow NBSP)
    s = re.sub(r'[\s\u00A0\u202F]', '', s)

    # Optional leading '+'
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
        raise ValueError(f'Invalid number: {s}')
