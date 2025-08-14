from datetime import date, datetime
from decimal import Decimal, InvalidOperation

def today_ddmmyyyy():
    return date.today().strftime('%d.%m.%Y')

def parse_date_de_or_today(s: str | None) -> date:
    if not s or not s.strip():
        return date.today()
    return datetime.strptime(s.strip(), '%d.%m.%Y').date()

def format_date_de(d: date) -> str:
    return d.strftime('%d.%m.%Y')

def parse_money(s: str | None) -> Decimal:
    if s is None:
        return Decimal('0')
    s = s.strip()
    if not s:
        return Decimal('0')
    s = s.replace('.', '').replace(',', '.')
    try:
        return Decimal(s)
    except InvalidOperation:
        raise ValueError(f'Ungültige Zahl: {s}')

def format_eur_de(value: Decimal | float | int) -> str:
    d = Decimal(value).quantize(Decimal('0.01'))
    sign = '-' if d < 0 else ''
    d = abs(d)
    whole, frac = divmod(int(d * 100), 100)
    whole_str = f"{whole:,}".replace(',', '.')
    return f"{sign}{whole_str},{frac:02d} €"
