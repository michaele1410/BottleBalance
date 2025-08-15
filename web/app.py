import os
import secrets
import ssl
import logging
import re
from logging.handlers import RotatingFileHandler
from smtplib import SMTP, SMTP_SSL, SMTPException
from email.message import EmailMessage
from datetime import datetime, date, timedelta
from decimal import Decimal, InvalidOperation
from flask_babel import Babel, gettext as _
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, abort, render_template_string
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash, check_password_hash
from smtp_check import check_smtp_configuration
from email.mime.text import MIMEText
from email.header import Header
from functools import wraps
import csv
import io
import time
import pyotp
import qrcode
import base64

import subprocess

import json

# PDF (ReportLab)
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm

# -----------------------
# Konfiguration
# -----------------------
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(24)
DB_HOST = os.getenv("DB_HOST", "bottlebalance-db")
DB_NAME = os.getenv("DB_NAME", "bottlebalance")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "admin")

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_TLS  = os.getenv("SMTP_TLS", "true").lower() in ("1","true","yes","on")
SMTP_SSL_ON = os.getenv("SMTP_SSL", "false").lower() in ("1","true","yes","on")
SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "10"))
SEND_TEST_MAIL = os.getenv("SEND_TEST_MAIL", "false").lower() in ("1", "true", "yes", "on")
                   
FROM_EMAIL = os.getenv("FROM_EMAIL") or SMTP_USER or "no-reply@example.com"
APP_BASE_URL = os.getenv("APP_BASE_URL") or "http://localhost:5000"

DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"
engine: Engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True)

# -----------------------
# Feature Switches (ENV)
# -----------------------
IMPORT_USE_PREVIEW   = os.getenv("IMPORT_USE_PREVIEW", "true").lower() in ("1","true","yes","on")
IMPORT_ALLOW_MAPPING = os.getenv("IMPORT_ALLOW_MAPPING", "true").lower() in ("1","true","yes","on")
IMPORT_ALLOW_DRYRUN  = os.getenv("IMPORT_ALLOW_DRYRUN", "true").lower() in ("1","true","yes","on")

# Optionaler API-Token für CI/Headless-Dry-Runs (Header: X-Import-Token)
IMPORT_API_TOKEN     = os.getenv("IMPORT_API_TOKEN")  # leer = kein Token erlaubt


# -----------------------
# Logging
# -----------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.getenv("LOG_FILE", "app.log")
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", "10485760"))  # 10 MB
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))

def configure_logging():
    root = logging.getLogger()
    if root.handlers:
        return
    root.setLevel(LOG_LEVEL)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    fh = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(sh)

configure_logging()
logger = logging.getLogger(__name__)

ROLES = {
    'Admin': {
        'entries:view', 'entries:add', 'entries:edit:any', 'entries:delete:any',
        'export:csv', 'export:pdf', 'import:csv', 'users:manage', 'audit:view'
    },
    'Manager': {
        'entries:view', 'entries:add', 'entries:edit:any', 'entries:delete:any',
        'export:csv', 'export:pdf', 'import:csv'
    },
    'Editor': {
        'entries:view', 'entries:add', 'entries:edit:own', 'entries:delete:own',
        'export:csv', 'export:pdf'
    },
    'Viewer': {
        'entries:view', 'export:csv', 'export:pdf'
    },
    'Auditor': {
        'entries:view', 'audit:view'
    }
}


def get_locale():
    user = current_user()
    if user:
        # robust: dict ODER Row-Objekt unterstützen
        pref = user.get('locale') if isinstance(user, dict) else getattr(user, 'locale', None)
        return (
            pref
            or session.get('language')
            or request.accept_languages.best_match(['de', 'en'])
        )
    # anonyme Nutzer: Session-Override oder Browser-Header
    return session.get('language') or request.accept_languages.best_match(['de', 'en'])

def get_timezone():
    user = current_user()
    if user:
        return user.get('timezone') if isinstance(user, dict) else getattr(user, 'timezone', None)
    return None  # oder ein Default wie 'Europe/Berlin'

app = Flask(__name__, static_folder='static')

app.config['BABEL_DEFAULT_LOCALE'] = 'de'
babel = Babel(app, locale_selector=get_locale, timezone_selector=get_timezone)

app.secret_key = SECRET_KEY


# For Error Pages
app.config["SUPPORT_EMAIL"] = os.getenv("SUPPORT_EMAIL", "support@example.com")
app.config["SUPPORT_URL"]   = os.getenv("SUPPORT_URL", "https://support.example.com")

# CSV Upload Limit
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB


# ROLES und set() global für Jinja2 verfügbar machen
#app.jinja_env.globals.update(ROLES=ROLES, set=set, current_user=current_user)

# -----------------------
# DB Init & Migration
# -----------------------
CREATE_TABLE_ENTRIES = """
CREATE TABLE IF NOT EXISTS entries (
    id SERIAL PRIMARY KEY,
    datum DATE NOT NULL,
    vollgut INTEGER NOT NULL DEFAULT 0,
    leergut INTEGER NOT NULL DEFAULT 0,
    einnahme NUMERIC(12,2) NOT NULL DEFAULT 0,
    ausgabe NUMERIC(12,2) NOT NULL DEFAULT 0,
    bemerkung TEXT,
    created_by INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_TABLE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_TABLE_AUDIT = """
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action TEXT NOT NULL,
    entry_id INTEGER,
    detail TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_TABLE_RESET = """
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

def migrate_columns(conn):
    # Best-effort migrations for added columns
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_codes TEXT"))
    conn.execute(text("ALTER TABLE entries ADD COLUMN IF NOT EXISTS created_by INTEGER"))
    conn.execute(text("ALTER TABLE entries ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW()"))
    conn.execute(text("ALTER TABLE entries ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT NOW()"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS locale TEXT"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone TEXT"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_preference TEXT DEFAULT 'system'"))

def init_db():
    with engine.begin() as conn:
        conn.execute(text(CREATE_TABLE_ENTRIES))
        conn.execute(text(CREATE_TABLE_USERS))
        conn.execute(text(CREATE_TABLE_AUDIT))
        conn.execute(text(CREATE_TABLE_RESET))
        migrate_columns(conn)
        # default admin
        res = conn.execute(text("SELECT COUNT(*) FROM users")).scalar_one()
        if res == 0:
            conn.execute(text(
                """
                INSERT INTO users (username, password_hash, role, active, must_change_password)
                VALUES (:u, :ph, 'Admin', TRUE, TRUE)
                """
            ), {'u': 'admin', 'ph': generate_password_hash('admin')})

_initialized = False

def init_db_with_retry(retries: int = 10, delay_seconds: float = 1.0):
    last_err = None
    for _ in range(retries):
        try:
            init_db()
            return
        except OperationalError as err:
            last_err = err
            time.sleep(delay_seconds)
    if last_err:
        raise last_err

@app.before_request
def _ensure_init_once():
    global _initialized
    if not _initialized:
        init_db_with_retry()
        # Basen-URL Hygienecheck (nur Hinweis-Log)
        if "localhost" in (APP_BASE_URL or "") or APP_BASE_URL.strip() == "":
            logging.warning(
                "APP_BASE_URL ist nicht produktionsgeeignet gesetzt (aktuell '%s'). "
                "Setze eine öffentlich erreichbare Basis-URL, damit Hinweise/Links in Mails korrekt sind.",
                APP_BASE_URL,
            )
        _initialized = True

# -----------------------
# Error Handling
#404 – Not Found: Für nicht existierende Routen.
#500 – Internal Server Error: Für unerwartete Serverfehler.
#403 – Forbidden: Für Zugriffsverletzungen.
#401 – Unauthorized: Für fehlende Authentifizierung.
# -----------------------

@app.errorhandler(401)
def unauthorized(e):
    # Optional eigenes Template errors/401.html, sonst 404er Template weiterverwenden
    return render_template('errors/401.html'), 401

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(413)
def request_entity_too_large(e):
    flash(_('Upload zu groß. Bitte kleinere CSV-Datei hochladen.'))
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(e):
    return render_template('errors/500.html'), 500


# -----------------------
# Helpers: Current user, RBAC
# -----------------------
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, username, email, role, active, must_change_password, totp_enabled, backup_codes, locale, timezone, theme_preference
            FROM users WHERE id=:id
        """), {'id': uid}).mappings().first()
    return dict(row) if row else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

def require_perms(*perms):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for('login'))
            allowed = ROLES.get(user['role'], set())
            if not all(p in allowed for p in perms):
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# --- CSRF Utils ---
def _ensure_csrf_token():
    tok = session.get('_csrf_token')
    if not tok:
        tok = secrets.token_urlsafe(32)
        session['_csrf_token'] = tok
    return tok

def csrf_token():
    # für Jinja: {{ csrf_token() }}
    return _ensure_csrf_token()

def require_csrf(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Nur für state-changing requests
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            session_tok = session.get('_csrf_token') or ''
            sent_tok = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token') or ''
            if not (session_tok and sent_tok) or not secrets.compare_digest(session_tok, sent_tok):
                abort(403)
        return fn(*args, **kwargs)
    return wrapper

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

# Utility to parse strict integers
def parse_int_strict(value: str):
    if value is None:
        return None
    s = str(value).strip()
    if s == '':
        return None
    # nur Ziffern erlauben (optional führendes +/-, hier nicht nötig)
    if not s.isdigit():
        return None
    return int(s)

# -----------------------
# Data Access
# -----------------------
def fetch_entries(search: str | None = None, date_from: date | None = None, date_to: date | None = None):
    where = []
    params = {}
    if search:
        where.append("(bemerkung ILIKE :q OR to_char(datum, 'DD.MM.YYYY') ILIKE :q)")
        params['q'] = f"%{search}%"
    if date_from:
        where.append("datum >= :df")
        params['df'] = date_from
    if date_to:
        where.append("datum <= :dt")
        params['dt'] = date_to
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    with engine.begin() as conn:
        rows = conn.execute(text(f"""
            SELECT id, datum, vollgut, leergut, einnahme, ausgabe, bemerkung, created_by
            FROM entries
            {where_sql}
            ORDER BY datum ASC, id ASC
        """), params).mappings().all()

    inventar = 0
    kassenbestand = Decimal('0.00')
    result = []
    for r in rows:
        voll = r['vollgut'] or 0
        leer = r['leergut'] or 0
        ein = Decimal(r['einnahme'] or 0)
        aus = Decimal(r['ausgabe'] or 0)
        inventar = inventar + (voll - leer)
        kassenbestand = (kassenbestand + ein - aus).quantize(Decimal('0.01'))
        result.append({
            'id': r['id'], 'datum': r['datum'], 'vollgut': voll, 'leergut': leer,
            'einnahme': ein, 'ausgabe': aus, 'bemerkung': r['bemerkung'] or '',
            'inventar': inventar, 'kassenbestand': kassenbestand, 'created_by': r['created_by']
        })
    return result

def current_totals():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT vollgut, leergut, einnahme, ausgabe FROM entries ORDER BY datum ASC, id ASC")).fetchall()
    inv = 0
    kas = Decimal('0.00')
    for (voll, leer, ein, aus) in rows:
        inv += (voll or 0) - (leer or 0)
        kas = (kas + Decimal(ein or 0) - Decimal(aus or 0)).quantize(Decimal('0.01'))
    return inv, kas

def log_action(user_id: int | None, action: str, entry_id: int | None, detail: str | None = None):
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO audit_log (user_id, action, entry_id, detail) VALUES (:u,:a,:e,:d)"),
                     {'u': user_id, 'a': action, 'e': entry_id, 'd': detail})

# -----------------------
# Auth & 2FA
# -----------------------
@app.get('/login')
def login():
    return render_template('login.html')

@app.post('/login')
@require_csrf
def login_post():
    username = (request.form.get('username') or '').strip()
    password = (request.form.get('password') or '').strip()
    with engine.begin() as conn:
        user = conn.execute(text("SELECT id, username, password_hash, role, active, must_change_password, totp_enabled FROM users WHERE username=:u"), {'u': username}).mappings().first()
    if not user or not check_password_hash(user['password_hash'], password) or not user['active']:
        flash(_('Login fehlgeschlagen.'))
        return redirect(url_for('login'))

    if user['totp_enabled']:
        session['pending_2fa_user_id'] = user['id']
        return redirect(url_for('login_2fa_get'))

    session['user_id'] = user['id']
    session['role'] = user['role']
    if user['must_change_password']:
        flash(_('Bitte Passwort ändern (erforderlich).'))
        return redirect(url_for('profile'))
    return redirect(url_for('index'))

@app.get('/2fa')
def login_2fa_get():
    if not session.get('pending_2fa_user_id'):
        return redirect(url_for('login'))
    return render_template('2fa.html')

@app.post('/2fa')
@require_csrf
def login_2fa_post():
    uid = session.get('pending_2fa_user_id')
    if not uid:
        return redirect(url_for('login'))

    code = (request.form.get('code') or '').strip()

    with engine.begin() as conn:
        user = conn.execute(text("""
            SELECT id, role, totp_secret, backup_codes
            FROM users WHERE id=:id
        """), {'id': uid}).mappings().first()

    if not user or not user['totp_secret']:
        flash(_('2FA nicht aktiv.'))
        return redirect(url_for('login'))

    totp = pyotp.TOTP(user['totp_secret'])

    # 1) TOTP
    if totp.verify(code, valid_window=1):
        session.pop('pending_2fa_user_id', None)
        session['user_id'] = user['id']
        session['role'] = user['role']
        return redirect(url_for('index'))

    # 2) Backup-Code (Hash oder Legacy-Klartext)
    bc_raw = user.get('backup_codes')
    if bc_raw:
        try:
            hashes = json.loads(bc_raw) if bc_raw.strip().startswith('[') else bc_raw.split(',')
        except Exception:
            hashes = bc_raw.split(',')

        matched_idx = None
        for i, h in enumerate(hashes):
            if (h and h.startswith('pbkdf2:') and check_password_hash(h, code)) or (h == code):
                matched_idx = i
                break

        if matched_idx is not None:
            del hashes[matched_idx]
            with engine.begin() as conn2:
                conn2.execute(text("UPDATE users SET backup_codes=:bc WHERE id=:id"),
                              {'bc': json.dumps(hashes), 'id': uid})
            session.pop('pending_2fa_user_id', None)
            session['user_id'] = user['id']
            session['role'] = user['role']
            flash(_('Backup-Code verwendet. Bitte neue Codes generieren.'))
            return redirect(url_for('index'))

    flash(_('Ungültiger 2FA-Code oder Backup-Code.'))
    return redirect(url_for('login_2fa_get'))

def generate_and_store_backup_codes(uid: int) -> list[str]:
    """Erzeugt 10 Backup-Codes, speichert nur Hashes in DB und liefert die Klartext-Codes zurück (einmalige Anzeige)."""
    codes = [secrets.token_hex(4) for _ in range(10)]
    hashes = [generate_password_hash(c) for c in codes]
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET backup_codes=:bc WHERE id=:id"),
                     {'bc': json.dumps(hashes), 'id': uid})
    return codes

@app.post('/profile/2fa/regen')
@login_required
@require_csrf
def regen_backup_codes():
    uid = session['user_id']
    codes = generate_and_store_backup_codes(uid)
    # Einmalige Anzeige im Profil
    session['new_backup_codes'] = codes
    flash(_('Neue Backup-Codes wurden generiert. Bitte sicher aufbewahren.'))
    return redirect(url_for('profile'))

@app.post('/logout')
@login_required
@require_csrf
def logout():
    uid = session.get('user_id')
    log_action(uid, 'logout', None, None)
    session.clear()
    return redirect(url_for('login'))


# -----------------------
# Profile & 2FA management
# -----------------------
@app.get('/profile')
@login_required
def profile():
    user = current_user()
    theme = user.get('theme_preference') if user else 'system'
    return render_template('profile.html', user=user, theme_preference=theme, ROLES=ROLES)


@app.post('/profile')
@login_required
@require_csrf
def profile_post():
    pwd = (request.form.get('password') or '').strip()
    pwd2 = (request.form.get('password2') or '').strip()
    email = (request.form.get('email') or '').strip()
    if pwd or pwd2:
        if len(pwd) < 8:
            flash(_('Passwort muss mindestens 8 Zeichen haben.'))
            return redirect(url_for('profile'))
        if pwd != pwd2:
            flash(_('Passwörter stimmen nicht überein.'))
            return redirect(url_for('profile'))
    uid = session['user_id']
    with engine.begin() as conn:
        if pwd:
            conn.execute(text("UPDATE users SET password_hash=:ph, must_change_password=FALSE, email=:em, updated_at=NOW() WHERE id=:id"),
                         {'ph': generate_password_hash(pwd), 'em': email or None, 'id': uid})
        else:
            conn.execute(text("UPDATE users SET email=:em, updated_at=NOW() WHERE id=:id"),
                         {'em': email or None, 'id': uid})
    flash(_('Profil aktualisiert.'))
    return redirect(url_for('index'))

@app.post('/profile/2fa/enable')
@login_required
@require_csrf
def enable_2fa():
    uid = session['user_id']
    secret = pyotp.random_base32()
    session['enroll_totp_secret'] = secret
    with engine.begin() as conn:
        username = conn.execute(text("SELECT username FROM users WHERE id=:id"), {'id': uid}).scalar_one()
    issuer = 'BottleBalance'
    otpauth = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    img = qrcode.make(otpauth)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    data_url = 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode('ascii')
    return render_template('2fa_enroll.html', qr_data_url=data_url, secret=secret)

@app.post('/profile/2fa/confirm')
@login_required
@require_csrf
def confirm_2fa():
    uid = session['user_id']
    secret = session.get('enroll_totp_secret')
    if not secret:
        flash(_('Kein 2FA-Setup aktiv.'))
        return redirect(url_for('profile'))
    code = (request.form.get('code') or '').strip()
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        flash(_('Ungültiger 2FA-Code.'))
        return redirect(url_for('enable_2fa'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET totp_secret=:s, totp_enabled=TRUE, updated_at=NOW() WHERE id=:id"),
                     {'s': secret, 'id': uid})
    session.pop('enroll_totp_secret', None)
    # neue Codes generieren und im Profil einmalig anzeigen
    codes = generate_and_store_backup_codes(uid)
    session['new_backup_codes'] = codes
    flash(_('2FA aktiviert.'))
    return redirect(url_for('profile'))

@app.post('/profile/2fa/disable')
@login_required
@require_csrf
def disable_2fa():
    uid = session['user_id']
    pwd = (request.form.get('password') or '').strip()
    with engine.begin() as conn:
        user = conn.execute(text("SELECT password_hash FROM users WHERE id=:id"), {'id': uid}).mappings().first()
    if not user or not check_password_hash(user['password_hash'], pwd):
        flash(_('Passwortprüfung fehlgeschlagen.'))
        return redirect(url_for('profile'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET totp_secret=NULL, totp_enabled=FALSE, updated_at=NOW() WHERE id=:id"), {'id': uid})
    flash(_('2FA deaktiviert.'))
    return redirect(url_for('profile'))

@app.post('/profile/theme')
@login_required
@require_csrf
def update_theme():
    theme = request.form.get('theme')
    if theme not in ['light', 'dark', 'system']:
        flash(_('Ungültige Theme-Auswahl.'))
        return redirect(url_for('profile'))
    uid = session.get('user_id')
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET theme_preference=:t, updated_at=NOW() WHERE id=:id"),
                     {'t': theme, 'id': uid})
    flash(_('Theme-Einstellung gespeichert.'))
    return redirect(url_for('profile'))

@app.post('/profile/preferences')
@login_required
@require_csrf
def update_preferences():
    uid = session.get('user_id')
    language = request.form.get('language')
    theme = request.form.get('theme') or 'system'


    if language not in ['de', 'en']:
        flash(_('Ungültige Sprache.'))
        return redirect(url_for('profile'))

    if theme not in ['light', 'dark', 'system']:
        flash(_('Ungültige Theme-Auswahl.'))
        return redirect(url_for('profile'))

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE users SET locale=:lang, theme_preference=:theme, updated_at=NOW() WHERE id=:id
        """), {'lang': language, 'theme': theme, 'id': uid})

    flash(_('Einstellungen gespeichert.'))
    return redirect(url_for('profile'))

@app.context_processor
def inject_theme():
    user = current_user()
    theme = user.get('theme_preference') if user else 'system'
    return {
        'theme_preference': theme,
        'current_user': current_user,
        'ROLES': ROLES,
        'set': set,
        'IMPORT_USE_PREVIEW': IMPORT_USE_PREVIEW,
        'IMPORT_ALLOW_MAPPING': IMPORT_ALLOW_MAPPING,
        'format_date_de': format_date_de,
        'format_eur_de': format_eur_de,
        'csrf_token': csrf_token,
    }

# -----------------------
# Password reset tokens
# -----------------------
def build_base_url():
    # bevorzuge APP_BASE_URL, fallback auf request.url_root
    try:
        from flask import request
        base = os.getenv("APP_BASE_URL") or request.url_root
    except RuntimeError:
        base = os.getenv("APP_BASE_URL") or "http://localhost:5000/"
    return base.rstrip("/") + "/"

def send_mail(to_email: str, subject: str, body: str) -> bool:
    if not SMTP_HOST:
        logger.warning("SMTP_HOST nicht gesetzt – Mailversand übersprungen (to=%s, subject=%s).", to_email, subject)
        return False
    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if SMTP_SSL_ON:
            context = ssl.create_default_context()
            with SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context) as s:
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as s:
                s.ehlo()
                if SMTP_TLS:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        logger.info("E-Mail erfolgreich gesendet (to=%s, subject=%s).", to_email, subject)
        return True
    except SMTPException as e:
        logger.error("SMTP-Fehler beim Mailversand (to=%s, subject=%s): %s", to_email, subject, e, exc_info=True)
        # optional zusätzlich ins Audit-Log schreiben (best effort)
        try:
            log_action(None, "email_error", None, f"to={to_email}, subject={subject}, err={e}")
        except Exception:
            logger.debug("Audit-Log für SMTP-Fehler konnte nicht geschrieben werden.", exc_info=True)
        return False

@app.post('/admin/users/<int:uid>/resetlink')
@login_required
@require_perms('users:manage')
@require_csrf
def users_reset_link(uid: int):
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(minutes=30)
    base = build_base_url()
    reset_url = f"{base}reset/{token}"
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (:u,:t,:e)"),
                     {'u': uid, 't': token, 'e': expires})
        email = conn.execute(text("SELECT email FROM users WHERE id=:id"), {'id': uid}).scalar_one()
    body = f"""
    Dein Passwort-Reset-Token lautet:

    {token}

    Dieser Token ist 30 Minuten gültig.
    Bitte gib ihn auf der Reset-Seite ein: {APP_BASE_URL}/reset
    """
    if email and SMTP_HOST:
        sent = send_mail(email, 'Passwort zurücksetzen', body)
        if sent:
            flash(_('Reset-Link per E-Mail versendet.'))
        else:
            flash(f"{_('Reset-Link:')} {reset_url}")
            logger.warning("E-Mail-Versand fehlgeschlagen – Token im UI angezeigt (user_id=%s).", uid)
    else:
        flash(f"{_('Reset-Link:')} {reset_url}")
        logger.warning("Keine E-Mail-Adresse oder kein SMTP_HOST – Token im UI angezeigt (user_id=%s).", uid)
    return redirect(url_for('users_list'))

# Reset-Formular (Token-only)
@app.get('/reset')
def reset_form():
    return render_template('reset.html')

@app.post('/reset')
@require_csrf
def reset_post():
    token = (request.form.get('token') or '').strip()
    pwd   = (request.form.get('password')  or '').strip()
    pwd2  = (request.form.get('password2') or '').strip()
    if not token:
        flash('Reset‑Token fehlt.')
        return redirect(url_for('reset_form'))
    if len(pwd) < 8 or pwd != pwd2:
        flash(_('Passwortanforderungen nicht erfüllt oder stimmen nicht überein.'))
        return redirect(url_for('reset_form'))
    with engine.begin() as conn:
        trow = conn.execute(
            text("SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token=:t"),
            {'t': token}
        ).mappings().first()
        if not trow or trow['used'] or trow['expires_at'] < datetime.utcnow():
            flash(_('Link ungültig oder abgelaufen.'))
            return redirect(url_for('login'))
        conn.execute(text("UPDATE users SET password_hash=:ph, must_change_password=FALSE, updated_at=NOW() WHERE id=:id"),
                     {'ph': generate_password_hash(pwd), 'id': trow['user_id']})
        conn.execute(text("UPDATE password_reset_tokens SET used=TRUE WHERE user_id=:uid AND used=FALSE"), {"uid": trow['user_id']})
    flash(_('Passwort aktualisiert. Bitte einloggen.'))
    return redirect(url_for('login'))

# -----------------------
# Admin: Users & Audit
# -----------------------
@app.get('/admin/users')
@login_required
@require_perms('users:manage')
def users_list():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT id, username, email, role, active, must_change_password, created_at FROM users ORDER BY username ASC")).mappings().all()
    return render_template('users.html', users=rows)

@app.post('/admin/users/add')
@login_required
@require_perms('users:manage')
@require_csrf
def users_add():
    username = (request.form.get('username') or '').strip()
    email = (request.form.get('email') or '').strip() or None
    role = (request.form.get('role') or 'Viewer').strip()
    pwd = (request.form.get('password') or '').strip()
    if not username:
        flash(_('Benutzername darf nicht leer sein.'))
        return redirect(url_for('users_list'))
    if role not in ROLES:
        flash(_('Ungültige Rolle.'))
        return redirect(url_for('users_list'))
    if len(pwd) < 8:
        flash(_('Passwort muss mindestens 8 Zeichen haben.'))
        return redirect(url_for('users_list'))
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO users (username, email, password_hash, role, active, must_change_password, theme_preference)
                VALUES (:u, :e, :ph, :r, TRUE, FALSE, 'system')
            """), {'u': username, 'e': email, 'ph': generate_password_hash(pwd), 'r': role})
        flash(_('Benutzer angelegt.'))
    except Exception as e:
        flash(f"{_('Fehler:')} {e}")
    return redirect(url_for('users_list'))

@app.post('/admin/users/<int:uid>/toggle')
@login_required
@require_perms('users:manage')
@require_csrf
def users_toggle(uid: int):
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET active = NOT active, updated_at=NOW() WHERE id=:id"), {'id': uid})
    return redirect(url_for('users_list'))

@app.post('/admin/users/<int:uid>/role')
@login_required
@require_perms('users:manage')
@require_csrf
def users_change_role(uid: int):
    role = (request.form.get('role') or 'Viewer').strip()
    if role not in ROLES:
        flash(_('Ungültige Rolle.'))
        return redirect(url_for('users_list'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET role=:r, updated_at=NOW() WHERE id=:id"), {'r': role, 'id': uid})
    return redirect(url_for('users_list'))

@app.post('/admin/users/<int:uid>/resetpw')
@login_required
@require_perms('users:manage')
@require_csrf
def users_reset_pw(uid: int):
    newpw = (request.form.get('password') or '').strip()
    if len(newpw) < 8:
        flash(_('Neues Passwort muss mindestens 8 Zeichen haben.'))
        return redirect(url_for('users_list'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET password_hash=:ph, must_change_password=FALSE, updated_at=NOW() WHERE id=:id"),
                     {'ph': generate_password_hash(newpw), 'id': uid})
    flash(_('Passwort gesetzt.'))
    return redirect(url_for('users_list'))

@app.get('/audit')
@login_required
@require_perms('audit:view')
def audit_list():
    q = (request.args.get('q') or '').strip()
    date_from = request.args.get('from')
    date_to = request.args.get('to')
    df = datetime.strptime(date_from, '%Y-%m-%d').date() if date_from else None
    dt = datetime.strptime(date_to, '%Y-%m-%d').date() if date_to else None
    params = {}
    where = []
    if q:
        where.append('(action ILIKE :q OR CAST(entry_id AS TEXT) ILIKE :q)')
        params['q'] = f"%{q}%"
    if df:
        where.append('DATE(created_at) >= :df')
        params['df'] = df
    if dt:
        where.append('DATE(created_at) <= :dt')
        params['dt'] = dt
    where_sql = ' WHERE ' + ' AND '.join(where) if where else ''
    with engine.begin() as conn:
        rows = conn.execute(text(f"""
            SELECT a.id, a.user_id, u.username, a.action, a.entry_id, a.detail, a.created_at
            FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
            {where_sql}
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT 500
        """), params).mappings().all()
    return render_template('audit.html', logs=rows)

@app.post('/admin/users/<int:uid>/delete')
@login_required
@require_perms('users:manage')
@require_csrf
def users_delete(uid: int):
    current_uid = session.get('user_id')
    if uid == current_uid:
        flash(_('Du kannst dich nicht selbst löschen.'))
        return redirect(url_for('users_list'))

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE id=:id"), {'id': uid})
    log_action(current_uid, 'users:delete', None, f"user_id={uid}")
    flash(_('Benutzer gelöscht.'))
    return redirect(url_for('users_list'))

# -----------------------
# CRUD & Index with filters
# -----------------------
@app.get('/')
@login_required
def index():
    q = (request.args.get('q') or '').strip()
    date_from_s = request.args.get('from')
    date_to_s = request.args.get('to')
    df = datetime.strptime(date_from_s, '%Y-%m-%d').date() if date_from_s else None
    dt = datetime.strptime(date_to_s, '%Y-%m-%d').date() if date_to_s else None

    entries = fetch_entries(q or None, df, dt)
    inv, kas = current_totals()

    # Serien
    series_inv = [e['inventar'] for e in entries]
    series_kas = [float(e['kassenbestand']) for e in entries]

    # Summen im Filterbereich
    finv = entries[-1]['inventar'] if entries else 0
    fkas = entries[-1]['kassenbestand'] if entries else Decimal('0')

    role = session.get('role')
    allowed = ROLES.get(role, set())

    return render_template('index.html',
        entries=entries,
        inv_aktuell=inv, kas_aktuell=kas,
        filter_inv=finv, filter_kas=fkas,
        default_date=today_ddmmyyyy(),
        format_eur_de=format_eur_de, format_date_de=format_date_de,
        can_add=('entries:add' in allowed),
        can_export_csv=('export:csv' in allowed),
        can_export_pdf=('export:pdf' in allowed),
        can_import=('import:csv' in allowed),
        role=role, series_inv=series_inv, series_kas=series_kas
    )

@app.post('/add')
@login_required
@require_perms('entries:add')
@require_csrf
def add():
    user = current_user()
    try:
        datum = parse_date_de_or_today(request.form.get('datum'))
        vollgut = int((request.form.get('vollgut') or '0').strip() or '0')
        leergut = int((request.form.get('leergut') or '0').strip() or '0')
        einnahme = parse_money(request.form.get('einnahme') or '0')
        ausgabe = parse_money(request.form.get('ausgabe') or '0')
        bemerkung = (request.form.get('bemerkung') or '').strip()
    except Exception as e:
        flash(f"{_('Eingabefehler:')} {e}")
        return redirect(url_for('index'))
    with engine.begin() as conn:
        res = conn.execute(text("""
            INSERT INTO entries (datum, vollgut, leergut, einnahme, ausgabe, bemerkung, created_by)
            VALUES (:datum,:vollgut,:leergut,:einnahme,:ausgabe,:bemerkung,:cb)
            RETURNING id
        """), {'datum': datum, 'vollgut': vollgut, 'leergut': leergut, 'einnahme': str(einnahme), 'ausgabe': str(ausgabe), 'bemerkung': bemerkung, 'cb': user['id']})
        new_id = res.scalar_one()
    log_action(user['id'], 'entries:add', new_id, None)
    return redirect(url_for('index'))

@app.get('/edit/<int:entry_id>')
@login_required
def edit(entry_id: int):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, datum, vollgut, leergut, einnahme, ausgabe, bemerkung, created_by FROM entries WHERE id=:id"), {'id': entry_id}).mappings().first()
    if not row:
        flash(_('Eintrag nicht gefunden.'))
        return redirect(url_for('index'))
    # RBAC
    allowed = ROLES.get(session.get('role'), set())
    if 'entries:edit:any' not in allowed:
        user = current_user()
        if not user or row['created_by'] != user['id'] or 'entries:edit:own' not in allowed:
            abort(403)
    data = {
        'id': row['id'], 'datum': format_date_de(row['datum']), 'vollgut': row['vollgut'], 'leergut': row['leergut'],
        'einnahme': str(Decimal(row['einnahme'] or 0)).replace('.', ','), 'ausgabe': str(Decimal(row['ausgabe'] or 0)).replace('.', ','),
        'bemerkung': row['bemerkung'] or ''
    }
    return render_template('edit.html', data=data)

@app.post('/edit/<int:entry_id>')
@login_required
@require_csrf
def edit_post(entry_id: int):
    with engine.begin() as conn:
        row = conn.execute(text('SELECT created_by FROM entries WHERE id=:id'), {'id': entry_id}).mappings().first()
    if not row:
        abort(404)
    allowed = ROLES.get(session.get('role'), set())
    if 'entries:edit:any' not in allowed:
        user = current_user()
        if not user or row['created_by'] != user['id'] or 'entries:edit:own' not in allowed:
            abort(403)
    try:
        datum = parse_date_de_or_today(request.form.get('datum'))
        vollgut = int((request.form.get('vollgut') or '0').strip() or '0')
        leergut = int((request.form.get('leergut') or '0').strip() or '0')
        einnahme = parse_money(request.form.get('einnahme') or '0')
        ausgabe = parse_money(request.form.get('ausgabe') or '0')
        bemerkung = (request.form.get('bemerkung') or '').strip()
    except Exception as e:
        flash(f"{_('Eingabefehler:')} {e}")
        return redirect(url_for('edit', entry_id=entry_id))
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE entries SET datum=:datum, vollgut=:vollgut, leergut=:leergut, einnahme=:einnahme, ausgabe=:ausgabe, bemerkung=:bemerkung, updated_at=NOW()
            WHERE id=:id
        """), {'id': entry_id, 'datum': datum, 'vollgut': vollgut, 'leergut': leergut, 'einnahme': str(einnahme), 'ausgabe': str(ausgabe), 'bemerkung': bemerkung})
    log_action(session.get('user_id'), 'entries:edit', entry_id, None)
    return redirect(url_for('index'))

@app.post('/delete/<int:entry_id>')
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
    return redirect(url_for('index'))

# -----------------------
# Export/Import
# -----------------------
@app.get('/export')
@login_required
@require_perms('export:csv')
def export_csv():
    q = (request.args.get('q') or '').strip()
    df = request.args.get('from')
    dt = request.args.get('to')
    date_from = datetime.strptime(df, '%Y-%m-%d').date() if df else None
    date_to = datetime.strptime(dt, '%Y-%m-%d').date() if dt else None
    entries = fetch_entries(q or None, date_from, date_to)
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', lineterminator='\n')
    writer.writerow(['Datum','Vollgut','Leergut','Inventar','Einnahme','Ausgabe','Kassenbestand','Bemerkung'])
    for e in entries:
        writer.writerow([
            format_date_de(e['datum']), e['vollgut'], e['leergut'], e['inventar'],
            str(e['einnahme']).replace('.', ','), str(e['ausgabe']).replace('.', ','), str(e['kassenbestand']).replace('.', ','), e['bemerkung']
        ])
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))
    mem.seek(0)
    filename = f"bottlebalance_export_{date.today().strftime('%Y%m%d')}.csv"
    return send_file(mem, as_attachment=True, download_name=filename, mimetype='text/csv')

@app.post('/import')
@login_required
@require_perms('import:csv')
@require_csrf
def import_csv():
    file = request.files.get('file')
    replace_all = request.form.get('replace_all') == 'on'
    if not file or file.filename == '':
        flash(_('Bitte eine CSV-Datei auswählen.'))
        return redirect(url_for('index'))
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
            return redirect(url_for('index'))
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
        flash(f"{_('Import successfull:')} {len(rows_to_insert)} {_('rows adopted.')}")
    except Exception as e:
        flash(f"{_('Import fehlgeschlagen:')} {e}")
    return redirect(url_for('index'))

# -----------------------
# CSV Import – Vorschau & Commit (NEU)
# -----------------------
from uuid import uuid4
from typing import List, Tuple

def _parse_csv_file_storage(file_storage):
    content = file_storage.read().decode('utf-8-sig')
    reader = csv.reader(io.StringIO(content), delimiter=';')
    headers = next(reader, None)
    # Robustheit: Header-Zeile prüfen und ggf. splitten
    if headers and len(headers) == 1 and ';' in headers[0]:
        headers = headers[0].split(';')

    expected = ['Datum','Vollgut','Leergut','Inventar','Einnahme','Ausgabe','Kassenbestand','Bemerkung']
    alt_expected = ['Datum','Vollgut','Leergut','Einnahme','Ausgabe','Bemerkung']
    if headers is None or [h.strip() for h in headers] not in (expected, alt_expected):
        raise ValueError(_('CSV-Header entspricht nicht dem erwarteten Format.'))

    rows = []
    for row in reader:
        if not row or all(not (c or '').strip() for c in row):
            continue  # leere Zeilen überspringen
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
        rows.append({
            'datum': datum,
            'vollgut': vollgut,
            'leergut': leergut,
            'einnahme': str(einnahme),
            'ausgabe': str(ausgabe),
            'bemerkung': bemerkung
        })
    return rows

def _fetch_existing_signature_set(conn) -> set[Tuple]:
    """
    Liefert eine Signaturmenge aller existierenden Datensätze
    für schnelle Duplikat-Erkennung (exakt über alle importrelevanten Felder).
    """
    existing = conn.execute(text("""
        SELECT datum, COALESCE(vollgut,0), COALESCE(leergut,0),
               COALESCE(einnahme,0), COALESCE(ausgabe,0), COALESCE(bemerkung,'')
        FROM entries
    """)).fetchall()
    return set((r[0], int(r[1]), int(r[2]), str(Decimal(r[3])), str(Decimal(r[4])), r[5] or '') for r in existing)

def _signature(row: dict) -> Tuple:
    return (
        row['datum'],
        int(row['vollgut']),
        int(row['leergut']),
        str(Decimal(row['einnahme'] or 0)),
        str(Decimal(row['ausgabe'] or 0)),
        row['bemerkung'] or ''
    )

#@app.post('/import/preview')
#@login_required
#@require_perms('import:csv')
#def import_preview():
#    file = request.files.get('file')
#    replace_all = request.form.get('replace_all') == 'on'
#    if not file or file.filename == '':
#        flash(_('Bitte eine CSV-Datei auswählen.'))
#        return redirect(url_for('index'))
#
#    try:
#        rows_to_insert = _parse_csv_file_storage(file)
#        with engine.begin() as conn:
#            existing = _fetch_existing_signature_set(conn)
#
#        preview = []
#        dup_count = 0
#        for r in rows_to_insert:
#            sig = _signature(r)
#            is_dup = (sig in existing) and not replace_all
#            preview.append({**r, 'is_duplicate': is_dup})
#            if is_dup:
#                dup_count += 1
#
#       token = str(uuid4())
#        # im Session-Speicher für Commit vorhalten
#        session.setdefault('import_previews', {})
#        session['import_previews'][token] = {
#            'rows': rows_to_insert,
#            'replace_all': replace_all,
#            'created_at': time.time()
#        }
#        session.modified = True
#
#        return render_template(
#            'import_preview.html',
#            preview_rows=preview,
#            token=token,
#            replace_all=replace_all,
#            dup_count=dup_count,
#            total=len(preview),
#        )
#    except Exception as e:
#        logger.exception("Import-Preview fehlgeschlagen: %s", e)
#        flash(f"{_('Vorschau fehlgeschlagen:')} {e}")
#        return redirect(url_for('index'))

#@app.post('/import/commit')
#@login_required
#@require_perms('import:csv')
#def import_commit():
#    token = (request.form.get('token') or '').strip()
#    mode = (request.form.get('mode') or 'skip_dups').strip()  # 'skip_dups' | 'insert_all'
#    if not token or 'import_previews' not in session or token not in session['import_previews']:
#        flash(_('Vorschau abgelaufen oder nicht gefunden.'))
#        return redirect(url_for('index'))

 #   stash = session['import_previews'].pop(token, None)
 #   session.modified = True
 #   if not stash:
 #       flash(_('Vorschau abgelaufen oder bereits verwendet.'))
 #       return redirect(url_for('index'))

  #  rows_to_insert = stash['rows']
  #  replace_all = bool(stash.get('replace_all'))

#    try:
#        inserted = 0
#        with engine.begin() as conn:
#            if replace_all:
#                conn.execute(text('DELETE FROM entries'))

#            if mode == 'skip_dups' and not replace_all:
#                existing = _fetch_existing_signature_set(conn)
#            else:
#                existing = set()

#            for r in rows_to_insert:
#                if not replace_all and mode == 'skip_dups' and _signature(r) in existing:
#                    continue
#                conn.execute(text("""
#                    INSERT INTO entries (datum, vollgut, leergut, einnahme, ausgabe, bemerkung)
#                    VALUES (:datum,:vollgut,:leergut,:einnahme,:ausgabe,:bemerkung)
#                """), r)
#                inserted += 1

#        log_action(session.get('user_id'), 'import:csv', None,
#                   f"commit: inserted={inserted}, replace_all={replace_all}, mode={mode}")
#        flash(_(f'Import erfolgreich: {inserted} Zeilen übernommen.'))
#        return redirect(url_for('index'))
#    except Exception as e:
#        logger.exception("Import-Commit fehlgeschlagen: %s", e)
#        flash(f"{_('Import fehlgeschlagen:')} {e}")
#        return redirect(url_for('index'))

@app.get('/import/sample')
@login_required
@require_perms('import:csv')
def import_sample():
    """
    Liefert eine Beispiel-CSV im langen Format mit allen Spalten.
    """
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', lineterminator='\n')
    writer.writerow(['Datum','Vollgut','Leergut','Inventar','Einnahme','Ausgabe','Kassenbestand','Bemerkung'])
    today = date.today()
    samples = [
        (today - timedelta(days=4), 10, 0, 'Getränkeeinkauf'),
        (today - timedelta(days=3), 0, 2, 'Leergutabgabe'),
        (today - timedelta(days=2), 0, 0, 'Kasse Start'),
        (today - timedelta(days=1), 5, 0, 'Nachkauf'),
        (today, 0, 1, 'Entnahme'),
    ]
    inv = 0
    kas = Decimal('0.00')
    for d, voll, leer, note in samples:
        inv += (voll - leer)
        einnahme = Decimal('12.50') if voll else Decimal('0')
        ausgabe = Decimal('1.20') if leer else Decimal('0')
        kas = (kas + einnahme - ausgabe).quantize(Decimal('0.01'))
        writer.writerow([
            d.strftime('%d.%m.%Y'), voll, leer, inv,
            str(einnahme).replace('.', ','), str(ausgabe).replace('.', ','), str(kas).replace('.', ','),
            note
        ])
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name='bottlebalance_beispiel.csv', mimetype='text/csv')

# -----------------------
# CSV Import – Vorschau, Mapping, Commit (Erweitert)
# -----------------------
from uuid import uuid4
from typing import Tuple

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


@app.post('/import/preview')
@login_required
@require_perms('import:csv')
@require_csrf
def import_preview():
    """
    Zeigt die Vorschau für den CSV-Import mit Auto-Mapping und manuellem Remapping.
    - Erster Aufruf: Datei wird gelesen, Auto-Mapping ermittelt, CSV in /tmp abgelegt.
    - Remap: Mapping-Indices aus dem Formular übernehmen, CSV aus /tmp erneut parsen.
    """
    # Falls Vorschau via Feature-Switch deaktiviert ist -> Legacy-Import verwenden
    if not IMPORT_USE_PREVIEW:
        return import_csv()

    replace_all = request.form.get('replace_all') == 'on'
    token = (request.form.get('token') or '').strip()
    is_remap = request.form.get('remap') == '1'

    # ---------- REMAP-PFAD (CSV erneut parsen mit manuellem Mapping) ----------
    if is_remap and token:
        stash = session.get('import_previews', {}).get(token)
        if not stash:
            flash(_('Vorschau abgelaufen oder nicht gefunden.'))
            return redirect(url_for('index'))

        tmp_path = stash.get('csv_path')
        if not tmp_path or not os.path.exists(tmp_path):
            flash(_('CSV-Datei nicht gefunden.'))
            return redirect(url_for('index'))

        # CSV laden
        try:
            with open(tmp_path, 'r', encoding='utf-8-sig') as f:
                content = f.read()
        except Exception as e:
            logger.exception("CSV lesen fehlgeschlagen: %s", e)
            flash(_('CSV konnte nicht gelesen werden.'))
            return redirect(url_for('index'))

        # Mapping aus Formular übernehmen
        if IMPORT_ALLOW_MAPPING:
            def _opt_int(v):
                return int(v) if (v not in (None, '', '__none__')) else None
            def _get(name):
                return request.form.get(f'map_{name.lower()}')
            mapping = {
                'Datum':     _opt_int(_get('Datum')),
                'Vollgut':   _opt_int(_get('Vollgut')),
                'Leergut':   _opt_int(_get('Leergut')),
                'Einnahme':  _opt_int(_get('Einnahme')),
                'Ausgabe':   _opt_int(_get('Ausgabe')),
                'Bemerkung': _opt_int(_get('Bemerkung')),
            }
        else:
            mapping = None

        try:
            preview_rows, headers, dup_count = _parse_csv_with_mapping(content, replace_all, mapping)
        except Exception as e:
            logger.exception("Import-Preview (remap) fehlgeschlagen: %s", e)
            flash(f"{_('Vorschau fehlgeschlagen:')} {e}")
            return redirect(url_for('index'))

        # Stash aktualisieren
        session['import_previews'][token]['mapping'] = mapping
        session['import_previews'][token]['replace_all'] = replace_all
        session.modified = True

        return render_template(
            'import_preview.html',
            preview_rows=preview_rows,
            token=token,
            replace_all=replace_all,
            dup_count=dup_count,
            total=len(preview_rows),
            headers=headers,
            allow_mapping=IMPORT_ALLOW_MAPPING,
            mapping=mapping  # <- für Auto-Vorauswahl in den Dropdowns
        )

    # ---------- ERSTER UPLOAD (Datei kommt vom Client) ----------
    file = request.files.get('file')
    if not file or file.filename == '':
        flash(_('Bitte eine CSV-Datei auswählen.'))
        return redirect(url_for('index'))

    try:
        # Inhalt einlesen
        content = file.read().decode('utf-8-sig')

        # Vorschau ohne explizites Mapping -> Auto-Mapping im Parser
        preview_rows, headers, dup_count = _parse_csv_with_mapping(content, replace_all, mapping=None)

        # Token erzeugen
        token = str(uuid4())

        # CSV serverseitig in /tmp ablegen (keine großen Sessions)
        tmp_dir = '/tmp'
        os.makedirs(tmp_dir, exist_ok=True)
        tmp_path = os.path.join(tmp_dir, f"bb_import_{token}.csv")
        with open(tmp_path, 'w', encoding='utf-8-sig') as f:
            f.write(content)

        # Auto-Mapping separat berechnen und für die UI im Stash speichern
        auto_map = compute_auto_mapping(headers) if IMPORT_ALLOW_MAPPING else {}
        session.setdefault('import_previews', {})
        session['import_previews'][token] = {
            'csv_path': tmp_path,
            'replace_all': replace_all,
            'created_at': time.time(),
            'mapping': auto_map if auto_map else None
        }
        session.modified = True

        return render_template(
            'import_preview.html',
            preview_rows=preview_rows,
            token=token,
            replace_all=replace_all,
            dup_count=dup_count,
            total=len(preview_rows),
            headers=headers,
            allow_mapping=IMPORT_ALLOW_MAPPING,
            mapping=session['import_previews'][token].get('mapping')  # <- Auto-Vorauswahl
        )
    except Exception as e:
        logger.exception("Import-Preview fehlgeschlagen: %s", e)
        flash(f"{_('Vorschau fehlgeschlagen:')} {e}")
        return redirect(url_for('index'))


@app.post('/import/commit')
@login_required
@require_perms('import:csv')
@require_csrf
def import_commit():
    token = (request.form.get('token') or '').strip()
    mode = (request.form.get('mode') or 'skip_dups').strip()  # 'skip_dups' | 'insert_all'
    import_invalid = request.form.get('import_invalid') == 'on'

    if not token or 'import_previews' not in session or token not in session['import_previews']:
        flash(_('Vorschau abgelaufen oder nicht gefunden.'))
        return redirect(url_for('index'))

    stash = session['import_previews'].pop(token, None)
    session.modified = True
    if not stash:
        flash(_('Vorschau abgelaufen oder bereits verwendet.'))
        return redirect(url_for('index'))

    tmp_path = stash.get('csv_path')
    replace_all = bool(stash.get('replace_all'))
    mapping = stash.get('mapping')

    if not tmp_path or not os.path.exists(tmp_path):
        flash(_('CSV-Datei nicht gefunden.'))
        return redirect(url_for('index'))

    try:
        with open(tmp_path, 'r', encoding='utf-8-sig') as f:
            content = f.read()

        preview_rows, _headers, _dup = _parse_csv_with_mapping(content, replace_all, mapping)

        inserted = 0
        with engine.begin() as conn:
            if replace_all:
                conn.execute(text('DELETE FROM entries'))

            existing = set()
            if not replace_all and mode == 'skip_dups':
                existing = _fetch_existing_signature_set(conn)

            for r in preview_rows:
                if (r['errors'] and not import_invalid):
                    continue
                if not replace_all and mode == 'skip_dups' and not r['errors']:
                    if _signature(r) in existing:
                        continue
                conn.execute(text("""
                    INSERT INTO entries (datum, vollgut, leergut, einnahme, ausgabe, bemerkung)
                    VALUES (:datum,:vollgut,:leergut,:einnahme,:ausgabe,:bemerkung)
                """), {k: r[k] for k in ('datum','vollgut','leergut','einnahme','ausgabe','bemerkung')})
                inserted += 1

        # Temporäre Datei löschen
        try:
            os.remove(tmp_path)
        except Exception:
            pass

        log_action(session.get('user_id'), 'import:csv', None,
                   f"commit: inserted={inserted}, replace_all={replace_all}, mode={mode}, import_invalid={import_invalid}")
        flash(_(f'Import erfolgreich: {inserted} Zeilen übernommen.'))
        return redirect(url_for('index'))
    except Exception as e:
        logger.exception("Import-Commit fehlgeschlagen: %s", e)
        flash(f"{_('Import fehlgeschlagen:')} {e}")
        return redirect(url_for('index'))

# -----------------------
# Hilfsfunktionen CSV Import
# -----------------------
# --- Strikte Parser/Validatoren für die Vorschau ---
def parse_date_de_strict(s: str) -> date:
    s = (s or '').strip()
    if not s:
        raise ValueError(_('Datum fehlt'))
    try:
        return datetime.strptime(s, '%d.%m.%Y').date()
    except Exception:
        raise ValueError(_('Ungültiges Datum (erwartet TT.MM.JJJJ): ') + s)

_money_re = re.compile(r'^\s*[+-]?\d{1,3}([.,]\d{3})*([.,]\d{1,2})?\s*(€)?\s*$')
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

# --- CSV Header Normalisierung & Auto-Mapping ---
def _norm(h: str) -> str:
    return re.sub(r'[^a-z0-9]', '', (h or '').strip().lower())

# Kanonische Zielfelder
CANONICAL_FIELDS = ['Datum','Vollgut','Leergut','Einnahme','Ausgabe','Bemerkung']

# Synonyme (frei erweiterbar)
HEADER_SYNONYMS = {
    'Datum':     {'datum','date','ttmmjjjj','tt.mm.jjjj','day','tag'},
    'Vollgut':   {'vollgut','voll','in','eingang','bestandszugang','bottlesin'},
    'Leergut':   {'leergut','leer','out','ausgang','bestandsabgang','bottlesout','pfand'},
    'Einnahme':  {'einnahme','einzahlung','revenue','income','cashin'},
    'Ausgabe':   {'ausgabe','auszahlung','expense','cost','cashout'},
    'Bemerkung': {'bemerkung','notiz','kommentar','comment','note','description','desc'},
    # Optional ignorierbare Spalten:
    # 'Inventar', 'Kassenbestand'
}

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


@app.post('/api/import/dry-run')
def api_import_dry_run():
    if not IMPORT_ALLOW_DRYRUN:
        return {'error': 'dry-run disabled'}, 403

    # Auth …
    token = request.headers.get('X-Import-Token')
    authed = False
    if IMPORT_API_TOKEN and token == IMPORT_API_TOKEN:
        authed = True
    else:
        if session.get('user_id'):
            allowed = ROLES.get(session.get('role'), set())
            authed = 'import:csv' in allowed
    if not authed:
        return {'error': 'unauthorized'}, 401

    replace_all = (request.args.get('replace_all') == '1') or (request.form.get('replace_all') == 'on')

    # NEU: mapping vorinitialisieren
    content = None
    mapping = None
    # Datenquellen …
    if 'file' in request.files and request.files['file'].filename:
        content = request.files['file'].read().decode('utf-8-sig')
    elif request.is_json:
        body = request.get_json(force=True, silent=True) or {}
        if 'csv' in body and isinstance(body['csv'], str):
            import base64 as _b64
            c = body['csv']
            try:
                try:
                    content = _b64.b64decode(c).decode('utf-8-sig')
                except Exception:
                    content = c
            except Exception:
                return {'error':'invalid csv payload'}, 400
        elif 'rows' in body and isinstance(body['rows'], list):
            si = io.StringIO()
            w = csv.writer(si, delimiter=';', lineterminator='\n')
            w.writerow(['Datum','Vollgut','Leergut','Einnahme','Ausgabe','Bemerkung'])
            for r in body['rows']:
                w.writerow([
                    r.get('Datum',''),
                    r.get('Vollgut',''),
                    r.get('Leergut',''),
                    r.get('Einnahme',''),
                    r.get('Ausgabe',''),
                    r.get('Bemerkung',''),
                ])
            content = si.getvalue()
        mapping = body.get('mapping')
    else:
        return {'error':'no input'}, 400

    try:
        preview_rows, headers, dup_count = _parse_csv_with_mapping(content, replace_all, mapping if IMPORT_ALLOW_MAPPING else None)
        total = len(preview_rows)
        invalid = sum(1 for r in preview_rows if r['errors'])
        valid   = total - invalid
        duplicates = dup_count

        # Response
        return {
            'summary': {
                'total': total,
                'valid': valid,
                'invalid': invalid,
                'duplicates': duplicates,
                'replace_all': replace_all,
            },
            'headers': headers,
            'rows': [
                {
                    'line_no': r['line_no'],
                    'datum': r['datum'].strftime('%Y-%m-%d') if r['datum'] else None,
                    'vollgut': r['vollgut'],
                    'leergut': r['leergut'],
                    'einnahme': r['einnahme'],
                    'ausgabe': r['ausgabe'],
                    'bemerkung': r['bemerkung'],
                    'is_duplicate': r['is_duplicate'],
                    'errors': r['errors'],
                } for r in preview_rows
            ]
        }, 200
    except Exception as e:
        logger.exception("Dry-Run failed: %s", e)
        return {'error': str(e)}, 400

# -----------------------
# PDF Export with optional logo
# -----------------------
@app.get('/export/pdf')
@login_required
@require_perms('export:pdf')
def export_pdf():
    q = (request.args.get('q') or '').strip()
    df = request.args.get('from')
    dt = request.args.get('to')
    date_from = datetime.strptime(df, '%Y-%m-%d').date() if df else None
    date_to = datetime.strptime(dt, '%Y-%m-%d').date() if dt else None
    entries = fetch_entries(q or None, date_from, date_to)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4),
        leftMargin=15, rightMargin=15, topMargin=15, bottomMargin=15
    )
    styles = getSampleStyleSheet()
    story = []

    logo_path = os.path.join(app.root_path, 'static', 'images/logo.png')
    if os.path.exists(logo_path):
        story.append(RLImage(logo_path, width=40*mm, height=12*mm))
        story.append(Spacer(1, 6))

    # Titel in echtem HTML (ReportLab-Paragraph versteht <b>…</b>)
    story.append(Paragraph(f"<b>{_('BottleBalance – Export')}</b>", styles['Title']))
    story.append(Spacer(1, 6))

    # Tabelle
    data = [[
        _('Datum'), _('Vollgut'), _('Leergut'), _('Inventar'),
        _('Einnahme'), _('Ausgabe'), _('Kassenbestand'), _('Bemerkung')
    ]]
    for e in entries:
        data.append([
            format_date_de(e['datum']),
            str(e['vollgut']),
            str(e['leergut']),
            str(e['inventar']),
            str(e['einnahme']).replace('.', ',') + " " + _('waehrung'),
            str(e['ausgabe']).replace('.', ',') + " " + _('waehrung'),
            str(e['kassenbestand']).replace('.', ',') + " " + _('waehrung'),
            Paragraph(e['bemerkung'] or '', styles['Normal'])
        ])

    col_widths = [25*mm, 25*mm, 25*mm, 25*mm, 30*mm, 30*mm, 30*mm, 110*mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f3f5')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#212529')),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('ALIGN', (1,1), (3,-1), 'RIGHT'),
        ('ALIGN', (4,1), (6,-1), 'RIGHT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fcfcfd')]),
        ('GRID', (0,0), (-1,-1), 0.25, colors.HexColor('#dee2e6')),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(table)

    doc.build(story)
    buffer.seek(0)
    filename = f"bottlebalance_{date.today().strftime('%Y%m%d')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')

@app.post('/profile/lang')
@login_required
@require_csrf
def set_language():
    lang = request.form.get('language')
    if lang in ['de', 'en']:
        session['language'] = lang
        # optional: persistent per-user preference
        uid = session.get('user_id')
        if uid:
            with engine.begin() as conn:
                conn.execute(text("UPDATE users SET locale=:lang, updated_at=NOW() WHERE id=:id"),
                             {'lang': lang, 'id': uid})
        flash(_('Sprache geändert.'))
    return redirect(url_for('profile'))

# -----------------------
# DB Export url/admin/export-db
# -----------------------

@app.get('/admin/export-db')
@login_required
@require_perms('users:manage')  # oder eigene Permission wie 'db:export'
def admin_export_page():
    return render_template('admin_export.html')

@app.post('/admin/export-db')
@login_required
@require_perms('users:manage')
@require_csrf
def admin_export_dump():
    dump_file = "/tmp/bottlebalance_dump.sql"
    db_user = DB_USER
    db_name = DB_NAME
    db_host = DB_HOST
    db_pass = DB_PASS

    # Passwort für pg_dump setzen
    env = os.environ.copy()
    env["PGPASSWORD"] = db_pass

    try:
        with open(dump_file, "w") as f:
            subprocess.run([
                "pg_dump",
                "-U", db_user,
                "-h", db_host,
                db_name
            ], stdout=f, env=env, check=True)

        # Audit-Log-Eintrag
        log_action(session.get('user_id'), 'db:export', None, f'Dump von {db_name} erzeugt')

        flash(_('Datenbank-Dump erfolgreich erzeugt.'))
        return send_file(dump_file, as_attachment=True, download_name="bottlebalance_dump.sql")

    except subprocess.CalledProcessError as e:
        flash(_('Fehler beim Datenbank-Dump: ') + str(e))
        log_action(session.get('user_id'), 'db:export:error', None, f'Dump fehlgeschlagen: {e}')
        return redirect(url_for('admin_export_page'))


# -----------------------
# SMTP Test Mail via url/admin/smtp
# -----------------------

@app.route("/admin/smtp", methods=["GET", "POST"])
@login_required
@require_perms('users:manage')
@require_csrf
def admin_smtp():
    status = None
    if request.method == "POST":
        try:
            if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
                flash("SMTP configuration incomplete.", "error")
                return redirect(url_for("admin_smtp"))

            # Verbindung aufbauen
            if SMTP_SSL_ON:
                context = ssl.create_default_context()
                server = SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context)
            else:
                server = SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
                if SMTP_TLS:
                    server.starttls(context=ssl.create_default_context())

            server.login(SMTP_USER, SMTP_PASS)

            # UTF-8 sicheres Test-Mail-Objekt
            subject = Header("SMTP test by BottleBalance", "utf-8")
            body_text = "This is a test message to check the SMTP configuration."
            message = MIMEText(body_text, "plain", "utf-8")
            message["Subject"] = subject
            message["From"] = FROM_EMAIL
            message["To"] = SMTP_USER

            server.sendmail(FROM_EMAIL, SMTP_USER, message.as_string())
            server.quit()

            flash("SMTP test successful – test email sent.", "success")
        except Exception as e:
            flash(f"SMTP test failed: {e}", "error")
        return redirect(url_for("admin_smtp"))

    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        status = "SMTP configuration incomplete."
    else:
        status = f"SMTP configuration detected for host {SMTP_HOST}:{SMTP_PORT}."

    return render_template("admin_smtp.html", status=status)

# -----------------------
# SMTP Test Mail if paraam SEND_TEST_MAIL is set to true
# -----------------------
logger.info("ENV SEND_TEST_MAIL in .env  is set to %s", SEND_TEST_MAIL)
if SEND_TEST_MAIL:
    check_smtp_configuration()

# -----------------------
# SMTP Test Mail if paraam SEND_TEST_MAIL is set to true
# -----------------------

@app.route("/admin/tools", methods=["GET", "POST"])
@login_required
@require_perms('users:manage')
@require_csrf
def admin_tools():
    status = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "smtp":
            try:
                if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
                    flash(_("SMTP configuration incomplete."), "error")
                else:
                    server = SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) if SMTP_SSL_ON else SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
                    if SMTP_TLS:
                        server.starttls(context=ssl.create_default_context())
                    server.login(SMTP_USER, SMTP_PASS)
                    message = MIMEText("This is a test message to check the SMTP configuration.", "plain", "utf-8")
                    message["Subject"] = Header("SMTP test by BottleBalance", "utf-8")
                    message["From"] = FROM_EMAIL
                    message["To"] = SMTP_USER
                    server.sendmail(FROM_EMAIL, SMTP_USER, message.as_string())
                    server.quit()
                    flash(_("SMTP test successful – test email sent."), "success")
            except Exception as e:
                flash(_("SMTP test failed: ") + str(e), "error")

        elif action == "dump":
            dump_file = "/tmp/bottlebalance_dump.sql"
            env = os.environ.copy()
            env["PGPASSWORD"] = DB_PASS
            try:
                with open(dump_file, "w") as f:
                    subprocess.run([
                        "pg_dump",
                        "-U", DB_USER,
                        "-h", DB_HOST,
                        DB_NAME
                    ], stdout=f, env=env, check=True)
                log_action(session.get('user_id'), 'db:export', None, f'Dump von {DB_NAME} erzeugt')
                flash(_('Database dump successfully generated.'), "success")
                return send_file(dump_file, as_attachment=True, download_name="bottlebalance_dump.sql")
            except subprocess.CalledProcessError as e:
                flash(_('Error during database dump: ') + str(e), "error")
                log_action(session.get('user_id'), 'db:export:error', None, f'Dump failed: {e}')

    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        status = _("SMTP configuration incomplete.")
    else:
        status = _("SMTP configuration detected for host {}:{}.".format(SMTP_HOST, SMTP_PORT))
        

    return render_template("admin_tools.html", status=status)

if __name__ == '__main__':
    os.environ.setdefault('TZ', 'Europe/Berlin')
    app.run(host='0.0.0.0', port=5000, debug=False)