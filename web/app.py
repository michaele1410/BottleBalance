import os
import secrets
import ssl
import logging
from logging.handlers import RotatingFileHandler
from smtplib import SMTP, SMTP_SSL, SMTPException
from email.message import EmailMessage
from datetime import datetime, date, timedelta
from decimal import Decimal, InvalidOperation
from flask_babel import Babel, gettext as _
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, abort
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash, check_password_hash
from smtp_check import check_smtp_configuration
import csv
import io
import time
import pyotp
import qrcode
import base64
from PIL import Image

# PDF (ReportLab)
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm


check_smtp_configuration()

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

FROM_EMAIL = os.getenv("FROM_EMAIL") or SMTP_USER or "no-reply@example.com"
APP_BASE_URL = os.getenv("APP_BASE_URL") or "http://localhost:5000"

DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"
engine: Engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True)

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

app = Flask(__name__)

app.config['BABEL_DEFAULT_LOCALE'] = 'de'
babel = Babel(app, locale_selector=get_locale, timezone_selector=get_timezone)

app.secret_key = SECRET_KEY

# ROLES und set() global für Jinja2 verfügbar machen
app.jinja_env.globals.update(ROLES=ROLES, set=set)

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
# Helpers: Current user, RBAC
# -----------------------
from functools import wraps

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, username, email, role, active, must_change_password, totp_enabled, backup_codes, locale, timezone
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

def parse_german_decimal(s: str | None) -> Decimal:
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
        return redirect(url_for('login_2fa'))

    session['user_id'] = user['id']
    session['role'] = user['role']
    if user['must_change_password']:
        flash(_('Bitte Passwort ändern (erforderlich).'))
        return redirect(url_for('profile'))
    return redirect(url_for('index'))

@app.get('/2fa')
def login_2fa():
    if not session.get('pending_2fa_user_id'):
        return redirect(url_for('login'))
    return render_template('2fa.html')

@app.post('/2fa')
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

        # ✅ TOTP-Code gültig
        if totp.verify(code, valid_window=1):
            session.pop('pending_2fa_user_id', None)
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('index'))

        # ✅ Backup-Code gültig
        if user.get('backup_codes'):
            codes = user['backup_codes'].split(',')
            if code in codes:
                codes.remove(code)
                conn.execute(text("UPDATE users SET backup_codes=:bc WHERE id=:id"),
                             {'bc': ",".join(codes), 'id': uid})
                session.pop('pending_2fa_user_id', None)
                session['user_id'] = user['id']
                session['role'] = user['role']
                flash(_('Backup-Code verwendet. Bitte neue Codes generieren.'))
                return redirect(url_for('index'))

    flash(_('Ungültiger 2FA-Code oder Backup-Code.'))
    return redirect(url_for('login_2fa'))

@app.post('/profile/2fa/regen')
@login_required
def regen_backup_codes():
    uid = session['user_id']
    codes = [secrets.token_hex(4) for _ in range(10)]
    codes_str = ",".join(codes)
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET backup_codes=:bc WHERE id=:id"), {'bc': codes_str, 'id': uid})
    flash(_('Neue Backup-Codes wurden generiert:'))
    return redirect(url_for('profile'))

@app.get('/logout')
@login_required
def logout():
    uid = session.get('user_id')
    log_action(uid, 'logout', None, None)
    session.clear()
    return redirect(url_for('login'))

# Profile & 2FA management
@app.get('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user(), ROLES=ROLES)

@app.post('/profile')
@login_required
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
        conn.execute(text("UPDATE users SET totp_secret=:s, totp_enabled=TRUE, updated_at=NOW() WHERE id=:id"), {'s': secret, 'id': uid})
    session.pop('enroll_totp_secret', None)
    flash(_('2FA aktiviert.'))
    return redirect(url_for('profile'))

@app.post('/profile/2fa/disable')
@login_required
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
                INSERT INTO users (username, email, password_hash, role, active, must_change_password)
                VALUES (:u, :e, :ph, :r, TRUE, FALSE)
            """), {'u': username, 'e': email, 'ph': generate_password_hash(pwd), 'r': role})
        flash(_('Benutzer angelegt.'))
    except Exception as e:
        flash(f"{_('Fehler:')} {e}")
    return redirect(url_for('users_list'))

@app.post('/admin/users/<int:uid>/toggle')
@login_required
@require_perms('users:manage')
def users_toggle(uid: int):
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET active = NOT active, updated_at=NOW() WHERE id=:id"), {'id': uid})
    return redirect(url_for('users_list'))

@app.post('/admin/users/<int:uid>/role')
@login_required
@require_perms('users:manage')
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
def add():
    user = current_user()
    try:
        datum = parse_date_de_or_today(request.form.get('datum'))
        vollgut = int((request.form.get('vollgut') or '0').strip() or '0')
        leergut = int((request.form.get('leergut') or '0').strip() or '0')
        einnahme = parse_german_decimal(request.form.get('einnahme') or '0')
        ausgabe = parse_german_decimal(request.form.get('ausgabe') or '0')
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
        einnahme = parse_german_decimal(request.form.get('einnahme') or '0')
        ausgabe = parse_german_decimal(request.form.get('ausgabe') or '0')
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
    writer = csv.writer(output, delimiter=';', lineterminator='')
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
            einnahme = parse_german_decimal(ein_s or '0')
            ausgabe = parse_german_decimal(aus_s or '0')
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
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), leftMargin=15, rightMargin=15, topMargin=15, bottomMargin=15)
    styles = getSampleStyleSheet()
    story = []

    logo_path = os.path.join(app.root_path, 'static', 'logo.png')
    if os.path.exists(logo_path):
        story.append(RLImage(logo_path, width=40*mm, height=12*mm))
        story.append(Spacer(1, 6))
    story.append(Paragraph('<b>BottleBalance – Export</b>', styles['Title']))
    story.append(Spacer(1, 6))

    data = [['Datum','Vollgut','Leergut','Inventar','Einnahme','Ausgabe','Kassenbestand','Bemerkung']]
    for e in entries:
        data.append([
            format_date_de(e['datum']), str(e['vollgut']), str(e['leergut']), str(e['inventar']),
            str(e['einnahme']).replace('.', ',') + ' €', str(e['ausgabe']).replace('.', ',') + ' €', str(e['kassenbestand']).replace('.', ',') + ' €', e['bemerkung']
        ])
    col_widths = [25*mm,20*mm,20*mm,25*mm,30*mm,30*mm,35*mm,110*mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#f1f3f5')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#212529')),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,0),10),
        ('ALIGN',(1,1),(3,-1),'RIGHT'),
        ('ALIGN',(4,1),(6,-1),'RIGHT'),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, colors.HexColor('#fcfcfd')]),
        ('GRID',(0,0),(-1,-1),0.25,colors.HexColor('#dee2e6')),
        ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
    ]))
    story.append(table)
    doc.build(story)
    buffer.seek(0)
    filename = f"bottlebalance_{date.today().strftime('%Y%m%d')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')

@app.post('/profile/lang')
@login_required
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

if __name__ == '__main__':
    os.environ.setdefault('TZ', 'Europe/Berlin')
    app.run(host='0.0.0.0', port=5000, debug=False)