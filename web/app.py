# -----------------
# Checked: auth, bbalance, 
# -----------------


import os
import secrets
import ssl
import logging
import re
import base64
from logging.handlers import RotatingFileHandler
from smtplib import SMTP, SMTP_SSL as SMTP_SSL_CLASS  # ← alias gegen Konflikt
from email.message import EmailMessage
from datetime import datetime, date, timedelta
from decimal import Decimal
from flask_babel import Babel, gettext as _, gettext as translate
from flask import Flask, render_template, request, redirect, url_for, session, send_file, send_from_directory, flash, abort, current_app, render_template_string
from flask_mail import Message, Mail
mail = Mail()
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from email.header import Header
from functools import wraps
from typing import Tuple
from urllib.parse import urlencode
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage, PageBreak, KeepTogether

from types import SimpleNamespace

from auth import auth_routes
from bbalance import bbalance_routes
from attachments import attachments_routes
from admin import admin_routes
from user import user_routes
from payment import payment_routes
from mail import mail_routes

# UTILS (def)
from modules.core_utils import (
    DB_HOST,
    DB_NAME,
    DB_USER,
    DB_PASS,
    engine, 
    ROLES, 
    SECRET_KEY,
    log_action,
    APP_BASE_URL,
    _entry_dir, 
    _temp_dir,
    localize_dt,
    localize_dt_str
)
from modules.system_utils import (
    get_version
)

from modules.bbalance_utils import (
    fetch_entries,
    format_date_de,
    format_eur_de,
    _user_can_view_entry
)

from modules.mail_utils import (
    SMTP_HOST, 
    SMTP_PORT, 
    SMTP_USER, 
    SMTP_PASS,
    SMTP_TLS, 
    SMTP_SSL_ON, 
    SMTP_TIMEOUT, 
    FROM_EMAIL
)

from modules.auth_utils import (
    login_required, 
    current_user, 
    require_perms, 
    require_csrf, 
    csrf_token,
    generate_and_store_backup_codes
)

from modules.payment_utils import (
    _user_can_view_antrag,
    _user_can_edit_antrag,
    get_antrag_email,
    _require_approver,
    _approvals_done,
    _approvals_total
)

from modules.csv_utils import (
    parse_money,
    _parse_csv_with_mapping,
    compute_auto_mapping,
    parse_date_de_or_today,
    _signature,
    _fetch_existing_signature_set
)


#from users import users_bp
#from entries import entries_bp
#from payment import payment_bp
#from attachments import attachments_bp
#from auth import auth_bp

import csv
import io
import time
import pyotp
import qrcode

import subprocess

import json

# PDF (ReportLab)
from reportlab.lib.pagesizes import A4, landscape, portrait
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm

# Document Upload
from werkzeug.utils import secure_filename
from uuid import uuid4
from pathlib import Path
import mimetypes


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

def setup_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

app = Flask(__name__, static_folder='static')
app.config.update({
        "MAIL_SERVER": SMTP_HOST,    
        "MAIL_PORT": SMTP_PORT,    
        "MAIL_USE_TLS": bool(SMTP_TLS) and not bool(SMTP_SSL_ON),    
        "MAIL_USE_SSL": bool(SMTP_SSL_ON),    
        "MAIL_USERNAME": SMTP_USER,    
        "MAIL_PASSWORD": SMTP_PASS,    
        "MAIL_DEFAULT_SENDER": FROM_EMAIL,    
        "MAIL_TIMEOUT": SMTP_TIMEOUT, # Flask-Mail unterstützt timeout ab neueren Versionen teils via kwargs})
})
# Flask-Mail initialisieren
mail.init_app(app)
# Upload-Ordner sicherstellen
app.config.setdefault('UPLOAD_FOLDER', os.path.join(app.instance_path, 'uploads'))
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)



# -----------------------
# Feature Switches (ENV)
# -----------------------

# Developer Information
DEVELOPER_EMAIL = "webmaster@michaeleitdorf.de"
DEVELOPER_URL = "https://github.com/michaele1410/BottleBalance"

IMPORT_USE_PREVIEW   = os.getenv("IMPORT_USE_PREVIEW", "true").lower() in ("1","true","yes","on")
IMPORT_ALLOW_MAPPING = os.getenv("IMPORT_ALLOW_MAPPING", "true").lower() in ("1","true","yes","on")
IMPORT_ALLOW_DRYRUN  = os.getenv("IMPORT_ALLOW_DRYRUN", "true").lower() in ("1","true","yes","on")

# Optionaler API-Token für CI/Headless-Dry-Runs (Header: X-Import-Token)
IMPORT_API_TOKEN     = os.getenv("IMPORT_API_TOKEN")  # leer = kein Token erlaubt

def serialize_attachment(att):
    return {
        "filename": att.original_name,
        "download_url": url_for('download_file', filename=att.filename),
        "view_url": url_for('view_file', filename=att.filename),
        "mime_type": att.mime_type,
        "size_kb": round(att.size_bytes / 1024, 1)
    }

# -----------------------
# Antrag
# -----------------------
def notify_managing_users(antrag_id, antragsteller, betrag, datum):
    subject = _('Neuer Zahlungsfreigabeantrag von %(requester)s', requester=antragsteller)
    body = _(
        "Es wurde ein neuer Zahlungsfreigabeantrag erstellt.\n\n"
        "Antragsteller: %(requester)s\n"
        "Betrag: %(amount).2f EUR\n"
        "Datum: %(date)s\n"
        "Antrag-ID: %(id)d\n\n"
        "Bitte prüfen Sie den Antrag im System.",
        requester=antragsteller, amount=betrag, date=datum, id=antrag_id
    )

    with engine.begin() as conn:
        emails = conn.execute(text("""
            SELECT email
            FROM users
            WHERE role = 'manager' AND active = TRUE AND email IS NOT NULL
        """)).scalars().all()

    for to_addr in emails:
        msg = Message(subject=subject, recipients=[to_addr], body=body, sender=FROM_EMAIL)
        mail.send(msg)


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

# Register Blueprints
app.register_blueprint(auth_routes)
app.register_blueprint(bbalance_routes)
app.register_blueprint(attachments_routes)
app.register_blueprint(admin_routes)
app.register_blueprint(user_routes)
app.register_blueprint(payment_routes)
app.register_blueprint(mail_routes)


app.config['BABEL_DEFAULT_LOCALE'] = 'de'
babel = Babel(app, locale_selector=get_locale, timezone_selector=get_timezone)

app.secret_key = SECRET_KEY


# For Error Pages
app.config["SUPPORT_EMAIL"] = os.getenv("SUPPORT_EMAIL", "webmaster@michaeleitdorf.de")
app.config["SUPPORT_URL"]   = os.getenv("SUPPORT_URL", "https://github.com/michaele1410/BottleBalance")

# CSV Upload Limit
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB


# ROLES und set() global für Jinja2 verfügbar machen
#app.jinja_env.globals.update(ROLES=ROLES, set=set, current_user=current_user)

#Zeitstempel
app.jinja_env.filters['localize_dt'] = localize_dt
app.jinja_env.filters['localize_dt_str'] = localize_dt_str

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
    sort_order_desc BOOLEAN DEFAULT FALSE,
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

CREATE_TABLE_ATTACHMENTS = """
CREATE TABLE IF NOT EXISTS attachments (
    id SERIAL PRIMARY KEY,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    stored_name TEXT NOT NULL,           -- serverseitiger Dateiname (uuid.ext)
    original_name TEXT NOT NULL,         -- Originalname
    content_type TEXT,
    size_bytes BIGINT,
    uploaded_by INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_TABLE_ATTACHMENTS_TEMP = """
CREATE TABLE IF NOT EXISTS attachments_temp (
    id SERIAL PRIMARY KEY,
    temp_token TEXT NOT NULL,            -- clientseitiges Token für die Add-Session
    stored_name TEXT NOT NULL,           -- serverseitiger Dateiname (uuid.ext)
    original_name TEXT NOT NULL,         -- Originalname
    content_type TEXT,
    size_bytes BIGINT,
    uploaded_by INTEGER,                 -- User-ID
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_INDEX_ATTACHMENTS_TEMP = """
CREATE INDEX IF NOT EXISTS idx_attachments_temp_token
ON attachments_temp (temp_token, uploaded_by, created_at);
"""

CREATE_TABLE_BEMERKUNGSOPTIONEN = """
CREATE TABLE IF NOT EXISTS bemerkungsoptionen (
    id SERIAL PRIMARY KEY,
    text TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_TABLE_ZAHLUNGSFREIGABE = """
CREATE TABLE IF NOT EXISTS zahlungsantraege (
    id SERIAL PRIMARY KEY,
    antragsteller_id INTEGER NOT NULL,
    datum DATE NOT NULL,
    paragraph VARCHAR(50),
    verwendungszweck TEXT,
    betrag NUMERIC(10,2),
    lieferant TEXT,
    begruendung TEXT,
    status VARCHAR(20) DEFAULT 'offen',
    read_only BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    approver_snapshot JSONB
);
"""

CREATE_TABLE_ZAHLUNGSFREIGABE_AUDIT = """
CREATE TABLE IF NOT EXISTS zahlungsantrag_audit (
    id SERIAL PRIMARY KEY,
    antrag_id INTEGER NOT NULL,
    user_id INTEGER,
    action VARCHAR(50),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    detail TEXT
);
"""

CREATE_TABLE_ZAHLUNGSFREIGABE_ATTACHMENTS = """
CREATE TABLE IF NOT EXISTS antrag_attachments (
    id SERIAL PRIMARY KEY,
    antrag_id INTEGER NOT NULL REFERENCES zahlungsantraege(id) ON DELETE CASCADE,
    stored_name TEXT NOT NULL,       -- serverseitiger Dateiname (uuid.ext)
    original_name TEXT NOT NULL,     -- Originalname
    content_type TEXT,
    size_bytes BIGINT,
    uploaded_by INTEGER,             -- users.id
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_INDEX_ZAHLUNGSFREIGABE_ATTACHMENTS = """
CREATE INDEX IF NOT EXISTS idx_antrag_attachments_antrag_created
ON antrag_attachments(antrag_id, created_at DESC, id DESC);
"""

CREATE_TABLE_ZAHLUNGSFREIGABE_TRANSITIONS = """
CREATE TABLE IF NOT EXISTS status_transitions (
    id SERIAL PRIMARY KEY,
    from_status VARCHAR(50) NOT NULL,
    to_status VARCHAR(50) NOT NULL,
    role_required VARCHAR(50) NOT NULL,
    conditions TEXT
);
"""

CREATE_INDEX_ENTRIES_DATUM = """
CREATE INDEX IF NOT EXISTS idx_entries_datum_id ON entries(datum, id);
"""

def migrate_columns(conn):
    # Best-effort migrations for added columns
    conn.execute(text(CREATE_TABLE_ATTACHMENTS))
    conn.execute(text(CREATE_TABLE_ATTACHMENTS_TEMP))
    conn.execute(text(CREATE_TABLE_BEMERKUNGSOPTIONEN))
    conn.execute(text(CREATE_TABLE_ZAHLUNGSFREIGABE))
    conn.execute(text(CREATE_TABLE_ZAHLUNGSFREIGABE_AUDIT))
    # Schneller zählen: DISTINCT user_id je Antrag/Aktion
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_za_antrag_action_user " "ON zahlungsantrag_audit(antrag_id, action, user_id)"))
    conn.execute(text(CREATE_TABLE_ZAHLUNGSFREIGABE_ATTACHMENTS))
    conn.execute(text(CREATE_TABLE_ZAHLUNGSFREIGABE_TRANSITIONS))
    conn.execute(text(CREATE_INDEX_ENTRIES_DATUM))


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
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS can_approve BOOLEAN NOT NULL DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS sort_order_desc BOOLEAN DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE zahlungsantraege ADD COLUMN IF NOT EXISTS approver_snapshot JSONB"))
    
    try:
        current_len = conn.execute(text("""
            SELECT character_maximum_length
            FROM information_schema.columns
            WHERE table_name='zahlungsantraege'
            AND column_name='paragraph'
            AND data_type='character varying'
        """)).scalar_one_or_none()

        if current_len is not None and current_len < 50:
            conn.execute(text("ALTER TABLE zahlungsantraege ALTER COLUMN paragraph TYPE VARCHAR(50)"))
    except Exception:
        # bewusst best effort – kein Crash, nur loggen
        logging.getLogger(__name__).exception("Migration paragraph -> VARCHAR(50) fehlgeschlagen")

    # Standardwerte einfügen, falls Tabelle leer ist
    default_bemerkungen = [
        "Entnahme",
        "Inventur",
        "Kassenzählung",
        "Leerung Kasse GR",
        "Lieferung Getränke",
        "Einzelkauf Getränke",
        "Einzahlung Paypal",
        "Spende"
    ]
    existing = conn.execute(text("SELECT COUNT(*) FROM bemerkungsoptionen")).scalar_one()
    if existing == 0:
        for text_value in default_bemerkungen:
            conn.execute(text("""
                INSERT INTO bemerkungsoptionen (text) VALUES (:t)
            """), {'t': text_value})

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

@app.cli.command('cleanup-temp')
def cleanup_temp():
    """Temp-Uploads z.B. älter als 24h löschen."""
    cutoff = datetime.utcnow() - timedelta(hours=24)
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, temp_token, stored_name FROM attachments_temp
            WHERE created_at < :cut
        """), {'cut': cutoff}).mappings().all()

    removed = 0
    for r in rows:
        tdir = _temp_dir(r['temp_token'])
        path = os.path.join(tdir, r['stored_name'])
        try:
            if os.path.exists(path):
                os.remove(path)
            removed += 1
        except Exception:
            pass
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM attachments_temp WHERE id=:id"), {'id': r['id']})
        try:
            if os.path.isdir(tdir) and not os.listdir(tdir):
                os.rmdir(tdir)
        except Exception:
            pass
    print(f"Temp cleanup done. Files removed: {removed}")







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
    flash(_('Datei zu groß. Bitte kleinere Datei hochladen.'))
    return redirect(request.referrer or url_for('bbalance_routes.index'))


@app.errorhandler(500)
def internal_error(e):
    return render_template('errors/500.html'), 500

try:
    from importlib.metadata import version, PackageNotFoundError
    try:
        fb_ver = version("Flask-Babel")
    except PackageNotFoundError:
        fb_ver = "unknown"
except Exception:
    fb_ver = "unknown"

logger.info("Flask-Babel version: %s", fb_ver)

# -----------------------
# Helpers: Current user, RBAC
# -----------------------















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




# -----------------------
# Auth & 2FA
# -----------------------





# -----------------------
# Profile & 2FA management
# -----------------------
@app.get('/profile')
@login_required
def profile():
    user = current_user()
    theme = user.get('theme_preference') if user else 'system'
    themes = ['system', 'light', 'dark']
    # Backup-Codes EINMALIG aus Session holen
    new_codes = session.pop('new_backup_codes', None)
    return render_template(
        'profile.html',
        user=user,
        theme_preference=theme,
        ROLES=ROLES,
        themes=themes,
        new_backup_codes=new_codes,  # <-- hier übergeben
    )

@app.post('/profile')
@login_required
@require_csrf
def profile_post():
    pwd = (request.form.get('password') or '').strip()
    pwd2 = (request.form.get('password2') or '').strip()
    email = (request.form.get('email') or '').strip()
    uid = session['user_id']

    if pwd or pwd2:
        if len(pwd) < 8:
            flash(_('Passwort muss mindestens 8 Zeichen haben.'))
            return redirect(url_for('profile'))
        if pwd != pwd2:
            flash(_('Passwörter stimmen nicht überein.'))
            return redirect(url_for('profile'))

    with engine.begin() as conn:
        if pwd:
            conn.execute(text("""
                UPDATE users SET password_hash=:ph, must_change_password=FALSE, email=:em, updated_at=NOW()
                WHERE id=:id
            """), {'ph': generate_password_hash(pwd), 'em': email or None, 'id': uid})

            # Nach Passwortänderung: 2FA aktivieren, falls noch nicht aktiv
            user = conn.execute(text("SELECT totp_enabled FROM users WHERE id=:id"), {'id': uid}).mappings().first()
            if user and not user['totp_enabled']:
                flash(_('Bitte aktiviere die Zwei-Faktor-Authentifizierung (2FA), um dein Konto zusätzlich zu schützen.'))
                return redirect(url_for('enable_2fa'))  # <-- Sofortige Rückgabe
        else:
            conn.execute(text("""
                UPDATE users SET email=:em, updated_at=NOW()
                WHERE id=:id
            """), {'em': email or None, 'id': uid})

    flash(_('Profil aktualisiert.'))
    return redirect(url_for('bbalance_routes.index'))

@app.get('/profile/2fa/enable')
@login_required
def enable_2fa_get():
    uid = session['user_id']
    secret = pyotp.random_base32()
    session['enroll_totp_secret'] = secret

    with engine.begin() as conn:
        username = conn.execute(
            text("SELECT username FROM users WHERE id=:id"), {'id': uid}
        ).scalar_one_or_none()

    if username is None:
        flash(_('Benutzer nicht gefunden.'))
        return redirect(url_for('profile'))

    issuer = 'BottleBalance'
    otpauth = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    img = qrcode.make(otpauth)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    data_url = 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode('ascii')

    return render_template('2fa_enroll.html', qr_data_url=data_url, secret=secret)

@app.post('/profile/2fa/enable')
@login_required
@require_csrf
def enable_2fa():
    uid = session['user_id']
    secret = pyotp.random_base32()
    session['enroll_totp_secret'] = secret
    with engine.begin() as conn:
        username = conn.execute(
            text("SELECT username FROM users WHERE id=:id"), {'id': uid}
        ).scalar_one_or_none()

    if username is None:
        flash(_('Benutzer nicht gefunden.'))
        return redirect(url_for('profile'))

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
    log_action(uid, '2fa:enabled', None, None)
    return redirect(url_for('profile'))

@app.post('/profile/2fa/disable')
@login_required
@require_csrf
def disable_2fa():
    uid = session['user_id']
    pwd = (request.form.get('password') or '').strip()

    # Passwort prüfen
    with engine.begin() as conn:
        user = conn.execute(
            text("SELECT password_hash FROM users WHERE id=:id"),
            {'id': uid}
        ).mappings().first()

    if not user or not check_password_hash(user['password_hash'], pwd):
        flash(_('Passwortprüfung fehlgeschlagen.'))
        return redirect(url_for('profile'))

    # 2FA deaktivieren + Backup-Codes löschen
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE users
            SET totp_secret=NULL,
                totp_enabled=FALSE,
                backup_codes='[]',
                updated_at=NOW()
            WHERE id=:id
        """), {'id': uid})

    flash(_('2FA deaktiviert.'))
    log_action(uid, '2fa:disabled', None, None)
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
    sort_order_desc = (request.form.get('sort_order_desc') == 'on')

    if language not in ['de', 'en']:
        flash(_('Ungültige Sprache.'))
        return redirect(url_for('profile'))

    if theme not in ['light', 'dark', 'system']:
        flash(_('Ungültige Theme-Auswahl.'))
        return redirect(url_for('profile'))

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE users
            SET locale=:lang,
                theme_preference=:theme,
                sort_order_desc=:desc,
                updated_at=NOW()
            WHERE id=:id
        """), {
            'lang': language,
            'theme': theme,
            'desc': sort_order_desc,
            'id': uid
    })

    flash(_('Einstellungen gespeichert.'))
    return redirect(url_for('profile'))

@app.context_processor
def utility_processor():
    def safe_url_for(endpoint, **values):
        try:
            return url_for(endpoint, **values)
        except Exception:
            return '#'
    def has_endpoint(endpoint):
        try:
            return endpoint in current_app.view_functions
        except Exception:
            return False
    return dict(safe_url_for=safe_url_for, has_endpoint=has_endpoint)


# ---- Jinja current_user Proxy (callable + dict-like) ----
class _CurrentUserProxy(SimpleNamespace):
    def __call__(self):
        # erlaubt legacy {{ current_user() }} - gibt sich selbst zurück
        return self
    def get(self, key, default=None):
        # erlaubt legacy {{ current_user().get('feld') }}
        return getattr(self, key, default)

@app.context_processor
def inject_theme():
    """
    Stellt globale Template-Variablen bereit.
    Backwards-compat:
      - {{ current_user.is_authenticated }}
      - {{ current_user().get('username') }}
    """
    user_dict = current_user()  # nutzt deine bestehende DB-Funktion
    theme = 'system'
    if user_dict:
        cu = _CurrentUserProxy(**user_dict, is_authenticated=True)
        theme = user_dict.get('theme_preference') or 'system'
    else:
        cu = _CurrentUserProxy(is_authenticated=False)

    return {
        'theme_preference': theme,
        'current_user': cu,               # Objekt, aber auch aufrufbar
        'ROLES': ROLES,
        'set': set,
        'IMPORT_USE_PREVIEW': IMPORT_USE_PREVIEW,
        'IMPORT_ALLOW_MAPPING': IMPORT_ALLOW_MAPPING,
        'format_date_de': format_date_de,
        'format_eur_de': format_eur_de,
        'csrf_token': csrf_token,
        '_': translate                   # Babel-Funktion für Templates
    }

@app.context_processor
def inject_helpers():
    def qs(_remove=None, **overrides):
        # aktuelle args kopieren
        current = request.args.to_dict()
        # entfernen
        for k in (_remove or []):
            current.pop(k, None)
        # überschreiben/hinzufügen (nur nicht-None)
        for k, v in overrides.items():
            if v is None:
                current.pop(k, None)
            else:
                current[k] = v
        return urlencode(current, doseq=True)
    return dict(qs=qs)

@app.context_processor
def inject_developer_and_support_info():
    encoded_developer_email = base64.b64encode(DEVELOPER_EMAIL.encode()).decode()
    encoded_support_email = base64.b64encode(app.config["SUPPORT_EMAIL"].encode()).decode()
    return {
        'developer_email_encoded': encoded_developer_email,
        'developer_url': DEVELOPER_URL,
        'developer_email': DEVELOPER_EMAIL,
        'support_email_encoded': encoded_support_email,
        'support_url': app.config["SUPPORT_URL"]
    }

# -----------------------
# Password reset tokens
# -----------------------








# -----------------------
# Admin: Users & Audit
# -----------------------


# Userverwaltung

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
        where.append('(a.action ILIKE :q OR CAST(a.entry_id AS TEXT) ILIKE :q)')
        params['q'] = f"%{q}%"
    if df:
        where.append('DATE(a.created_at) >= :df')
        params['df'] = df
    if dt:
        where.append('DATE(a.created_at) <= :dt')
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



@app.post('/admin/users/<int:uid>/toggle_approve')
@login_required
@require_perms('users:setApprover')
@require_csrf
def users_toggle_approve(uid: int):
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET can_approve = NOT can_approve, updated_at=NOW() WHERE id=:id"), {'id': uid})
    flash(_('Freigabeberechtigung geändert.'))
    return redirect(url_for('user_routes.users_list'))




# -----------------------
# CSV Import – Vorschau & Commit (NEU)
# -----------------------
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




#@app.post('/import/preview')
#@login_required
#@require_perms('import:csv')
#def import_preview():
#    file = request.files.get('file')
#    replace_all = request.form.get('replace_all') == 'on'
#    if not file or file.filename == '':
#        flash(_('Bitte eine CSV-Datei auswählen.'))
#        return redirect(url_for('bbalance_routes.index'))
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
#        return redirect(url_for('bbalance_routes.index'))

#@app.post('/import/commit')
#@login_required
#@require_perms('import:csv')
#def import_commit():
#    token = (request.form.get('token') or '').strip()
#    mode = (request.form.get('mode') or 'skip_dups').strip()  # 'skip_dups' | 'insert_all'
#    if not token or 'import_previews' not in session or token not in session['import_previews']:
#        flash(_('Vorschau abgelaufen oder nicht gefunden.'))
#        return redirect(url_for('bbalance_routes.index'))

 #   stash = session['import_previews'].pop(token, None)
 #   session.modified = True
 #   if not stash:
 #       flash(_('Vorschau abgelaufen oder bereits verwendet.'))
 #       return redirect(url_for('bbalance_routes.index'))

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
#        return redirect(url_for('bbalance_routes.index'))
#    except Exception as e:
#        logger.exception("Import-Commit fehlgeschlagen: %s", e)
#        flash(f"{_('Import fehlgeschlagen:')} {e}")
#        return redirect(url_for('bbalance_routes.index'))

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
        flash(_('CSV-Preview ist deaktiviert.'))
        return redirect(url_for('bbalance_routes.index'))

    replace_all = request.form.get('replace_all') == 'on'
    token = (request.form.get('token') or '').strip()
    is_remap = request.form.get('remap') == '1'

    # ---------- REMAP-PFAD (CSV erneut parsen mit manuellem Mapping) ----------
    if is_remap and token:
        stash = session.get('import_previews', {}).get(token)
        if not stash:
            flash(_('Vorschau abgelaufen oder nicht gefunden.'))
            return redirect(url_for('bbalance_routes.index'))

        tmp_path = stash.get('csv_path')
        if not tmp_path or not os.path.exists(tmp_path):
            flash(_('CSV-Datei nicht gefunden.'))
            return redirect(url_for('bbalance_routes.index'))

        # CSV laden
        try:
            with open(tmp_path, 'r', encoding='utf-8-sig') as f:
                content = f.read()
        except Exception as e:
            logger.exception("CSV lesen fehlgeschlagen: %s", e)
            flash(_('CSV konnte nicht gelesen werden.'))
            return redirect(url_for('bbalance_routes.index'))

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
            return redirect(url_for('bbalance_routes.index'))

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
        return redirect(url_for('bbalance_routes.index'))

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
        return redirect(url_for('bbalance_routes.index'))


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
        return redirect(url_for('bbalance_routes.index'))

    stash = session['import_previews'].pop(token, None)
    session.modified = True
    if not stash:
        flash(_('Vorschau abgelaufen oder bereits verwendet.'))
        return redirect(url_for('bbalance_routes.index'))

    tmp_path = stash.get('csv_path')
    replace_all = bool(stash.get('replace_all'))
    mapping = stash.get('mapping')

    if not tmp_path or not os.path.exists(tmp_path):
        flash(_('CSV-Datei nicht gefunden.'))
        return redirect(url_for('bbalance_routes.index'))

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

        log_action(
            session.get('user_id'),
            'import:csv',
            None,
            f"commit: inserted={inserted}, replace_all={replace_all}, mode={mode}, import_invalid={import_invalid}"
        )

        # Success message with placeholder
        flash(_('Import erfolgreich: %(rows)d Zeilen übernommen.', rows=inserted))
        return redirect(url_for('bbalance_routes.index'))

    except Exception as e:
        logger.exception("Import-Commit fehlgeschlagen: %s", e)
        # Error message with placeholder
        flash(_('Import fehlgeschlagen: %(error)s', error=str(e)))
        return redirect(url_for('bbalance_routes.index'))

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
    attachments_filter = request.args.get('attachments')

    date_from = datetime.strptime(df, '%Y-%m-%d').date() if df else None
    date_to   = datetime.strptime(dt, '%Y-%m-%d').date() if dt else None

    year_raw = (request.args.get('year') or '').strip().lower()
    year_val = None
    if year_raw not in ('', 'all'):
        try:
            year_val = int(year_raw)
        except ValueError:
            year_val = None

    entries = fetch_entries(
        search=q or None,
        date_from=date_from,
        date_to=date_to,
        attachments_filter=attachments_filter,
        year=year_val
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=portrait(A4),
        leftMargin=10, rightMargin=5, topMargin=20, bottomMargin=20
    )
    styles = getSampleStyleSheet()
    story = []

    logo_path = os.path.join(app.root_path, 'static', 'images', 'logo.png')
    waehrung = _("waehrung")

    if os.path.exists(logo_path):
        story.append(RLImage(logo_path, width=40*mm, height=12*mm))
        story.append(Spacer(1, 6))

    story.append(Paragraph(f"<b>{_('BottleBalanceTitle')}{_(' - Export')}</b>", styles['Title']))
    story.append(Spacer(1, 6))

    # Filterzusammenfassung
    filters = []
    if q:
        filters.append(f"{_('Suche')}: {q}")
    if date_from or date_to:
        df_disp = date_from.strftime('%d.%m.%Y') if date_from else '—'
        dt_disp = date_to.strftime('%d.%m.%Y') if date_to else '—'
        filters.append(f"{_('Zeitraum')}: {df_disp} – {dt_disp}")
    if year_val is not None:
        filters.append(f"{_('Jahr')}: {year_val}")
    if attachments_filter == 'only':
        filters.append(f"{_('Anhänge')}: {_('Nur mit Anhang')}")
    elif attachments_filter == 'none':
        filters.append(f"{_('Anhänge')}: {_('Ohne Anhang')}")
    if filters:
        story.append(Paragraph(", ".join(filters), styles['Normal']))
        story.append(Spacer(1, 6))

    # Tabelle
    data = [[
        _('Datum'), _('Vollgut'), _('Leergut'), _('Inventar'),
        _('Einnahme'), _('Ausgabe'), _('Kassenbestand'), _('Bemerkung')
    ]]

    for e in entries:
        data.append([
            format_date_de(e['datum']),
            f"{e['vollgut']} Fl.",
            f"{e['leergut']} Fl.",
            f"{e['inventar']} Fl.",
            format_eur_de(e['einnahme']),
            format_eur_de(e['ausgabe']),
            format_eur_de(e['kassenbestand']),
            Paragraph(e['bemerkung'] or '', styles['Normal'])
        ])

    col_widths = [25*mm, 14*mm, 14*mm, 14*mm, 29*mm, 29*mm, 29*mm, 45*mm]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f3f5')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#212529')),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),

        ('ALIGN', (1,1), (2,-1), 'RIGHT'),   # Vollgut, Leergut
        ('ALIGN', (3,1), (5,-1), 'RIGHT'),   # Einnahme, Ausgabe, Kassenbestand

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
# Temporäre Attachments für "Datensatz hinzufügen"
# -----------------------



# -----------------------
# Zahlungsfreigabe
# -----------------------
def parse_date_iso_or_today(s: str | None) -> date:
    try:
        return datetime.strptime(s.strip(), '%Y-%m-%d').date()
    except Exception:
        return date.today()






# -----------------------
# SMTP Test Mail if paraam SEND_TEST_MAIL is set to true
# -----------------------
@app.route("/admin/tools", methods=["GET", "POST"])
@login_required
@require_perms('admin:tools')
def admin_tools():
    """
    Admin-Werkzeuge:
      - SMTP-Testmail senden
      - Datenbank-Dump erzeugen und herunterladen
      - Bemerkungsoptionen vollständig überschreiben

    Sicherheit:
      - Login + Rollenberechtigung (admin:tools) sind Pflicht.
      - CSRF-Schutz nur für POST-Aktionen.
    """
    status = None
    current_options = []

    # --- POST-AKTIONEN ---
    if request.method == "POST":
        # CSRF nur bei POST prüfen
        require_csrf(lambda: None)()

        action = (request.form.get("action") or "").strip()

        # 1) SMTP-Test
        if action == "smtp":
            try:
                if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
                    flash(_("SMTP configuration incomplete."), "error")
                else:
                    # SSL oder Plain
                    server = (
                        SMTP_SSL_CLASS(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
                        if SMTP_SSL_ON
                        else SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
                    )

                    # TLS nur starten, wenn keine SSL-Verbindung genutzt wird
                    if SMTP_TLS and not SMTP_SSL_ON:
                        server.starttls(context=ssl.create_default_context())

                    server.login(SMTP_USER, SMTP_PASS)

                    # Testmail vorbereiten
                    message = MIMEText(
                        "This is a test message to check the SMTP configuration.",
                        "plain",
                        "utf-8"
                    )
                    message["Subject"] = Header("SMTP test by BottleBalance", "utf-8")
                    message["From"] = FROM_EMAIL
                    message["To"] = SMTP_USER

                    server.sendmail(FROM_EMAIL, [SMTP_USER], message.as_string())
                    server.quit()

                    flash(_("SMTP test successful – test email sent."), "success")
            except Exception as e:
                flash(_("SMTP test failed: ") + str(e), "error")

        # 2) Datenbank-Dump
        elif action == "dump":
            dump_file = "/tmp/bottlebalance_dump.sql"
            env = os.environ.copy()
            env["PGPASSWORD"] = DB_PASS
            try:
                # Dump erzeugen
                with open(dump_file, "w") as f:
                    subprocess.run(
                        ["pg_dump", "-U", DB_USER, "-h", DB_HOST, DB_NAME],
                        stdout=f,
                        env=env,
                        check=True
                    )

                # Audit + Download
                log_action(session.get('user_id'), 'db:export', None, f'Dump von {DB_NAME} erzeugt')
                flash(_('Database dump successfully generated.'), "success")
                return send_file(dump_file, as_attachment=True, download_name="bottlebalance_dump.sql")

            except subprocess.CalledProcessError as e:
                flash(_('Error during database dump: %(error)s', error=str(e)), "error")
                log_action(session.get('user_id'), 'db:export:error', None, f'Dump failed: {e}')

        # 3) Bemerkungsoptionen überschreiben
        elif action == "update_bemerkungen":
            raw = request.form.get("options") or ""
            lines = [line.strip() for line in raw.splitlines() if line.strip()]
            try:
                with engine.begin() as conn:
                    conn.execute(text("DELETE FROM bemerkungsoptionen"))
                    for line in lines:
                        conn.execute(
                            text("INSERT INTO bemerkungsoptionen (text) VALUES (:t)"),
                            {'t': line}
                        )
                flash(_("Bemerkungsoptionen aktualisiert."), "success")
            except Exception as e:
                flash(_("Fehler beim Speichern der Bemerkungsoptionen: %(error)s", error=str(e)), "error")

        # Fallback bei unbekannter Aktion
        else:
            flash(_("Unbekannte Aktion."), "error")

        # Nach jeder POST-Aktion Redirect, um Doppeleinreichungen zu vermeiden
        return redirect(url_for("admin_tools"))

    # --- GET: Status & aktuelle Optionen anzeigen ---
    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        status = _("SMTP configuration incomplete.")
    else:
        status = _("SMTP configuration detected for host {}:{}.".format(SMTP_HOST, SMTP_PORT))

    try:
        with engine.begin() as conn:
            current_options = conn.execute(
                text("SELECT text FROM bemerkungsoptionen ORDER BY text ASC")
            ).scalars().all()
    except Exception:
        current_options = []   # ← deine Zeile hatte Tippfehler („current        current_options“)

    return render_template("admin_tools.html", status=status, current_options=current_options)






@app.template_filter('strftime')
def _jinja2_filter_datetime(value, format='%Y-%m-%d'):
    """
    Formatiert ein datetime/date-Objekt mit strftime.
    Gibt leeren String zurück, wenn value None ist.
    """
    if value is None:
        return ''
    try:
        return value.strftime(format)
    except AttributeError:
        return str(value)











@app.route('/view/<filename>')
def view_file(filename):
    response = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:;"
    return response

@app.route("/attachments/<int:att_id>/view")
@login_required
def attachments_view(att_id: int):
    # 1) Details aus DB holen
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT a.id, a.entry_id, a.stored_name, a.original_name, a.content_type
            FROM attachments a
            WHERE a.id = :id
        """), {'id': att_id}).mappings().first()

    if not r:
        abort(404)

    # 2) Zugriffsrecht prüfen
    if not _user_can_view_entry(r['entry_id']):
        abort(403)

    # 3) Dateipfad auflösen & prüfen
    path = os.path.join(_entry_dir(r['entry_id']), r['stored_name'])
    if not os.path.exists(path):
        abort(404)

    # 4) MIME-Type bestimmen (DB-Wert bevorzugen, sonst raten)
    mimetype = r.get('content_type') or (
        mimetypes.guess_type(r['original_name'])[0] or 'application/octet-stream'
    )

    # 5) Audit-Log
    log_action(session.get('user_id'), 'attachments:view', r['entry_id'], f"att_id={att_id}")

    # 6) Inline anzeigen + Sicherheits-Header
    resp = send_file(
        path,
        as_attachment=False,
        mimetype=mimetype,
        download_name=r['original_name']  # optional: hilft Browsern beim Anzeigen
    )
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    # Optional: CSP, wenn du sehr restriktiv sein willst
    # resp.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:;"

    return resp

def get_version():
    try:
        with open("VERSION") as f:
            return f.read().strip()
    except Exception:
        return "dev"

@app.context_processor
def inject_version():
    return dict(app_version=os.getenv("APP_VERSION", get_version()))

if __name__ == '__main__':
    os.environ.setdefault('TZ', 'Europe/Berlin')
    app.run(host='0.0.0.0', port=5000, debug=False)