# -----------------
# Checked: auth, bbalance, 
# -----------------

import os
import ssl
import logging
import base64
from smtplib import SMTP, SMTP_SSL as SMTP_SSL_CLASS
from datetime import datetime, date, timedelta
from decimal import Decimal
from flask_babel import Babel, gettext as _, gettext as translate
from flask import Flask, render_template, request, redirect, url_for, session, send_file, send_from_directory, flash, abort, current_app
from flask_mail import Message, Mail
mail = Mail()
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO
from email.mime.text import MIMEText
from email.header import Header
from urllib.parse import urlencode
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from types import SimpleNamespace
from auth import auth_routes
from bbalance import bbalance_routes
from attachments import attachments_routes
from admin import admin_routes
from user import user_routes
from payment import payment_routes
from mail import mail_routes
from modules.core_utils import get_setting, set_setting

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

from modules.csv_utils import (
    parse_money,
    _parse_csv_with_mapping,
    compute_auto_mapping,
    parse_date_de_or_today,
    _signature,
    _fetch_existing_signature_set
)

import csv
import io
import time
import pyotp
import qrcode
import subprocess

# PDF (ReportLab)
from reportlab.lib.pagesizes import A4, landscape, portrait
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm

# Document Upload
from werkzeug.utils import secure_filename
from uuid import uuid4
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
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
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
        "MAIL_TIMEOUT": SMTP_TIMEOUT, # Flask-Mail supports timeout in newer versions, partly via kwargs.
})

# Initialize Flask-Mail
mail.init_app(app)

# Make sure the upload folder is there
#app.config.setdefault('UPLOAD_FOLDER', os.path.join(app.instance_path, 'uploads'))
#os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Upload folder from ENV or fallback
UPLOAD_BASE = os.getenv("UPLOAD_FOLDER", os.path.join(app.instance_path, 'uploads'))
app.config['UPLOAD_FOLDER'] = UPLOAD_BASE
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

BRANDING_DIR = os.path.join(app.config['UPLOAD_FOLDER'], 'branding')
os.makedirs(BRANDING_DIR, exist_ok=True)

ALLOWED_LOGO_EXTS = {'svg', 'png', 'jpg', 'jpeg', 'webp'}

def _find_custom_logo():
    """Returns (filename, full_path, mtime) of the existing logo in BRANDING_DIR or (None, None, None)."""
    for ext in ('svg', 'png', 'jpg', 'jpeg', 'webp'):
        fname = f"logo.{ext}"
        fpath = os.path.join(BRANDING_DIR, fname)
        if os.path.isfile(fpath):
            try:
                mtime = int(os.path.getmtime(fpath))
            except Exception:
                mtime = None
            return (fname, fpath, mtime)
    return (None, None, None)

def brand_logo_url():
    """Provides the URL for the logo: Custom (Uploads) with cache buster or fallback to static/images/logo.png."""
    fname, _fpath, mtime = _find_custom_logo()
    if fname:
        # Served from Uploads/branding via /view/<filename>
        # Attach Cache-Buster via mtime
        url = url_for('view_file', filename=f"branding/{fname}")
        return f"{url}?t={mtime or ''}"
    # Fallback to static standard graphics
    return url_for('static', filename='images/logo.png')

@app.context_processor
def inject_branding():
    return {'brand_logo_url': brand_logo_url()}

# Get AppTile
@app.context_processor
def inject_app_title():
    return {
        'app_title': get_setting('app_title', 'BottleBalance')
    }

# -----------------------
# Feature Switches (ENV)
# -----------------------
# Developer Information
DEVELOPER_EMAIL = "webmaster@michaeleitdorf.de"
DEVELOPER_URL = "https://github.com/michaele1410/BottleBalance"

IMPORT_USE_PREVIEW   = os.getenv("IMPORT_USE_PREVIEW", "true").lower() in ("1","true","yes","on")
IMPORT_ALLOW_MAPPING = os.getenv("IMPORT_ALLOW_MAPPING", "true").lower() in ("1","true","yes","on")
IMPORT_ALLOW_DRYRUN  = os.getenv("IMPORT_ALLOW_DRYRUN", "true").lower() in ("1","true","yes","on")

# Optional API token for CI/headless dry runs (Header: X-Import-Token)
IMPORT_API_TOKEN     = os.getenv("IMPORT_API_TOKEN")  # empty = no token allowed

def serialize_attachment(att):
    return {
        "filename": att.original_name,
        "download_url": url_for('download_file', filename=att.filename),
        "view_url": url_for('view_file', filename=att.filename),
        "mime_type": att.mime_type,
        "size_kb": round(att.size_bytes / 1024, 1)
    }

# -----------------------
# Payment requests
# -----------------------
def notify_managing_users(request_id, requestor, amount, date):
    subject = _('New payment request from %(requester)s', requester=requestor)
    body = _(
        "A new payment request has been created.\n\n"
        "Requestor: %(requester)s\n"
        "Amount: %(amount).2f EUR\n"
        "Date: %(date)s\n"
        "Request-ID: %(id)d\n\n"
        "Please check the request in the system.",
        requester=requestor, amount=amount, date=date, id=request_id
    )

    with engine.begin() as conn:
        emails = conn.execute(text("""
            SELECT email
            FROM users
            WHERE role = 'manager' AND active = TRUE AND email IS NOT NULL
        """)).scalars().all()

    recipients = sorted({(e or "").strip() for e in emails if (e or "").strip()})
    if not recipients:
        current_app.logger.warning("No manager emails found for request %s", request_id)
        return

    for to_addr in recipients:
        msg = Message(subject=str(subject), recipients=[to_addr], body=str(body), sender=FROM_EMAIL or SMTP_USER)
        mail.send(msg)

    current_app.logger.info("Manager notifications for request %s sent to %s", request_id, ", ".join(recipients))

def get_locale():
    user = current_user()
    if user:
        # robust: dict OR Row object support
        pref = user.get('locale') if isinstance(user, dict) else getattr(user, 'locale', None)
        return (
            pref
            or session.get('language')
            or request.accept_languages.best_match(['de', 'en'])
        )
    # Anonymous users: Session override or browser header
    return session.get('language') or request.accept_languages.best_match(['de', 'en'])

def get_timezone():
    user = current_user()
    if user:
        return user.get('timezone') if isinstance(user, dict) else getattr(user, 'timezone', None)
    return None  # or a default like 'Europe/Berlin'

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

# SocketIO initializing
socketio = SocketIO(app)

# For Error Pages
app.config["SUPPORT_EMAIL"] = os.getenv("SUPPORT_EMAIL", "webmaster@michaeleitdorf.de")
app.config["SUPPORT_URL"]   = os.getenv("SUPPORT_URL", "https://github.com/michaele1410/BottleBalance")

# CSV Upload Limit
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB


# Make ROLES and set() globally available for Jinja2
#app.jinja_env.globals.update(ROLES=ROLES, set=set, current_user=current_user)

#Timestamp
app.jinja_env.filters['localize_dt'] = localize_dt
app.jinja_env.filters['localize_dt_str'] = localize_dt_str

# -----------------------
# DB Init & Migration
# -----------------------
CREATE_TABLE_ENTRIES = """
CREATE TABLE IF NOT EXISTS entries (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    date DATE NOT NULL,
    "full" INTEGER NOT NULL DEFAULT 0,
    "empty" INTEGER NOT NULL DEFAULT 0,
    revenue NUMERIC(12,2) NOT NULL DEFAULT 0,
    expense NUMERIC(12,2) NOT NULL DEFAULT 0,
    note TEXT,
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
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    role TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Preferences
    sort_order_desc BOOLEAN DEFAULT FALSE,
    default_filter BOOLEAN DEFAULT TRUE,
    theme_preference TEXT DEFAULT 'system',
    locale TEXT,
    timezone TEXT,

    -- 2FA
    totp_secret TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    backup_codes TEXT DEFAULT '[]',

    -- Approvals
    can_approve BOOLEAN NOT NULL DEFAULT FALSE,

    -- Login tracking
    last_login_at TIMESTAMP,

    -- Timestamps
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
    stored_name TEXT NOT NULL,           -- server-side filename (uuid.ext)
    original_name TEXT NOT NULL,         -- Original name
    content_type TEXT,
    size_bytes BIGINT,
    uploaded_by INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_TABLE_ATTACHMENTS_TEMP = """
CREATE TABLE IF NOT EXISTS attachments_temp (
    id SERIAL PRIMARY KEY,
    temp_token TEXT NOT NULL,            -- client-side token for the add session
    stored_name TEXT NOT NULL,           -- server-side filename (uuid.ext)
    original_name TEXT NOT NULL,         -- Original name
    content_type TEXT,
    size_bytes BIGINT,
    uploaded_by INTEGER,                 -- User-ID
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_TABLE_NOTES = """
CREATE TABLE IF NOT EXISTS notes (
    id SERIAL PRIMARY KEY,
    text TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_TABLE_PAYMENT_REQUESTS = """
CREATE TABLE IF NOT EXISTS payment_requests (
    id SERIAL PRIMARY KEY,
    requestor_id INTEGER NOT NULL,
    date DATE NOT NULL,
    paragraph VARCHAR(50),
    purpose TEXT,
    amount NUMERIC(10,2),
    supplier TEXT,
    justification TEXT,
    state VARCHAR(20) DEFAULT 'pending',
    read_only BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    approver_snapshot JSONB
);
"""

CREATE_TABLE_PAYMENT_REQUESTS_AUDIT = """
CREATE TABLE IF NOT EXISTS payment_requests_audit (
    id SERIAL PRIMARY KEY,
    request_id INTEGER NOT NULL,
    user_id INTEGER,
    action VARCHAR(50),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    detail TEXT
);
"""

CREATE_TABLE_PAYMENT_REQUESTS_ATTACHMENTS = """
CREATE TABLE IF NOT EXISTS payment_requests_attachments (
    id SERIAL PRIMARY KEY,
    request_id INTEGER NOT NULL REFERENCES payment_requests(id) ON DELETE CASCADE,
    stored_name TEXT NOT NULL,       -- server-side file name (uuid.ext)
    original_name TEXT NOT NULL,     -- Original name
    content_type TEXT,
    size_bytes BIGINT,
    uploaded_by INTEGER,             -- users.id
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

CREATE_TABLE_PAYMENT_REQUESTS_TRANSITIONS = """
CREATE TABLE IF NOT EXISTS state_transitions (
    id SERIAL PRIMARY KEY,
    from_state VARCHAR(50) NOT NULL,
    to_state VARCHAR(50) NOT NULL,
    role_required VARCHAR(50) NOT NULL,
    conditions TEXT
);
"""

CREATE_TABLE_SETTINGS = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

CREATE_UNIQUE_INDEX_USER_USERNAME = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower
ON users (LOWER(username));
"""

CREATE_UNIQUE_INDEX_USERS_EMAIL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower_unique
ON users (LOWER(email))
WHERE email IS NOT NULL AND email <> '';
"""

CREATE_INDEX_ENTRIES_DATE = """
CREATE INDEX IF NOT EXISTS idx_entries_date_id ON entries(date, id);
"""

CREATE_INDEX_USERNAME_LOWER = """
CREATE INDEX IF NOT EXISTS idx_users_username_lower 
ON users (LOWER(username));
"""
CREATE_INDEX_USERS_EMAIL = """
CREATE INDEX IF NOT EXISTS idx_users_email_lower    
ON users (LOWER(email)) 
WHERE email IS NOT NULL AND email <> '';
"""

CREATE_INDEX_ATTACHMENTS_TEMP = """
CREATE INDEX IF NOT EXISTS idx_attachments_temp_token
ON attachments_temp (temp_token, uploaded_by, created_at);
"""

CREATE_INDEX_PAYMENT_REQUESTS_ATTACHMENTS = """
CREATE INDEX IF NOT EXISTS idx_payment_requests_attachments_payment_requests_created
ON payment_requests_attachments(request_id, created_at DESC, id DESC);
"""

CREATE_INDEX_PAYMENT_REQUESTS_ACTION_USER = """
CREATE INDEX IF NOT EXISTS idx_za_payment_requests_action_user
ON payment_requests_audit(request_id, action, user_id);
"""

def migrate_columns(conn):
    conn.execute(text(CREATE_TABLE_ATTACHMENTS))
    conn.execute(text(CREATE_TABLE_ATTACHMENTS_TEMP))
    conn.execute(text(CREATE_TABLE_NOTES))
    conn.execute(text(CREATE_TABLE_PAYMENT_REQUESTS))
    conn.execute(text(CREATE_TABLE_PAYMENT_REQUESTS_AUDIT))
    conn.execute(text(CREATE_TABLE_PAYMENT_REQUESTS_ATTACHMENTS))
    conn.execute(text(CREATE_TABLE_PAYMENT_REQUESTS_TRANSITIONS))
    conn.execute(text(CREATE_TABLE_SETTINGS))

    conn.execute(text(CREATE_INDEX_ENTRIES_DATE))
    conn.execute(text(CREATE_INDEX_ATTACHMENTS_TEMP))
    conn.execute(text(CREATE_INDEX_PAYMENT_REQUESTS_ATTACHMENTS))
    conn.execute(text(CREATE_INDEX_PAYMENT_REQUESTS_ACTION_USER))
    conn.execute(text(CREATE_UNIQUE_INDEX_USER_USERNAME))
    conn.execute(text(CREATE_UNIQUE_INDEX_USERS_EMAIL))

    #conn.execute(text("ALTER TABLE payment_requests ADD COLUMN IF NOT EXISTS approver_snapshot JSONB"))
    
    try:
        current_len = conn.execute(text("""
            SELECT character_maximum_length
            FROM information_schema.columns
            WHERE table_name='payment_requests'
            AND column_name='paragraph'
            AND data_type='character varying'
        """)).scalar_one_or_none()

        if current_len is not None and current_len < 50:
            conn.execute(text("ALTER TABLE payment_requests ALTER COLUMN paragraph TYPE VARCHAR(50)"))
    except Exception:
        # Deliberately best effort – no crash, just logging
        logging.getLogger(__name__).exception("Migration paragraph -> VARCHAR(50) fehlgeschlagen")

    # Insert default values ​​if table is empty
    default_notes = [
        _("Withdrew money"),
        _("Inventory"),
        _("Count cash register"),
        _("Emptying cash register GR"),
        _("Delivery of Bottles"),
        _("Individual bottle purchase"),
        _("Deposit PayPal"),
        _("Donation")
    ]
    existing = conn.execute(text("SELECT COUNT(*) FROM notes")).scalar_one()
    if existing == 0:
        for text_value in default_notes:
            conn.execute(text("""
                INSERT INTO notes (text) VALUES (:t)
            """), {'t': text_value})

def init_db():
    with engine.begin() as conn:
        conn.execute(text("SELECT pg_advisory_lock(9223372036854775707)"))
        try:    
            conn.execute(text(CREATE_TABLE_ENTRIES))
            conn.execute(text(CREATE_TABLE_USERS))
            conn.execute(text(CREATE_TABLE_AUDIT))
            conn.execute(text(CREATE_TABLE_RESET))
            migrate_columns(conn)        
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(9223372036854775707)"))

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
            current_app.config['DB_INITIALIZED'] = True
            app.config['DB_INITIALIZED'] = True
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
        # Base URL hygiene check (for information only)
        if "localhost" in (APP_BASE_URL or "") or (APP_BASE_URL or "").strip() == "":
            logging.warning(
                _("APP_BASE_URL is not set to production-ready (currently '%(url)s'). "
                  "Set a publicly accessible base URL so that hints/links in emails are correct.",
                  url=(APP_BASE_URL or "")
                )
            )
        _initialized = True

@app.cli.command('cleanup-temp')
def cleanup_temp():
    """Delete temporary uploads, e.g., older than 24 hours."""
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
#404 – Not Found: For non-existent routes.
#500 – Internal Server Error: For unexpected server errors.
#403 – Forbidden: For access violations.
#401 – Unauthorized: For missing authentication.
# -----------------------
@app.errorhandler(401)
def unauthorized(e):
    # Optionally, use your own template errors/401.html; otherwise, continue using the 404 template.
    return render_template('errors/401.html'), 401

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(413)
def request_entity_too_large(e):
    flash(_('File too large. Please upload a smaller file.'), 'info')
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
    # Allow only digits (optional leading +/-, not necessary here)
    if not s.isdigit():
        return None
    return int(s)

# -----------------------
# Profile & 2FA management
# -----------------------
@app.get('/profile')
@login_required
def profile():
    user = current_user()
    theme = user.get('theme_preference') if user else 'system'
    themes = ['system', 'light', 'dark']
    # Retrieve backup codes from session ONCE
    new_codes = session.pop('new_backup_codes', None)
    return render_template(
        'profile.html',
        user=user,
        theme_preference=theme,
        ROLES=ROLES,
        themes=themes,
        new_backup_codes=new_codes,  # <-- hand over here
    )


@app.post('/profile')
@login_required
@require_csrf
def profile_post():
    uid = session['user_id']

    username = (request.form.get('username') or '').strip()
    email    = (request.form.get('email') or '').strip()
    pwd      = (request.form.get('password') or '').strip()
    pwd2     = (request.form.get('password2') or '').strip()

    # Passwortprüfung
    if pwd or pwd2:
        if len(pwd) < 8:
            flash(_('Password must be at least 8 characters long.'), 'info')
            return redirect(url_for('profile'))
        if pwd != pwd2:
            flash(_('Passwords do not match.'), 'info')
            return redirect(url_for('profile'))

    with engine.begin() as conn:

        # Username Duplicate-Check (case-insensitive, außer eigener User)
        exists_username = conn.execute(text("""
            SELECT 1 FROM users
            WHERE id <> :id AND LOWER(username) = LOWER(:u)
        """), {'id': uid, 'u': username}).scalar_one_or_none()

        if exists_username:
            flash(_('Username already exists.'), 'danger')
            return redirect(url_for('profile'))

        # E-Mail Duplicate-Check (falls gesetzt)
        if email:
            exists_email = conn.execute(text("""
                SELECT 1 FROM users
                WHERE id <> :id
                  AND email IS NOT NULL AND email <> ''
                  AND LOWER(email) = LOWER(:e)
            """), {'id': uid, 'e': email}).scalar_one_or_none()

            if exists_email:
                flash(_('Email already in use.'), 'danger')
                return redirect(url_for('profile'))

        # Query abhängig davon, ob das Passwort geändert wird
        if pwd:
            conn.execute(text("""
                UPDATE users
                SET username=:username,
                    email=:email,
                    password_hash=:ph,
                    must_change_password=FALSE,
                    updated_at=NOW()
                WHERE id=:id
            """), {
                'username': username,
                'email': email or None,
                'ph': generate_password_hash(pwd),
                'id': uid
            })
        else:
            conn.execute(text("""
                UPDATE users
                SET username=:username,
                    email=:email,
                    updated_at=NOW()
                WHERE id=:id
            """), {
                'username': username,
                'email': email or None,
                'id': uid
            })

    flash(_('Profile updated.'), 'success')
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
        flash(_('User not found.'), 'warning')
        return redirect(url_for('profile'))

    issuer = get_setting('app_title', 'BottleBalance')
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
        flash(_('User not found.'), 'warning')
        return redirect(url_for('profile'))

    issuer = get_setting('app_title', 'BottleBalance')
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
        flash(_('No 2FA setup active.'), 'warning')
        return redirect(url_for('profile'))
    code = (request.form.get('code') or '').strip()
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        flash(_('Invalid 2FA code.'), 'warning')
        return redirect(url_for('enable_2fa'))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET totp_secret=:s, totp_enabled=TRUE, updated_at=NOW() WHERE id=:id"),
                     {'s': secret, 'id': uid})
    session.pop('enroll_totp_secret', None)
    # Generate new codes and display them once in the profile
    codes = generate_and_store_backup_codes(uid)
    session['new_backup_codes'] = codes
    flash(_('2FA enabled.'), 'success')
    log_action(uid, '2fa:enabled', None, None)
    return redirect(url_for('profile'))

@app.post('/profile/2fa/disable')
@login_required
@require_csrf
def disable_2fa():
    uid = session['user_id']
    pwd = (request.form.get('password') or '').strip()

    # Check password
    with engine.begin() as conn:
        user = conn.execute(
            text("SELECT password_hash FROM users WHERE id=:id"),
            {'id': uid}
        ).mappings().first()

    if not user or not check_password_hash(user['password_hash'], pwd):
        flash(_('Password verification failed.'), 'warning')
        return redirect(url_for('profile'))

    # Disable 2FA + delete backup codes
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE users
            SET totp_secret=NULL,
                totp_enabled=FALSE,
                backup_codes='[]',
                updated_at=NOW()
            WHERE id=:id
        """), {'id': uid})

    flash(_('2FA disabled.'))
    log_action(uid, '2fa:disabled', None, None)
    return redirect(url_for('profile'))

@app.post('/profile/theme')
@login_required
@require_csrf
def update_theme():
    theme = request.form.get('theme')
    if theme not in ['light', 'dark', 'system']:
        flash(_('Invalid theme selection.'), 'danger')
        return redirect(url_for('profile'))
    uid = session.get('user_id')
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET theme_preference=:t, updated_at=NOW() WHERE id=:id"),
                     {'t': theme, 'id': uid})
    flash(_('Theme settings saved.'), 'success')
    return redirect(url_for('profile'))

@app.post('/profile/preferences')
@login_required
@require_csrf
def update_preferences():
    uid = session.get('user_id')
    language = request.form.get('language')
    theme = request.form.get('theme') or 'system'
    sort_order_desc = (request.form.get('sort_order_desc') == 'on')

    # UI (checked) = "current year only"  -> DB default_filter = False
    # UI (unchecked) = "All"              -> DB default_filter = True
    default_filter = (request.form.get('default_filter') != 'on')

    if language not in ['de', 'en']:
        flash(_('Invalid language.'), 'danger')
        return redirect(url_for('profile'))

    if theme not in ['light', 'dark', 'system']:
        flash(_('Invalid theme selection.'), 'danger')
        return redirect(url_for('profile'))

    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE users
            SET locale=:lang,
                theme_preference=:theme,
                sort_order_desc=:desc,
                default_filter=:df,
                updated_at=NOW()
            WHERE id=:id
        """), {
            'lang': language,
            'theme': theme,
            'desc': sort_order_desc,
            'df': default_filter,
            'id': uid
        })

    flash(_('Settings saved.'), 'success')
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
        # allows legacy {{ current_user() }} - returns itself
        return self
    def get(self, key, default=None):
        # allow legacy {{ current_user().get('field') }}
        return getattr(self, key, default)

@app.context_processor
def inject_theme():
    """
    Provides global template variables.
    Backwards-compat:
      - {{ current_user.is_authenticated }}
      - {{ current_user().get('username') }}
    """
    user_dict = current_user()  # uses existing DB function
    theme = 'system'
    if user_dict:
        cu = _CurrentUserProxy(**user_dict, is_authenticated=True)
        theme = user_dict.get('theme_preference') or 'system'
    else:
        cu = _CurrentUserProxy(is_authenticated=False)

    return {
        'theme_preference': theme,
        'current_user': cu,               # Object, but also accessible
        'ROLES': ROLES,
        'set': set,
        'IMPORT_USE_PREVIEW': IMPORT_USE_PREVIEW,
        'IMPORT_ALLOW_MAPPING': IMPORT_ALLOW_MAPPING,
        'format_date_de': format_date_de,
        'format_eur_de': format_eur_de,
        'csrf_token': csrf_token,
        '_': translate                   # Babel function for templates
    }

@app.context_processor
def inject_helpers():
    def qs(_remove=None, **overrides):
        # copy current arguments
        current = request.args.to_dict()
        # remove
        for k in (_remove or []):
            current.pop(k, None)
        # overwrite/add (only non-None)
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
# Admin: Users & Audit
# -----------------------
# User management

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
    flash(_('Approval authorization changed.'), 'success')
    return redirect(url_for('user_routes.users_list'))

# -----------------------
# CSV Import – Preview & Commit
# -----------------------
def _parse_csv_file_storage(file_storage):
    content = file_storage.read().decode('utf-8-sig')
    reader = csv.reader(io.StringIO(content), delimiter=';')
    headers = next(reader, None)
    # Robustness: Check header row and split if necessary
    if headers and len(headers) == 1 and ';' in headers[0]:
        headers = headers[0].split(';')

    expected = ['Date','Full','Empty','Inventory','Revenue','Expense','Cash balance','Note']
    alt_expected = ['Date','Full','Empty','Revenue','Expense','Note']
    if headers is None or [h.strip() for h in headers] not in (expected, alt_expected):
        raise ValueError(_('CSV header does not match the expected format.'))

    rows = []
    for row in reader:
        if not row or all(not (c or '').strip() for c in row):
            continue  # skip blank lines
        if len(row) == 8:
            date_s, voll_s, leer_s, _inv, ein_s, aus_s, _kas, note = row
        else:
            date_s, voll_s, leer_s, ein_s, aus_s, note = row
        date = parse_date_de_or_today(date_s)
        full = int((voll_s or '0').strip() or 0)
        empty = int((leer_s or '0').strip() or 0)
        revenue = parse_money(ein_s or '0')
        expense = parse_money(aus_s or '0')
        note = (note or '').strip()
        rows.append({
            'date': date,
            'full': full,
            'empty': empty,
            'revenue': str(revenue),
            'expense': str(expense),
            'note': note
        })
    return rows

@app.get('/import/sample')
@login_required
@require_perms('import:csv')
def import_sample():
    """
    Provides a sample CSV file in long format with all columns.
    """
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', lineterminator='\n')
    writer.writerow(['Date','Full','Empty','Inventory','Revenue','Expense','Cash balance','Note'])
    today = date.today()
    samples = [
        (today - timedelta(days=4), 10, 0, 'Bottle purchasing'),
        (today - timedelta(days=3), 0, 2, 'Return empties'),
        (today - timedelta(days=2), 0, 0, 'Cash register start'),
        (today - timedelta(days=1), 5, 0, 'Repurchase'),
        (today, 0, 1, 'Withdrawal'),
    ]
    inv = 0
    kas = Decimal('0.00')
    for d, voll, leer, note in samples:
        inv += (voll - leer)
        revenue = Decimal('12.50') if voll else Decimal('0')
        expense = Decimal('1.20') if leer else Decimal('0')
        kas = (kas + revenue - expense).quantize(Decimal('0.01'))
        writer.writerow([
            d.strftime('%d.%m.%Y'), voll, leer, inv,
            str(revenue).replace('.', ','), str(expense).replace('.', ','), str(kas).replace('.', ','),
            note
        ])
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))
    mem.seek(0)
    download_name = f"{get_setting('app_title', 'BottleBalance')}_{_('example')}.csv"
    return send_file(mem, as_attachment=True, download_name=download_name, mimetype='text/csv')


@app.post('/import/preview')
@login_required
@require_perms('import:csv')
@require_csrf
def import_preview():
    """
    Shows the preview for CSV import with auto-mapping and manual remapping.
    - First call: File is read, auto-mapping is determined, CSV is stored in /tmp.
    - Remap: Apply mapping indices from the form, parse CSV from /tmp again.
    """
    # If preview is disabled via feature switch -> use legacy import
    if not IMPORT_USE_PREVIEW: 
        flash(_('CSV preview is disabled.'), 'info')
        return redirect(url_for('bbalance_routes.index'))

    replace_all = request.form.get('replace_all') == 'on'
    token = (request.form.get('token') or '').strip()
    is_remap = request.form.get('remap') == '1'

    # ---------- REMAP PATH (Parse CSV again with manual mapping) ----------
    if is_remap and token:
        stash = session.get('import_previews', {}).get(token)
        if not stash:
            flash(_('Preview expired or not found.'), 'warning')
            return redirect(url_for('bbalance_routes.index'))

        tmp_path = stash.get('csv_path')
        if not tmp_path or not os.path.exists(tmp_path):
            flash(_('CSV file not found.'), 'danger')
            return redirect(url_for('bbalance_routes.index'))

        # Load CSV
        try:
            with open(tmp_path, 'r', encoding='utf-8-sig') as f:
                content = f.read()
        except Exception as e:
            logger.exception("CSV read failed: %s", e)
            flash(_('CSV could not be read.'), 'danger')
            return redirect(url_for('bbalance_routes.index'))

        # Apply mapping from form
        if IMPORT_ALLOW_MAPPING:
            def _opt_int(v):
                return int(v) if (v not in (None, '', '__none__')) else None
            def _get(name):
                return request.form.get(f'map_{name.lower()}')
            mapping = {
                'Date':     _opt_int(_get('Date')),
                'Full':   _opt_int(_get('Full')),
                'Empty':   _opt_int(_get('Empty')),
                'Revenue':  _opt_int(_get('Revenue')),
                'Expense':   _opt_int(_get('Expense')),
                'Note': _opt_int(_get('Note')),
            }
        else:
            mapping = None

        try:
            preview_rows, headers, dup_count = _parse_csv_with_mapping(content, replace_all, mapping)
        except Exception as e:
            logger.exception("Import preview (remap) failed: %s", e)
            flash(f"{_('Preview failed:')} {e}", 'danger')
            return redirect(url_for('bbalance_routes.index'))

        # Update Stash
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
            mapping=mapping  # <- for auto-preselection in the drop-down menus
        )

    # ---------- FIRST UPLOAD (file comes from the client) ----------
    file = request.files.get('file')
    if not file or file.filename == '':
        flash(_('Please select a CSV file.'), 'info')
        return redirect(url_for('bbalance_routes.index'))

    try:
        # Load content
        content = file.read().decode('utf-8-sig')

        # Preview without explicit mapping -> Auto-mapping in the parser
        preview_rows, headers, dup_count = _parse_csv_with_mapping(content, replace_all, mapping=None)

        # Generate tokens
        token = str(uuid4())

        # Store CSV on the server side in /tmp (no large sessions)
        tmp_dir = '/tmp'
        os.makedirs(tmp_dir, exist_ok=True)
        tmp_path = os.path.join(tmp_dir, f"bb_import_{token}.csv")
        with open(tmp_path, 'w', encoding='utf-8-sig') as f:
            f.write(content)

        # Calculate auto-mapping separately and save it in Stash for the UI
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
            mapping=session['import_previews'][token].get('mapping')  # <- Auto preselection
        )
    except Exception as e:
        logger.exception("Import preview failed: %s", e)
        flash(f"{_('Preview failed:')} {e}", 'danger')
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
        flash(_('Preview expired or not found.'), 'warning')
        return redirect(url_for('bbalance_routes.index'))

    stash = session['import_previews'].pop(token, None)
    session.modified = True
    if not stash:
        flash(_('Preview expired or already used.'), 'warning')
        return redirect(url_for('bbalance_routes.index'))

    tmp_path = stash.get('csv_path')
    replace_all = bool(stash.get('replace_all'))
    mapping = stash.get('mapping')

    if not tmp_path or not os.path.exists(tmp_path):
        flash(_('CSV file not found.'), 'danger')
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
                    INSERT INTO entries (date, "full", "empty", revenue, expense, note)
                    VALUES (:date,:full,:empty,:revenue,:expense,:note)
                """), {k: r[k] for k in ('date','full','empty','revenue','expense','note')})
                inserted += 1

        # Delete temporary file
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
        flash(_('Import successful: %(rows)d lines transferred.', rows=inserted), 'success')
        return redirect(url_for('bbalance_routes.index'))

    except Exception as e:
        logger.exception("Import commit failed: %s", e)
        # Error message with placeholder
        flash(_('Import failed: %(error)s', error=str(e)), 'danger')
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

    # NEW: Pre-initialize mapping
    content = None
    mapping = None
    # Data sources …
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
            w.writerow(['Date','Full','Empty','Revenue','Expense','Note'])
            for r in body['rows']:
                w.writerow([
                    r.get('Date',''),
                    r.get('Full',''),
                    r.get('Empty',''),
                    r.get('Revenue',''),
                    r.get('Expense',''),
                    r.get('Note',''),
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
                    'date': r['date'].strftime('%Y-%m-%d') if r['date'] else None,
                    'full': r['full'],
                    'empty': r['empty'],
                    'revenue': r['revenue'],
                    'expense': r['expense'],
                    'note': r['note'],
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
def _pdf_logo_path():
    fname, fpath, _ = _find_custom_logo()
    if fname:
        ext = fname.rsplit('.', 1)[1].lower()
        if ext in ('png', 'jpg', 'jpeg'):
            return fpath  # ReportLab kann SVG nicht direkt rendern
    return os.path.join(app.root_path, 'static', 'images', 'logo.png')

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

    logo_path = _pdf_logo_path()
    if os.path.exists(logo_path):
        story.append(RLImage(logo_path, width=25*mm, height=25*mm))
        story.append(Spacer(1, 6))

    # --- Title (real markup, no HTML entities) ---
    #story.append(Paragraph(f"<b>get_setting('app_title'){_(' - Export')}</b>", styles['Title']))
    #story.append(Spacer(1, 6))
    app_name = get_setting('app_title', 'BottleBalance')
    title = f"<b>{app_name}{_(' - Export')}</b>"
    story.append(Paragraph(title, styles['Title']))
    story.append(Spacer(1, 6))

    # ---- HELP FORMATTER: Show only changed cells ----
    def fmt_fl(n: int | None) -> str:
        """Number of bottles; empty if 0/None, otherwise 'N bottles' (localized)."""
        n = int(n or 0)
        return '' if n == 0 else f"{n} {_('Btl.')}"

    def fmt_money(d: Decimal | None) -> str:
        """Currency; empty if 0/None, otherwise formatted."""
        d = d if d is not None else Decimal('0')
        return '' if d == 0 else format_eur_de(d)

    HIDE_CUMULATIVE_WHEN_UNCHANGED = True

    # ---- Build table ----
    data = [[
        _('Date'), _('Full'), _('Empty'), _('Inventory'),
        _('Revenue'), _('Expense'), _('Cash balance'), _('Note')
    ]]

    for e in entries:
        # "changed" criterion
        changed = any([
            int(e['full'] or 0) != 0,
            int(e['empty'] or 0) != 0,
            Decimal(e['revenue'] or 0) != 0,
            Decimal(e['expense'] or 0) != 0
        ])

        # Cell values ​​(with optional hiding)
        inv_cell = '' if (HIDE_CUMULATIVE_WHEN_UNCHANGED and not changed) else fmt_fl(e['inventory'])
        kas_cell = '' if (HIDE_CUMULATIVE_WHEN_UNCHANGED and not changed) else format_eur_de(e['cashBalance'])

        data.append([
            # Date always display
            format_date_de(e['date']),

            # Only changed fields (0 -> empty)
            fmt_fl(e['full']),
            fmt_fl(e['empty']),

            # Inventory: Optionally clear the line if it remains unchanged.
            inv_cell,
            fmt_money(e['revenue']),
            fmt_money(e['expense']),

            # Cash balance: optional emptyif cell unchanged
            kas_cell,

            # Note: empty if None/''; left aligned
            Paragraph(e['note'] or '', styles['Normal'])
        ])

    # Dynamic column widths (fit securely into the type area)
    table_width = doc.width
    col_widths = [table_width * w for w in [
        0.10,  # Date
        0.08,  # Full
        0.08,  # Empty
        0.09,  # Inventory
        0.10,  # Revenue
        0.10,  # Expense
        0.14,  # Cash balance
        0.21,  # Note
    ]]

    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        # Center header
        ('ALIGN', (0,0), (-1,0), 'CENTER'),

        # Data rows: everything right-aligned, except for the note on the left
        ('ALIGN', (0,1), (6,-1), 'RIGHT'),
        ('ALIGN', (7,1), (7,-1), 'LEFT'),

        # Header styling
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f3f5')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#212529')),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),

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

    filename = f"{get_setting('app_title', 'BottleBalance')}_{_('export')}_{date.today().strftime('%Y%m%d')}.pdf"
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
        flash(_('Language changed.'), 'success')
    return redirect(url_for('profile'))

# -----------------------
# Payment requests
# -----------------------
def parse_date_iso_or_today(s: str | None) -> date:
    try:
        return datetime.strptime(s.strip(), '%Y-%m-%d').date()
    except Exception:
        return date.today()

# -----------------------
# SMTP Test Mail if param SEND_TEST_MAIL is set to true
# -----------------------
@app.route("/admin/tools", methods=["GET", "POST"])
@login_required
@require_perms('admin:tools')
def admin_tools():
    """
    Settings for administrative tools:
        - Send SMTP test email
        - Create and download database dump
        - Completely override notes

    Safety:
        - Login and role permissions (admin:tools) are required.
        - CSRF protection is only available for POST actions.
    """
    state = None
    current_notes = []

    # --- POST-ACTIONS ---
    if request.method == "POST":
        # Only check CSRF for POST
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

                    # Only start TLS if no SSL connection is being used
                    if SMTP_TLS and not SMTP_SSL_ON:
                        server.starttls(context=ssl.create_default_context())

                    server.login(SMTP_USER, SMTP_PASS)

                    # Prepare test email
                    message = MIMEText(
                        _("This is a test message to check the SMTP configuration."),
                        "plain",
                        "utf-8"
                    )
                    message["Subject"] = Header(_("SMTP test by %(app)s", app=get_setting('app_title', 'BottleBalance')), "utf-8")
                    message["From"] = FROM_EMAIL
                    message["To"] = SMTP_USER

                    server.sendmail(FROM_EMAIL, [SMTP_USER], message.as_string())
                    server.quit()

                    flash(_("SMTP test successful – test email sent."), "success")
            except Exception as e:
                flash(_("SMTP test failed: ") + str(e), "error")

        # 2) Database dump
        elif action == "dump":
            dump_file = f"/tmp/{get_setting('app_title', 'BottleBalance')}_{_('dump')}.sql"
            env = os.environ.copy()
            env["PGPASSWORD"] = DB_PASS
            try:
                # Create dump
                with open(dump_file, "w") as f:
                    subprocess.run(
                        ["pg_dump", "-U", DB_USER, "-h", DB_HOST, DB_NAME],
                        stdout=f,
                        env=env,
                        check=True
                    )

                # Audit + Download
                log_action(session.get('user_id'), 'db:export', None, f'Dump from {DB_NAME} created')
                flash(_('Database dump successfully generated.'), "success")
                download_name = f"{get_setting('app_title', 'BottleBalance')}_{_('dump')}.sql"
                return send_file(dump_file, as_attachment=True, download_name=download_name)

            except subprocess.CalledProcessError as e:
                flash(_('Error during database dump: %(error)s', error=str(e)), "error")
                log_action(session.get('user_id'), 'db:export:error', None, f'Dump failed: {e}')

        # 3) Override notes
        elif action == "update_notes":
            raw = request.form.get("options") or ""
            lines = [line.strip() for line in raw.splitlines() if line.strip()]
            try:
                with engine.begin() as conn:
                    conn.execute(text("DELETE FROM notes"))
                    for line in lines:
                        conn.execute(
                            text("INSERT INTO notes (text) VALUES (:t)"),
                            {'t': line}
                        )
                flash(_("Updated notes."), "success")
            except Exception as e:
                flash(_("Error saving notes: %(error)s", error=str(e)), "error")

        # 4) Upload branding logo
        elif action == "branding_upload":
            file = request.files.get("logo")
            if not file or file.filename == "":
                flash(_("Please select an image file."), "info")
                return redirect(url_for("admin_tools"))

            # Check size (if function available): MAX_CONTENT_LENGTH caps on the server side anyway
            try:
                from modules.core_utils import validate_file
                if not validate_file(file):
                    return redirect(url_for("admin_tools"))
            except Exception:
                pass

            # Strictly check the extension against your ALLOWED_LOGO_EXTS
            ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
            if ext not in ALLOWED_LOGO_EXTS:
                flash(_("Invalid file format. Permitted formats: SVG, PNG, JPG, WEBP."), "danger")
                return redirect(url_for("admin_tools"))

            target_name = f"logo.{ext}"
            target_path = os.path.join(BRANDING_DIR, target_name)

            # Alte Logos entfernen
            for old_ext in ('svg', 'png', 'jpg', 'jpeg', 'webp'):
                old_path = os.path.join(BRANDING_DIR, f"logo.{old_ext}")
                try:
                    if os.path.isfile(old_path):
                        os.remove(old_path)
                except Exception:
                    pass

            # Speichern
            try:
                os.makedirs(BRANDING_DIR, exist_ok=True)
                file.save(target_path)
                flash(_("Logo successfully uploaded."), "success")
            except Exception as e:
                flash(_("Upload failed: %(error)s", error=str(e)), "danger")

            return redirect(url_for("admin_tools"))
        
        elif action == "branding_remove":
            removed_files = []
            errors = []

            for old_ext in ('svg', 'png', 'jpg', 'jpeg', 'webp'):
                old_path = os.path.join(BRANDING_DIR, f"logo.{old_ext}")
                try:
                    if os.path.isfile(old_path):
                        os.remove(old_path)
                        removed_files.append(f"logo.{old_ext}")
                except Exception as e:
                    errors.append(f"{old_path}: {e}")

            if removed_files:
                log_action(session.get('user_id'), 'branding:remove', None, f"removed={removed_files}")
                flash(_("Custom logo removed. Fallback to default logo active."), "success")
            elif errors:
                # Mindestens eine Datei war da, aber löschen schlug fehl
                for msg in errors:
                    flash(_("Could not delete file: %(msg)s", msg=msg), "danger")
                log_action(session.get('user_id'), 'branding:remove:error', None, "; ".join(errors))
            else:
                flash(_("No logo found."), "info")

            return redirect(url_for("admin_tools"))
        
        # 5) Set application title
        elif action == "set_app_title":
            new_title = (request.form.get("app_title") or "").strip()
            if not new_title:
                flash(_("App title cannot be empty."), "danger")
                return redirect(url_for("admin_tools"))
            set_setting('app_title', new_title)
            flash(_("Application title updated."), "success")
            return redirect(url_for("admin_tools"))

        # Fallback for unknown action
        else:
            flash(_("Unknown action."), "error")

        # Redirect after each POST action to avoid duplicate submissions
        return redirect(url_for("admin_tools"))

    # --- GET: View state & current options ---
    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        state = _("SMTP configuration incomplete.")
    else:        
        state = _("SMTP configuration detected for host %(host)s:%(port)s.",
                host=SMTP_HOST, port=SMTP_PORT)

    try:
        with engine.begin() as conn:
            current_notes = conn.execute(
                text("SELECT text FROM notes ORDER BY text ASC")
            ).scalars().all()
    except Exception:
        current_notes = []

    return render_template("admin_tools.html", state=state, current_notes=current_notes)

@app.template_filter('strftime')
def _jinja2_filter_datetime(value, format='%Y-%m-%d'):
    """
    Formats a datetime/date object with strftime.
    Returns an empty string if value is None.
    """
    if value is None:
        return ''
    try:
        return value.strftime(format)
    except AttributeError:
        return str(value)

@app.route('/view/<path:filename>')
def view_file(filename):
    response = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:;"
    return response

@app.route("/attachments/<int:att_id>/view")
@login_required
def attachments_view(att_id: int):
    # 1) Get details from DB
    with engine.begin() as conn:
        r = conn.execute(text("""
            SELECT a.id, a.entry_id, a.stored_name, a.original_name, a.content_type
            FROM attachments a
            WHERE a.id = :id
        """), {'id': att_id}).mappings().first()

    if not r:
        abort(404)

    # 2) Check access rights
    if not _user_can_view_entry(r['entry_id']):
        abort(403)

    # 3) Resolve & check file path
    path = os.path.join(_entry_dir(r['entry_id']), r['stored_name'])
    if not os.path.exists(path):
        abort(404)

    # 4) Determine MIME type (prefer DB value, otherwise guess)
    mimetype = r.get('content_type') or (
        mimetypes.guess_type(r['original_name'])[0] or 'application/octet-stream'
    )

    # 5) Audit-Log
    log_action(session.get('user_id'), 'attachments:view', r['entry_id'], f"att_id={att_id}")

    # 6) Display inline + security header
    resp = send_file(
        path,
        as_attachment=False,
        mimetype=mimetype,
        download_name=r['original_name']  # Optional: helps browsers display
    )
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    # Optional: CSP, if you want to be very restrictive
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
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)