# modules/core_utils.py
# -----------------------
# CORE Configuration
# -----------------------
import os
import pytz
import secrets
from flask import session,flash, abort, request
from flask_babel import _
from sqlalchemy import text
from sqlalchemy.engine import Engine, create_engine
from functools import lru_cache

APP_BASE_URL = os.getenv("APP_BASE_URL") or "http://localhost:5000"

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(24)

if not os.getenv("SECRET_KEY"):
    # Nur Logging – damit du erkennst, wenn du versehentlich ohne festen Key startest
    import logging
    logging.getLogger(__name__).warning(
        "SECRET_KEY fehlt – es wird ein zufälliger Key verwendet. "
        "Sessions/CSRF-Tokens sind nach Neustart ungültig. Bitte SECRET_KEY in der ENV setzen."
    )
DB_HOST = os.getenv("DB_HOST", "bottlebalance-db")
DB_NAME = os.getenv("DB_NAME", "bottlebalance")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "admin")
DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"

engine: Engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
    pool_recycle=1800,    # Recycle after 30 minutes
    pool_timeout=30       # Optional: Waiting time when borrowing a connection
)

def _require_temp_token(token: str) -> None:
    """
    Validiert, dass der übergebene Token syntaktisch korrekt ist und
    exakt der Session-Token ist, der beim Rendern gesetzt wurde.
    """
    if not token:
        abort(403)

    # 1) Syntax: 32-64 Zeichen Hex (anpassen an deine Erzeugung)
    allowed_len = {32, 64}
    if len(token) not in allowed_len or any(c not in '0123456789abcdef' for c in token.lower()):
        abort(403)

    # 2) Session-Match
    sess_tok = session.get('temp_token')
    if not sess_tok or token != sess_tok:
        abort(403)

def localize_dt(dt, tz_name=None):
    if not dt:
        return ''
    if not tz_name:
        tz_name = session.get('timezone', 'Europe/Berlin')
    tz = pytz.timezone(tz_name)
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(tz)

def localize_dt_str(dt, tz_name=None, fmt='%Y-%m-%d %H:%M:%S'):
    """
    Returns a localized timestamp as a formatted string.
    Default format: '2025-09-10 19:44:47'
    """
    if not dt:
        return ''
    local_dt = localize_dt(dt, tz_name)
    return local_dt.strftime(fmt)

# -----------------------
# Roles
# -----------------------
ROLES = {
    'Admin': {
        'entries:view', 'entries:add', 'entries:edit:any', 'entries:delete:any',
        'export:csv', 'export:pdf', 'export:db', 
        'import:csv', 
        'users:manage', 'users:setApprover', 
        'payment:view', 'payment:manage', 'payment:audit',
        'audit:view',
        'admin:tools'
    },
    'Manager': {
        'entries:view', 'entries:add', 'entries:edit:any', 'entries:delete:any','export:csv', 'export:pdf',
        'import:csv', 
        'users:manage', 'users:setApprover', 
        'payment:view', 'payment:manage'
    },
    'Payment Viewer': {
        'payment:view'
    },
    'Editor': {
        'entries:view', 'entries:add', 'entries:edit:own', 'entries:delete:own', 'export:pdf', 'entries:edit:any'
    },
    'Viewer': {
        'entries:view', 
        'export:csv', 'export:pdf'
    },
    'Auditor': {
        'entries:view', 
        'audit:view'
    }
}

# -----------------------
# Document Upload
# -----------------------
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER") or "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    'pdf','png','jpg','jpeg','gif','webp','heic','heif','svg',
    'txt','csv','doc','docx','xls','xlsx','ppt','pptx','xml','json'
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def allowed_file(filename: str) -> bool:
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def validate_file(file):
    if file.content_length > MAX_FILE_SIZE:
        flash(_("File too large. Maximum allowed: 10 MB."), "danger")
        return False
    return True

# --- Directories ---
def _entry_dir(entry_id: int) -> str:
    p = os.path.join(UPLOAD_FOLDER, str(entry_id))
    os.makedirs(p, exist_ok=True)
    return p

def _temp_dir(token: str) -> str:
    p = os.path.join(UPLOAD_FOLDER, "temp", token)
    os.makedirs(p, exist_ok=True)
    return p

# --- Audit-Log ---
def log_action(user_id: int | None, action: str, entry_id: int | None, detail: str | None = None):
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO audit_log (user_id, action, entry_id, detail)
                VALUES (:u, :a, :e, :d)
            """), {'u': user_id, 'a': action, 'e': entry_id, 'd': detail})
    except Exception:
        # Just log – never jeopardize the main action.
        import logging
        logging.getLogger(__name__).exception("Audit-Log fehlgeschlagen: %s", action)


def build_base_url():
    # prefer APP_BASE_URL, fallback to request.url_root
    try:
        base = os.getenv("APP_BASE_URL") or request.url_root
    except RuntimeError:
        base = os.getenv("APP_BASE_URL") or "http://localhost:5000/"
    return base.rstrip("/") + "/"

@lru_cache(maxsize=256)
def get_setting(key: str, default: str | None = None) -> str | None:
    """
    Liest einen App-Setting-Wert aus der Tabelle 'settings'.
    Gibt 'default' zurück, wenn nicht vorhanden oder DB noch nicht erreichbar.
    """
    try:
        with engine.begin() as conn:
            val = conn.execute(
                text("SELECT value FROM settings WHERE key = :k"),
                {'k': key}
            ).scalar_one_or_none()
        return val if val is not None else default
    except Exception:
        # robust gegen Import-/Init-Reihenfolge (z.B. Tabelle noch nicht angelegt)
        return default

def set_setting(key: str, value: str) -> None:
    """
    Schreibt/aktualisiert einen Setting-Wert und invalidiert den Cache.
    """
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO settings (key, value)
            VALUES (:k, :v)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        """), {'k': key, 'v': value})
    # Cache leeren, damit get_setting sofort den neuen Wert liefert
    try:
        get_setting.cache_clear()
    except Exception:
        pass

def find_custom_logo():
    """
    Returns (filename, full_path) for the uploaded branding logo.
    Searches UPLOAD_FOLDER/branding/ for files named:
    logo.svg, logo.png, logo.jpg, logo.jpeg, logo.webp

    Returns (None, None) if no custom logo exists.
    """
    try:
        branding_dir = os.path.join(UPLOAD_FOLDER, "branding")
        if not os.path.isdir(branding_dir):
            return None, None

        for ext in ("svg", "png", "jpg", "jpeg", "webp"):
            fname = f"logo.{ext}"
            fpath = os.path.join(branding_dir, fname)
            if os.path.isfile(fpath):
                return fname, fpath
    except Exception:
        pass  # Fail silently to avoid blocking PDF generation

    return None, None
