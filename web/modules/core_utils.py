# -----------------------
# CORE Configuration
# -----------------------

import os
import pytz
from flask import session,flash, abort, request
from flask_babel import _
from sqlalchemy import text
from sqlalchemy.engine import Engine, create_engine
from datetime import datetime

APP_BASE_URL = os.getenv("APP_BASE_URL") or "http://localhost:5000"

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(24)
DB_HOST = os.getenv("DB_HOST", "bottlebalance-db")
DB_NAME = os.getenv("DB_NAME", "bottlebalance")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "admin")
DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"

engine: Engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True)

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
    Gibt einen lokalisierten Zeitstempel als formatierten String zurück.
    Standardformat: '2025-09-10 19:44:47'
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
        'entries:view', 'entries:add', 'entries:edit:any', 'entries:delete:any','export:pdf', 
        'import:csv', 
        'users:manage', 'users:setApprover', 
        'payment:view', 'payment:manage'
    },
    'Payment Viewer': {
        'payment:view'
    },
    'Editor': {
        'entries:view', 'entries:add', 'entries:edit:own', 'entries:delete:own', 'export:pdf'
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
        flash(_("Datei zu groß. Maximal erlaubt: 10 MB."), "danger")
        return False
    return True

# --- Verzeichnisse ---
def _entry_dir(entry_id: int) -> str:
    p = os.path.join(UPLOAD_FOLDER, str(entry_id))
    os.makedirs(p, exist_ok=True)
    return p

def _temp_dir(token: str) -> str:
    p = os.path.join(UPLOAD_FOLDER, "temp", token)
    os.makedirs(p, exist_ok=True)
    return p

def _require_temp_token(token: str):
    if not token or session.get('add_temp_token') != token:
        abort(403)

# --- Audit-Log ---
def log_action(user_id: int | None, action: str, entry_id: int | None, detail: str | None = None):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO audit_log (user_id, action, entry_id, detail)
            VALUES (:u, :a, :e, :d)
        """), {'u': user_id, 'a': action, 'e': entry_id, 'd': detail})

def build_base_url():
    # bevorzuge APP_BASE_URL, fallback auf request.url_root
    try:
        base = os.getenv("APP_BASE_URL") or request.url_root
    except RuntimeError:
        base = os.getenv("APP_BASE_URL") or "http://localhost:5000/"
    return base.rstrip("/") + "/"
