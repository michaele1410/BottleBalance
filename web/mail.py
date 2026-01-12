# -----------------------
# SMTP Test Mail via url/admin/smtp
# -----------------------
import ssl

from flask import render_template, request, redirect, url_for, flash, Blueprint
from flask_babel import _
from markupsafe import escape
from email.mime.text import MIMEText
from email.header import Header
from smtplib import SMTP, SMTP_SSL

from modules.auth_utils import (
    login_required,
    require_perms,
    require_csrf
)

from modules.mail_utils import (
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASS,
    SMTP_TLS,
    SMTP_SSL_ON,
    SMTP_TIMEOUT
)
mail_routes = Blueprint('mail_routes', __name__)

@mail_routes.route("/admin/smtp", methods=["GET", "POST"])
@login_required
@require_perms('admin:tools')
@require_csrf
def admin_smtp():
    state = None
    if request.method == "POST":
        try:
            if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
                flash(_("SMTP configuration incomplete."), "error")
                return redirect(url_for("admin_smtp"))

            # Establish connection
            if SMTP_SSL_ON:
                context = ssl.create_default_context()
                server = SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context)
            else:
                server = SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
                if SMTP_TLS:
                    server.starttls(context=ssl.create_default_context())

            server.login(SMTP_USER, SMTP_PASS)

            # UTF-8 secure test mail object
            subject = Header(_("SMTP test by %(app)s", app=_("AppTitle")), "utf-8")
            body_text = _("This is a test message to check the SMTP configuration.")
            message = MIMEText(body_text, "plain", "utf-8")
            message["Subject"] = subject
            message["From"] = FROM_EMAIL
            message["To"] = SMTP_USER

            server.sendmail(FROM_EMAIL, SMTP_USER, message.as_string())
            server.quit()

            flash(_("SMTP test successful – test email sent."), "success")
        except Exception as e:
            flash(_('SMTP test failed: %(error)s', error=escape(str(e))), "error")
        return redirect(url_for("admin_smtp"))

    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        state = "SMTP configuration incomplete."
    else:
        state = f"SMTP configuration detected for host {SMTP_HOST}:{SMTP_PORT}."

    return render_template("admin_smtp.html", state=state)
