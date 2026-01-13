
# -----------------------
# SMTP Test Mail via /admin/smtp
# -----------------------
import ssl
from flask import render_template, request, redirect, url_for, flash, Blueprint
from flask_babel import _
from markupsafe import escape
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr, make_msgid
from smtplib import SMTP, SMTP_SSL

from modules.auth_utils import login_required, require_perms, require_csrf
from modules.mail_utils import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
    SMTP_TLS, SMTP_SSL_ON, SMTP_TIMEOUT, FROM_EMAIL
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
            if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS or not FROM_EMAIL:
                flash(_("SMTP configuration incomplete."), "error")
                return redirect(url_for("admin_smtp"))

            # 1) Establishing a connection
            if SMTP_SSL_ON:
                context = ssl.create_default_context()
                server = SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context)
            else:
                server = SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
                if SMTP_TLS:
                    server.starttls(context=ssl.create_default_context())

            server.login(SMTP_USER, SMTP_PASS)

            # 2) Build message UTF-8 correctly
            subject = Header(_("SMTP test by %(app)s", app=_("AppTitle")), "utf-8")
            body_text = _("This is a test message to check the SMTP configuration.")

            msg = MIMEText(body_text, "plain", "utf-8")
            msg["Subject"] = str(subject)

            # Encode display names (UTF-8) correctly for headers:
            from_display = str(Header(_("BottleBalance"), 'utf-8'))
            to_display = str(Header(_("SMTP Recipient"), 'utf-8'))

            # Envelope addresses MUST be ASCII:
            from_envelope = FROM_EMAIL                 # e.g. 'mailer@example.com'
            to_envelope = SMTP_USER                    # e.g. 'admin@example.com'

            # Headers (may contain encoded words):
            msg["From"] = formataddr((from_display, from_envelope))
            msg["To"] = formataddr((to_display, to_envelope))
            msg["Message-ID"] = make_msgid()
            msg["X-Mailer"] = "BottleBalance"

            #3) Send – preferably send_message (correctly formats headers/bytes)
            # If the server supports SMTPUTF8 and you have NON-ASCII in the header/display name:
            mail_opts = []
            try:
                # Check CAPA (optional defensive measure, does not cause fatal errors on some servers)
                if server.has_extn('smtputf8'):
                    mail_opts.append('SMTPUTF8')
            except Exception:
                pass

            server.send_message(
                msg,
                from_addr=from_envelope,
                to_addrs=[to_envelope],
                mail_options=mail_opts
            )
            server.quit()

            flash(_("SMTP test successful – test email sent."), "success")

        except Exception as e:
            #e can contain non-ASCII characters. str(e) is usually okay; escape protects HTML.
            flash(_('SMTP test failed: %(error)s', error=escape(str(e))), "error")

        return redirect(url_for("admin_smtp"))

    # GET: Status display
    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        state = "SMTP configuration incomplete."
    else:
        state = f"SMTP configuration detected for host {SMTP_HOST}:{SMTP_PORT}."

    return render_template("admin_smtp.html", state=state)
