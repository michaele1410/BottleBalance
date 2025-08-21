# -----------------------
# SMTP Test Mail via url/admin/smtp
# -----------------------

mail_routes = Blueprint('mail_routes', __name__)

@mail_routes.route("/admin/smtp", methods=["GET", "POST"])
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