import smtplib
import ssl
import os
import logging

# SMTP-Konfiguration aus Umgebungsvariablen laden
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "0"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_TLS = os.getenv("SMTP_TLS", "false").lower() == "true"
SMTP_SSL = os.getenv("SMTP_SSL", "false").lower() == "true"
SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "10"))
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER)
TO_EMAIL = os.getenv("SMTP_TEST_RECIPIENT", SMTP_USER)  # Optional: Empfänger für Testmail
# Logging konfigurieren
logger = logging.getLogger("smtp_check")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[SMTP Check] %(levelname)s: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

def check_smtp_configuration():
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS]):
        logger.warning("SMTP-Konfiguration unvollständig – keine Verbindung möglich.")
        return

    try:
        if SMTP_SSL:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
            if SMTP_TLS:
                server.starttls()

        server.login(SMTP_USER, SMTP_PASS)

        # UTF-8-kodierte Test-E-Mail senden
        message = (
            "Subject: SMTP-Test von BottleBalance\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Dies ist eine automatische Testnachricht zum Überprüfen der SMTP-Konfiguration. Enthält Umlaute wie Ü, Ä, Ö und ß."
        ).encode("utf-8")

        server.sendmail(FROM_EMAIL, TO_EMAIL, message)
        server.quit()
        logger.info("SMTP-Verbindung erfolgreich und Test-E-Mail versendet.")
    except Exception as e:
        logger.warning(f"SMTP-Test fehlgeschlagen: {e}")