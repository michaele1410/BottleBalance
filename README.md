
# 🥤 BottleBalance Webapp – RBAC + 2FA + Audit + CI

[Deutsch](#-deutsch) • [English](#-english)

---

## 🇩🇪 Deutsch

### Highlights
- **RBAC**: Rollen *Admin, Manager, Editor, Viewer, Auditor*
- **Benutzerverwaltung** (Admin): Anlegen, aktivieren/deaktivieren, Rolle ändern, Passwort setzen, **Reset‑Link generieren**
- **2FA (TOTP)**: Einrichten über QR‑Code, Login mit Code (Microsoft/Google Authenticator)
- **Passwort‑Reset**: Tokenbasiert, Link 2h gültig (SMTP optional)
- **Audit‑Log**: Ansicht mit Filter (Zeit, Text), bis 500 Einträge
- **Filter**: Datum von/bis + Suche, **Summen im Filterbereich**
- **Sparklines** unter Inventar/Kassenbestand
- **CSV/PDF‑Export**, **CSV‑Import**
- **Keine Klartext‑Logins** in Dateien; Default‑Admin zur Laufzeit
- **CI/CD (GitHub Actions)**: Image bauen & in GHCR pushen

### Schnellstart
```bash
docker compose up --build
# Browser: http://localhost:5000
# Erstlogin: admin / admin  → Passwortänderung wird erzwungen
```

### Konfiguration (ENV)
- **Optional**: `SECRET_KEY` (sonst wird zufällig generiert)
- **SMTP (optional)** für Passwort‑Reset per E‑Mail:
  - `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USER`, `SMTP_PASS`, `SMTP_TLS` (true/false)
  - `FROM_EMAIL` (Default = SMTP_USER)
  - `APP_BASE_URL` (Default `http://localhost:5000`) für Links im Mailtext

### CI/CD (GitHub Actions)
Workflow unter `.github/workflows/docker.yml` baut ein Image und pusht nach **GHCR** (`ghcr.io/<OWNER>/<REPO>:latest`).
Für Push brauchst du Packages‑Berechtigung; Standard `GITHUB_TOKEN` reicht in privaten Repos je nach Sichtbarkeit/Policy.

### Sicherheit
- **Nach Erstlogin**: Passwort stark setzen
- **Produktion**: `SECRET_KEY` als Secret/ENV setzen; SMTP‑Zugangsdaten als Secrets

### Lizenz / Kontakt
© [Michael Eitdorf](mailto:webmaster@michaeleitdorf.de)

---

## 🇬🇧 English

### Highlights
- **RBAC**: roles *Admin, Manager, Editor, Viewer, Auditor*
- **User admin** (Admin): create, enable/disable, change role, set password, **generate reset link**
- **2FA (TOTP)**: enroll via QR, login with 6‑digit code
- **Password reset**: token‑based, 2h validity (SMTP optional)
- **Audit log**: view with filters (time/text), up to 500 entries
- **Filters**: date range + search, **filtered totals**
- **Sparklines** under inventory/cash
- **CSV/PDF export**, **CSV import**
- **No plaintext credentials** in files; default admin at runtime
- **CI/CD (GitHub Actions)**: build & push to GHCR

### Quick Start
```bash
docker compose up --build
# Open: http://localhost:5000
# First login: admin / admin → forced password change
```

### Config (ENV)
- Optional `SECRET_KEY`
- SMTP (optional) for email reset: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_TLS`, `FROM_EMAIL`, `APP_BASE_URL`

### Security
- Change admin password after first login
- Pass `SECRET_KEY` and SMTP creds via secrets in production

© [Michael Eitdorf](mailto:webmaster@michaeleitdorf.de)
