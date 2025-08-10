# Getränkekassen-Webapp

[![CI/CD](https://img.shields.io/github/actions/workflow/status/<USERNAME>/<REPO>/ci.yml?label=CI%2FCD)](https://github.com/<USERNAME>/<REPO>/actions)
[![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)](https://hub.docker.com/r/<USERNAME>/<REPO>)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-black?logo=flask)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?logo=postgresql)](https://www.postgresql.org/)

Eine **Flask-basierte Webanwendung** zur Verwaltung einer Getränkekasse mit moderner Architektur, Sicherheitsfunktionen und Exportmöglichkeiten.

---

## Inhaltsverzeichnis
- [Features](#-features)
- [Tech-Stack](#️-tech-stack)
- [Installation & Setup](#-installation--setup)
- [Beispiel `.env`](#-beispiel-env)
- [Nutzung](#-nutzung)
- [Tests](#-tests)
- [Sicherheit](#-sicherheit)
- [Screenshots](#-screenshots)
- [Lizenz](#-lizenz)

## 🚀 Features
- **Inventar- und Kassenverwaltung** (Vollgut, Leergut, Einnahmen, Ausgaben)
- **Benutzerverwaltung mit RBAC** (Role-Based Access Control)
- **Zwei-Faktor-Authentifizierung (2FA)**
- **Audit-Logs** für Nachvollziehbarkeit
- **Export als CSV und PDF**
- **Responsive UI** mit Jinja2-Templates
- **CI/CD** via GitHub Actions
- **Docker-Compose Setup** für einfache Bereitstellung

## 🛠️ Tech-Stack
- **Backend:** Flask (Python)
- **Frontend:** Jinja2, HTML, CSS
- **Datenbank:** PostgreSQL
- **Containerisierung:** Docker & Docker-Compose
- **CI/CD:** GitHub Actions

## 📦 Installation & Setup

### Voraussetzungen
- Docker & Docker-Compose
- Git

### Schritte
```bash
# Repository klonen
git clone [https://github.com/<USERNAME>/<REPO>.git](https://github.com/michaele1410/BottleBalance)
cd <REPO>

# .env anlegen (siehe unten)
cp .env.example .env || true

# Docker-Compose starten
# Falls deine Datei "docker-compose 1.yml" heißt:
docker compose -f "docker-compose 1.yml" up -d --build
# Ansonsten (Standardname):
# docker compose up -d --build
```

Lokaler Start (ohne Docker):
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
flask --app app.py run
```

## ⚙️ Beispiel .env
```env
SECRET_KEY=dein-geheimer-schlüssel
DB_HOST=getraenkekasse-db
DB_NAME=getraenkekasse
DB_USER=db-user
DB_PASS=db-password
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=mailer@example.com
SMTP_PASS=dein-smtp-passwort
SMTP_TLS=true
FROM_EMAIL=mailer@example.com
APP_BASE_URL=http://localhost:5000
```

## ▶️ Nutzung
- **Startseite:** Übersicht Inventar & Kassenbestand
- **Filter:** Zeitraum & Suche
- **Export:** PDF & CSV
- **Admin:** Benutzerrollen & Audit-Logs

## ✅ Tests
```bash
pytest -q
```

## 🔒 Sicherheit
- Passwort-Hashing (Werkzeug)
- 2FA via TOTP
- Rollenbasierte Zugriffssteuerung
- Empfohlene Header: HSTS, CSP, X-Frame-Options, X-Content-Type-Options

## 🖼️ Screenshots
Füge deine Screenshots im Ordner `docs/screenshots/` hinzu und verlinke sie hier:

```markdown
![Dashboard](docs/screenshots/dashboard.png)
![Formular](docs/screenshots/form.png)
![Export](docs/screenshots/export.png)
```

## 📄 Lizenz
Dieses Projekt steht unter der MIT-Lizenz. Siehe [LICENSE](LICENSE).
