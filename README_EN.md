# Beverage Cash Management Web App

[![CI/CD](https://img.shields.io/github/actions/workflow/status/<USERNAME>/<REPO>/ci.yml?label=CI%2FCD)](https://github.com/<USERNAME>/<REPO>/actions)
[![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)](https://hub.docker.com/r/<USERNAME>/<REPO>)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-black?logo=flask)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?logo=postgresql)](https://www.postgresql.org/)

A **Flask-based application** to manage a beverage cash box with modern architecture, security features, and export options.

---

## Table of Contents
- [Features](#-features)
- [Tech Stack](#️-tech-stack)
- [Installation & Setup](#-installation--setup)
- [Example `.env`](#-example-env)
- [Usage](#-usage)
- [Tests](#-tests)
- [Security](#-security)
- [Screenshots](#-screenshots)
- [License](#-license)

## 🚀 Features
- **Inventory and cash tracking** (full bottles, empties, income, expenses)
- **User management with RBAC** (Role-Based Access Control)
- **Two-Factor Authentication (2FA)**
- **Audit logs** for traceability
- **CSV and PDF export**
- **Responsive UI** using Jinja2 templates
- **CI/CD** via GitHub Actions
- **Docker-Compose** for simple deployment

## 🛠️ Tech Stack
- **Backend:** Flask (Python)
- **Frontend:** Jinja2, HTML, CSS
- **Database:** PostgreSQL
- **Containerization:** Docker & Docker-Compose
- **CI/CD:** GitHub Actions

## 📦 Installation & Setup

### Requirements
- Docker & Docker-Compose
- Git

### Steps
```bash
# Clone
git clone https://github.com/<USERNAME>/<REPO>.git
cd <REPO>

# Create .env (see below)
cp .env.example .env || true

# Start with Docker Compose
# If your file is named "docker-compose 1.yml":
docker compose -f "docker-compose 1.yml" up -d --build
# Otherwise (default):
# docker compose up -d --build
```

Local run (without Docker):
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
flask --app app.py run
```

## ⚙️ Example .env
```env
SECRET_KEY=your-secret-key
DB_HOST=getraenkekasse-db
DB_NAME=getraenkekasse
DB_USER=db-user
DB_PASS=db-password
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=mailer@example.com
SMTP_PASS=your-smtp-password
SMTP_TLS=true
FROM_EMAIL=mailer@example.com
APP_BASE_URL=http://localhost:5000
```

## ▶️ Usage
- **Dashboard:** Overview of inventory and cash balance
- **Filters:** Date range & search
- **Export:** PDF & CSV
- **Admin:** User roles & audit logs

## ✅ Tests
```bash
pytest -q
```

## 🔒 Security
- Password hashing (Werkzeug)
- 2FA via TOTP
- Role-based access control
- Recommended headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options

## 🖼️ Screenshots
Place screenshots into `docs/screenshots/` and reference them here:

```markdown
![Dashboard](docs/screenshots/dashboard.png)
![Form](docs/screenshots/form.png)
![Export](docs/screenshots/export.png)
```

## 📄 License
This project is licensed under the MIT License. See [LICENSE](LICENSE).
