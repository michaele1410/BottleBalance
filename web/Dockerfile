
FROM python:3.11-slim

# Basics
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENV WSGI_MODULE=app:app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libfreetype6 \
    libjpeg62-turbo \
    libjpeg-dev \
    zlib1g-dev \
    gettext \
    locales \
    tzdata \
    postgresql-client \
    findutils \
    grep \
  && rm -rf /var/lib/apt/lists/*

# Locale
RUN sed -i '/de_DE.UTF-8/s/^# //g' /etc/locale.gen && locale-gen
ENV TZ=Europe/Berlin \
    LANG=de_DE.UTF-8 \
    LC_ALL=de_DE.UTF-8

# Code-Verzeichnis (stabil, NICHT übermounten)
WORKDIR /opt/app

# Python-Dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Quellen
COPY . /opt/app

# Uploads-Verzeichnis (separates Volume)
RUN mkdir -p /app/uploads

# Non-root User + Besitzrechte
RUN addgroup --system app && adduser --system --ingroup app app \
 && chown -R app:app /opt/app \
 && chown -R app:app /app

# Optional: Übersetzungsskript ausführbar machen
RUN if [ -f /opt/app/scripts/update_translations.sh ]; then \
      sed -i 's/\r$//' /opt/app/scripts/update_translations.sh && \
      sed -i '1s/^\xEF\xBB\xBF//' /opt/app/scripts/update_translations.sh && \
      chmod +x /opt/app/scripts/update_translations.sh; \
    fi

# Buildzeit: Babel kompilieren, wenn .po vorhanden; mit robusten Checks
RUN set -eux; \
    if [ -d /opt/app/translations ] && find /opt/app/translations -type f -name '*.po' | grep -q .; then \
      python -m babel.messages.frontend compile -d /opt/app/translations || { echo 'pybabel module compile failed'; exit 1; }; \
      chown -R app:app /opt/app/translations; \
    else \
      echo 'No translations to compile, skipping pybabel'; \
    fi


# Gunicorn/WSGI
ENV GUNICORN_WORKERS=2 \
    GUNICORN_THREADS=2 \
    GUNICORN_TIMEOUT=90 \
    PYTHONPATH=/opt/app

EXPOSE 5000

USER app

# Start: optionales Babel-Update; dann Gunicorn mit konfigurierbarem WSGI-Entry
CMD sh -lc "[ -f /opt/app/scripts/update_translations.sh ] && sh /opt/app/scripts/update_translations.sh || echo 'skip translations'; \            exec gunicorn -w ${GUNICORN_WORKERS} --threads ${GUNICORN_THREADS} --timeout ${GUNICORN_TIMEOUT} \            --access-logfile - -b 0.0.0.0:5000 ${WSGI_MODULE}"