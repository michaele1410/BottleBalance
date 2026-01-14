
FROM python:3.11-slim

# Basics
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

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

# Stable code dir
WORKDIR /opt/app

# ---- Security-first: create non-root User as early as possible
RUN addgroup --system app && adduser --system --ingroup app app

# Python-Dependencies
COPY --chown=app:app requirements.txt /opt/app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Sources
COPY --chown=app:app . /opt/app

# Version file creation
RUN echo "${APP_VERSION}" > /opt/app/VERSION

# Uploads directory (separate volume) + ownership rights
RUN mkdir -p /opt/app/uploads && chown -R app:app /opt/app/uploads

# Remove BOM/CRLF & make it executable
RUN if [ -f /opt/app/scripts/update_translations.sh ]; then \
      sed -i 's/\r$//' /opt/app/scripts/update_translations.sh && \
      sed -i '1s/^\xEF\xBB\xBF//' /opt/app/scripts/update_translations.sh && \
      chmod +x /opt/app/scripts/update_translations.sh; \
    fi

# build time: compile Babel if a po exists with robust checks
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

# JSON-CMD (avoids signal/shell problems)
# - if update_translations.sh exists, it is executed once; otherwise, "skip translations"
CMD ["/bin/sh","-lc","[ -f /opt/app/scripts/update_translations.sh ] && sh /opt/app/scripts/update_translations.sh || echo 'skip translations'; exec gunicorn -w ${GUNICORN_WORKERS} --threads ${GUNICORN_THREADS} --timeout ${GUNICORN_TIMEOUT} --access-logfile - -b 0.0.0.0:5000 ${WSGI_MODULE}"]