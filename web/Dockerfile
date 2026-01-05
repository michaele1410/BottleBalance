# Use official Python image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev libfreetype6 libjpeg62-turbo locales \
    libjpeg-dev \
    zlib1g-dev  \
    gettext  \
    nano  \
    postgresql-client  \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i '/de_DE.UTF-8/s/^# //g' /etc/locale.gen && locale-gen

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . /app

# Optional: Besitzrechte für Non-Root-User vorbereiten
RUN addgroup --system app && adduser --system --ingroup app app \
&& chown -R app:app /app

# Make optional translation script executable if present
RUN if [ -f ./scripts/update_translations.sh ]; then \
      sed -i 's/\r$//' ./scripts/update_translations.sh && chmod +x ./scripts/update_translations.sh; \
    fi

# Compile translation files if translation directory exists and has .po files
# This avoids failing the build when translations are not yet created.

RUN if [ -d translations ] && find translations -type f -name '*.po' | grep -q .; then \
      pybabel compile -d translations || (echo 'pybabel compile failed' && exit 1); \
    else \
      echo 'No translations to compile, skipping pybabel'; \
    fi \
 && chown -R app:app /app/translations

# Expose port
EXPOSE 5000

# Set timezone
ENV TZ=Europe/Berlin

ENV LANG=de_DE.UTF-8 \
    LC_ALL=de_DE.UTF-8


# Set version
ARG APP_VERSION
ENV APP_VERSION=${APP_VERSION}

# Gunicorn runtime settings
ENV GUNICORN_WORKERS=2 \
    GUNICORN_THREADS=2 \
    GUNICORN_TIMEOUT=90

# Switch to non-root user (optional but recommended)
USER app

# Start script: erst update_translations.sh, dann gunicorn


# Start: run update_translations.sh if present, then gunicorn
# 'exec' ensures signals are forwarded properly.
CMD sh -lc "[ -f ./scripts/update_translations.sh ] && sh ./scripts/update_translations.sh || echo 'skip translations'; \
            exec gunicorn -w ${GUNICORN_WORKERS} --threads ${GUNICORN_THREADS} --timeout ${GUNICORN_TIMEOUT} \
            --access-logfile - -b 0.0.0.0:5000 app:app"
