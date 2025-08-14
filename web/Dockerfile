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


# Script ausführbar machen + CRLF entfernen (falls aus Windows-Checkout)
RUN test -f ./scripts/update_translations.sh \
 && sed -i 's/\r$//' ./scripts/update_translations.sh \
 && chmod +x ./scripts/update_translations.sh


# Compile translation files (initial)
RUN pybabel compile -d translations



# Expose port
EXPOSE 5000

# Set timezone
ENV TZ=Europe/Berlin

# Start script: erst update_translations.sh, dann gunicorn
CMD ["sh", "-c", "sh ./scripts/update_translations.sh && gunicorn -b 0.0.0.0:5000 app:app"]
