FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev libfreetype6 libjpeg62-turbo locales \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i '/de_DE.UTF-8/s/^# //g' /etc/locale.gen && locale-gen

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
