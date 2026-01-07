#!/bin/bash

# Wechsle in das Verzeichnis, in dem dieses Script liegt
cd "$(dirname "$0")" || { echo "Verzeichnis nicht gefunden"; exit 1; }

# Name des Volumes
VOLUME_NAME="bottlebalance-dev_bottlebalance-dev-app"

echo ">>> Container stoppen (aber Volumes behalten)..."
docker compose -f docker-compose-dev.yml down

echo ">>> Lösche nur das Volume: $VOLUME_NAME"
if docker volume ls --format "{{.Name}}" | grep -q "^${VOLUME_NAME}$"; then
    docker volume rm "$VOLUME_NAME"
    echo "Volume $VOLUME_NAME erfolgreich entfernt."
else
    echo "Volume $VOLUME_NAME nicht gefunden oder bereits entfernt."
fi

echo ">>> Neu bauen und starten..."
docker compose -f docker-compose-dev.yml --env-file .env up --build -d

echo ">>> Logs (Strg+C zum Beenden)"
docker compose logs -f