#!/bin/bash

# Verzeichnisse anpassen (falls nötig)
APP_DIR="/var/lib/docker/volumes/bottlebalance"

echo ">>> Wechsel in das App-Verzeichnis: $APP_DIR"
cd "$APP_DIR" || { echo "Verzeichnis nicht gefunden!"; exit 1; }

echo ">>> Container stoppen und alte Images & volumes entfernen..."
#docker-compose down -v --rmi all
docker compose down
docker volume rm bottlebalance_bottlebalance-app

echo ">>> Neu bauen und starten..."
docker compose up --build -d

echo ">>> Logs (Strg+C zum Beenden)"
docker compose logs -f
