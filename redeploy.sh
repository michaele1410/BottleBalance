#!/bin/bash

# Name des Volumes
VOLUME_NAME="bottlebalance-dev_bottlebalance-dev-app"

echo ">>> Container stoppen (aber Volumes behalten)..."
docker compose down

echo ">>> Lösche nur das Volume: $VOLUME_NAME"
docker volume rm "$VOLUME_NAME" || echo "Volume $VOLUME_NAME nicht gefunden."

echo ">>> Neu bauen und starten..."
docker compose up --build -d

echo ">>> Logs (Strg+C zum Beenden)"
docker compose logs -f