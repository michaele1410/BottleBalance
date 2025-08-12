#!/bin/bash
# Customise directories (if necessary)
APP_DIR="/var/lib/docker/volumes//bottlebalance"

echo ">>> Switch to the app directory: $APP_DIR"
cd "$APP_DIR" || { echo "Directory not found!"; exit 1; }

echo ">>> Stop containers and remove old images..."
#docker compose down --volumes
docker compose down

echo ">>> Build anew and start over..."
docker compose up --build -d

echo ">>> Logs (Strg+C to exit)"
docker compose logs -f
