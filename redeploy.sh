#!/bin/bash

# Change to the directory where this script is located.
cd "$(dirname "$0")" || { echo "Directory not found"; exit 1; }

# Volume name
VOLUME_NAME="bottlebalance-dev_bottlebalance-dev-app"

echo ">>> Stop containers (but keep volumes)..."
docker compose -f docker-compose-dev.yml down

echo ">>> Delete only the volume: $VOLUME_NAME"
if docker volume ls --format "{{.Name}}" | grep -q "^${VOLUME_NAME}$"; then
    docker volume rm "$VOLUME_NAME"
    echo "Volume $VOLUME_NAME successfully removed."
else
    echo "Volume $VOLUME_NAME not found or already removed."
fi

echo ">>> Build new and start over..."
docker compose -f docker-compose-dev.yml --env-file .env up --build -d

echo ">>> Logs (Ctrl+C to exit)"
docker compose logs -f