#!/bin/bash
set -e

# Extrahieren
pybabel extract -F babel.cfg -o messages.pot .

# Aktualisieren
pybabel update -i messages.pot -d translations

# Kompilieren
pybabel compile -d translations