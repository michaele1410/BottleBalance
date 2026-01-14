#!/bin/bash
set -e

# Extract
pybabel extract -F babel.cfg -o messages.pot .

# Update
pybabel update -i messages.pot -d translations

# Compile
pybabel compile -d translations