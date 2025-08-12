#!/usr/bin/env bash
set -euo pipefail

# Resolve project root based on this script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

EN_URL="https://www.gnu.org/licenses/gpl-3.0.txt"
DE_URL="https://www.gnu.org/licenses/gpl-3.0.de.html"

_fetch() {
  local url="$1"; local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$out"
  else
    echo "Neither curl nor wget found. Please install one of them." >&2
    exit 1
  fi
}

echo "Fetching GPL v3 (EN) → ${ROOT_DIR}/LICENSE";
_fetch "$EN_URL" "${ROOT_DIR}/LICENSE"

TMP_DE="${ROOT_DIR}/LICENSE_DE.raw.html"

_echo_notice() {
  cat <<'NOTICE' >"${ROOT_DIR}/LICENSE_DE.md"
> **Hinweis:** Dies ist eine inoffizielle Übersetzung der **GNU GPL v3**. Sie dient nur der Information. 
> Rechtsverbindlich ist ausschließlich der englische Originaltext in **LICENSE**.

NOTICE
}

_echo_notice

echo "Fetching GPL v3 (DE translation) → ${TMP_DE}";
_fetch "$DE_URL" "$TMP_DE"

# Append raw HTML (keine Konvertierung notwendig; GitHub stellt HTML in MD-Dateien nicht immer dar).
# Wir hängen die HTML-Quelle an, damit der Text vollständig und nachvollziehbar ist.
{
  echo "\n<!-- Originalquelle: ${DE_URL} (Stand: $(date -u +%Y-%m-%d)) -->\n";
  cat "$TMP_DE";
} >> "${ROOT_DIR}/LICENSE_DE.md"

rm -f "$TMP_DE"

echo "Done. LICENSE and LICENSE_DE.md are updated."
