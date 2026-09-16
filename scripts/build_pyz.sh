#!/usr/bin/env bash
# Build blindagem.pyz: one file to copy to a server, no pip and no virtualenv there.
# Usage: bash scripts/build_pyz.sh [output]
set -euo pipefail
OUT="${1:-blindagem.pyz}"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

cd "$(dirname "$0")/.."
python3 -m pip install --quiet --target "$BUILD" .

# __main__.py is the entry point zipapp runs.
cat > "$BUILD/__main__.py" <<'PY'
from blindagem.cli import app

app()
PY

find "$BUILD" -name '*.dist-info' -type d -exec rm -rf {} + 2>/dev/null || true
find "$BUILD" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
python3 -m zipapp "$BUILD" -o "$OUT" -p "/usr/bin/env python3" -c
chmod +x "$OUT"
echo "Built $OUT ($(du -h "$OUT" | cut -f1)) - run it with: sudo python3 $OUT audit"
