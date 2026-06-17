#!/usr/bin/env bash
# Build vfa-audit standalone binary for macOS / Linux.
# Usage: bash scripts/build.sh
#
# Output: dist/vfa-audit  (macOS/Linux binary)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

cd "$ROOT"

echo "==> Installing build dependencies..."
pip install --quiet pyinstaller PyYAML Pillow fonttools pytesseract

echo "==> Running PyInstaller..."
pyinstaller scripts/vfa_audit.spec \
    --distpath dist \
    --workpath dist/work \
    --clean \
    --noconfirm

BINARY=dist/vfa-audit
echo ""
echo "==> Build complete: $BINARY"
echo "    Size: $(du -sh "$BINARY" | cut -f1)"
echo ""
echo "Test it:"
echo "    $BINARY --help"
echo "    $BINARY /path/to/project --format console --skip-requirements-check"
