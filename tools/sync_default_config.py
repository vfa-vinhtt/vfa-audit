#!/usr/bin/env python3
"""Guard against config drift.

``config.yaml`` (repo root) is the source of truth; ``scanner/default_config.yaml``
is the copy bundled inside the installed pip package (see ``pyproject.toml``
package-data). They must stay byte-identical so users who ``pip install`` the
tool get the same defaults as someone running from a source checkout.

Usage:
    python tools/sync_default_config.py          # check; exit 1 if they differ
    python tools/sync_default_config.py --fix     # re-copy config.yaml -> default
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "config.yaml"
BUNDLED = ROOT / "scanner" / "default_config.yaml"


def main() -> int:
    fix = "--fix" in sys.argv[1:]

    if not SOURCE.exists():
        print(f"error: source config not found: {SOURCE}", file=sys.stderr)
        return 2

    src = SOURCE.read_bytes()
    cur = BUNDLED.read_bytes() if BUNDLED.exists() else None

    if cur == src:
        print("OK: scanner/default_config.yaml is in sync with config.yaml")
        return 0

    if fix:
        BUNDLED.write_bytes(src)
        print("Fixed: copied config.yaml -> scanner/default_config.yaml")
        return 0

    print(
        "DRIFT: scanner/default_config.yaml does not match config.yaml.\n"
        "       The default bundled into the installed package is stale, so\n"
        "       `pip install`ed users would get different defaults than a clone.\n"
        "       Run:  python tools/sync_default_config.py --fix",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
