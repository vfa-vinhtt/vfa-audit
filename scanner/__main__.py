"""Enables ``python -m scanner ...`` as a PATH-independent entry point.

The installed ``vfa-audit`` console command lives in pip's ``Scripts``/``bin``
directory, which is not always on ``PATH`` (notably on Windows, where the per-user
``Scripts`` folder is frequently missing from ``PATH``). ``python -m scanner`` works
anywhere the package is importable, with no PATH setup required.
"""
from scanner.cli import main

if __name__ == "__main__":
    main()
