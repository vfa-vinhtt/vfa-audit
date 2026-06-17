# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for vfa-audit
# Build: pyinstaller scripts/vfa_audit.spec --distpath dist --workpath dist/work --clean

import re
import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent

_ver_match = re.search(r'^VERSION\s*=\s*"([^"]+)"', (ROOT / 'main.py').read_text(), re.MULTILINE)
_version = _ver_match.group(1) if _ver_match else "0.0.0"
_binary_name = f"vfa-audit_v{_version}"

a = Analysis(
    [str(ROOT / 'main.py')],
    pathex=[str(ROOT)],
    datas=[
        (str(ROOT / 'config.yaml'), '.'),
    ],
    hiddenimports=[
        # Plugins (auto-discovered at runtime, must be explicit for PyInstaller)
        'scanner.plugins.pii_checker',
        'scanner.plugins.secret_checker',
        'scanner.plugins.dependency_checker',
        'scanner.plugins.license_checker',
        'scanner.plugins.env_checker',
        'scanner.plugins.config_checker',
        'scanner.plugins.asset_checker',
        'scanner.plugins.gitignore_checker',
        # Adapters
        'scanner.adapters.node',
        'scanner.adapters.python',
        'scanner.adapters.go',
        'scanner.adapters.java',
        'scanner.adapters.dotnet',
        'scanner.adapters.swift',
        'scanner.adapters.php',
        # Core & utils
        'scanner.core.report_engine',
        'scanner.core.trivy_adapter',
        'scanner.core.requirements',
        'scanner.core.file_scanner',
        'scanner.core.git_scanner',
        'scanner.reports.html_template',
        'scanner.utils.license_utils',
        'scanner.utils.gitignore_utils',
        # Third-party
        'yaml',
        # Optional — included so asset_checker works out-of-the-box
        'PIL', 'PIL.Image', 'PIL.ExifTags',
        'fontTools', 'fontTools.ttLib',
    ],
    excludes=[
        'tkinter', 'matplotlib', 'scipy', 'numpy', 'pandas',
        'IPython', 'notebook', 'jupyter',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name=_binary_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    onefile=True,
)
