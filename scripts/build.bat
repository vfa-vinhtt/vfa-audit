@echo off
REM Build vfa-audit standalone binary for Windows.
REM Usage: scripts\build.bat
REM
REM Output: dist\vfa-audit.exe

cd /d "%~dp0.."

echo =^> Installing build dependencies...
pip install --quiet pyinstaller PyYAML Pillow fonttools pytesseract

echo =^> Running PyInstaller...
pyinstaller scripts\vfa_audit.spec ^
    --distpath dist ^
    --workpath dist\work ^
    --clean ^
    --noconfirm

echo.
echo =^> Build complete: dist\vfa-audit.exe
echo.
echo Test it:
echo     dist\vfa-audit.exe --help
echo     dist\vfa-audit.exe C:\path\to\project --format console --skip-requirements-check
