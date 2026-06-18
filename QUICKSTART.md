# vfa-audit — Quick Start Guide

## Requirements

- Python **3.10** or later
- Git

---

## 1. Create a virtual environment

Create the venv **once** in a fixed location outside the project — do not place it inside the project you intend to scan.

**macOS / Linux** — recommended path: `~/.venvs/vfa-audit`

```bash
python3 -m venv ~/.venvs/vfa-audit
```

**Windows** — recommended path: `%USERPROFILE%\venvs\vfa-audit`

```bat
python -m venv %USERPROFILE%\venvs\vfa-audit
```

Activate the venv each time you open a new terminal:

```bash
# macOS / Linux
source ~/.venvs/vfa-audit/bin/activate

# Windows (Command Prompt)
%USERPROFILE%\venvs\vfa-audit\Scripts\activate.bat

# Windows (PowerShell)
~\venvs\vfa-audit\Scripts\Activate.ps1
```

---

## 2. Install vfa-audit

```bash
pip install git+https://github.com/vfa-vinhtt/vfa-audit.git
```

---

## 3. Run the scanner

Make sure the venv is active (you should see `(vfa-audit)` at the beginning of the terminal prompt), then **navigate into the project directory you want to scan**. The venv remains active after `cd` — no need to re-activate.

```bash
cd /path/to/your-project
```

```bash
vfa-audit
```

The scanner will scan the current directory and save the report to `./vfa-audit-report/`.

---

## 4. Output

Reports are saved to:

```
./vfa-audit-report/<YYYYMMDD_HHmm>_<project-name>.json
```

With `--format policy`, the output is a directory containing 3 files:

```
./vfa-audit-report/<YYYYMMDD_HHmm>_<project-name>/
├── blockers.json
├── review-required.json
└── warnings.json
```

---

## 5. Update to the latest version

```bash
pip install --upgrade git+https://github.com/vfa-vinhtt/vfa-audit.git
```
