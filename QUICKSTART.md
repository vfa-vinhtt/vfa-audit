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

> **Note:** Additional tools (such as `pip-audit`, `fonttools`, `gitleaks`, `trivy`...) **do not need to be installed in advance** — the scanner checks for them at runtime and reports what is missing. Use `--install-missing` to install them automatically, or follow the printed instructions to install manually.

---

## 3. Run the scanner

Make sure the venv is active (you should see `(vfa-audit)` at the beginning of the terminal prompt), then **navigate into the project directory you want to scan**. The venv remains active after `cd` — no need to re-activate.

```bash
cd /path/to/your-project
```

### Basic command

> **Note:** The venv must be active before running this command (check for `(vfa-audit)` at the start of the terminal prompt). If it is not active, run the activate command from step 1 again.

```bash
vfa-audit
```

The scanner will scan the current directory and save the report to `./vfa-audit-report/`. This folder is automatically excluded from scanning to prevent the scanner from reading its own output.

### Common options

| Option | Description |
|--------|-------------|
| `--format json` | JSON output *(default)* |
| `--format html` | HTML report |
| `--format md` | Markdown report |
| `--format console` | Print results to terminal |
| `--format policy` | Split into 3 files: blockers / review-required / warnings |
| `-o ./my-report` | Custom output name or directory |
| `--zip` | Compress output into a `.zip` archive |
| `--config config.yaml` | Use a custom config file |
| `--install-missing` | Auto-install missing external tools before scanning |
| `--no-strict-requirements` | Skip missing tools and scan anyway |
| `--skip-requirements-check` | Skip the requirements check entirely |
| `--version` | Print scanner version |

### Examples

```bash
# HTML report, auto-install missing tools
vfa-audit --format html --install-missing

# Custom config, compressed output
vfa-audit --config ./config.yaml --format json --zip

# Quick scan, skip requirements check
vfa-audit --format console --skip-requirements-check
```

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
