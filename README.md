# vfa-audit

**Version 1.0.0** — A multi-language, extensible security & compliance scanner. Detects hardcoded
secrets, vulnerable dependencies, license-policy violations, PII, insecure configuration,
`.env`/`.gitignore` exposure, and unlicensed assets — then produces a scored report in
console, JSON, Markdown, HTML, or policy-gate format.

Runs on **Windows, Linux, and macOS** (Python 3.10+).

> 📑 For the formal specification — per-plugin functional requirements, severity mapping,
> language/tool matrices, config & JSON schema, scoring, exit codes, and known limitations
> — see **[SPEC.md](SPEC.md)**.

---

## Audit purpose

Answers four questions before delivering a product or reviewing code received from a partner / third party:

| Question | Plugin | Tools |
|---|---|---|
| **Sensitive information** — Does the source code contain secrets? (passwords, AWS keys, tokens, private keys…) | `secret_checker` | regex + entropy, Gitleaks (git history), TruffleHog, Trivy |
| **CVE** — Do the dependencies have known security vulnerabilities? | `dependency_checker` | OSV API, pip-audit / npm audit / govulncheck / dotnet / composer, Trivy |
| **Font license** — Are any fonts used without a commercial license? | `asset_checker` | fonttools (fsType embedding rights), ExifTool (copyright/license text), SHA256 |
| **Library license** — Are dependency licenses compatible with commercial use? | `license_checker` | lockfile/manifest content, pip-licenses / license-checker / go-licenses / …, Trivy `--license-full` |

Additional checks: **PII** in source code, **insecure configuration**, **`.env` exposure**, **`.gitignore` gaps**.

---

## Highlights

**What it detects** — eight independent checks:

- 🔑 **Secrets** — hardcoded API keys, tokens, passwords, and private keys (regex + entropy, `gitleaks`, `trufflehog`, Trivy).
- 📦 **Vulnerable & risky dependencies** — known CVEs (OSV + native audits + Trivy) plus malicious & typosquat packages.
- 📄 **License compliance** — dependency licenses against your `deny`/`allow` policy, and a missing project `LICENSE`.
- 🕵️ **PII** — emails, phones, SSNs, credit cards, IBANs, and IDs, with **confidence scoring** to cut false positives.
- ⚙️ **Insecure configuration** — debug mode, disabled TLS verification, weak crypto, `CORS *`, default credentials, `JWT alg=none`.
- 🔐 **`.env` exposure** — graded by *committed-to-git / un-ignored / has-real-values*.
- 🚫 **`.gitignore` gaps** — missing rules for secrets/keys, plus git-tracked "dangerous" files.
- 🖼️ **Unlicensed assets** — font embedding rights (`fsType`), ExifTool copyright metadata, and image EXIF/XMP.

**How it works** — the capabilities behind those checks:

- **Multi-language** — Python, Node.js/TypeScript, Java/Android/Kotlin, C#/.NET, PHP, Go, and iOS (Objective-C/Swift), via auto-discovered *adapters*.
- **Layered** — each area has a fast built-in check that needs no setup, and *additionally* runs best-in-class external tools when installed (Gitleaks, TruffleHog, Trivy, pip-audit, npm audit, …); results are merged.
- **Self-provisioning** — a pre-scan check verifies, and can **auto-install**, the tools your enabled features need (scoped to the detected languages).
- **Clean reports** — the same issue found by several tools is shown and **counted once** (others noted as *"also detected by …"*); findings are grouped by area with a clickable **per-section summary**, plus a 0–100 **score and A–F grade**.
- **Extensible** — every check is an auto-discovered plugin and every language an auto-discovered adapter; drop a file in to add one.

---

## Installation

### Run from source

```bash
git clone <repo-url> vfa-audit
cd vfa-audit

python -m venv .venv
# Windows:        .venv\Scripts\activate
# Linux / macOS:  source .venv/bin/activate

pip install -r requirements.txt   # only hard dependency is PyYAML
```

Run the scanner:

```bash
# as a script
python main.py /path/to/project --format html -o report

# as a package
python -m vfa_audit /path/to/project --format console
```

### Standalone binary

Pre-built binaries (no Python required) are published on each tagged release via GitHub Actions:

| Platform | Artifact |
|---|---|
| macOS | `vfa-audit-macos` (wraps `vfa-audit_v1.0.0`) |
| Linux | `vfa-audit-linux` (wraps `vfa-audit_v1.0.0`) |
| Windows | `vfa-audit-windows.exe` (wraps `vfa-audit_v1.0.0.exe`) |

Download the binary for your platform, make it executable, and run it directly:

```bash
# macOS / Linux — scan current directory, report saved alongside the binary in ./report/
chmod +x vfa-audit-macos
cd /path/to/project && /path/to/vfa-audit-macos
```

### Build the binary locally

```bash
bash scripts/build.sh        # macOS / Linux  → dist/vfa-audit_v1.0.0
scripts\build.bat            # Windows        → dist\vfa-audit_v1.0.0.exe
```

Run the built binary:

```bash
# macOS / Linux — scan current directory, report saved to dist/report/<timestamp>_<project>.json
chmod +x dist/vfa-audit_v1.0.0
cd /path/to/project && /path/to/dist/vfa-audit_v1.0.0

# Windows — report saved to dist\report\<timestamp>_<project>.json
cd C:\path\to\project && C:\path\to\dist\vfa-audit_v1.0.0.exe
```

> The binary is fully self-contained — no Python installation required on the target machine.
> Copy it anywhere and run it as-is.

### Optional tooling

| Purpose | Tool(s) |
|---|---|
| Secret scanning | `gitleaks`, `trufflehog`, `trivy` (all optional, built-in regex needs nothing) |
| Vulnerability & license scanning | `trivy` (covers all ecosystems) |
| Python deps | `pip-audit`, `pip-licenses` |
| Node deps | `npm`, `license-checker` |
| Go deps | `govulncheck`, `go-licenses` |
| .NET deps | `dotnet` SDK, `dotnet-project-licenses` |
| PHP deps | `composer` |
| Swift/iOS deps | GitHub Advisory DB (network), `license_finder` |
| Font metadata | `fonttools`, `ExifTool` |
| Image metadata | `Pillow` (pip), `tesseract` for OCR |

---

## Usage

```bash
# default: scan current directory, write JSON report to <tool-dir>/report/
python main.py

# scan a specific project
python main.py /path/to/project
```

### Command-line arguments

| Argument | Description |
|---|---|
| `path` | Project to scan (default: current directory). |
| `--config` | Config file path (default: `config.yaml`). |
| `-o, --output` | Output report basename or directory. Defaults to `<tool-dir>/report/<YYYYMMDD_HHmm>_<project-name>`. |
| `--format` | `json` (default), `console`, `md`, `html`, or `policy`. |
| `--zip` | Compress the output file (or policy directory) into a `.zip` archive. |
| `--strict-requirements` | Stop the scan if any required tool is missing (default). |
| `--no-strict-requirements` | Warn about missing tools but scan anyway (this run). |
| `--skip-requirements-check` | Skip the pre-scan requirements check entirely. |
| `--install-missing` | Attempt to auto-install missing tools before scanning. |

**Exit codes:** `1` if any CRITICAL/HIGH findings exist (CI gate), `0` otherwise, `2` if a strict requirements check aborts.

> **Tip:** install Python-based tools into the *same* interpreter that runs the scanner
> (`python -m pip install pip-audit pip-licenses`). The scanner resolves tools from PATH
> **and** common install dirs (pip Scripts, winget Packages, scoop shims, `~/go/bin`,
> `~/.dotnet/tools`, Homebrew).

---

## Pre-scan requirements check & auto-install

Before scanning, the tool builds the list of external CLIs the **enabled** features need,
**scoped to the detected languages**, and verifies they're installed.

- **Strict by default** — if a required tool is missing the scan **stops** and prints how to install it (override per-run with `--no-strict-requirements`, or disable with `preflight.strict: false`).
- **Auto-install** (`auto_install: true` or `--install-missing`):
  - pip / npm / dotnet / gem / `go install` for toolchain installers,
  - OS package managers for standalone binaries (`scoop`/`winget`/`choco`/`brew`),
  - **GitHub release binaries** as a last resort (e.g. Trivy, Gitleaks, TruffleHog) → installed to `~/.security-scanner/bin`,
  - optional **Go bootstrap** via a signed package manager when a tool needs `go install` and Go is absent.
- **Optional tools** — list commands under `preflight.optional` to downgrade them to a non-blocking `[WARN]`.

```text
Checking tool requirements (enabled config features x detected languages):
  [ OK ]  gitleaks        secret_checker (gitleaks)
  [ OK ]  trivy           secret_checker (trivy), dependency_checker (trivy), license_checker (trivy)
  [MISS]  pip-licenses    license_checker tool (python)
          install: pip install pip-licenses
  [NOTE]  api.osv.dev     dependency_checker (OSV CVE lookup) (network)
```

---

## Configuration (`config.yaml`)

```yaml
preflight:
  enabled: true
  strict: true
  auto_install: true
  binary_installer: auto   # scoop | winget | choco | brew | none
  bootstrap_runtimes: true
  optional: []

file_scanner:
  ignore_dirs: ["logs", "tmp", "dist", "build", "out"]
  ignore_patterns: ["*.log", "package-lock.json"]

plugins:
  secret_checker:
    enabled: true
    tool_config:
      python_regex: { enabled: false }  # built-in, no install
      gitleaks:     { enabled: true }   # external CLI
      trufflehog:   { enabled: true }   # external CLI
      trivy:        { enabled: true }   # Trivy secret scan

  dependency_checker:
    enabled: true
    tools:
      osv:           { enabled: true }   # OSV.dev CVE lookup (network)
      project_audit: { enabled: true }   # native audit (pip-audit, npm audit, govulncheck, …)
      trivy:         { enabled: true }   # Trivy CVE scan

  license_checker:
    enabled: true
    tools:
      content:      true   # read licenses from lockfiles/metadata
      project_tool: true   # native license tool (pip-licenses, license-checker, …)
      trivy:        true   # Trivy --license-full scan
    deny: ["GPL-2.0-only", "AGPL-3.0-only"]
    allow_classifications: ["permissive"]

  asset_checker:
    enabled: true
    tools:
      font_metadata:     true   # fonttools fsType + embedded license
      image_metadata:    true   # Pillow EXIF/IPTC/XMP
      ocr_text_in_image: true   # tesseract OCR (manual font-license review)
      exiftool_metadata: true   # ExifTool copyright/UsageTerms fields

  env_checker:       { enabled: true }
  gitignore_checker: { enabled: true }
  config_checker:    { enabled: true }

  pii_checker:
    enabled: false          # off by default (noisy). Enable for data-handling audits.
    min_confidence: high    # high = validated/context-confirmed only; low = every match
    bulk_threshold: 6
    disabled_categories: []
    allowlist: []

adapters: {}
```

---

## Plugins

| Plugin | What it does |
|---|---|
| **secret_checker** | Hardcoded secrets/keys/tokens. Runs all enabled tools (built-in regex, `gitleaks`, `trufflehog`, Trivy) and merges results under per-tool sub-groups. Secrets are masked in evidence. |
| **dependency_checker** | Known-**malicious** & **typosquat** packages, **OSV** CVE lookups (PyPI/npm/Maven/NuGet/Packagist/Go), per-language **native audits** (pip-audit, npm audit, `dotnet list --vulnerable`, `composer audit`, govulncheck, Swift→GitHub Advisory DB), and **Trivy** CVE scanning. |
| **license_checker** | Missing project `LICENSE`, dependency licenses from lockfiles **and** native tools **and** Trivy (`--license-full`), and policy enforcement (`deny` / `allow_classifications`). |
| **env_checker** | Finds `.env` files and grades exposure using a matrix of *committed-to-git / un-ignored / populated*: committed real `.env` → CRITICAL, properly ignored → INFO. |
| **gitignore_checker** | Context-aware required patterns (Terraform/Java only for those stacks), git-tracked "dangerous file" detection, `.env`-aware severity. Defers `.env` exposure to `env_checker` (no duplicate findings). |
| **pii_checker** | Emails, phones, SSNs, Luhn-validated cards, mod-97-validated IBANs, passports, tax/medical IDs. **Confidence-based**: high mode stays quiet on bare matches and flags only validated or context-confirmed PII and data-dump bulk files. Disabled by default. |
| **config_checker** | Insecure settings in YAML/JSON/etc.: debug mode, disabled TLS verification, weak crypto, CORS `*`, hardcoded/default credentials, `JWT alg=none`, and more. |
| **asset_checker** | Fonts: `fsType` embedding rights (fonttools) + copyright/license text fields (ExifTool) + SHA256 for renamed-font tracking. Images: EXIF/IPTC/XMP copyright (Pillow). Optional OCR flags rendered text for manual font-license review. |

---

## Adapters (language support)

Adapters detect a project's languages and extract dependency/framework metadata. Discovered automatically.

| Adapter | Detects | Native audit | Native license tool |
|---|---|---|---|
| `python` | `requirements*.txt`, `pyproject.toml`, `Pipfile` | `pip-audit` | `pip-licenses` |
| `node` | `package.json` (+ lockfile) | `npm audit` | `license-checker` |
| `java` | `pom.xml`, `build.gradle(.kts)` incl. Android/Kotlin DSL | OSV (Maven) | — |
| `dotnet` | `*.csproj`, `packages.config` | `dotnet list --vulnerable` | `dotnet-project-licenses` |
| `php` | `composer.json` (+ `composer.lock`) | `composer audit` | `composer licenses` |
| `go` | `go.mod` | `govulncheck` | `go-licenses` |
| `swift` | `Package.swift`, `Podfile`/`Podfile.lock`, `*.xcodeproj` | GitHub Advisory DB | `license_finder` |

---

## Security score

A 0–100 score with an **A–F grade** using **diminishing returns** per severity
(`penalty = weight × count^0.7`), so the score stays a meaningful gradient as you fix
issues. INFO findings never affect the score.

| Grade | Score |
|---|---|
| A | 90–100 |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | < 40 |

---

## Reports

`--format` selects the output:

- **console** — colored summary + critical/high finding list.
- **json** — full structured data (real plugin names, `info.scanner_version`; ideal for CI).
- **md** — Markdown report.
- **html** — self-contained, collapsible HTML report.
- **policy** — writes `blockers.json`, `review-required.json`, `warnings.json`, and `summary_policy.json` into a directory. Status: `FAIL` / `REVIEW_REQUIRED` / `WARNING` / `PASS`.

Add `--zip` to compress the output into a `.zip` archive (works with all formats).

**Cross-tool de-duplication.** The same data point found by multiple sub-tools is shown once
— the highest-severity finding is kept and the others are noted as *"also detected by …"*.
Counts and the score run on the de-duplicated set.

**Security Summary by Section.** A per-section severity breakdown (most-severe section first).
In HTML each row is **clickable** and scrolls to that section's findings.

The JSON `info` block records the scanner version and all external tool versions used in the scan:

```json
"info": {
  "scanner_version": "1.0.0",
  "tools": [
    { "name": "gitleaks", "version": "8.x.x", "path": "..." },
    { "name": "trivy",    "version": "0.x.x",  "path": "..." }
  ]
}
```

---

## Extending the scanner

### New plugin

1. Add a file in `scanner/plugins/`.
2. Subclass `BasePlugin`, set `name`/`description`, implement `scan(root, files, context)`.
3. If the plugin uses PyInstaller-frozen builds, add its module to `hiddenimports` in `scripts/vfa_audit.spec`.

### New adapter

1. Add a file in `scanner/adapters/`.
2. Subclass `BaseAdapter`, implement `detect()` and `collect()` (return `packages` as `{ecosystem: {pkg: version}}`).
3. Optionally declare:
   - `REQUIRED_TOOLS = {"audit": (cmd, hint), "license": (cmd, hint)}` — wired into the pre-scan requirements check.
   - `IGNORE_DIRS = {"node_modules", ...}` — merged into the global ignore list automatically.
   - `audit_dependencies()` / `check_licenses_with_tool(config)` — native tool integrations.
4. Add the new module to `hiddenimports` in `scripts/vfa_audit.spec`.

---

## Project layout

```
main.py                       # entry point, CLI, orchestration, preflight
__main__.py                   # enables `python -m vfa_audit` invocation
pyproject.toml                # package metadata, version (1.0.0), console script entry point
config.yaml                   # default configuration
scripts/
  build.sh                    # macOS/Linux PyInstaller build → dist/vfa-audit
  build.bat                   # Windows PyInstaller build      → dist\vfa-audit.exe
  vfa_audit.spec              # PyInstaller one-file spec (hiddenimports for all plugins/adapters)
.github/workflows/build.yml   # CI: builds binaries for macOS, Linux, Windows on tag push
scanner/
  core/
    file_scanner.py           # file walk, language detection, ignore handling
    git_scanner.py            # git metadata
    report_engine.py          # scoring, grade, console/json/md/html/policy output, deduplication
    requirements.py           # pre-scan requirements check + auto-install + collect_tool_info()
    trivy_adapter.py          # shared Trivy runner (vuln / license / secret scan modes)
  plugins/
    secret_checker.py         # secrets via regex, gitleaks, trufflehog, trivy
    dependency_checker.py     # CVEs via OSV, native audits, trivy
    license_checker.py        # license policy via content, native tools, trivy
    env_checker.py            # .env exposure grading
    gitignore_checker.py      # .gitignore gap analysis
    pii_checker.py            # PII with confidence scoring
    config_checker.py         # insecure configuration patterns
    asset_checker.py          # font (fonttools + exiftool) and image (Pillow) license checks
    base_plugin.py            # BasePlugin, Finding, Severity
  adapters/
    node.py  python.py  java.py  dotnet.py  php.py  go.py  swift.py
    base_adapter.py
  reports/
    html_template.py          # self-contained HTML renderer
  utils/
    license_utils.py          # SPDX classification helpers
    gitignore_utils.py        # .gitignore pattern parsing
```
