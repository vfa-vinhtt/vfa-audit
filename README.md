# Project Security Scanner

A multi-language, extensible security & compliance scanner. It detects hardcoded
secrets, vulnerable/malicious dependencies, license-policy violations, PII,
insecure configuration, `.env`/`.gitignore` exposure, and unlicensed assets — then
produces a scored report in console, JSON, Markdown, or HTML.

Runs on **Windows, Linux, and macOS** (Python 3.10+).

> 📑 For the formal specification — per-plugin functional requirements, severity
> mapping, language/tool matrices, config & JSON schema, scoring, exit codes, and
> known limitations — see **[SPEC.md](SPEC.md)**.

---

## Highlights

**What it detects** — eight independent checks:

- 🔑 **Secrets** — hardcoded API keys, tokens, passwords, and private keys (regex + entropy, optionally `gitleaks`/`trufflehog`).
- 📦 **Vulnerable & risky dependencies** — known CVEs (OSV + native audits) plus malicious & typosquat packages.
- 📄 **License compliance** — dependency licenses against your `deny`/`allow` policy, and a missing project `LICENSE`.
- 🕵️ **PII** — emails, phones, SSNs, credit cards, IBANs, and IDs, with **confidence scoring** to cut false positives.
- ⚙️ **Insecure configuration** — debug mode, disabled TLS verification, weak crypto, `CORS *`, default credentials, `JWT alg=none`.
- 🔐 **`.env` exposure** — graded by *committed-to-git / un-ignored / has-real-values*.
- 🚫 **`.gitignore` gaps** — missing rules for secrets/keys, plus git-tracked "dangerous" files.
- 🖼️ **Unlicensed assets** — font embedding rights (`fsType`) and image copyright metadata (EXIF/XMP).

**How it works** — the capabilities behind those checks:

- **Multi-language** — Python, Node.js/TypeScript, Java, Kotlin/Android, C#/.NET, PHP, Go, and iOS (Objective-C/Swift), via auto-discovered *adapters*.
- **Layered** — each area has a fast built-in check that needs no setup, and *additionally* runs a best-in-class external tool when installed (gitleaks, trufflehog, pip-audit, npm audit, OSV, govulncheck, GHSA, …); results are merged.
- **Self-provisioning** — a pre-scan check verifies, and can **auto-install**, the tools your enabled features need (scoped to the detected languages).
- **Clean reports** — the same issue found by several tools is shown and **counted once** (others noted as *"also detected by …"*); findings are grouped by area with a clickable **per-section summary**, plus a 0–100 **score and A–F grade** — in console, JSON, Markdown, or self-contained HTML.
- **Extensible** — every check is an auto-discovered plugin and every language an auto-discovered adapter; drop a file in to add one.

---

## Installation

```bash
git clone <your-repo-url> security-scanner
cd security-scanner

python -m venv venv
# Windows:        venv\Scripts\activate
# Linux / macOS:  source venv/bin/activate

pip install -r requirements.txt   # only hard dependency is PyYAML
```

> The only required dependency is **PyYAML**. Everything else is optional and used
> only when the corresponding check is enabled — the scanner degrades gracefully
> and (with `auto_install`) can install what it needs (see *Pre-scan requirements*).

### Optional tooling

| Purpose | Tool(s) |
|---|---|
| Secret scanning | `gitleaks`, `trufflehog` (built-in regex needs nothing) |
| Python deps | `pip-audit`, `pip-licenses` |
| Node deps | `npm`, `license-checker` |
| Go deps | `govulncheck`, `go-licenses` |
| .NET deps | `dotnet` SDK, `dotnet-project-licenses` |
| PHP deps | `composer` |
| Swift/iOS deps | GitHub Advisory DB (network), `license_finder` |
| Asset metadata | `fonttools`, `Pillow` (pip); `tesseract` for OCR |

---

## Usage

Run from anywhere, pointing at the project to scan:

```bash
python main.py /path/to/your/project --format html -o report
```

### Command-line arguments

| Argument | Description |
|---|---|
| `path` | Project to scan (default: current directory). |
| `--config` | Config file path (default: `config.yaml`). |
| `-o, --output` | Output report basename (`report` → `report.html`/`.json`/`.md`). |
| `--format` | `console` (default), `json`, `md`, or `html`. |
| `--strict-requirements` | Stop the scan if any required tool is missing (this is the default). |
| `--no-strict-requirements` | Warn about missing tools but scan anyway (this run). |
| `--skip-requirements-check` | Skip the pre-scan requirements check entirely. |
| `--install-missing` | Attempt to auto-install missing tools before scanning. |

**Exit code:** `1` if any CRITICAL/HIGH findings exist (useful for CI gates), `0` otherwise; `2` if a strict requirements check aborts.

> **Tip:** install Python-based tools into the *same* interpreter that runs the
> scanner (`python -m pip install pip-audit pip-licenses`). The scanner resolves
> tools from PATH **and** common install dirs (pip Scripts, winget Packages, scoop
> shims, `~/go/bin`, `~/.dotnet/tools`, Homebrew), so a freshly-installed tool is
> found without opening a new shell.

---

## Pre-scan requirements check & auto-install

Before scanning, the tool builds the list of external CLIs the **enabled** features
need, **scoped to the languages it detects**, and verifies they're installed.

- **Strict by default** — if a required tool is missing the scan **stops** and prints how to install it (override per-run with `--no-strict-requirements`, or disable with `preflight.strict: false`).
- **Auto-install** (`auto_install: true` or `--install-missing`):
  - pip / npm / dotnet / gem / `go install` for tool-chain installers,
  - OS package managers for standalone binaries (`scoop`/`winget`/`choco`/`brew`),
  - **GitHub release binaries** as a last resort (e.g. trufflehog, gitleaks) → installed to `~/.security-scanner/bin`,
  - optional **Go bootstrap** via a signed package manager when a tool needs `go install` and Go is absent (never via remote scripts).
- **Optional tools** — list commands under `preflight.optional` to downgrade them to a non-blocking `[WARN]`.

```text
Checking tool requirements (enabled config features x detected languages):
  [ OK ]  gitleaks        secret_checker (gitleaks)
  [MISS]  pip-licenses    license_checker tool (python)
          install: pip install pip-licenses
  [NOTE]  api.osv.dev     dependency_checker (OSV CVE lookup) (network)
```

---

## Configuration (`config.yaml`)

```yaml
preflight:
  enabled: true            # run the requirements check before scanning
  strict: true             # stop the scan when a required tool is missing
  auto_install: true       # install missing tools before scanning
  binary_installer: auto   # scoop | winget | choco | brew | none (for gitleaks/trufflehog)
  bootstrap_runtimes: true # install Go via a signed package manager if a tool needs it
  optional: []             # tools that should WARN (not block) if missing

file_scanner:
  ignore_dirs:   ["logs", "tmp"]
  ignore_patterns: ["*.log", "package-lock.json"]

plugins:
  secret_checker:
    enabled: true
    tool_config:           # every enabled tool runs; results are merged
      python_regex: { enabled: true }   # built-in, no install
      gitleaks:     { enabled: false }  # external CLI
      trufflehog:   { enabled: false }  # external CLI

  dependency_checker:
    enabled: true
    tools:
      osv:           { enabled: true }  # OSV.dev CVE lookup (network)
      project_audit: { enabled: true }  # native audit (pip-audit, npm audit, govulncheck, ...)

  license_checker:
    enabled: true
    tools:
      content: true        # read licenses from lockfiles/metadata
      project_tool: true   # run the native license tool (pip-licenses, license-checker, ...)
    deny: ["GPL-2.0-only", "AGPL-3.0-only"]
    allow_classifications: ["permissive"]

  asset_checker:
    enabled: true
    tools:
      font_metadata: true      # read embedded font license + fsType (pip: fonttools)
      image_metadata: true     # read image EXIF/IPTC/XMP license (pip: Pillow)
      ocr_text_in_image: false # OCR images to flag text for manual font review (tesseract)

  env_checker:      { enabled: true }
  gitignore_checker:{ enabled: true }
  config_checker:   { enabled: true }

  pii_checker:
    enabled: true
    min_confidence: high   # high = only validated/context-confirmed PII (quiet); low = every match
    bulk_threshold: 6      # N bare emails/phones in one file => flagged as a likely real dataset
    disabled_categories: []  # PII pattern names to skip, e.g. ["IPv4 Address (non-private)"]
    allowlist: []            # regexes for your own known-safe values

adapters: {}
```

---

## Plugins

| Plugin | What it does |
|---|---|
| **secret_checker** | Hardcoded secrets/keys/tokens. Runs **all enabled tools** (built-in regex + entropy, `gitleaks`, `trufflehog`) and merges results under per-tool sub-groups. Secrets are masked in evidence. |
| **dependency_checker** | Known-**malicious** & **typosquat** packages (all ecosystems), **OSV** CVE lookups (PyPI/npm/Maven/NuGet/Packagist/Go), and per-language **native audits** (pip-audit, npm audit, `dotnet list --vulnerable`, `composer audit`, govulncheck, Swift→GitHub Advisory DB). |
| **license_checker** | Missing project `LICENSE`, dependency licenses from lockfiles **and** native tools (per-tool sub-groups), and policy enforcement (`deny` / `allow_classifications`). Verbose license names (e.g. "Apache Software License") are classified correctly. |
| **env_checker** | Finds `.env` files and grades exposure using a matrix of *committed-to-git / un-ignored / populated*: committed real `.env` → CRITICAL, properly ignored → INFO. |
| **gitignore_checker** | Context-aware required patterns (Terraform/Java patterns only for those stacks), git-tracked "dangerous file" detection, and `.env`-aware severity. Defers `.env` exposure to `env_checker` (no duplicate findings). |
| **pii_checker** | Emails, phones, SSNs, Luhn-validated cards, mod-97-validated IBANs, passports, tax/medical IDs, etc. **Confidence-based**: by default (`min_confidence: high`) reports only validated or context-confirmed PII and stays quiet on bare emails/phones/IPs, while flagging data-dump files in bulk. Documented dummy values (example.com, test cards, sample SSNs) are allowlisted; test/mock files downgraded. Set `min_confidence: low` for every match. |
| **config_checker** | Insecure settings in YAML/JSON/etc.: debug mode, disabled TLS verification, weak crypto, CORS `*`, hardcoded/default credentials, `JWT alg=none`, and more. |
| **asset_checker** | Fonts: embedded license + **`fsType` embedding rights** via `fontTools`. Images: **EXIF/IPTC/XMP** copyright/usage via `Pillow`. Optional OCR flags images containing rendered text for **manual** font-license review (the font itself can't be auto-identified). Falls back to filename/nearby-LICENSE heuristics without the libs. |

---

## Adapters (language support)

Adapters detect a project's languages and extract dependency/framework metadata
(with versions). Discovered automatically.

| Adapter | Detects | Native audit | Native license tool |
|---|---|---|---|
| `python` | `requirements*.txt`, `pyproject.toml`, `Pipfile` | `pip-audit` | `pip-licenses` |
| `node` | `package.json` (+ lockfile) | `npm audit` | `license-checker` |
| `java` | `pom.xml`, `build.gradle(.kts)` incl. Android modules & Kotlin DSL | OSV (Maven) | — |
| `dotnet` | `*.csproj`, `packages.config` | `dotnet list --vulnerable` | `dotnet-project-licenses` |
| `php` | `composer.json` (+ `composer.lock`) | `composer audit` | `composer licenses` |
| `go` | `go.mod` | `govulncheck` | `go-licenses` |
| `swift` | `Package.swift`, `Podfile`/`Podfile.lock`, `*.xcodeproj` | GitHub Advisory DB (SwiftPM URLs) | `license_finder` |

---

## Security score

A 0–100 score with an **A–F grade** using **diminishing returns** per severity
(`penalty = weight × count^0.7`), so the score is a meaningful gradient that moves
as you fix issues — not a flat 0 the moment a few criticals appear. INFO findings
never affect the score.

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

- **console** — colored summary + critical/high list.
- **json** — full structured data (real plugin names; ideal for CI).
- **md** — Markdown.
- **html** — self-contained, collapsible HTML report.

Findings group by plugin → sub-tool. Related plugins are merged into one section
(`.env` + `.gitignore` → **"Environment & Gitignore"**). The Project Information
panel shows OS + version, languages, framework + version, scanned path, git info,
and files scanned. Timestamps use the machine's **local timezone**.

**Cross-tool de-duplication.** The same data point found by multiple sub-tools is
shown once — the highest-severity finding is kept and the others are noted as
*"also detected by …"*. Counts and the score run on the de-duplicated set, so three
tools finding one secret don't inflate the numbers. (Findings with a file+line dedupe
on section+file+line; file-less findings like licenses dedupe on section+title.)

**Security Summary by Section.** Below Project Information, a per-section severity
breakdown (most-severe section first). In HTML each row is **clickable** and scrolls
to that section's findings.

---

## Extending the scanner

### New plugin
1. Add a file in `scanner/plugins/`.
2. Subclass `BasePlugin`, set `name`/`description`, implement `scan(root, files, context)`.
3. Use `self.add_finding(...)`. It's auto-discovered.

### New adapter
1. Add a file in `scanner/adapters/`.
2. Subclass `BaseAdapter`, implement `detect()` and `collect()` (return `packages` nested as `{ecosystem: {pkg: version}}`).
3. Optionally declare:
   - `REQUIRED_TOOLS = {"audit": (cmd, hint), "license": (cmd, hint)}` — wired into the pre-scan requirements check.
   - `ENV_ACCESS_PATTERNS = [(regex, label), ...]` — aggregated by `env_checker`.
   - `audit_dependencies()` / `check_licenses_with_tool(config)` — native tool integrations.

---

## Project layout

```
main.py                     # entry point, CLI, orchestration, preflight
config.yaml                 # configuration
scanner/
  core/
    file_scanner.py         # file walk, language detection, ignore handling
    git_scanner.py          # git metadata
    report_engine.py        # scoring, grade, console/json/md output, grouping
    requirements.py         # pre-scan requirements + auto-install
  plugins/                  # secret/dependency/license/env/gitignore/pii/config/asset checkers
  adapters/                 # python, node, java, dotnet, php, go, swift
  reports/html_template.py  # HTML renderer
  utils/                    # license + gitignore helpers
```
