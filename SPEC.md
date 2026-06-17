# Project Security Scanner — Specification

Formal reference for behavior, requirements, and contracts. For install/usage see
[README.md](README.md). This document reflects the implemented source.

---

## 1. Scope & non-goals

**In scope.** Static detection of: hardcoded secrets, vulnerable, malicious, or typosquatted
dependencies, license-policy violations, PII in source, insecure configuration,
`.env`/`.gitignore` exposure, and unlicensed font/image assets — across multiple
languages — with a scored, multi-format report.

**Non-goals / explicit limitations.**
- It **flags potential issues for human review**; it is not a substitute for SAST,
  DAST, or a penetration test.
- It does **not** identify the typeface used in text *rendered inside an image*
  (no reliable offline method exists); it only flags such images for manual review.
- Adapters read manifests at the **scan-path root** only — scan monorepo
  subprojects individually for dependency/license results.
- It does not execute project code; checks are static (plus optional network calls
  to OSV / GitHub Advisory DB).

---

## 2. Platform & runtime requirements

| Requirement | Value |
|---|---|
| Python | 3.10+ (Linux OS detection uses `platform.freedesktop_os_release`, added in 3.10) |
| Hard dependency | `PyYAML` |
| OS | Windows, Linux, macOS |
| Console | stdout/stderr reconfigured to UTF-8 (`errors="replace"`) at startup so output is safe on any locale (e.g. Windows cp932) and when redirected |

Optional Python libs and external CLIs are required **only** when the corresponding
feature is enabled — see §7.

---

## 3. CLI contract

```
python main.py [path] [--config FILE] [-o BASENAME] [--format {console,json,md,html}]
               [--strict-requirements | --no-strict-requirements]
               [--skip-requirements-check] [--install-missing]
```

| Argument | Default | Meaning |
|---|---|---|
| `path` | `.` | Project directory to scan (must exist). |
| `--config` | `config.yaml` | YAML config path (read as UTF-8). |
| `-o, --output` | `report` | Report basename; extension added per format. |
| `--format` | `console` | `console`, `json`, `md`, `html`. |
| `--strict-requirements` | (default on) | Abort if a required tool is missing. |
| `--no-strict-requirements` | — | Warn but continue this run. |
| `--skip-requirements-check` | — | Skip the requirements check entirely. |
| `--install-missing` | — | Attempt auto-install before scanning. |

**Exit codes:** `0` = scan completed, no CRITICAL/HIGH; `1` = scan completed with ≥1
CRITICAL or HIGH finding; `2` = aborted by a strict requirements check.

---

## 4. Severity model

| Severity | Use |
|---|---|
| `CRITICAL` | Confirmed/likely exploitable exposure (live secret, committed `.env`, denied license). |
| `HIGH` | Serious risk needing prompt action (likely secret, restrictive license, vuln). |
| `MEDIUM` | Should fix (weaker secret signal, medium CVE, copyright-unclear image). |
| `WARNING` | Tool/runtime failure surfaced as a finding. |
| `LOW` | Hygiene/advisory (preventative gitignore rule, undetermined license, no image metadata). |
| `INFO` | Informational / "scan ran" confirmation; never affects the score. |

False-positive controls: findings in **test/mock/example/sample** paths are
downgraded (HIGH/MEDIUM → LOW); credit cards are **Luhn**-validated and IBANs
**mod-97**-validated; PII defaults to high-confidence only (validated or keyword-
confirmed) with documented dummy values allowlisted (§5.6); secret entropy checks
require Shannon ≥ 4.5 and length ≥ 20; comment-only lines are skipped for PII.

---

## 5. Functional requirements per plugin

All plugins are auto-discovered from `scanner/plugins/` and gated by
`plugins.<name>.enabled` (default `true`).

### 5.1 secret_checker
- Runs **every enabled tool** and merges results under `secret_checker:<tool>`:
  - `python_regex` (built-in): ~40 patterns across cloud (AWS/GCP/Azure), SCM tokens
    (GitHub/GitLab), payments (Stripe/PayPal/Square), comms (Twilio/Slack/SendGrid/
    Mailgun), private keys (RSA/EC/PGP/OpenSSH/cert), DB connection strings
    (Mongo/Postgres/MySQL/Redis/JDBC), generic password/API-key/token/bearer/JWT, and
    infra (npm token, docker, k8s, ssh). Plus Shannon-entropy detection on config/env files.
  - `gitleaks`, `trufflehog` (external): exit-code aware (gitleaks exit 1 = leaks found, not failure); report parsed from a temp file.
- Severity per pattern; example/test files downgrade HIGH/MEDIUM → LOW. Evidence is masked.
- Emits an INFO "scan completed — no secrets found" per tool that runs clean (so the tool's execution is visible in the report).

### 5.2 dependency_checker
- Consumes `{ecosystem: {package: version}}` from adapters.
- **Known-malicious** packages → CRITICAL; **typosquat** candidates → HIGH (all ecosystems).
- **OSV** (`tools.osv`): queries OSV.dev per ecosystem (PyPI/npm/Maven/NuGet/Packagist/Go/RubyGems/crates.io); severity from CVSS v3 (≥9.0 CRITICAL, ≥7.0 HIGH, ≥4.0 MEDIUM, else LOW; default MEDIUM). Up to 20 packages/ecosystem; emits an INFO when an ecosystem has no OSV DB (e.g. Swift).
- **Native audit** (`tools.project_audit`): per-adapter `audit_dependencies()` (pip-audit, npm audit, `dotnet list --vulnerable`, `composer audit`, govulncheck, Swift→GitHub Advisory DB).

### 5.3 license_checker
- Missing root `LICENSE` → HIGH.
- **content** (`tools.content`): dependency licenses from lockfiles/metadata; `deny` → CRITICAL, classification ∉ `allow_classifications` → HIGH, undetermined/no-license → a single LOW summary.
- **project_tool** (`tools.project_tool`): native tool per adapter, grouped under `license_checker:<tool>`; emits a completion INFO when clean.
- When `content` and `project_tool` flag the same package+license, the report shows it once (file-less de-duplication on section+title — see §9); both paths still run and either can be toggled off in config.
- Classification is keyword-based and recognizes verbose names (e.g. "Apache Software License" → permissive). Classes: `permissive`, `weak-copyleft`, `strong-copyleft`, `restricted`, `no-license`, `unknown`.

### 5.4 env_checker
- Detects `.env`, `.env.*`, `*.env`; `example`/`sample` treated as templates.
- Exposure matrix (using git-tracked + populated + ignored signals):

  | State | Severity |
  |---|---|
  | committed to git, real values | CRITICAL |
  | committed to git, template-like | HIGH |
  | not covered by `.gitignore` | CRITICAL (populated) / HIGH |
  | ignored, has real values | INFO |
  | ignored, clean | INFO |
  | `.env.example` with real values | MEDIUM |

- Env-var access in source with no `.env`/template → MEDIUM (access patterns aggregated from adapters).

### 5.5 gitignore_checker
- No `.gitignore` → CRITICAL.
- **Required patterns**: always (`.env`, `.env.*`, `*.pem`, `*.key`); conditional on detected stack (node `node_modules`; java `*.jks/*.keystore/*.p12`; terraform `*.tfstate`/`terraform.tfvars`; sql dumps). `.env`/`.env.*` severity is CRITICAL/HIGH only when a real `.env` is **present**, else MEDIUM (preventative); when present, defers to `env_checker` to avoid duplicates.
- **Dangerous files**: sensitive files that are git-tracked (or present-and-un-ignored when no git data) → severity per list (`id_rsa`, `*.pem`, `*.key`, `*secret*`, `*.tfstate`, …). `.env*` excluded (owned by env_checker).
- `.gitignore` parsing is negation-aware (`!pattern`).

### 5.6 pii_checker
Pattern set (base severity): email (MEDIUM), US/intl phone (MEDIUM), SSN (CRITICAL),
credit card — **Luhn**-validated (CRITICAL), non-private IPv4 (LOW), date-of-birth
(HIGH), passport (HIGH), driver license (HIGH), national/tax ID (HIGH), IBAN —
**mod-97**-validated (CRITICAL), medical record number (CRITICAL).

**Confidence model.** Each match is `high` (validated — card/IBAN — or confirmed by a
PII keyword near the value, with the value itself excluded from the keyword check so an
email's own domain can't self-confirm) or `low` (a bare match). `min_confidence`
(default `high`) reports only high-confidence findings and stays quiet on bare
emails/phones/IPs; set `low` to report every match.
- **Bulk heuristic:** a file with ≥ `bulk_threshold` (default 6) bare emails/phones is
  flagged once as a likely real dataset (CSV/SQL dump), even in `high` mode.
- **Allowlists:** documented dummies are never flagged (example.com / `noreply` emails,
  reserved 555-01xx phones, canonical test cards, sample SSNs); `allowlist` adds custom
  regexes; `disabled_categories` skips named patterns.
- **Passport** is keyword-gated (requires a passport keyword on the line).
- Test/mock/fixture paths downgrade MEDIUM/HIGH → LOW; comment-only lines skipped; PII
  masked in evidence.

### 5.7 config_checker
Scans `.yaml/.yml/.json/.xml/.properties/.toml/.ini/.cfg/.conf/.config` for: debug
mode (HIGH), disabled SSL/TLS verification & insecure-skip-verify (CRITICAL), weak
crypto MD5/SHA1/DES/RC4 (HIGH), weak TLS version (HIGH), CORS `*` (HIGH), admin/root
password & default/weak password (CRITICAL), bind `0.0.0.0` (MEDIUM), unsafe upload
path (MEDIUM), hardcoded secret key (HIGH), `JWT alg=none` (CRITICAL), DB user `root`
(HIGH), verbose log level (LOW), exposed management port (MEDIUM). JSON files also get
a recursive sensitive-key walk (HIGH, placeholder-aware).

### 5.8 asset_checker
- **Fonts** (`tools.font_metadata`, lib `fonttools`): reads `OS/2.fsType` embedding
  rights + `name` table — Restricted → HIGH, Preview&Print-only → MEDIUM,
  Installable/Editable → INFO, unreadable fsType → LOW. When active it is authoritative
  (the nearby-LICENSE directory heuristic is suppressed). Without the lib: filename
  heuristics (stock-name HIGH, commercial-risk MEDIUM, no nearby LICENSE HIGH).
- **Images** (`tools.image_metadata`, lib `Pillow`): EXIF/PNG-text/XMP → no metadata
  LOW, copyright-without-license MEDIUM, permissive (CC0/Unsplash/…) INFO; stock
  filename → CRITICAL.
- **OCR** (`tools.ocr_text_in_image`, `tesseract`+`pytesseract`, default off): flags
  images containing rendered text for **manual** font-license review (font not auto-identified).
- **SVG**: stock filename (HIGH), copyright-unclear (MEDIUM).

---

## 6. Language / ecosystem support

| Adapter | Detection | OSV ecosystem | Native audit | Native license tool | Framework version |
|---|---|---|---|---|---|
| `python` | `requirements*.txt`, `pyproject.toml`, `setup.py/cfg`, `Pipfile` | PyPI | `pip-audit` | `pip-licenses` | ✅ |
| `node` | `package.json` (+ lock) | npm | `npm audit` | `license-checker` | ✅ |
| `java` | `pom.xml`, `build.gradle(.kts)` (root + modules, Kotlin DSL) | Maven | OSV only | — | partial |
| `dotnet` | `*.csproj`, `packages.config` | NuGet | `dotnet list --vulnerable` | `dotnet-project-licenses` | TFM |
| `php` | `composer.json` (+ `composer.lock`) | Packagist | `composer audit` | `composer licenses` | ✅ |
| `go` | `go.mod` | Go | `govulncheck` | `go-licenses` | ✅ |
| `swift` | `Package.swift`, `Podfile`/`Podfile.lock`, `*.xcodeproj` | — (GitHub Advisory DB) | GHSA (SwiftPM URLs) | `license_finder` | — |

Adapters return `packages = {ecosystem: {name: version}}`, a `dependencies` map with
licenses, and `framework`/`project_version`.

---

## 7. External tool requirements & install

The pre-scan check ([scanner/core/requirements.py](scanner/core/requirements.py))
builds requirements from **enabled config × detected languages**.

| Feature (config) | Tool | Detected via | Auto-install method |
|---|---|---|---|
| `secret_checker.tool_config.gitleaks` | `gitleaks` | PATH/install dirs | scoop/winget/choco/brew, else GitHub release binary |
| `secret_checker.tool_config.trufflehog` | `trufflehog` | PATH/install dirs | scoop/choco/brew, else **GitHub release binary** (not on winget; `go install` unsupported) |
| `dependency_checker.tools.osv` | network → `api.osv.dev` | — | n/a (network) |
| `dependency_checker.tools.project_audit` | per-adapter audit CLI | module/PATH | pip / npm / `go install` / dotnet / composer |
| `license_checker.tools.project_tool` | per-adapter license CLI | module/PATH | pip / npm / `go install` / dotnet / composer / gem |
| `asset_checker.tools.font_metadata` | `fonttools` (module `fontTools`) | import | `pip install fonttools` |
| `asset_checker.tools.image_metadata` | `Pillow` (module `PIL`) | import | `pip install Pillow` |
| `asset_checker.tools.ocr_text_in_image` | `tesseract` + `pytesseract` | PATH + import | package manager + pip |

**Tool resolution** searches PATH plus install dirs that may not be on PATH yet
(pip Scripts, winget `Packages`/`Links`, scoop shims, `~/go/bin`, `~/.dotnet/tools`,
Homebrew, `~/.security-scanner/bin`) and tool-specific install locations (e.g.
Tesseract's `Program Files\Tesseract-OCR` / user-scope `Programs` dir, which its MSI
installer never adds to PATH). Python tools are detected by import and run via
`python -m <module>`; for OCR the resolved `tesseract` path is also handed to
`pytesseract`, so OCR works in the current shell without a PATH refresh.

**Auto-install order per tool:** tool-chain/pip installer → OS package manager
(`auto` preference: scoop → brew → winget → choco) → GitHub release binary. If a tool
needs `go install` and Go is absent, Go is bootstrapped via a signed package manager
(`bootstrap_runtimes`) — never via remote scripts.

---

## 8. Configuration schema

| Key | Type | Default | Effect |
|---|---|---|---|
| `preflight.enabled` | bool | `true` | Run the requirements check. |
| `preflight.strict` | bool | `true` | Abort scan if a required tool is missing. |
| `preflight.auto_install` | bool | `false`* | Auto-install missing tools first. |
| `preflight.binary_installer` | enum | `auto` | `auto`/`scoop`/`winget`/`choco`/`brew`/`none` for binaries. |
| `preflight.bootstrap_runtimes` | bool | `true` | Bootstrap Go via a signed manager when needed. |
| `preflight.optional` | list[str] | `[]` | Tools that WARN (not block) if missing. |
| `file_scanner.ignore_dirs` | list[str] | — | Extra directories to skip. |
| `file_scanner.ignore_patterns` | list[str] | — | Extra glob patterns to skip. |
| `plugins.<name>.enabled` | bool | `true` | Enable/disable a plugin. |
| `plugins.secret_checker.tool_config.<tool>.enabled` | bool | — | Enable a secret tool (all enabled run). |
| `plugins.dependency_checker.tools.{osv,project_audit}.enabled` | bool | `true` | Toggle dependency check paths. |
| `plugins.license_checker.tools.{content,project_tool}` | bool | — | Toggle license check paths. |
| `plugins.license_checker.deny` | list[str] | — | Denied SPDX licenses → CRITICAL. |
| `plugins.license_checker.allow_classifications` | list[str] | `[permissive]` | Allowed license classes. |
| `plugins.asset_checker.tools.{font_metadata,image_metadata,ocr_text_in_image}` | bool | `true`/`true`/`false` | Asset deep-checks. |
| `plugins.pii_checker.min_confidence` | enum | `high` | `high` = only validated/context-confirmed PII; `low` = every match. |
| `plugins.pii_checker.bulk_threshold` | int | `6` | N bare emails/phones in one file → flagged as a likely real dataset. |
| `plugins.pii_checker.disabled_categories` | list[str] | `[]` | PII pattern names to skip. |
| `plugins.pii_checker.allowlist` | list[str] | `[]` | Regexes for values never to flag. |

\* The shipped `config.yaml` enables `auto_install`; the code default when the key is
absent is `false`.

---

## 9. Output / JSON schema

Top-level report object:

```jsonc
{
  "generated_at": "<ISO-8601 local time with UTC offset, e.g. 2026-06-15 14:18:33+07:00>",
  "score": 0-100,
  "grade": "A|B|C|D|F",
  "project": {
    "project_name", "path", "scan_path", "languages", "framework",
    "environment", "files_scanned",
    "git_remote", "git_branch", "git_last_commit", "git_author", "repo_name"
  },
  "summary": { "CRITICAL": n, "HIGH": n, "MEDIUM": n, "WARNING": n, "LOW": n, "INFO": n },
  "sections": [ { "section": "<title>", "counts": { "<severity>": n }, "total": n, "worst": "<severity>" } ],
  "total_findings": n,
  "findings": [ {
    "severity", "plugin", "title", "description", "recommendation",
    "file", "line", "evidence", "tags": [], "also_detected_by": []
  } ]
}
```

`plugin` uses `name` or `name:subtool` (e.g. `secret_checker:gitleaks`,
`dependency_checker:osv`, `license_checker:pip-licenses`). JSON keeps real plugin
names; Markdown/HTML group related plugins into sections (`.env` + `.gitignore` →
"Environment & Gitignore") and group by sub-tool.

**De-duplication (applied before counting/scoring).** The same data point reported by
multiple sub-tools is collapsed to one finding: findings with a `file`+`line` dedupe on
`(section, file, line)` (a line-less finding folds into a lined one for the same file;
two line-less findings are never merged); file-less findings dedupe on
`(section, title)`. The highest-severity finding is kept; the other detectors' subgroup
labels are recorded in **`also_detected_by`**. `total_findings`, `summary`, and the
score all reflect the de-duplicated set.

**`sections`** is the per-report-section severity breakdown (sorted most-severe first,
then largest), powering the HTML "Security Summary by Section" card — whose rows are
clickable and scroll to the section — and the Markdown table.

`generated_at` is the machine's **local** time with its UTC offset (not UTC).

---

## 10. Scoring specification

```
penalty = Σ_severity ( weight[severity] × count[severity] ^ 0.7 )
score   = max(0, round(100 − penalty))
```

| Severity | Weight |
|---|---|
| CRITICAL | 25.0 |
| HIGH | 12.0 |
| MEDIUM | 4.0 |
| WARNING | 2.5 |
| LOW | 1.0 |
| INFO | 0.0 |

Diminishing returns (exponent 0.7) keep the score a meaningful gradient (it does not
flat-line at 0 once a few criticals appear) and improve as issues are fixed.

| Grade | Score |
|---|---|
| A | 90–100 |
| B | 75–89 |
| C | 60–74 |
| D | 40–59 |
| F | < 40 |

---

## 11. Known limitations

- **Monorepos:** adapters read root manifests only → scan each subproject for deps/licenses.
- **Font-in-image:** typeface inside a raster image cannot be auto-identified; OCR only flags for manual review.
- **Swift vulns:** GHSA matches SwiftPM URL identifiers, not CocoaPods short names; no OSV ecosystem for Swift.
- **trufflehog:** not on winget; `go install` unsupported (replace directives) → installed via release binary.
- **license content vs tool:** both `content` and `project_tool` evaluate licenses; when they flag the same package the report **de-duplicates** it (shown once, with the other path noted in `also_detected_by`) and counts it once. Toggle either path off in config if you want only one.
- **pip-licenses:** inspects the active interpreter's environment, not an arbitrary target venv.
- **Auto-installed binaries:** may require a new shell for PATH to refresh (the scanner resolves common install dirs to mitigate this).
