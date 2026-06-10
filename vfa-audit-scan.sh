#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# vfa-audit-scan.sh —  Source-code security audit, URL-friendly runner
#
#   Layer 1 — Secrets  : Gitleaks + Trivy  (credentials, tokens, API keys)
#   Layer 2 — CVE      : Trivy + Grype + GitHub Advisory (pip)
#   Layer 3 — License  : Trivy + ExifTool  (library & font license compliance)
#
# Usage:
#   ./vfa-audit-scan.sh [OPTIONS] [project-path]
#   curl -fsSL <raw-github-url>/vfa-audit-scan.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash -s -- --severity HIGH
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

RUN_DIR="$(pwd)"
SCRIPT_SOURCE="${BASH_SOURCE[0]:-$0}"
if [[ -f "$SCRIPT_SOURCE" && "$SCRIPT_SOURCE" != /dev/fd/* && "$SCRIPT_SOURCE" != /proc/self/fd/* ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
else
  SCRIPT_DIR="$RUN_DIR"
fi
SCRIPT_NAME="$(basename "$SCRIPT_SOURCE")"
case "$SCRIPT_NAME" in
  bash|sh|zsh|[0-9]*|fd/*) SCRIPT_NAME="vfa-audit-scan.sh" ;;
esac
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# ── Defaults ──────────────────────────────────────────────────────────────────
OUTPUT_BASE=""             # -o: base dir; reports go to <base>/<ts>_<project>
OUTPUT_DIR=""              # resolved in parse_args, always a folder this run creates
SEVERITY="UNKNOWN"         # UNKNOWN | LOW | MEDIUM | HIGH | CRITICAL
SKIP_SECRETS=false
SKIP_CVE=false
SKIP_LICENSE=false
NO_GIT_HISTORY=false       # Gitleaks: skip git history, scan files only
AUTO_INSTALL=true
VERBOSE=false
PROJECT_PATH=""

# ── Counters ──────────────────────────────────────────────────────────────────
SECRET_COUNT=0
TRIVY_SECRET_COUNT=0
TRIVY_CVE_COUNT=0
GRYPE_CVE_COUNT=0
FRESH_ADVISORY_COUNT=0
LICENSE_ISSUE_COUNT=0
FONT_FILE_COUNT=0
FONT_LICENSE_ISSUE_COUNT=0
TOOL_ERRORS=0

# ── Per-scanner status: ok | findings | failed | skipped ─────────────────────
SECRETS_STATUS="skipped"
TRIVY_STATUS="skipped"
GRYPE_STATUS="skipped"
ADVISORY_STATUS="skipped"
FONT_STATUS="skipped"

FAILED_TOOLS=" "           # space-separated tools that could not be installed
KEEP_LOGS=" "              # logs to keep in the report — only those explaining
                           # an error that affects audit quality

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
log()     { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()      { echo -e "${GRN}[ OK ]${NC}  $*"; }
no()      { echo -e "${YEL}[ NO ]${NC}  $*"; }
warn()    { echo -e "${YEL}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERR ]${NC}  $*" >&2; }
section() {
  echo ""
  echo -e "${BLD}${CYN}┌──────────────────────────────────────────────────────────┐${NC}"
  printf  "${BLD}${CYN}│  %-56s│${NC}\n" "$*"
  echo -e "${BLD}${CYN}└──────────────────────────────────────────────────────────┘${NC}"
}
cmd_ok()      { command -v "$1" &>/dev/null; }
tool_failed() { [[ "$FAILED_TOOLS" == *" $1 "* ]]; }
keep_log()    { KEEP_LOGS+="$(basename "$1") "; }

# Returns comma-separated severity list from $SEVERITY upward
# e.g. MEDIUM → "MEDIUM,HIGH,CRITICAL"
severity_list() {
  local all=("UNKNOWN" "LOW" "MEDIUM" "HIGH" "CRITICAL")
  local out="" active=false
  for lvl in "${all[@]}"; do
    [[ "$lvl" == "$SEVERITY" ]] && active=true
    [[ "$active" == true ]] && out+="${lvl},"
  done
  echo "${out%,}"
}

# ─────────────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BLD}USAGE${NC}
  ${SCRIPT_NAME} [OPTIONS] [project-path]

${BLD}DESCRIPTION${NC}
  3-layer source code security audit combining four scanners:
    • Secrets  — Gitleaks (files + git history) + Trivy secret scanner
    • CVE      — Trivy + Grype + GitHub Advisory: known dependency vulnerabilities
    • License  — Trivy + ExifTool: library and font license compliance

  If project-path is omitted, the script scans the current directory.
  This makes it safe to run directly from a raw GitHub URL.

${BLD}OPTIONS${NC}
  -o, --output <dir>       Base output directory; reports are written to
                           <dir>/<timestamp>_<project>  (default: ./vfa_audit_output)
  -s, --severity <level>   Minimum severity: UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL
                           (default: UNKNOWN — include everything)
      --skip-secrets       Skip Gitleaks scan
      --skip-cve           Skip CVE scan (Trivy vuln/secret + Grype + GitHub Advisory)
      --skip-license       Skip license scan (Trivy license + ExifTool)
      --no-git-history     Scan files only, skip git commit history (Gitleaks)
      --no-install         Do not auto-install missing tools; exit instead
  -v, --verbose            Show full raw scanner output
  -h, --help               Show this help

${BLD}EXAMPLES${NC}
  ${SCRIPT_NAME} /path/to/project
  curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/<branch>/vfa-audit-scan.sh | bash
  curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/<branch>/vfa-audit-scan.sh | bash -s -- --severity HIGH
  ${SCRIPT_NAME} --severity HIGH ~/projects/api
  ${SCRIPT_NAME} --skip-license --verbose /opt/app
  ${SCRIPT_NAME} --no-git-history -o /tmp/audit-out /path/to/project

${BLD}OUTPUT${NC}
  <output-base>/<timestamp>_<project>.zip  (folder is zipped after the run)
    gitleaks.json          Secrets findings (Gitleaks)
    trivy.json             Vuln + secret + license findings (Trivy, JSON)
    trivy.txt              Vuln + secret + license findings (Trivy, table)
    grype.json             CVE findings (Grype, JSON)
    grype.txt              CVE findings (Grype, table)
    fresh-advisory.json    Latest CVE/advisory findings (GitHub Advisory, all ecosystems)
    fresh-advisory.txt     Latest CVE/advisory findings (text)
    font-license-exiftool.json
                          Font metadata from ExifTool (JSON)
    font-license-exiftool.txt
                          Font license/copyright review (text)
    summary.md             Markdown summary
    summary.json           Machine-readable summary
    <tool>.log             Scanner error log — only present when that scanner
                          hit an error affecting audit quality (gitleaks.log,
                          trivy.log, grype.log, fresh-advisory.log, exiftool.log)
EOF
}

# ─────────────────────────────────────────────────────────────────────────────
parse_args() {
  [[ $# -eq 0 ]] && PROJECT_PATH="$RUN_DIR"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output)          OUTPUT_BASE="$2";       shift 2 ;;
      -s|--severity)        SEVERITY="$(printf '%s' "$2" | tr '[:lower:]' '[:upper:]')"; shift 2 ;;
      --skip-secrets)       SKIP_SECRETS=true;      shift   ;;
      --skip-cve)           SKIP_CVE=true;          shift   ;;
      --skip-license)       SKIP_LICENSE=true;      shift   ;;
      --no-git-history)     NO_GIT_HISTORY=true;    shift   ;;
      --no-install)         AUTO_INSTALL=false;     shift   ;;
      -v|--verbose)         VERBOSE=true;           shift   ;;
      -h|--help)            usage; exit 0           ;;
      -*)                   err "Unknown option: $1"; usage; exit 2 ;;
      *)                    PROJECT_PATH="$1";      shift   ;;
    esac
  done

  [[ -z "$PROJECT_PATH" ]] && PROJECT_PATH="$RUN_DIR"
  [[ ! -d "$PROJECT_PATH" ]] && { err "Not a directory: $PROJECT_PATH"; exit 2; }
  PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"

  # Reports always go into a timestamped folder this run creates, so the
  # archive step can safely delete it even when -o points at an existing dir.
  OUTPUT_DIR="${OUTPUT_BASE:-${RUN_DIR}/vfa_audit_output}/${TIMESTAMP}_$(basename "$PROJECT_PATH")"

  case "$SEVERITY" in
    UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL) ;;
    *) err "Invalid severity '$SEVERITY'. Use: UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL"; exit 2 ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
install_tool() {
  local tool="$1"
  log "Installing ${tool}..."

  if cmd_ok brew; then
    brew install "$tool" && return 0 || return 1
  fi

  # Linux fallback — official install scripts
  case "$tool" in
    trivy)
      curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sudo sh -s -- -b /usr/local/bin && return 0 ;;
    grype)
      curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sudo sh -s -- -b /usr/local/bin && return 0 ;;
    exiftool)
      if cmd_ok apt-get; then
        sudo apt-get update && sudo apt-get install -y libimage-exiftool-perl && return 0
      fi
      if cmd_ok apk; then
        sudo apk add --no-cache exiftool && return 0
      fi
      if cmd_ok yum; then
        sudo yum install -y perl-Image-ExifTool && return 0
      fi ;;
    gitleaks)
      local tag ver arch
      tag=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
            | grep '"tag_name"' | cut -d'"' -f4)
      ver="${tag#v}"
      arch=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/')
      curl -sSfL \
        "https://github.com/gitleaks/gitleaks/releases/download/${tag}/gitleaks_${ver}_linux_${arch}.tar.gz" \
        | sudo tar -xz -C /usr/local/bin gitleaks && return 0 ;;
  esac
  return 1
}

# ─────────────────────────────────────────────────────────────────────────────
check_tools() {
  section "Tool Check"
  local -a missing=()

  # python3 is required for all result counting — without it every count
  # silently becomes 0, which is worse than failing fast.
  if ! cmd_ok python3; then
    err "python3 is required but not found. Install it and rerun."
    exit 2
  fi

  _check() {
    local tool="$1"
    local ver_cmd="$2"
    if cmd_ok "$tool"; then
      local ver; ver=$(eval "$ver_cmd" 2>/dev/null | head -1 || echo "?")
      ok "${tool}  ${DIM}${ver}${NC}"
    else
      warn "${tool} not found"
      missing+=("$tool")
    fi
  }

  _check python3 "python3 --version"
  [[ "$SKIP_SECRETS" != true ]] && _check gitleaks "gitleaks version"
  [[ "$SKIP_CVE" != true || "$SKIP_LICENSE" != true ]] && _check trivy "trivy version"
  [[ "$SKIP_CVE" != true ]] && _check grype "grype version"
  [[ "$SKIP_LICENSE" != true ]] && _check exiftool "exiftool -ver"
  cmd_ok zip || warn "zip not found — report folder will not be archived"

  if [[ ${#missing[@]} -gt 0 ]]; then
    if [[ "$AUTO_INSTALL" == true ]]; then
      for t in "${missing[@]}"; do
        if ! install_tool "$t"; then
          err "Failed to install $t — its scan will be marked as failed"
          TOOL_ERRORS=$((TOOL_ERRORS+1))
          FAILED_TOOLS+="$t "
        fi
      done
    else
      err "Missing tools: ${missing[*]}"
      log "Install:  brew install gitleaks trivy grype exiftool"
      log "Or rerun without --no-install to auto-install."
      exit 2
    fi
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_secrets_scan() {
  section "1/4  Secrets  (Gitleaks)"
  local out="${OUTPUT_DIR}/gitleaks.json"
  local scan_log="${OUTPUT_DIR}/gitleaks.log"

  if tool_failed gitleaks || ! cmd_ok gitleaks; then
    SECRETS_STATUS="failed"
    err "gitleaks unavailable — secrets scan NOT performed"
    return
  fi

  if [[ ! -d "${PROJECT_PATH}/.git" ]]; then
    no "No git in project"
    log "Scanning files only (no git history available)"
    NO_GIT_HISTORY=true
  fi

  local -a flags
  if [[ "$NO_GIT_HISTORY" == true ]] && gitleaks dir --help &>/dev/null; then
    # gitleaks 8.19+: `dir` replaces the deprecated `detect --no-git`
    flags=(dir "$PROJECT_PATH"
      --report-path "$out"
      --report-format json
      --no-banner
      --exit-code 1
    )
  else
    flags=(detect
      --source      "$PROJECT_PATH"
      --report-path "$out"
      --report-format json
      --no-banner
      --exit-code 1
    )
    [[ "$NO_GIT_HISTORY" == true ]] && flags+=(--no-git)
  fi

  log "Scanning for secrets in $(basename "$PROJECT_PATH")..."
  local rc=0
  gitleaks "${flags[@]}" >"$scan_log" 2>&1 || rc=$?
  if [[ "$VERBOSE" == true ]]; then
    cat "$scan_log"
  else
    grep -E "(leak|ERR|WRN)" "$scan_log" || true
  fi

  # gitleaks: 0 = clean, 1 = leaks found, anything else = tool error
  if [[ $rc -gt 1 ]]; then
    SECRETS_STATUS="failed"
    TOOL_ERRORS=$((TOOL_ERRORS+1))
    keep_log "$scan_log"
    err "Gitleaks failed (exit ${rc}) — see ${scan_log}"
    return
  fi

  if [[ -f "$out" ]]; then
    SECRET_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d) if isinstance(d, list) else 0)
except Exception:
    print('ERR')
" "$out" 2>>"$scan_log" || echo ERR)
    if [[ "$SECRET_COUNT" == "ERR" ]]; then
      SECRETS_STATUS="failed"
      TOOL_ERRORS=$((TOOL_ERRORS+1))
      SECRET_COUNT=0
      keep_log "$scan_log"
      err "Gitleaks report unreadable: ${out} — see ${scan_log}"
      return
    fi
  fi

  if [[ "$SECRET_COUNT" -eq 0 ]]; then
    SECRETS_STATUS="ok"
    ok "No secrets detected"
  else
    SECRETS_STATUS="findings"
    warn "${SECRET_COUNT} secret(s) found  →  ${out}"
    if cmd_ok jq; then
      jq -r '.[] | "  [\(.RuleID)]  \(.File):\(.StartLine)  \(.Description)"' \
        "$out" 2>/dev/null | head -20 || true
    fi
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Single full Trivy pass: vuln + secret (+ license) depending on skip flags.
run_trivy_scan() {
  local scanners=""
  [[ "$SKIP_CVE" != true ]] && scanners="vuln,secret"
  [[ "$SKIP_LICENSE" != true ]] && scanners="${scanners:+${scanners},}license"

  section "2/4  Trivy  (${scanners})"
  local tj="${OUTPUT_DIR}/trivy.json"
  local tt="${OUTPUT_DIR}/trivy.txt"
  local scan_log="${OUTPUT_DIR}/trivy.log"

  if tool_failed trivy || ! cmd_ok trivy; then
    TRIVY_STATUS="failed"
    err "trivy unavailable — vuln/secret/license scan NOT performed"
    return
  fi

  local -a flags=(fs --scanners "$scanners" --severity "$(severity_list)" --quiet)
  [[ "$scanners" == *license* ]] && flags+=(--license-full)

  log "Trivy: scanning ${scanners} (severity ${SEVERITY}+)..."
  local rc=0
  trivy "${flags[@]}" --format json --output "$tj" "$PROJECT_PATH" 2>"$scan_log" || rc=$?

  if [[ $rc -ne 0 || ! -f "$tj" ]]; then
    TRIVY_STATUS="failed"
    TOOL_ERRORS=$((TOOL_ERRORS+1))
    keep_log "$scan_log"
    err "Trivy failed (exit ${rc}) — see ${scan_log}"
    return
  fi

  # Table view: convert from JSON (fast); rescan on old Trivy without `convert`
  trivy convert --format table --output "$tt" "$tj" 2>>"$scan_log" \
    || trivy "${flags[@]}" --format table --output "$tt" "$PROJECT_PATH" 2>>"$scan_log" \
    || { keep_log "$scan_log"; warn "Trivy table view generation failed (JSON report unaffected) — see ${scan_log}"; }

  local counts
  counts="$(python3 - "$tj" <<'PY' 2>>"$scan_log"
import json, sys
FLAGGED_CATS = {"restricted", "reciprocal", "unknown"}
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("ERR")
    sys.exit(0)
vulns = secrets = licenses = 0
for r in d.get("Results", []):
    vulns += len(r.get("Vulnerabilities") or [])
    secrets += len(r.get("Secrets") or [])
    for lic in (r.get("Licenses") or []):
        sev = (lic.get("Severity") or "").upper()
        cat = (lic.get("Category") or "").lower()
        if sev in ("HIGH", "CRITICAL") or cat in FLAGGED_CATS:
            licenses += 1
print(vulns, secrets, licenses)
PY
)" || counts="ERR"
  if [[ "$counts" == "ERR" ]]; then
    TRIVY_STATUS="failed"
    TOOL_ERRORS=$((TOOL_ERRORS+1))
    keep_log "$scan_log"
    err "Trivy report unparsable: ${tj} — see ${scan_log}"
    return
  fi
  read -r TRIVY_CVE_COUNT TRIVY_SECRET_COUNT LICENSE_ISSUE_COUNT <<< "$counts"

  if [[ "$SKIP_CVE" != true ]]; then
    if [[ "$TRIVY_CVE_COUNT" -eq 0 ]]; then
      ok "Trivy CVE: none at ${SEVERITY}+"
    else
      warn "Trivy CVE: ${TRIVY_CVE_COUNT} found  →  ${tj}"
    fi
    if [[ "$TRIVY_SECRET_COUNT" -eq 0 ]]; then
      ok "Trivy secrets: none"
    else
      warn "Trivy secrets: ${TRIVY_SECRET_COUNT} found  →  ${tj}"
    fi
  fi

  if [[ "$SKIP_LICENSE" != true ]]; then
    if [[ "$LICENSE_ISSUE_COUNT" -eq 0 ]]; then
      ok "Trivy license: no flagged licenses"
    else
      warn "Trivy license: ${LICENSE_ISSUE_COUNT} issue(s) found  →  ${tj}"
      if cmd_ok jq; then
        jq -r '
          .Results[]?.Licenses[]?
          | select(.Severity == "HIGH" or .Severity == "CRITICAL")
          | "  [\(.Severity)]  \(.PkgName // "?")  \(.Name)"
        ' "$tj" 2>/dev/null | head -20 || true
      fi
    fi
    log "${DIM}Note: Trivy reads package-manager metadata. Standalone font files (.ttf/.woff)${NC}"
    log "${DIM}      not managed by a package registry are covered by the ExifTool layer.${NC}"
  fi

  [[ "$VERBOSE" == true && -f "$tt" ]] && cat "$tt"

  if [[ $((TRIVY_CVE_COUNT + TRIVY_SECRET_COUNT + LICENSE_ISSUE_COUNT)) -gt 0 ]]; then
    TRIVY_STATUS="findings"
  else
    TRIVY_STATUS="ok"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_grype_scan() {
  section "3/4  CVE cross-check  (Grype)"
  local gj="${OUTPUT_DIR}/grype.json"
  local gt="${OUTPUT_DIR}/grype.txt"
  local scan_log="${OUTPUT_DIR}/grype.log"

  if tool_failed grype || ! cmd_ok grype; then
    GRYPE_STATUS="failed"
    err "grype unavailable — CVE cross-check NOT performed"
    return
  fi

  log "Grype: cross-checking vulnerabilities..."
  local rc=0
  # Single scan, two outputs; fall back to two scans on old Grype versions
  grype "dir:${PROJECT_PATH}" -o "json=${gj}" -o "table=${gt}" --quiet 2>"$scan_log" || rc=$?
  if [[ $rc -ne 0 || ! -f "$gj" ]]; then
    rc=0
    grype "dir:${PROJECT_PATH}" --output json  --file "$gj" --quiet 2>>"$scan_log" || rc=$?
    grype "dir:${PROJECT_PATH}" --output table --file "$gt" --quiet 2>>"$scan_log" || true
  fi

  if [[ $rc -ne 0 || ! -f "$gj" ]]; then
    GRYPE_STATUS="failed"
    TOOL_ERRORS=$((TOOL_ERRORS+1))
    keep_log "$scan_log"
    err "Grype failed (exit ${rc}) — see ${scan_log}"
    return
  fi

  # Grype has no scan-time severity filter: the table lists everything while
  # the summary count is thresholded — make that explicit in the report.
  if [[ "$SEVERITY" != "UNKNOWN" && -f "$gt" ]]; then
    {
      echo "NOTE: this table lists ALL severities; the audit summary only counts ${SEVERITY}+."
      echo ""
      cat "$gt"
    } > "${gt}.tmp" && mv "${gt}.tmp" "$gt"
  fi

  GRYPE_CVE_COUNT=$(python3 -c "
import json, sys
try:
    d    = json.load(open(sys.argv[1]))
    lvl  = {'unknown':0,'negligible':0,'low':1,'medium':2,'high':3,'critical':4}
    thr  = lvl.get(sys.argv[2].lower(), 0)
    count = sum(
        1 for m in d.get('matches', [])
        if lvl.get((m.get('vulnerability', {}).get('severity') or 'unknown').lower(), 0) >= thr
    )
    print(count)
except Exception:
    print('ERR')
" "$gj" "$SEVERITY" 2>>"$scan_log" || echo ERR)
  if [[ "$GRYPE_CVE_COUNT" == "ERR" ]]; then
    GRYPE_STATUS="failed"
    TOOL_ERRORS=$((TOOL_ERRORS+1))
    GRYPE_CVE_COUNT=0
    keep_log "$scan_log"
    err "Grype report unparsable: ${gj} — see ${scan_log}"
    return
  fi

  if [[ "$GRYPE_CVE_COUNT" -eq 0 ]]; then
    GRYPE_STATUS="ok"
    ok "Grype: no CVEs at ${SEVERITY}+"
  else
    GRYPE_STATUS="findings"
    warn "Grype: ${GRYPE_CVE_COUNT} CVE(s) found  →  ${gj}"
    [[ "$VERBOSE" == true && -f "$gt" ]] && cat "$gt"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_fresh_advisory_scan() {
  section "3b/4  Fresh CVE  (GitHub Advisory)"
  local out_json="${OUTPUT_DIR}/fresh-advisory.json"
  local out_txt="${OUTPUT_DIR}/fresh-advisory.txt"
  local trivy_json="${OUTPUT_DIR}/trivy.json"
  local grype_json="${OUTPUT_DIR}/grype.json"
  local scan_log="${OUTPUT_DIR}/fresh-advisory.log"

  log "Checking GitHub Advisory for pinned dependencies (all supported ecosystems)..."
  log "${DIM}Unauthenticated API (60 req/h limit) — by design, no token is used.${NC}"

  local count rc=0
  count="$(python3 - "$PROJECT_PATH" "$SEVERITY" "$out_json" "$out_txt" "$trivy_json" "$grype_json" <<'PY' 2>"$scan_log"
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

project, threshold, out_json, out_txt, trivy_json, grype_json = sys.argv[1:7]
sev_rank = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
threshold_rank = sev_rank.get(threshold.upper(), 0)


class RateLimited(Exception):
    pass


# Track request outcomes so total network failure is reported as an error,
# never as "0 findings".
api_calls = {"ok": 0, "failed": 0}

# Deliberately unauthenticated: no token is read or sent.
def fetch(url, accept="application/vnd.github+json"):
    req = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "User-Agent": "vfa-audit-scan",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", "replace")
        api_calls["ok"] += 1
        return body
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            raise RateLimited(f"GitHub API rate limit reached (HTTP {e.code})")
        api_calls["failed"] += 1
        sys.stderr.write(f"API request failed: HTTP {e.code} {url}\n")
        raise
    except RateLimited:
        raise
    except Exception as e:
        api_calls["failed"] += 1
        sys.stderr.write(f"API request failed: {e} {url}\n")
        raise

def fetch_json(url):
    return json.loads(fetch(url))

def fetch_advisories(params):
    q = urllib.parse.urlencode(params)
    return fetch_json(f"https://api.github.com/advisories?{q}")

def norm_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()

def advisory_severity(item):
    sev = (item.get("severity") or "").upper()
    if sev in sev_rank:
        return sev
    metrics = item.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
        vals = metrics.get(key) or []
        if vals:
            return (vals[0].get("cvssData", {}).get("baseSeverity") or "UNKNOWN").upper()
    return "UNKNOWN"

def existing_ids():
    ids = set()
    try:
        data = json.load(open(trivy_json, encoding="utf-8"))
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                for key in ("VulnerabilityID", "PrimaryURL"):
                    val = vuln.get(key)
                    if val:
                        ids.add(str(val).upper())
    except Exception:
        pass
    try:
        data = json.load(open(grype_json, encoding="utf-8"))
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            if vuln.get("id"):
                ids.add(str(vuln["id"]).upper())
            for rel in vuln.get("relatedVulnerabilities") or []:
                if rel.get("id"):
                    ids.add(str(rel["id"]).upper())
    except Exception:
        pass
    return ids

# ── Dependency collection — every GitHub Advisory ecosystem ─────────────────
# pip, npm, go, maven, rubygems, composer, rust, nuget, pub, swift, actions, erlang
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules",
             "__pycache__", "vendor", "dist", "build", ".next", ".terraform", "Pods"}

deps = {}

def add_dep(eco, name, version, path):
    name = str(name or "").strip()
    version = str(version or "").strip().lstrip("vV")
    if not name or not re.match(r"^\d[\w.+-]*$", version):
        return
    key = (eco, norm_name(name))
    deps.setdefault(key, {
        "ecosystem": eco,
        "name": name,
        "version": version,
        "files": [],
    })["files"].append(path)

def read_text(path):
    return open(path, encoding="utf-8", errors="ignore").read()

def read_json(path):
    return json.load(open(path, encoding="utf-8", errors="ignore"))

def parse_requirements(path):
    req_re = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9_.!+*-]+)")
    for line in read_text(path).splitlines():
        line = line.split("#", 1)[0].strip()
        m = req_re.match(line)
        if m:
            add_dep("pip", m.group(1), m.group(2), path)

def parse_pipfile_lock(path):
    data = read_json(path)
    for sect in ("default", "develop"):
        for name, meta in (data.get(sect) or {}).items():
            ver = (meta or {}).get("version") or ""
            if ver.startswith("=="):
                add_dep("pip", name, ver[2:], path)

def parse_poetry_lock(path):
    for m in re.finditer(r'\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"', read_text(path)):
        add_dep("pip", m.group(1), m.group(2), path)

def parse_package_lock(path):
    data = read_json(path)
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):  # lockfile v2/v3
        for p, meta in pkgs.items():
            if "node_modules/" in p and isinstance(meta, dict) and meta.get("version"):
                add_dep("npm", p.rsplit("node_modules/", 1)[-1], meta["version"], path)
        return
    def walk_v1(tree):
        for name, meta in (tree or {}).items():
            if isinstance(meta, dict):
                if meta.get("version"):
                    add_dep("npm", name, meta["version"], path)
                walk_v1(meta.get("dependencies"))
    walk_v1(data.get("dependencies"))

def parse_yarn_lock(path):
    for m in re.finditer(
        r'^"?((?:@[\w.-]+/)?[\w.-]+)@[^\n]*:\n(?:[ \t][^\n]*\n)*?[ \t]+version:?[ \t]+"?(\d[\w.+-]*)"?',
        read_text(path), re.M):
        add_dep("npm", m.group(1), m.group(2), path)

def parse_pnpm_lock(path):
    text = read_text(path)
    for m in re.finditer(r"^\s+['\"/]((?:@[\w.-]+/)?[\w.-]+)@(\d[\w.+-]*)[^:\n]*:", text, re.M):  # v6+/v9
        add_dep("npm", m.group(1), m.group(2), path)
    for m in re.finditer(r"^\s+/((?:@[\w.-]+/)?[\w.-]+)/(\d[\w.+-]*)", text, re.M):  # v5
        add_dep("npm", m.group(1), m.group(2), path)

def parse_go_mod(path):
    for line in read_text(path).splitlines():
        line = line.split("//", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9._/~-]+)\s+v(\d[\w.+-]*)$", line)
        if m and "/" in m.group(1):
            add_dep("go", m.group(1), m.group(2), path)

def parse_gemfile_lock(path):
    for m in re.finditer(r"^ {4}([\w.-]+) \((\d[\w.]*)\)$", read_text(path), re.M):
        add_dep("rubygems", m.group(1), m.group(2), path)

def parse_composer_lock(path):
    data = read_json(path)
    for sect in ("packages", "packages-dev"):
        for pkg in data.get(sect) or []:
            add_dep("composer", pkg.get("name"), pkg.get("version"), path)

def parse_cargo_lock(path):
    for m in re.finditer(r'\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"', read_text(path)):
        add_dep("rust", m.group(1), m.group(2), path)

def parse_nuget_lock(path):
    data = read_json(path)
    for framework in (data.get("dependencies") or {}).values():
        for name, meta in (framework or {}).items():
            if isinstance(meta, dict) and meta.get("resolved"):
                add_dep("nuget", name, meta["resolved"], path)

def parse_csproj(path):
    for m in re.finditer(r'<PackageReference[^>]*Include="([^"]+)"[^>]*Version="([^"]+)"', read_text(path)):
        add_dep("nuget", m.group(1), m.group(2), path)

def parse_pom(path):
    # property-resolved versions (${...}) are skipped — cannot pin them statically
    for m in re.finditer(
        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<$]+)</version>",
        read_text(path)):
        add_dep("maven", f"{m.group(1).strip()}:{m.group(2).strip()}", m.group(3).strip(), path)

def parse_pubspec_lock(path):
    for m in re.finditer(r'^  ([a-z0-9_]+):\n(?:[ \t][^\n]*\n)*?[ \t]+version:\s*"([^"]+)"', read_text(path), re.M):
        add_dep("pub", m.group(1), m.group(2), path)

def parse_swift_resolved(path):
    data = read_json(path)
    pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
    for pin in pins:
        loc = pin.get("location") or pin.get("repositoryURL") or ""
        ver = (pin.get("state") or {}).get("version") or ""
        name = re.sub(r"^https?://", "", loc)
        if name.endswith(".git"):
            name = name[:-4]
        if name and ver:
            add_dep("swift", name, ver, path)

def parse_workflow(path):
    # only version-tag refs; commit-SHA refs cannot be matched to a version
    for m in re.finditer(r"uses:\s*['\"]?([\w.-]+/[\w.-]+)(?:/[^@\s'\"]+)?@v?(\d[\w.]*)", read_text(path)):
        add_dep("actions", m.group(1), m.group(2), path)

def parse_mix_lock(path):
    for m in re.finditer(r'"([\w.-]+)":\s*\{:hex,\s*:[\w.-]+,\s*"(\d[\w.-]*)"', read_text(path)):
        add_dep("erlang", m.group(1), m.group(2), path)

PARSERS = {
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_lock,
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
    "Cargo.lock": parse_cargo_lock,
    "packages.lock.json": parse_nuget_lock,
    "pom.xml": parse_pom,
    "pubspec.lock": parse_pubspec_lock,
    "Package.resolved": parse_swift_resolved,
    "mix.lock": parse_mix_lock,
}

for root, dirs, files in os.walk(project):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    in_workflows = root.replace("\\", "/").endswith(".github/workflows")
    for fname in files:
        path = os.path.join(root, fname)
        try:
            if fname in PARSERS:
                PARSERS[fname](path)
            elif fname == "requirements.txt" or (fname.startswith("requirements") and fname.endswith(".txt")):
                parse_requirements(path)
            elif fname.endswith(".csproj"):
                parse_csproj(path)
            elif in_workflows and fname.endswith((".yml", ".yaml")):
                parse_workflow(path)
        except Exception:
            pass

if not deps:
    print("SKIP")
    sys.exit(0)

seen = existing_ids()
findings = []
rate_limited = False
ecosystems = sorted({d["ecosystem"] for d in deps.values()})
by_eco = {}
for d in deps.values():
    by_eco.setdefault(d["ecosystem"], []).append(d)

def text_has_package_and_version(text, dep):
    needle = norm_name(dep["name"])
    normalized = norm_name(text)
    has_name = re.search(r"(^|[^a-z0-9])" + re.escape(needle) + r"([^a-z0-9]|$)", normalized) is not None
    if not has_name:
        return False
    version = dep["version"]
    version_parts = re.findall(r"\d+", version)
    hints = {version}
    if len(version_parts) >= 2:
        hints.add(".".join(version_parts[:2]))
    return any(h in text for h in hints)

def has_advisory_signal(adv, dep):
    text = " ".join([
        adv.get("summary") or "",
        adv.get("description") or "",
        adv.get("source_code_location") or "",
        " ".join(adv.get("references") or []),
    ])
    return text_has_package_and_version(text, dep)

def add_finding(dep, adv, matched_by, review_required):
    sev = advisory_severity(adv)
    primary = (adv.get("cve_id") or adv.get("ghsa_id") or "").upper()
    ids = [i.get("value") for i in adv.get("identifiers", []) if i.get("value")]
    all_ids = {primary, *(str(i).upper() for i in ids if i)}
    if not primary or all_ids & seen or sev_rank.get(sev, 0) < threshold_rank:
        return
    findings.append({
        "source": "GitHub Advisory",
        "ecosystem": dep["ecosystem"],
        "package": dep["name"],
        "version": dep["version"],
        "id": adv.get("cve_id") or adv.get("ghsa_id"),
        "ghsa_id": adv.get("ghsa_id"),
        "type": adv.get("type"),
        "severity": sev,
        "summary": adv.get("summary") or "",
        "url": adv.get("html_url") or "",
        "matched_by": matched_by,
        "review_required": review_required,
        "identifiers": ids,
    })
    seen.update(all_ids)

def ver_key(v):
    parts = re.findall(r"\d+", str(v))
    return tuple(int(p) for p in parts[:6]) if parts else None

def version_in_range(version, rng):
    # rng like ">= 1.0.0, < 1.2.5" / "<= 2.0.1" / "= 1.0.0"; permissive on parse failure
    vk = ver_key(version)
    if vk is None or not rng:
        return True
    for cond in str(rng).split(","):
        m = re.match(r"\s*(<=|>=|<|>|=)\s*v?([\w.+-]+)", cond)
        if not m:
            return True
        op, val = m.groups()
        ck = ver_key(val)
        if ck is None:
            return True
        width = max(len(vk), len(ck))
        a = vk + (0,) * (width - len(vk))
        b = ck + (0,) * (width - len(ck))
        ok = {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "=": a == b}[op]
        if not ok:
            return False
    return True

def affected_deps(adv):
    # Batched `affects` queries return advisories matching ANY package in the
    # batch — map each advisory back to our deps via its vulnerabilities list.
    out = []
    for vuln in adv.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        eco = (pkg.get("ecosystem") or "").lower()
        dep = deps.get((eco, norm_name(pkg.get("name") or "")))
        if dep and version_in_range(dep["version"], vuln.get("vulnerable_version_range") or ""):
            out.append(dep)
    return out

def fetch_affects(eco, dep_list, adv_type):
    # `affects` accepts a comma-separated list (max 1000) — batch to keep the
    # unauthenticated request budget small.
    found = []
    BATCH = 100
    for i in range(0, len(dep_list), BATCH):
        chunk = dep_list[i:i + BATCH]
        affects = ",".join(f"{d['name']}@{d['version']}" for d in chunk)
        for page in range(1, 6):
            try:
                batch = fetch_advisories({
                    "ecosystem": eco,
                    "affects": affects,
                    "type": adv_type,
                    "per_page": "100",
                    "page": str(page),
                })
            except RateLimited:
                raise
            except Exception:
                batch = []
            found.extend(batch)
            if len(batch) < 100:
                break
    return found

POOL_PAGES = 5 if len(ecosystems) == 1 else 3

def recent_advisory_pool(eco, adv_type):
    items = []
    for page in range(1, POOL_PAGES + 1):
        try:
            batch = fetch_advisories({
                "ecosystem": eco,
                "type": adv_type,
                "per_page": "100",
                "page": str(page),
                "sort": "published",
                "direction": "desc",
            })
        except RateLimited:
            raise
        except Exception:
            break
        if not batch:
            break
        items.extend(batch)
    return items

try:
    for eco in ecosystems:
        eco_deps = by_eco[eco]

        # Strongest signal first: `affects=name@version` for all advisory types.
        for adv_type in ("reviewed", "malware", "unreviewed"):
            for adv in fetch_affects(eco, eco_deps, adv_type):
                for dep in affected_deps(adv):
                    add_finding(dep, adv, f"github_{adv_type}_affects", adv_type != "reviewed")

        # Fallback: text matching over recent malware/unreviewed advisories,
        # whose package/version metadata may lag behind the `affects` index.
        for adv_type in ("malware", "unreviewed"):
            pool = recent_advisory_pool(eco, adv_type)
            for dep in eco_deps:
                for adv in pool:
                    if has_advisory_signal(adv, dep):
                        add_finding(dep, adv, f"github_{adv_type}_recent_text", True)
except RateLimited as e:
    rate_limited = True
    sys.stderr.write(f"{e}; results below are partial\n")

# Exit codes let the shell name the failure: 3 = rate limit, 4 = some API
# requests failed (partial), 5 = API unreachable (every request failed).
exit_code = 0
if rate_limited:
    exit_code = 3
elif api_calls["failed"] and not api_calls["ok"]:
    exit_code = 5
elif api_calls["failed"]:
    exit_code = 4
partial = exit_code != 0

with open(out_json, "w", encoding="utf-8") as f:
    json.dump({
        "findings": findings,
        "partial": partial,
        "api_requests_ok": api_calls["ok"],
        "api_requests_failed": api_calls["failed"],
        "dependencies_checked": len(deps),
        "ecosystems": ecosystems,
    }, f, ensure_ascii=False, indent=2)

with open(out_txt, "w", encoding="utf-8") as f:
    f.write("Fresh CVE Advisory Review (GitHub Advisory)\n")
    f.write("=" * 80 + "\n")
    if rate_limited:
        f.write("WARNING: GitHub API rate limit hit — results are PARTIAL\n")
    elif exit_code == 5:
        f.write("WARNING: GitHub API unreachable — NO advisory data was retrieved\n")
    elif exit_code == 4:
        f.write(f"WARNING: {api_calls['failed']} API request(s) failed — results are PARTIAL\n")
    f.write(f"Dependencies checked: {len(deps)} ({', '.join(ecosystems)})\n")
    f.write(f"Findings: {len(findings)}\n\n")
    for row in findings:
        f.write(f"[{row['severity']}] {row['id']} {row['package']}@{row['version']} ({row['ecosystem']})\n")
        if row.get("ghsa_id"):
            f.write(f"  GHSA:      {row['ghsa_id']}\n")
        f.write(f"  Type:      {row.get('type') or '-'}\n")
        f.write(f"  Source:    {row['source']} ({row['matched_by']})\n")
        if row.get("review_required"):
            f.write("  Note:      advisory requires manual verification of affected package/version\n")
        f.write(f"  Summary:   {row['summary']}\n")
        f.write(f"  URL:       {row['url']}\n\n")

print(len(findings))
sys.exit(exit_code)
PY
)" || rc=$?

  if [[ "$count" == "SKIP" ]]; then
    ADVISORY_STATUS="skipped"
    ok "Skipped — no pinned dependencies found in supported manifests/lockfiles"
    return
  fi

  FRESH_ADVISORY_COUNT="${count:-0}"
  [[ "$FRESH_ADVISORY_COUNT" =~ ^[0-9]+$ ]] || FRESH_ADVISORY_COUNT=0

  if [[ $rc -ne 0 ]]; then
    ADVISORY_STATUS="failed"
    TOOL_ERRORS=$((TOOL_ERRORS+1))
    keep_log "$scan_log"
    case $rc in
      3) err "GitHub Advisory: rate limit reached (unauthenticated, 60 req/h) — results PARTIAL. See ${scan_log}" ;;
      4) err "GitHub Advisory: some API requests failed — results PARTIAL. See ${scan_log}" ;;
      5) err "GitHub Advisory: API unreachable (network/DNS?) — NO advisory data. See ${scan_log}" ;;
      *) err "GitHub Advisory check crashed (exit ${rc}) — see ${scan_log}" ;;
    esac
    [[ "$FRESH_ADVISORY_COUNT" -gt 0 ]] && warn "Partial results: ${FRESH_ADVISORY_COUNT} finding(s)  →  ${out_txt}"
    return
  fi

  if [[ "$FRESH_ADVISORY_COUNT" -eq 0 ]]; then
    ADVISORY_STATUS="ok"
    ok "No supplemental fresh CVEs found"
  else
    ADVISORY_STATUS="findings"
    warn "${FRESH_ADVISORY_COUNT} supplemental fresh CVE(s) found  →  ${out_txt}"
    [[ "$VERBOSE" == true && -f "$out_txt" ]] && cat "$out_txt"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_font_license_scan() {
  section "4/4  Font License  (ExifTool)"
  local fj="${OUTPUT_DIR}/font-license-exiftool.json"
  local ft="${OUTPUT_DIR}/font-license-exiftool.txt"
  local scan_log="${OUTPUT_DIR}/exiftool.log"

  if tool_failed exiftool || ! cmd_ok exiftool; then
    FONT_STATUS="failed"
    err "exiftool unavailable — font license scan NOT performed"
    return
  fi

  log "Reading font license and copyright metadata..."

  local rc=0
  exiftool -r -json -m -q -q \
    -ext ttf -ext otf -ext woff -ext woff2 \
    -FileName -Directory -FileType -MIMEType \
    -FontFamily -FontSubfamily -FontName -Name \
    -Copyright -CopyrightNotice -Rights \
    -License -LicenseInfo -LicenseURL -UsageTerms \
    -Description -Designer -VendorID \
    "$PROJECT_PATH" > "$fj" 2>"$scan_log" || rc=$?

  # exiftool exits non-zero on real read errors; an empty JSON just means no
  # fonts were found and is not an error by itself.
  if [[ $rc -ne 0 && ! -s "$fj" ]]; then
    FONT_STATUS="failed"
    TOOL_ERRORS=$((TOOL_ERRORS+1))
    keep_log "$scan_log"
    err "ExifTool failed (exit ${rc}) — see ${scan_log}"
    return
  fi
  [[ $rc -ne 0 ]] && { keep_log "$scan_log"; warn "ExifTool finished with errors (exit ${rc}) — see ${scan_log}"; }

  if [[ -f "$fj" ]]; then
    local font_counts
    if ! font_counts="$(python3 - "$fj" "$ft" 2>>"$scan_log" <<'PY'
import json
import re
import sys

src, report = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(src, encoding="utf-8"))
except Exception:
    data = []

license_keys = ("license", "rights", "usage", "permission", "terms")
copyright_keys = ("copyright",)
restricted = re.compile(
    r"(agpl|gpl|sspl|non[- ]?commercial|personal use|trial|demo|evaluation|"
    r"not for commercial|not\s+for\s+resale|restricted|proprietary|desktop license)",
    re.I,
)

def values_for(item, needles):
    vals = []
    for key, val in item.items():
        key_l = key.lower()
        if any(n in key_l for n in needles):
            if isinstance(val, list):
                vals.extend(str(v) for v in val if v not in (None, ""))
            elif val not in (None, ""):
                vals.append(str(val))
    return vals

rows = []
issues = 0
for item in data:
    path = item.get("SourceFile") or "/".join(
        p for p in (item.get("Directory"), item.get("FileName")) if p
    )
    license_vals = values_for(item, license_keys)
    copyright_vals = values_for(item, copyright_keys)
    combined = " | ".join(license_vals + copyright_vals)

    reasons = []
    if not license_vals:
        reasons.append("missing license metadata")
    if restricted.search(combined):
        reasons.append("restricted/non-commercial terms")

    status = "ISSUE" if reasons else "OK"
    if reasons:
        issues += 1

    rows.append({
        "path": path,
        "status": status,
        "reason": ", ".join(reasons) if reasons else "-",
        "license": " | ".join(license_vals) if license_vals else "-",
        "copyright": " | ".join(copyright_vals) if copyright_vals else "-",
    })

with open(report, "w", encoding="utf-8") as out:
    out.write("Font License Review (ExifTool)\n")
    out.write("=" * 80 + "\n")
    out.write(f"Fonts scanned: {len(rows)}\n")
    out.write(f"Issues:        {issues}\n\n")
    for row in rows:
        out.write(f"[{row['status']}] {row['path']}\n")
        out.write(f"  Reason:    {row['reason']}\n")
        out.write(f"  License:   {row['license']}\n")
        out.write(f"  Copyright: {row['copyright']}\n\n")

print(len(rows), issues)
PY
)"; then
      FONT_STATUS="failed"
      TOOL_ERRORS=$((TOOL_ERRORS+1))
      keep_log "$scan_log"
      err "Font license report generation failed — see ${scan_log}"
      return
    fi
    read -r FONT_FILE_COUNT FONT_LICENSE_ISSUE_COUNT <<< "$font_counts"
  fi

  if [[ "$FONT_FILE_COUNT" -eq 0 ]]; then
    FONT_STATUS="ok"
    ok "No standalone font files found"
  elif [[ "$FONT_LICENSE_ISSUE_COUNT" -eq 0 ]]; then
    FONT_STATUS="ok"
    ok "ExifTool: ${FONT_FILE_COUNT} font file(s), no flagged font license metadata"
  else
    FONT_STATUS="findings"
    warn "ExifTool: ${FONT_LICENSE_ISSUE_COUNT}/${FONT_FILE_COUNT} font file(s) need license review  →  ${ft}"
    [[ "$VERBOSE" == true && -f "$ft" ]] && cat "$ft"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
generate_summary() {
  section "Audit Summary"
  local total=$((SECRET_COUNT + TRIVY_SECRET_COUNT + TRIVY_CVE_COUNT + GRYPE_CVE_COUNT + FRESH_ADVISORY_COUNT + LICENSE_ISSUE_COUNT + FONT_LICENSE_ISSUE_COUNT))
  local stxt="${OUTPUT_DIR}/summary.md"
  local sjson="${OUTPUT_DIR}/summary.json"

  # FAIL = at least one scanner could not run (results unreliable)
  # WARN = all scanners ran, findings present; PASS = all ran, nothing found
  local status="PASS"
  [[ $total -gt 0 ]] && status="WARN"
  [[ $TOOL_ERRORS -gt 0 ]] && status="FAIL"

  {
    echo "# Security Audit Summary"
    echo ""
    echo "| Field | Value |"
    echo "|---|---|"
    printf '| Date | %s |\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '| Project | `%s` |\n' "$PROJECT_PATH"
    printf '| Severity | `%s+` |\n' "$SEVERITY"
    printf '| Status | `%s` |\n' "$status"
    echo ""
    # Trivy sub-rows share one run: skipped follows the layer's skip flag,
    # failed comes from the run itself, otherwise the row follows its count.
    _row_status() {
      local base="$1" count="$2" skipped="$3"
      if [[ "$skipped" == true ]]; then echo "skipped"; return; fi
      case "$base" in
        failed|skipped) echo "$base" ;;
        *) [[ "$count" -gt 0 ]] && echo "findings" || echo "ok" ;;
      esac
    }
    echo "| Scanner | Status | Findings |"
    echo "|---|---|---:|"
    printf '| Secrets (Gitleaks) | %s | %d |\n' "$SECRETS_STATUS" "$SECRET_COUNT"
    printf '| Secrets (Trivy) | %s | %d |\n' "$(_row_status "$TRIVY_STATUS" "$TRIVY_SECRET_COUNT" "$SKIP_CVE")" "$TRIVY_SECRET_COUNT"
    printf '| CVE (Trivy) | %s | %d |\n' "$(_row_status "$TRIVY_STATUS" "$TRIVY_CVE_COUNT" "$SKIP_CVE")" "$TRIVY_CVE_COUNT"
    printf '| CVE (Grype) | %s | %d |\n' "$GRYPE_STATUS" "$GRYPE_CVE_COUNT"
    printf '| Fresh CVE (GitHub Advisory) | %s | %d |\n' "$ADVISORY_STATUS" "$FRESH_ADVISORY_COUNT"
    printf '| License (Trivy) | %s | %d |\n' "$(_row_status "$TRIVY_STATUS" "$LICENSE_ISSUE_COUNT" "$SKIP_LICENSE")" "$LICENSE_ISSUE_COUNT"
    printf '| Font License (ExifTool) | %s | %d |\n' "$FONT_STATUS" "$FONT_LICENSE_ISSUE_COUNT"
    printf '| **Total** | | **%d** |\n' "$total"
    if [[ $TOOL_ERRORS -gt 0 ]]; then
      printf '| Tool errors | | %d |\n' "$TOOL_ERRORS"
    fi
  } | tee "$stxt"

  # Strings (paths) go through argv so quotes/backslashes can't break the JSON
  python3 - "$sjson" "$PROJECT_PATH" "$OUTPUT_DIR" <<PY
import json, sys
out, project, outdir = sys.argv[1:4]
json.dump({
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "project": project,
    "severity_threshold": "${SEVERITY}",
    "status": "${status}",
    "scanners": {
        "secrets_gitleaks": {"status": "${SECRETS_STATUS}", "findings": ${SECRET_COUNT}},
        "trivy": {
            "status": "${TRIVY_STATUS}",
            "cve": ${TRIVY_CVE_COUNT},
            "secrets": ${TRIVY_SECRET_COUNT},
            "license_issues": ${LICENSE_ISSUE_COUNT}
        },
        "cve_grype": {"status": "${GRYPE_STATUS}", "findings": ${GRYPE_CVE_COUNT}},
        "fresh_advisories": {"status": "${ADVISORY_STATUS}", "findings": ${FRESH_ADVISORY_COUNT}},
        "font_license": {
            "status": "${FONT_STATUS}",
            "files": ${FONT_FILE_COUNT},
            "issues": ${FONT_LICENSE_ISSUE_COUNT}
        }
    },
    "total_findings": ${total},
    "tool_errors": ${TOOL_ERRORS},
    "output_dir": outdir
}, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
PY
  [[ $? -ne 0 ]] && warn "summary.json generation failed — summary.md is still valid"

  echo ""
  log "Full reports: ${OUTPUT_DIR}/"

  case "$status" in
    PASS) ok   "All scans passed — no findings at ${SEVERITY}+" ;;
    WARN) warn "Total findings : ${total}" ;;
    FAIL)
      [[ $total -gt 0 ]] && warn "Total findings : ${total}"
      err "Tool errors    : ${TOOL_ERRORS} — results are INCOMPLETE, see the *.log files in the report" ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"

  echo ""
  echo -e "${BLD}Source Code Security Audit${NC}"
  echo -e "${DIM}Project  : ${PROJECT_PATH}${NC}"
  echo -e "${DIM}Reports  : ${OUTPUT_DIR}${NC}"
  echo -e "${DIM}Severity : ${SEVERITY}+${NC}"

  mkdir -p "${OUTPUT_DIR}" \
    || { err "Cannot create output directory: ${OUTPUT_DIR}"; exit 2; }
  check_tools

  [[ "$SKIP_SECRETS" != true ]] && run_secrets_scan
  [[ "$SKIP_CVE" != true || "$SKIP_LICENSE" != true ]] && run_trivy_scan
  if [[ "$SKIP_CVE" != true ]]; then
    run_grype_scan
    run_fresh_advisory_scan
  fi
  [[ "$SKIP_LICENSE" != true ]] && run_font_license_scan

  generate_summary

  # Logs are kept only when they explain an error that affects audit quality;
  # logs of scanners that ran cleanly are removed before archiving.
  local lf
  for lf in gitleaks.log trivy.log grype.log fresh-advisory.log exiftool.log; do
    [[ "$KEEP_LOGS" == *" ${lf} "* ]] || rm -f "${OUTPUT_DIR}/${lf}"
  done

  # Zip the report folder and remove the original.
  # Only the timestamped folder this run created is ever deleted — never a
  # pre-existing directory the user pointed -o at.
  local zip_file="${OUTPUT_DIR}.zip"
  if ! cmd_ok zip; then
    warn "zip not found — report kept at: ${OUTPUT_DIR}"
    exit 0
  fi
  log "Archiving report..."
  if (cd "$(dirname "$OUTPUT_DIR")" && zip -qr "$(basename "$OUTPUT_DIR").zip" "$(basename "$OUTPUT_DIR")") 2>/dev/null; then
    if [[ "$(basename "$OUTPUT_DIR")" == "${TIMESTAMP}_"* ]]; then
      rm -rf "$OUTPUT_DIR"
    fi
    ok "Report archived: ${zip_file}"
  else
    warn "zip failed — report kept at: ${OUTPUT_DIR}"
  fi

  exit 0
}

main "$@"
