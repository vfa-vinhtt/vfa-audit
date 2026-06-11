#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# vfa-audit-scan.sh —  Source-code security audit, URL-friendly runner
#
#   Layer 1 — Secrets  : Gitleaks + Trivy  (credentials, tokens, API keys)
#   Layer 2 — CVE      : Trivy
#   Layer 3 — License  : Trivy + ExifTool  (library & font license compliance)
#
# Usage:
#   ./vfa-audit-scan.sh
#   curl -fsSL <raw-github-url>/vfa-audit-scan.sh | bash
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
OUTPUT_BASE="/tmp/vfa_audit"
OUTPUT_DIR=""              # resolved in parse_args, always a folder this run creates
PROJECT_PATH=""

# ── Counters ──────────────────────────────────────────────────────────────────
SECRET_COUNT=0
TRIVY_SECRET_COUNT=0
TRIVY_CVE_COUNT=0
LICENSE_ISSUE_COUNT=0
FONT_FILE_COUNT=0
FONT_LICENSE_ISSUE_COUNT=0
TOOL_ERRORS=0

# ── Per-scanner status: ok | findings | failed | skipped ─────────────────────
SECRETS_STATUS="skipped"
TRIVY_STATUS="skipped"
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

# ─────────────────────────────────────────────────────────────────────────────
init() {
  PROJECT_PATH="$RUN_DIR"
  OUTPUT_DIR="${OUTPUT_BASE}/${TIMESTAMP}_$(basename "$PROJECT_PATH")"
}

# ─────────────────────────────────────────────────────────────────────────────
install_tool() {
  local tool="$1"
  log "Installing ${tool}..."
  brew install "$tool" && return 0 || return 1
}

# ─────────────────────────────────────────────────────────────────────────────
check_tools() {
  section "Tool Check"
  local -a missing=()

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

  _check jq       "jq --version"
  _check gitleaks "gitleaks version"
  _check trivy    "trivy version"
  _check exiftool "exiftool -ver"
  cmd_ok zip || warn "zip not found — report folder will not be archived"

  if [[ ${#missing[@]} -gt 0 ]]; then
    for t in "${missing[@]}"; do
      if ! install_tool "$t"; then
        err "Failed to install $t — its scan will be marked as failed"
        TOOL_ERRORS=$((TOOL_ERRORS+1))
        FAILED_TOOLS+="$t "
      fi
    done
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_secrets_scan() {
  section "1/3  Secrets  (Gitleaks)"
  local out="${OUTPUT_DIR}/gitleaks.json"
  local scan_log="${OUTPUT_DIR}/gitleaks.log"

  if tool_failed gitleaks || ! cmd_ok gitleaks; then
    SECRETS_STATUS="failed"
    err "gitleaks unavailable — secrets scan NOT performed"
    return
  fi

  local no_git_history=false
  if [[ ! -d "${PROJECT_PATH}/.git" ]]; then
    no "No git in project"
    log "Scanning files only (no git history available)"
    no_git_history=true
  fi

  # Inline config: extend default rules + ignore .env files
  local GITLEAKS_CONFIG_TOML
  GITLEAKS_CONFIG_TOML="$(cat <<'TOML'
[extend]
  useDefault = true

[allowlist]
  description = "ignore .env files"
  paths = ['''^\.env$''', '''^\.env\..*''']
TOML
)"
  local gl_config="${OUTPUT_DIR}/gitleaks-config.toml"
  printf '%s\n' "$GITLEAKS_CONFIG_TOML" > "$gl_config"

  local -a flags
  if [[ "$no_git_history" == true ]] && gitleaks dir --help &>/dev/null; then
    # gitleaks 8.19+: `dir` replaces the deprecated `detect --no-git`
    flags=(dir "$PROJECT_PATH"
      --config      "$gl_config"
      --report-path "$out"
      --report-format json
      --no-banner
      --exit-code 1
    )
  else
    flags=(detect
      --source      "$PROJECT_PATH"
      --config      "$gl_config"
      --report-path "$out"
      --report-format json
      --no-banner
      --exit-code 1
    )
    [[ "$no_git_history" == true ]] && flags+=(--no-git)
  fi

  log "Scanning for secrets in $(basename "$PROJECT_PATH")..."
  local rc=0
  gitleaks "${flags[@]}" >"$scan_log" 2>&1 || rc=$?

  # gitleaks: 0 = clean, 1 = leaks found, anything else = tool error
  if [[ $rc -gt 1 ]]; then
    SECRETS_STATUS="failed"
    TOOL_ERRORS=$((TOOL_ERRORS+1))
    keep_log "$scan_log"
    err "Gitleaks failed (exit ${rc}) — see ${scan_log}"
    return
  fi

  if [[ -f "$out" ]]; then
    SECRET_COUNT=$(jq 'if type == "array" then length else 0 end' "$out" 2>/dev/null || echo 0)
    [[ "$SECRET_COUNT" =~ ^[0-9]+$ ]] || SECRET_COUNT=0
  fi

  if [[ "$SECRET_COUNT" -eq 0 ]]; then
    SECRETS_STATUS="ok"
    ok "No secrets detected"
  else
    SECRETS_STATUS="findings"
    warn "${SECRET_COUNT} secret(s) found"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Single full Trivy pass: vuln + secret + license.
run_trivy_scan() {
  section "2/3  Trivy  (vuln, secret, license)"
  local tj="${OUTPUT_DIR}/trivy.json"
  local scan_log="${OUTPUT_DIR}/trivy.log"

  if tool_failed trivy || ! cmd_ok trivy; then
    TRIVY_STATUS="failed"
    err "trivy unavailable — vuln/secret/license scan NOT performed"
    return
  fi

  log "Trivy: scanning vuln, secret, license..."
  local rc=0
  trivy fs --scanners vuln,secret,license --license-full --quiet \
    --format json --output "$tj" "$PROJECT_PATH" 2>"$scan_log" || rc=$?

  if [[ $rc -ne 0 || ! -f "$tj" ]]; then
    TRIVY_STATUS="failed"
    TOOL_ERRORS=$((TOOL_ERRORS+1))
    keep_log "$scan_log"
    err "Trivy failed (exit ${rc}) — see ${scan_log}"
    return
  fi

  if cmd_ok jq; then
    TRIVY_CVE_COUNT=$(jq '[.Results[]? | (.Vulnerabilities // []) | length] | add // 0' "$tj" 2>/dev/null || echo 0)
    TRIVY_SECRET_COUNT=$(jq '[.Results[]? | (.Secrets // []) | length] | add // 0' "$tj" 2>/dev/null || echo 0)
    LICENSE_ISSUE_COUNT=$(jq '[.Results[]? | (.Licenses // [])[] | select(
      .Severity == "HIGH" or .Severity == "CRITICAL" or
      ((.Category // "") | ascii_downcase | test("restricted|reciprocal|unknown"))
    )] | length' "$tj" 2>/dev/null || echo 0)
  fi
  for _v in TRIVY_CVE_COUNT TRIVY_SECRET_COUNT LICENSE_ISSUE_COUNT; do
    [[ "${!_v}" =~ ^[0-9]+$ ]] || printf -v "$_v" '%s' 0
  done

  if [[ "$TRIVY_CVE_COUNT" -eq 0 ]]; then
    ok "Trivy CVE: none"
  else
    warn "Trivy CVE: ${TRIVY_CVE_COUNT} found"
  fi
  if [[ "$TRIVY_SECRET_COUNT" -eq 0 ]]; then
    ok "Trivy secrets: none"
  else
    warn "Trivy secrets: ${TRIVY_SECRET_COUNT} found"
  fi
  if [[ "$LICENSE_ISSUE_COUNT" -eq 0 ]]; then
    ok "Trivy license: no flagged licenses"
  else
    warn "Trivy license: ${LICENSE_ISSUE_COUNT} issue(s) found"
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

  if [[ $((TRIVY_CVE_COUNT + TRIVY_SECRET_COUNT + LICENSE_ISSUE_COUNT)) -gt 0 ]]; then
    TRIVY_STATUS="findings"
  else
    TRIVY_STATUS="ok"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_font_license_scan() {
  section "3/3  Font License  (ExifTool)"
  local fj="${OUTPUT_DIR}/font-license-exiftool.json"
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
    FONT_FILE_COUNT=$(jq 'length // 0' "$fj" 2>/dev/null || echo 0)
    [[ "$FONT_FILE_COUNT" =~ ^[0-9]+$ ]] || FONT_FILE_COUNT=0

    if cmd_ok jq; then
      FONT_LICENSE_ISSUE_COUNT=$(jq '[.[] |
        ([.License, .LicenseInfo, .Rights, .UsageTerms]
          | map(select(. != null and . != "")) | join(" | ")) as $lic |
        ([.Copyright, .CopyrightNotice]
          | map(select(. != null and . != "")) | join(" | ")) as $copy |
        select(
          ($lic == "") or
          (($lic + " " + $copy) | ascii_downcase | test("agpl|sspl|gpl|non.commercial|personal.use|trial|demo|evaluation|restricted|proprietary"))
        )
      ] | length' "$fj" 2>/dev/null || echo 0)
      [[ "$FONT_LICENSE_ISSUE_COUNT" =~ ^[0-9]+$ ]] || FONT_LICENSE_ISSUE_COUNT=0
    fi
  fi

  if [[ "$FONT_FILE_COUNT" -eq 0 ]]; then
    FONT_STATUS="ok"
    ok "No standalone font files found"
  elif [[ "$FONT_LICENSE_ISSUE_COUNT" -eq 0 ]]; then
    FONT_STATUS="ok"
    ok "ExifTool: ${FONT_FILE_COUNT} font file(s), no flagged font license metadata"
  else
    FONT_STATUS="findings"
    warn "ExifTool: ${FONT_LICENSE_ISSUE_COUNT}/${FONT_FILE_COUNT} font file(s) need license review"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
generate_summary() {
  section "Audit Summary"
  local total=$((SECRET_COUNT + TRIVY_SECRET_COUNT + TRIVY_CVE_COUNT + LICENSE_ISSUE_COUNT + FONT_LICENSE_ISSUE_COUNT))
  local stxt="${OUTPUT_DIR}/summary.txt"
  local sjson="${OUTPUT_DIR}/summary.json"

  # FAIL = at least one scanner could not run (results unreliable)
  # WARN = all scanners ran, findings present; PASS = all ran, nothing found
  local status="PASS"
  [[ $total -gt 0 ]] && status="WARN"
  [[ $TOOL_ERRORS -gt 0 ]] && status="FAIL"

  _trivy_row() {
    case "$TRIVY_STATUS" in
      failed|skipped) echo "$TRIVY_STATUS" ;;
      *) [[ "$1" -gt 0 ]] && echo "findings" || echo "ok" ;;
    esac
  }

  {
    printf '  %-12s %s\n' "Date"    "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '  %-12s %s\n' "Project" "$PROJECT_PATH"
    printf '  %-12s %s\n' "Status"  "$status"
    echo ""
    printf '┌─────────────────────────────┬────────────┬──────────┐\n'
    printf '│ %-27s │ %-10s │ %8s │\n' "Scanner" "Status" "Findings"
    printf '├─────────────────────────────┼────────────┼──────────┤\n'
    printf '│ %-27s │ %-10s │ %8d │\n' "Secrets (Gitleaks)"      "$SECRETS_STATUS"                          "$SECRET_COUNT"
    printf '│ %-27s │ %-10s │ %8d │\n' "Secrets (Trivy)"         "$(_trivy_row "$TRIVY_SECRET_COUNT")"      "$TRIVY_SECRET_COUNT"
    printf '│ %-27s │ %-10s │ %8d │\n' "CVE (Trivy)"             "$(_trivy_row "$TRIVY_CVE_COUNT")"         "$TRIVY_CVE_COUNT"
    printf '│ %-27s │ %-10s │ %8d │\n' "License (Trivy)"         "$(_trivy_row "$LICENSE_ISSUE_COUNT")"     "$LICENSE_ISSUE_COUNT"
    printf '│ %-27s │ %-10s │ %8d │\n' "Font License (ExifTool)" "$FONT_STATUS"                             "$FONT_LICENSE_ISSUE_COUNT"
    printf '├─────────────────────────────┼────────────┼──────────┤\n'
    printf '│ %-27s │ %-10s │ %8d │\n' "TOTAL" "" "$total"
    if [[ $TOOL_ERRORS -gt 0 ]]; then
      printf '│ %-27s │ %-10s │ %8d │\n' "Tool errors" "" "$TOOL_ERRORS"
    fi
    printf '└─────────────────────────────┴────────────┴──────────┘\n'
  } | tee "$stxt"

  if cmd_ok jq; then
    jq -n \
      --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg project    "$PROJECT_PATH" \
      --arg status     "$status" \
      --arg outdir     "$OUTPUT_DIR" \
      --argjson total         "$total" \
      --argjson tool_errors   "$TOOL_ERRORS" \
      --arg  secrets_status   "$SECRETS_STATUS" \
      --argjson secrets_count "$SECRET_COUNT" \
      --arg  trivy_status     "$TRIVY_STATUS" \
      --argjson trivy_cve     "$TRIVY_CVE_COUNT" \
      --argjson trivy_secrets "$TRIVY_SECRET_COUNT" \
      --argjson trivy_license "$LICENSE_ISSUE_COUNT" \
      --arg  font_status      "$FONT_STATUS" \
      --argjson font_files    "$FONT_FILE_COUNT" \
      --argjson font_issues   "$FONT_LICENSE_ISSUE_COUNT" \
      '{
        timestamp: $timestamp, project: $project, status: $status,
        scanners: {
          secrets_gitleaks: {status: $secrets_status, findings: $secrets_count},
          trivy: {status: $trivy_status, cve: $trivy_cve, secrets: $trivy_secrets, license_issues: $trivy_license},
          font_license: {status: $font_status, files: $font_files, issues: $font_issues}
        },
        total_findings: $total, tool_errors: $tool_errors, output_dir: $outdir
      }' > "$sjson" 2>/dev/null \
      || warn "summary.json generation failed — summary.txt is still valid"
  fi

  echo ""

  case "$status" in
    PASS) ok   "All scans passed — no findings" ;;
    WARN) warn "Total findings : ${total}" ;;
    FAIL)
      [[ $total -gt 0 ]] && warn "Total findings : ${total}"
      err "Tool errors    : ${TOOL_ERRORS} — results are INCOMPLETE, see the *.log files in the report" ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
main() {
  init

  echo ""
  echo -e "${BLD}VFA Security Audit${NC}"
  echo -e "${DIM}Project : ${PROJECT_PATH}${NC}"
  echo -e "${DIM}Reports : ${OUTPUT_DIR}${NC}"

  mkdir -p "${OUTPUT_DIR}" \
    || { err "Cannot create output directory: ${OUTPUT_DIR}"; exit 2; }
  check_tools

  run_secrets_scan
  run_trivy_scan
  run_font_license_scan

  generate_summary

  # Logs are kept only when they explain an error that affects audit quality;
  # logs of scanners that ran cleanly are removed before archiving.
  local lf
  for lf in gitleaks.log trivy.log exiftool.log; do
    [[ "$KEEP_LOGS" == *" ${lf} "* ]] || rm -f "${OUTPUT_DIR}/${lf}"
  done

  # Zip the report folder into the current working directory, then remove the original.
  local zip_name="$(basename "$OUTPUT_DIR").zip"
  local zip_file="${RUN_DIR}/${zip_name}"
  if ! cmd_ok zip; then
    warn "zip not found — report kept at: ${OUTPUT_DIR}"
    exit 0
  fi
  log "Archiving report..."
  if (cd "$(dirname "$OUTPUT_DIR")" && zip -qr "$zip_file" "$(basename "$OUTPUT_DIR")") 2>/dev/null; then
    if [[ "$(basename "$OUTPUT_DIR")" == "${TIMESTAMP}_"* ]]; then
      rm -rf "$OUTPUT_DIR"
    fi
    ok "Report archived: ${zip_file}"
  else
    warn "zip failed — report kept at: ${OUTPUT_DIR}"
  fi

  exit 0
}

main
