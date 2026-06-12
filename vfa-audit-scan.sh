#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# vfa-audit-scan.sh — Source intake security & license scanner, URL-friendly
#
#   Layer 1 — Secrets  : Gitleaks + Trivy  (credentials, tokens, API keys)
#   Layer 2 — CVE      : Trivy
#   Layer 3 — License  : Trivy + ExifTool (library & font license compliance)
#
# Findings are classified by policy (see policy.md):
#   FAIL > REVIEW_REQUIRED > WARNING > PASS
#   UNKNOWN is never treated as safe. Tool errors make the result FAIL
#   because the scan is incomplete.
#
# Usage:
#   cd /path/to/project
#   ./vfa-audit-scan.sh
#   curl -fsSL <raw-github-url>/vfa-audit-scan.sh | bash
# ─────────────────────────────────────────────────────────────────────────────
VERSION="1.0.0"

set -uo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

RUN_DIR="$(pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_PATH="$RUN_DIR"
OUTPUT_DIR="/tmp/vfa_audit/${TIMESTAMP}_$(basename "$PROJECT_PATH")"

# ── License policy (single place to edit — keep in sync with policy.md §5) ──
# Block-by-default for closed-source / commercial delivery (needs approval):
LICENSE_DENY_RE='^(AGPL|GPL|SSPL|BUSL)|Commons.?Clause|CC-BY-NC|CC-BY-ND'
# Needs a human decision before any commercial-use conclusion:
LICENSE_REVIEW_RE='^(LGPL|MPL|EPL|CDDL|OFL|Artistic|Unicode-DFS)|UNKNOWN|NOASSERTION|LicenseRef|Custom|Proprietary|Unrecognized|Non.?Standard'

# ── Font metadata policy (policy.md §6) ──────────────────────────────────────
FONT_BLOCK_RE='non.?commercial|personal.?use|trial|demo|evaluation|restricted|proprietary'
FONT_REVIEW_RE='gpl|sspl'

# ── Counters ──────────────────────────────────────────────────────────────────
SECRET_COUNT=0
TRIVY_SECRET_COUNT=0
TRIVY_CVE_COUNT=0
CVE_BLOCKER_COUNT=0
CVE_REVIEW_COUNT=0
CVE_WARN_COUNT=0
LICENSE_DENY_COUNT=0
LICENSE_REVIEW_COUNT=0
FONT_FILE_COUNT=0
FONT_BLOCKER_COUNT=0
FONT_REVIEW_COUNT=0
TOOL_ERRORS=0

# ── Per-scanner status: ok | findings | failed | skipped ─────────────────────
SECRETS_STATUS="skipped"
TRIVY_STATUS="skipped"
FONT_STATUS="skipped"

FAILED_TOOLS=" "
KEEP_LOGS=" "

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
# jq that never breaks the audit: empty/invalid input or jq errors yield 0.
# Usage: jq_count <file> [jq-args...] <filter>
jq_count() {
  local file="$1"; shift
  local n
  n=$(jq "$@" "$file" 2>/dev/null || echo 0)
  [[ "$n" =~ ^[0-9]+$ ]] && echo "$n" || echo 0
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
    local tool="$1" ver_cmd="$2"
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
    if cmd_ok brew; then
      local t
      for t in "${missing[@]}"; do
        if ! install_tool "$t"; then
          err "Failed to install $t — its scan will be marked as failed"
          TOOL_ERRORS=$((TOOL_ERRORS+1))
          FAILED_TOOLS+="$t "
        fi
      done
    else
      err "Homebrew not found — cannot install missing tools"
      local t
      for t in "${missing[@]}"; do
        err "${t} unavailable — its scan will be marked as failed"
        TOOL_ERRORS=$((TOOL_ERRORS+1))
        FAILED_TOOLS+="$t "
      done
      log "Install manually:  brew install ${missing[*]}"
    fi
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

  # Gitleaks default rules/config — no inline allowlist: real .env files and
  # sample files are both scanned. Allowlisting belongs in a reviewed
  # .gitleaks.toml in the project, never hard-coded here (policy.md §3.4).
  local -a flags
  if [[ "$no_git_history" == true ]] && gitleaks dir --help &>/dev/null; then
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
    SECRET_COUNT=$(jq_count "$out" 'if type == "array" then length else 0 end')
  fi

  if [[ "$SECRET_COUNT" -eq 0 ]]; then
    SECRETS_STATUS="ok"
    ok "No secrets detected"
  else
    SECRETS_STATUS="findings"
    warn "${SECRET_COUNT} secret(s) found — policy status: FAIL (rotate/revoke if real)"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Single full Trivy pass: vuln + secret + license, then classify each finding
# group by policy (policy.md §4, §5).
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
    TRIVY_CVE_COUNT=$(jq_count "$tj" '[.Results[]? | (.Vulnerabilities // []) | length] | add // 0')
    TRIVY_SECRET_COUNT=$(jq_count "$tj" '[.Results[]? | (.Secrets // []) | length] | add // 0')

    # CVE policy: HIGH/CRITICAL + fix available = FAIL; HIGH/CRITICAL without
    # fix or UNKNOWN severity = REVIEW_REQUIRED; MEDIUM/LOW = WARNING.
    CVE_BLOCKER_COUNT=$(jq_count "$tj" '[.Results[]? | (.Vulnerabilities // [])[]
      | select((.Severity == "CRITICAL" or .Severity == "HIGH") and ((.FixedVersion // "") != ""))] | length')
    CVE_REVIEW_COUNT=$(jq_count "$tj" '[.Results[]? | (.Vulnerabilities // [])[]
      | select(((.Severity == "CRITICAL" or .Severity == "HIGH") and ((.FixedVersion // "") == ""))
               or .Severity == "UNKNOWN")] | length')
    CVE_WARN_COUNT=$(jq_count "$tj" '[.Results[]? | (.Vulnerabilities // [])[]
      | select(.Severity == "MEDIUM" or .Severity == "LOW")] | length')

    # License policy: denylist = FAIL; review list / unclear category = REVIEW.
    LICENSE_DENY_COUNT=$(jq_count "$tj" --arg deny "$LICENSE_DENY_RE" '[.Results[]? | (.Licenses // [])[]
      | select(((.Name // "") | test($deny; "i")) or ((.Category // "") | ascii_downcase == "forbidden"))] | length')
    LICENSE_REVIEW_COUNT=$(jq_count "$tj" --arg deny "$LICENSE_DENY_RE" --arg review "$LICENSE_REVIEW_RE" '[.Results[]? | (.Licenses // [])[]
      | select((((.Name // "") | test($deny; "i")) or ((.Category // "") | ascii_downcase == "forbidden")) | not)
      | select(((.Name // "") | test($review; "i"))
               or ((.Category // "") | ascii_downcase | (. == "restricted" or . == "reciprocal" or . == "unknown")))] | length')
  else
    err "jq unavailable — Trivy findings cannot be classified by policy"
  fi

  if [[ "$TRIVY_CVE_COUNT" -eq 0 ]]; then
    ok "Trivy CVE: none"
  else
    warn "Trivy CVE: ${TRIVY_CVE_COUNT} found — ${CVE_BLOCKER_COUNT} FAIL (fix available), ${CVE_REVIEW_COUNT} review, ${CVE_WARN_COUNT} low-priority"
  fi
  if [[ "$TRIVY_SECRET_COUNT" -eq 0 ]]; then
    ok "Trivy secrets: none"
  else
    warn "Trivy secrets: ${TRIVY_SECRET_COUNT} found — policy status: FAIL"
  fi
  if [[ $((LICENSE_DENY_COUNT + LICENSE_REVIEW_COUNT)) -eq 0 ]]; then
    ok "Trivy license: no flagged licenses"
  else
    warn "Trivy license: ${LICENSE_DENY_COUNT} denied-by-default, ${LICENSE_REVIEW_COUNT} review required"
    if cmd_ok jq; then
      jq -r --arg deny "$LICENSE_DENY_RE" '
        .Results[]?.Licenses[]?
        | select(((.Name // "") | test($deny; "i")) or ((.Category // "") | ascii_downcase == "forbidden"))
        | "  [DENY]  \(.PkgName // .FilePath // "?")  \(.Name)"
      ' "$tj" 2>/dev/null | head -20 || true
    fi
  fi
  log "${DIM}Note: Trivy reads package-manager metadata. Standalone font files (.ttf/.woff)${NC}"
  log "${DIM}      not managed by a package registry are covered by the ExifTool layer.${NC}"

  if [[ $((TRIVY_CVE_COUNT + TRIVY_SECRET_COUNT + LICENSE_DENY_COUNT + LICENSE_REVIEW_COUNT)) -gt 0 ]]; then
    TRIVY_STATUS="findings"
  else
    TRIVY_STATUS="ok"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_font_license_scan() {
  section "3/3  Font License  (ExifTool)"
  local fj="${OUTPUT_DIR}/font-license-exiftool.json"
  local fhash="${OUTPUT_DIR}/font-sha256.txt"
  local scan_log="${OUTPUT_DIR}/exiftool.log"

  # Font hashes do not depend on exiftool: fonts can be renamed, the hash
  # identifies the original (policy.md §6.3).
  find "$PROJECT_PATH" -type f \
    \( -iname "*.ttf" -o -iname "*.otf" -o -iname "*.woff" -o -iname "*.woff2" -o -iname "*.eot" \) \
    -not -path "*/.git/*" -exec shasum -a 256 {} + > "$fhash" 2>/dev/null
  [[ -s "$fhash" ]] || rm -f "$fhash"

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

  if [[ -f "$fj" ]] && cmd_ok jq; then
    FONT_FILE_COUNT=$(jq_count "$fj" 'length // 0')

    # Font policy: restrictive metadata = FAIL; missing license metadata or
    # copyleft mention = REVIEW_REQUIRED. Metadata alone never proves a font
    # PASS legally — see policy.md §6.5.
    FONT_BLOCKER_COUNT=$(jq_count "$fj" --arg block "$FONT_BLOCK_RE" '[.[] |
      ([.License, .LicenseInfo, .LicenseURL, .UsageTerms, .Rights]
        | map(select(. != null and . != "")) | join(" | ")) as $lic |
      ([.Copyright, .CopyrightNotice, .Description]
        | map(select(. != null and . != "")) | join(" | ")) as $extra |
      select(($lic + " " + $extra) | ascii_downcase | test($block))
    ] | length')
    FONT_REVIEW_COUNT=$(jq_count "$fj" --arg block "$FONT_BLOCK_RE" --arg review "$FONT_REVIEW_RE" '[.[] |
      ([.License, .LicenseInfo, .LicenseURL, .UsageTerms, .Rights]
        | map(select(. != null and . != "")) | join(" | ")) as $lic |
      ([.Copyright, .CopyrightNotice, .Description]
        | map(select(. != null and . != "")) | join(" | ")) as $extra |
      select((($lic + " " + $extra) | ascii_downcase | test($block)) | not) |
      select(($lic == "") or (($lic + " " + $extra) | ascii_downcase | test($review)))
    ] | length')
  fi

  if [[ "$FONT_FILE_COUNT" -eq 0 ]]; then
    FONT_STATUS="ok"
    ok "No standalone font files found"
  elif [[ $((FONT_BLOCKER_COUNT + FONT_REVIEW_COUNT)) -eq 0 ]]; then
    FONT_STATUS="ok"
    ok "ExifTool: ${FONT_FILE_COUNT} font file(s), no flagged font license metadata"
    log "${DIM}Metadata alone is not legal proof — keep license files / purchase evidence.${NC}"
  else
    FONT_STATUS="findings"
    warn "ExifTool: ${FONT_FILE_COUNT} font file(s) — ${FONT_BLOCKER_COUNT} FAIL, ${FONT_REVIEW_COUNT} review required"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Prioritized reports so the reader does not have to parse raw trivy.json:
# blockers.json / review-required.json / warnings.json (policy.md §9).
# Raw evidence files are never modified.
build_priority_reports() {
  cmd_ok jq || return 0
  local gj="${OUTPUT_DIR}/gitleaks.json"
  local tj="${OUTPUT_DIR}/trivy.json"
  local fj="${OUTPUT_DIR}/font-license-exiftool.json"

  {
    [[ -s "$gj" ]] && jq '[ (if type == "array" then . else [] end)[]
      | {source: "gitleaks", type: "secret", severity: "BLOCKER",
         rule: (.RuleID // ""), file: (.File // ""), line: (.StartLine // null),
         detail: (.Description // "")} ]' "$gj" 2>/dev/null
    [[ -s "$tj" ]] && jq '[ .Results[]? as $r | ($r.Secrets // [])[]
      | {source: "trivy", type: "secret", severity: "BLOCKER",
         rule: (.RuleID // ""), file: $r.Target, line: (.StartLine // null),
         detail: (.Title // "")} ]' "$tj" 2>/dev/null
    [[ -s "$tj" ]] && jq '[ .Results[]? | (.Vulnerabilities // [])[]
      | select((.Severity == "CRITICAL" or .Severity == "HIGH") and ((.FixedVersion // "") != ""))
      | {source: "trivy", type: "cve", severity: .Severity,
         id: .VulnerabilityID, package: .PkgName,
         installed: (.InstalledVersion // ""), fixed: (.FixedVersion // ""),
         detail: (.Title // "")} ]' "$tj" 2>/dev/null
    [[ -s "$tj" ]] && jq --arg deny "$LICENSE_DENY_RE" '[ .Results[]? | (.Licenses // [])[]
      | select(((.Name // "") | test($deny; "i")) or ((.Category // "") | ascii_downcase == "forbidden"))
      | {source: "trivy", type: "license", severity: "DENY",
         package: (.PkgName // .FilePath // "?"), license: .Name,
         category: (.Category // "")} ]' "$tj" 2>/dev/null
    [[ -s "$fj" ]] && jq --arg block "$FONT_BLOCK_RE" '[ .[]
      | ([.License, .LicenseInfo, .LicenseURL, .UsageTerms, .Rights]
          | map(select(. != null and . != "")) | join(" | ")) as $lic
      | ([.Copyright, .CopyrightNotice, .Description]
          | map(select(. != null and . != "")) | join(" | ")) as $extra
      | select(($lic + " " + $extra) | ascii_downcase | test($block))
      | {source: "exiftool", type: "font-license", severity: "BLOCKER",
         file: .SourceFile, detail: (($lic + " | " + $extra) | .[0:300])} ]' "$fj" 2>/dev/null
  } | jq -s 'add // []' > "${OUTPUT_DIR}/blockers.json" 2>/dev/null

  {
    [[ -s "$tj" ]] && jq '[ .Results[]? | (.Vulnerabilities // [])[]
      | select(((.Severity == "CRITICAL" or .Severity == "HIGH") and ((.FixedVersion // "") == ""))
               or .Severity == "UNKNOWN")
      | {source: "trivy", type: "cve", severity: .Severity,
         id: .VulnerabilityID, package: .PkgName,
         installed: (.InstalledVersion // ""), fixed: null,
         detail: (.Title // "")} ]' "$tj" 2>/dev/null
    [[ -s "$tj" ]] && jq --arg deny "$LICENSE_DENY_RE" --arg review "$LICENSE_REVIEW_RE" '[ .Results[]? | (.Licenses // [])[]
      | select((((.Name // "") | test($deny; "i")) or ((.Category // "") | ascii_downcase == "forbidden")) | not)
      | select(((.Name // "") | test($review; "i"))
               or ((.Category // "") | ascii_downcase | (. == "restricted" or . == "reciprocal" or . == "unknown")))
      | {source: "trivy", type: "license", severity: "REVIEW",
         package: (.PkgName // .FilePath // "?"), license: .Name,
         category: (.Category // "")} ]' "$tj" 2>/dev/null
    [[ -s "$fj" ]] && jq --arg block "$FONT_BLOCK_RE" --arg review "$FONT_REVIEW_RE" '[ .[]
      | ([.License, .LicenseInfo, .LicenseURL, .UsageTerms, .Rights]
          | map(select(. != null and . != "")) | join(" | ")) as $lic
      | ([.Copyright, .CopyrightNotice, .Description]
          | map(select(. != null and . != "")) | join(" | ")) as $extra
      | select((($lic + " " + $extra) | ascii_downcase | test($block)) | not)
      | select(($lic == "") or (($lic + " " + $extra) | ascii_downcase | test($review)))
      | {source: "exiftool", type: "font-license", severity: "REVIEW",
         file: .SourceFile,
         detail: (if $lic == "" then "no license metadata" else (($lic + " | " + $extra) | .[0:300]) end)} ]' "$fj" 2>/dev/null
  } | jq -s 'add // []' > "${OUTPUT_DIR}/review-required.json" 2>/dev/null

  {
    [[ -s "$tj" ]] && jq '[ .Results[]? | (.Vulnerabilities // [])[]
      | select(.Severity == "MEDIUM" or .Severity == "LOW")
      | {source: "trivy", type: "cve", severity: .Severity,
         id: .VulnerabilityID, package: .PkgName,
         installed: (.InstalledVersion // ""), fixed: (.FixedVersion // null),
         detail: (.Title // "")} ]' "$tj" 2>/dev/null
  } | jq -s 'add // []' > "${OUTPUT_DIR}/warnings.json" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────────────
generate_summary() {
  section "Audit Summary"
  local stxt="${OUTPUT_DIR}/summary.txt"
  local sjson="${OUTPUT_DIR}/summary.json"

  local fail_total=$((SECRET_COUNT + TRIVY_SECRET_COUNT + CVE_BLOCKER_COUNT + LICENSE_DENY_COUNT + FONT_BLOCKER_COUNT))
  local review_total=$((CVE_REVIEW_COUNT + LICENSE_REVIEW_COUNT + FONT_REVIEW_COUNT))
  local warn_total=$((CVE_WARN_COUNT))
  local total=$((fail_total + review_total + warn_total))

  # Policy decision (policy.md §10): FAIL > REVIEW_REQUIRED > WARNING > PASS.
  # Tool errors force FAIL because the result is incomplete — UNKNOWN is not safe.
  local status="PASS"
  [[ $warn_total   -gt 0 ]] && status="WARNING"
  [[ $review_total -gt 0 ]] && status="REVIEW_REQUIRED"
  [[ $fail_total -gt 0 || $TOOL_ERRORS -gt 0 ]] && status="FAIL"

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
    printf '┌─────────────────────────────┬────────────┬────────┬────────┬────────┐\n'
    printf '│ %-27s │ %-10s │ %6s │ %6s │ %6s │\n' "Scanner" "Status" "FAIL" "REVIEW" "WARN"
    printf '├─────────────────────────────┼────────────┼────────┼────────┼────────┤\n'
    printf '│ %-27s │ %-10s │ %6d │ %6d │ %6d │\n' "Secrets (Gitleaks)"      "$SECRETS_STATUS"                                       "$SECRET_COUNT"       0                       0
    printf '│ %-27s │ %-10s │ %6d │ %6d │ %6d │\n' "Secrets (Trivy)"         "$(_trivy_row "$TRIVY_SECRET_COUNT")"                   "$TRIVY_SECRET_COUNT" 0                       0
    printf '│ %-27s │ %-10s │ %6d │ %6d │ %6d │\n' "CVE (Trivy)"             "$(_trivy_row "$TRIVY_CVE_COUNT")"                      "$CVE_BLOCKER_COUNT"  "$CVE_REVIEW_COUNT"     "$CVE_WARN_COUNT"
    printf '│ %-27s │ %-10s │ %6d │ %6d │ %6d │\n' "License (Trivy)"         "$(_trivy_row "$((LICENSE_DENY_COUNT+LICENSE_REVIEW_COUNT))")" "$LICENSE_DENY_COUNT" "$LICENSE_REVIEW_COUNT" 0
    printf '│ %-27s │ %-10s │ %6d │ %6d │ %6d │\n' "Font License (ExifTool)" "$FONT_STATUS"                                          "$FONT_BLOCKER_COUNT" "$FONT_REVIEW_COUNT"    0
    printf '├─────────────────────────────┼────────────┼────────┼────────┼────────┤\n'
    printf '│ %-27s │ %-10s │ %6d │ %6d │ %6d │\n' "TOTAL" "" "$fail_total" "$review_total" "$warn_total"
    if [[ $TOOL_ERRORS -gt 0 ]]; then
      printf '│ %-27s │ %-10s │ %6d │ %6s │ %6s │\n' "Tool errors" "" "$TOOL_ERRORS" "" ""
    fi
    printf '└─────────────────────────────┴────────────┴────────┴────────┴────────┘\n'
  } | tee "$stxt"

  if cmd_ok jq; then
    jq -n \
      --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg project    "$PROJECT_PATH" \
      --arg status     "$status" \
      --arg outdir     "$OUTPUT_DIR" \
      --argjson total         "$total" \
      --argjson fail_total    "$fail_total" \
      --argjson review_total  "$review_total" \
      --argjson warn_total    "$warn_total" \
      --argjson tool_errors   "$TOOL_ERRORS" \
      --arg  secrets_status   "$SECRETS_STATUS" \
      --argjson secrets_count "$SECRET_COUNT" \
      --arg  trivy_status     "$TRIVY_STATUS" \
      --argjson trivy_cve     "$TRIVY_CVE_COUNT" \
      --argjson cve_fail      "$CVE_BLOCKER_COUNT" \
      --argjson cve_review    "$CVE_REVIEW_COUNT" \
      --argjson cve_warn      "$CVE_WARN_COUNT" \
      --argjson trivy_secrets "$TRIVY_SECRET_COUNT" \
      --argjson license_deny  "$LICENSE_DENY_COUNT" \
      --argjson license_review "$LICENSE_REVIEW_COUNT" \
      --arg  font_status      "$FONT_STATUS" \
      --argjson font_files    "$FONT_FILE_COUNT" \
      --argjson font_fail     "$FONT_BLOCKER_COUNT" \
      --argjson font_review   "$FONT_REVIEW_COUNT" \
      '{
        timestamp: $timestamp, project: $project, status: $status,
        policy: {fail: $fail_total, review_required: $review_total, warning: $warn_total},
        scanners: {
          secrets_gitleaks: {status: $secrets_status, fail: $secrets_count},
          trivy: {
            status: $trivy_status,
            cve: {total: $trivy_cve, fail: $cve_fail, review: $cve_review, warn: $cve_warn},
            secrets: {fail: $trivy_secrets},
            license: {fail: $license_deny, review: $license_review}
          },
          font_license: {status: $font_status, files: $font_files, fail: $font_fail, review: $font_review}
        },
        total_findings: $total, tool_errors: $tool_errors, output_dir: $outdir
      }' > "$sjson" 2>/dev/null \
      || warn "summary.json generation failed — summary.txt is still valid"
  fi

  echo ""

  case "$status" in
    PASS)
      ok "No findings within the current scan scope and policy"
      log "${DIM}This is not a claim of absolute safety — see policy.md §13.${NC}" ;;
    WARNING)
      warn "Low-priority findings: ${warn_total} — see warnings.json" ;;
    REVIEW_REQUIRED)
      warn "${review_total} item(s) need human review — see review-required.json"
      [[ $warn_total -gt 0 ]] && warn "Plus ${warn_total} low-priority finding(s) — see warnings.json" ;;
    FAIL)
      [[ $fail_total -gt 0 ]] && err "Blockers: ${fail_total} — see blockers.json (must be resolved/approved before delivery)"
      [[ $review_total -gt 0 ]] && warn "${review_total} item(s) need human review — see review-required.json"
      [[ $TOOL_ERRORS -gt 0 ]] && err "Tool errors: ${TOOL_ERRORS} — results are INCOMPLETE, see the *.log files in the report" ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "${BLD}VFA Security Audit${NC}  ${DIM}v${VERSION}${NC}"
  echo -e "${DIM}Project : ${PROJECT_PATH}${NC}"
  echo -e "${DIM}Reports : ${OUTPUT_DIR}${NC}"

  mkdir -p "${OUTPUT_DIR}" \
    || { err "Cannot create output directory: ${OUTPUT_DIR}"; exit 2; }

  check_tools
  run_secrets_scan
  run_trivy_scan
  run_font_license_scan
  build_priority_reports
  generate_summary

  # Logs are kept only when they explain an error that affects audit quality;
  # logs of scanners that ran cleanly are removed before archiving.
  local lf
  for lf in gitleaks.log trivy.log exiftool.log; do
    [[ "$KEEP_LOGS" == *" ${lf} "* ]] || rm -f "${OUTPUT_DIR}/${lf}"
  done

  # Zip the report into the current working directory, then remove the temp folder.
  local zip_file="${RUN_DIR}/$(basename "$OUTPUT_DIR").zip"
  if ! cmd_ok zip; then
    warn "zip not found — report kept at: ${OUTPUT_DIR}"
    exit 0
  fi
  log "Archiving report..."
  if (cd "$(dirname "$OUTPUT_DIR")" && zip -qr "$zip_file" "$(basename "$OUTPUT_DIR")") 2>/dev/null; then
    rm -rf "$OUTPUT_DIR"
    ok "Report archived: ${zip_file}"
  else
    warn "zip failed — report kept at: ${OUTPUT_DIR}"
  fi

  exit 0
}

main
