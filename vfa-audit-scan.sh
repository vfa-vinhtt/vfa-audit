#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# vfa-audit-scan.sh —  Source-code security audit, URL-friendly runner
#
#   Layer 1 — Secrets  : Gitleaks  (credentials, tokens, API keys)
#   Layer 2 — CVE      : Trivy + Grype  (known dependency vulnerabilities)
#   Layer 3 — License  : Trivy  (library & font license compliance)
#
# Usage:
#   ./vfa-audit-scan.sh [OPTIONS] [project-path]
#   curl -fsSL <raw-github-url>/vfa-audit-scan.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/vfa-vinhtt/vfa-audit/main/vfa-audit-scan.sh | bash -s -- --severity HIGH
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

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
OUTPUT_DIR=""  # default set in parse_args after PROJECT_PATH is known
SEVERITY="MEDIUM"          # LOW | MEDIUM | HIGH | CRITICAL
SKIP_SECRETS=false
SKIP_CVE=false
SKIP_LICENSE=false
NO_GIT_HISTORY=false       # Gitleaks: skip git history, scan files only
AUTO_INSTALL=true
VERBOSE=false
PROJECT_PATH=""

# ── Counters ──────────────────────────────────────────────────────────────────
SECRET_COUNT=0
TRIVY_CVE_COUNT=0
GRYPE_CVE_COUNT=0
LICENSE_ISSUE_COUNT=0
TOOL_ERRORS=0

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
log()     { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()      { echo -e "${GRN}[ OK ]${NC}  $*"; }
warn()    { echo -e "${YEL}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERR ]${NC}  $*" >&2; }
section() {
  echo ""
  echo -e "${BLD}${CYN}┌──────────────────────────────────────────────────────────┐${NC}"
  printf  "${BLD}${CYN}│  %-56s│${NC}\n" "$*"
  echo -e "${BLD}${CYN}└──────────────────────────────────────────────────────────┘${NC}"
}
cmd_ok() { command -v "$1" &>/dev/null; }

# Returns comma-separated severity list from $SEVERITY upward
# e.g. MEDIUM → "MEDIUM,HIGH,CRITICAL"
severity_list() {
  local all=("LOW" "MEDIUM" "HIGH" "CRITICAL")
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
  3-layer source code security audit combining three scanners:
    • Secrets  — Gitleaks: credentials, tokens, API keys (files + git history)
    • CVE      — Trivy + Grype: known vulnerabilities in dependencies
    • License  — Trivy: library and font license compliance

  If project-path is omitted, the script scans the current directory.
  This makes it safe to run directly from a raw GitHub URL.

${BLD}OPTIONS${NC}
  -o, --output <dir>       Report output directory  (default: ./reports/<ts>_<project>)
  -s, --severity <level>   Minimum severity: LOW|MEDIUM|HIGH|CRITICAL (default: MEDIUM)
      --skip-secrets       Skip Gitleaks scan
      --skip-cve           Skip CVE scan (Trivy + Grype)
      --skip-license       Skip license scan
      --no-git-history     Scan files only, skip git commit history (Gitleaks)
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
  reports/<timestamp>/
    gitleaks.json          Secrets findings
    trivy-vuln.json        CVE findings (Trivy, JSON)
    trivy-vuln.txt         CVE findings (Trivy, table)
    grype.json             CVE findings (Grype, JSON)
    grype.txt              CVE findings (Grype, table)
    trivy-license.json     License findings (JSON)
    trivy-license.txt      License findings (table)
    summary.txt            Human-readable summary
    summary.json           Machine-readable summary
EOF
}

# ─────────────────────────────────────────────────────────────────────────────
parse_args() {
  [[ $# -eq 0 ]] && PROJECT_PATH="$RUN_DIR"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output)          OUTPUT_DIR="$2";        shift 2 ;;
      -s|--severity)        SEVERITY="${2^^}";      shift 2 ;;
      --skip-secrets)       SKIP_SECRETS=true;      shift   ;;
      --skip-cve)           SKIP_CVE=true;          shift   ;;
      --skip-license)       SKIP_LICENSE=true;      shift   ;;
      --no-git-history)     NO_GIT_HISTORY=true;    shift   ;;
      --install)            AUTO_INSTALL=true;      shift   ;;
      -v|--verbose)         VERBOSE=true;           shift   ;;
      -h|--help)            usage; exit 0           ;;
      -*)                   err "Unknown option: $1"; usage; exit 2 ;;
      *)                    PROJECT_PATH="$1";      shift   ;;
    esac
  done

  [[ -z "$PROJECT_PATH" ]] && PROJECT_PATH="$RUN_DIR"
  [[ ! -d "$PROJECT_PATH" ]] && { err "Not a directory: $PROJECT_PATH"; exit 2; }
  PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"

  # Set default output dir now that PROJECT_PATH is resolved
  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="${RUN_DIR}/reports/${TIMESTAMP}_$(basename "$PROJECT_PATH")"
  fi

  case "$SEVERITY" in
    LOW|MEDIUM|HIGH|CRITICAL) ;;
    *) err "Invalid severity '$SEVERITY'. Use: LOW|MEDIUM|HIGH|CRITICAL"; exit 2 ;;
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

  [[ "$SKIP_SECRETS" != true ]] && _check gitleaks "gitleaks version"
  [[ "$SKIP_CVE" != true || "$SKIP_LICENSE" != true ]] && _check trivy "trivy version"
  [[ "$SKIP_CVE" != true ]] && _check grype "grype version"

  if [[ ${#missing[@]} -gt 0 ]]; then
    if [[ "$AUTO_INSTALL" == true ]]; then
      for t in "${missing[@]}"; do
        install_tool "$t" || { err "Failed to install $t"; TOOL_ERRORS=$((TOOL_ERRORS+1)); }
      done
    else
      err "Missing tools: ${missing[*]}"
      log "Install:  brew install gitleaks trivy grype"
      log "Or rerun: $SCRIPT_NAME --install ..."
      exit 2
    fi
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_secrets_scan() {
  section "1/3  Secrets  (Gitleaks)"
  local out="${OUTPUT_DIR}/gitleaks.json"

  local -a flags=(detect
    --source      "$PROJECT_PATH"
    --report-path "$out"
    --report-format json
    --no-banner
    --exit-code 1
  )
  [[ "$NO_GIT_HISTORY" == true ]] && flags+=(--no-git)

  log "Scanning for secrets in $(basename "$PROJECT_PATH")..."
  gitleaks "${flags[@]}" 2>&1 \
    | ( [[ "$VERBOSE" == true ]] && cat || grep -E "(leak|ERR|WRN)" 2>/dev/null || true ) \
  || true   # exit 1 = findings found, not an error

  if [[ -f "$out" ]]; then
    SECRET_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d) if isinstance(d, list) else 0)
except Exception:
    print(0)
" "$out" 2>/dev/null || echo 0)
  fi

  if [[ "$SECRET_COUNT" -eq 0 ]]; then
    ok "No secrets detected"
  else
    warn "${SECRET_COUNT} secret(s) found  →  ${out}"
    if cmd_ok jq; then
      jq -r '.[] | "  [\(.RuleID)]  \(.File):\(.StartLine)  \(.Description)"' \
        "$out" 2>/dev/null | head -20 || true
    fi
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_cve_scan() {
  section "2/3  CVE  (Trivy + Grype)"
  local sev_list; sev_list="$(severity_list)"

  # ── Trivy ──────────────────────────────────────────────────────────────────
  local tj="${OUTPUT_DIR}/trivy-vuln.json"
  local tt="${OUTPUT_DIR}/trivy-vuln.txt"
  log "Trivy: scanning dependencies for CVEs..."

  trivy fs --scanners vuln \
    --severity "$sev_list" \
    --format json --output "$tj" \
    --quiet "$PROJECT_PATH" 2>/dev/null || true

  trivy fs --scanners vuln \
    --severity "$sev_list" \
    --format table --output "$tt" \
    --quiet "$PROJECT_PATH" 2>/dev/null || true

  if [[ -f "$tj" ]]; then
    TRIVY_CVE_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results', [])))
except Exception:
    print(0)
" "$tj" 2>/dev/null || echo 0)
  fi

  if [[ "$TRIVY_CVE_COUNT" -eq 0 ]]; then
    ok "Trivy: no CVEs at ${SEVERITY}+"
  else
    warn "Trivy: ${TRIVY_CVE_COUNT} CVE(s) found  →  ${tj}"
    [[ "$VERBOSE" == true && -f "$tt" ]] && cat "$tt"
  fi

  # ── Grype ──────────────────────────────────────────────────────────────────
  local gj="${OUTPUT_DIR}/grype.json"
  local gt="${OUTPUT_DIR}/grype.txt"
  log "Grype: cross-checking vulnerabilities..."

  grype "dir:${PROJECT_PATH}" --output json  --file "$gj" --quiet 2>/dev/null || true
  grype "dir:${PROJECT_PATH}" --output table --file "$gt" --quiet 2>/dev/null || true

  if [[ -f "$gj" ]]; then
    GRYPE_CVE_COUNT=$(python3 -c "
import json, sys
try:
    d    = json.load(open(sys.argv[1]))
    lvl  = {'negligible':0,'low':1,'medium':2,'high':3,'critical':4}
    thr  = lvl.get(sys.argv[2].lower(), 2)
    count = sum(
        1 for m in d.get('matches', [])
        if lvl.get((m.get('vulnerability', {}).get('severity') or '').lower(), 0) >= thr
    )
    print(count)
except Exception:
    print(0)
" "$gj" "$SEVERITY" 2>/dev/null || echo 0)
  fi

  if [[ "$GRYPE_CVE_COUNT" -eq 0 ]]; then
    ok "Grype: no CVEs at ${SEVERITY}+"
  else
    warn "Grype: ${GRYPE_CVE_COUNT} CVE(s) found  →  ${gj}"
    [[ "$VERBOSE" == true && -f "$gt" ]] && cat "$gt"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
run_license_scan() {
  section "3/3  License  (Trivy)"
  local lj="${OUTPUT_DIR}/trivy-license.json"
  local lt="${OUTPUT_DIR}/trivy-license.txt"

  log "Scanning library and font licenses..."

  # --license-full: scan file content in addition to package metadata
  trivy fs --scanners license --license-full \
    --format json  --output "$lj" \
    --quiet "$PROJECT_PATH" 2>/dev/null || true

  trivy fs --scanners license --license-full \
    --format table --output "$lt" \
    --quiet "$PROJECT_PATH" 2>/dev/null || true

  if [[ -f "$lj" ]]; then
    # Count licenses with HIGH/CRITICAL severity OR in restricted/reciprocal categories
    LICENSE_ISSUE_COUNT=$(python3 -c "
import json, sys
FLAGGED_CATS = {'restricted', 'reciprocal', 'unknown'}
try:
    d = json.load(open(sys.argv[1]))
    count = 0
    for r in d.get('Results', []):
        for lic in (r.get('Licenses') or []):
            sev = (lic.get('Severity') or '').upper()
            cat = (lic.get('Category') or '').lower()
            if sev in ('HIGH', 'CRITICAL') or cat in FLAGGED_CATS:
                count += 1
    print(count)
except Exception:
    print(0)
" "$lj" 2>/dev/null || echo 0)
  fi

  if [[ "$LICENSE_ISSUE_COUNT" -eq 0 ]]; then
    ok "No flagged licenses"
  else
    warn "${LICENSE_ISSUE_COUNT} license issue(s) found  →  ${lj}"
    if cmd_ok jq && [[ -f "$lj" ]]; then
      jq -r '
        .Results[]?.Licenses[]?
        | select(.Severity == "HIGH" or .Severity == "CRITICAL")
        | "  [\(.Severity)]  \(.PkgName // "?")  \(.Name)"
      ' "$lj" 2>/dev/null | head -20 || true
    fi
  fi

  [[ "$VERBOSE" == true && -f "$lt" ]] && cat "$lt"

  log "${DIM}Note: Trivy reads package-manager metadata. Standalone font files (.ttf/.woff)${NC}"
  log "${DIM}      not managed by a package registry require manual license review.${NC}"
}

# ─────────────────────────────────────────────────────────────────────────────
generate_summary() {
  section "Audit Summary"
  local total=$((SECRET_COUNT + TRIVY_CVE_COUNT + GRYPE_CVE_COUNT + LICENSE_ISSUE_COUNT))
  local stxt="${OUTPUT_DIR}/summary.txt"
  local sjson="${OUTPUT_DIR}/summary.json"

  local SEP="══════════════════════════════════════════════════════════════"
  local DIV="──────────────────────────────────────────────────────────────"

  {
    echo "$SEP"
    printf '  %-18s %s\n' "Security Audit" ""
    printf '  %-18s %s\n' "Date:"    "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '  %-18s %s\n' "Project:" "$PROJECT_PATH"
    printf '  %-18s %s\n' "Severity:" "${SEVERITY}+"
    echo "$DIV"
    printf '  %-34s %8s\n' "Scanner"                        "Findings"
    printf '  %-34s %8s\n' "──────────────────────────────" "────────"
    printf '  %-34s %8d\n' "Secrets      (Gitleaks)"        $SECRET_COUNT
    printf '  %-34s %8d\n' "CVE          (Trivy)"           $TRIVY_CVE_COUNT
    printf '  %-34s %8d\n' "CVE          (Grype)"           $GRYPE_CVE_COUNT
    printf '  %-34s %8d\n' "License      (Trivy)"           $LICENSE_ISSUE_COUNT
    printf '  %-34s %8s\n' "──────────────────────────────" "────────"
    printf '  %-34s %8d\n' "TOTAL"                          $total
    [[ $TOOL_ERRORS -gt 0 ]] && \
      printf '  %-34s %8d\n' "Tool errors"                  $TOOL_ERRORS
    echo "$SEP"
  } | tee "$stxt"

  cat > "$sjson" <<JSON
{
  "timestamp":          "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "project":            "${PROJECT_PATH}",
  "severity_threshold": "${SEVERITY}",
  "findings": {
    "secrets":        ${SECRET_COUNT},
    "cve_trivy":      ${TRIVY_CVE_COUNT},
    "cve_grype":      ${GRYPE_CVE_COUNT},
    "license_issues": ${LICENSE_ISSUE_COUNT},
    "total":          ${total}
  },
  "tool_errors": ${TOOL_ERRORS},
  "output_dir":  "${OUTPUT_DIR}"
}
JSON

  echo ""
  log "Full reports: ${OUTPUT_DIR}/"

  if [[ $total -eq 0 && $TOOL_ERRORS -eq 0 ]]; then
    ok "All scans passed — no findings at ${SEVERITY}+"
  else
    [[ $total       -gt 0 ]] && warn "Total findings : ${total}"
    [[ $TOOL_ERRORS -gt 0 ]] && err  "Tool errors    : ${TOOL_ERRORS}"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"

  echo ""
  echo -e "${BLD}Source Code Security Audit${NC}"
  echo -e "${DIM}Project  : ${PROJECT_PATH}${NC}"
  echo -e "${DIM}Reports  : ${OUTPUT_DIR}${NC}"
  echo -e "${DIM}Severity : ${SEVERITY}+${NC}"

  mkdir -p "$OUTPUT_DIR"
  check_tools

  [[ "$SKIP_SECRETS" != true ]] && run_secrets_scan
  [[ "$SKIP_CVE"     != true ]] && run_cve_scan
  [[ "$SKIP_LICENSE" != true ]] && run_license_scan

  generate_summary

  # Zip the report folder and remove the original
  local zip_file="${OUTPUT_DIR}.zip"
  log "Archiving report..."
  if (cd "$(dirname "$OUTPUT_DIR")" && zip -qr "$(basename "$OUTPUT_DIR").zip" "$(basename "$OUTPUT_DIR")") 2>/dev/null; then
    rm -rf "$OUTPUT_DIR"
    ok "Report archived: ${zip_file}"
  else
    warn "zip failed — report kept at: ${OUTPUT_DIR}"
  fi

  exit 0
}

main "$@"
