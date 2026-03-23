#!/usr/bin/env bash
# =============================================================================
#
#   websec-audit.sh — Professional Web Security Audit Framework
#
#   Author  : davidalvarezp (https://davidalvarezp.com)
#   Version : 1.0.1
#   License : MIT
#   GitHub  : https://github.com/davidalvarezp/websec-audit
#
#   LEGAL NOTICE:
#   This tool is intended for authorized security assessments only.
#   Unauthorized use against systems you do not own or have explicit
#   written permission to test is illegal and unethical.
#   The author assumes no liability for misuse of this software.
#
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS & METADATA
# ─────────────────────────────────────────────────────────────────────────────
readonly TOOL_NAME="websec-audit"
readonly TOOL_VERSION="1.0.1"
readonly TOOL_AUTHOR="davidalvarezp"
readonly TOOL_URL="https://github.com/davidalvarezp/websec-audit"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly DATE_HUMAN="$(date '+%Y-%m-%d %H:%M:%S')"
readonly AUDIT_PID=$$

# ─────────────────────────────────────────────────────────────────────────────
#  ANSI COLOR PALETTE
# ─────────────────────────────────────────────────────────────────────────────
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_MAGENTA='\033[0;35m'
readonly C_BOLD='\033[1m'
readonly C_DIM='\033[2m'
readonly C_RESET='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
#  RUNTIME VARIABLES  (set via parse_args, never hardcode below)
# ─────────────────────────────────────────────────────────────────────────────
TARGET=""
TARGET_DOMAIN=""
TARGET_IP=""
TARGET_SCHEME=""
OUTPUT_DIR=""
LOG_FILE=""
REPORT_HTML=""
REPORT_JSON=""
REPORT_TXT=""
FINDINGS_JSONL=""

# Module toggles (1 = enabled)
MOD_RECON=1
MOD_PORTSCAN=1
MOD_FINGERPRINT=1
MOD_SSL=1
MOD_HEADERS=1
MOD_DIRBRUTE=1
MOD_NIKTO=1
MOD_SQLI=1
MOD_XSS=1
MOD_CMS=1
MOD_CORS=1
MOD_REDIRECT=1
MOD_SSRF=1
MOD_SUBTAKEOVER=1
MOD_NUCLEI=1

# Scan options
OPT_THREADS=10
OPT_TIMEOUT=10
OPT_DEPTH=3
OPT_PORTS="top-1000"     # top-100 | top-1000 | full
OPT_AGGRESSIVE=0
OPT_STEALTH=0
OPT_PROXY=""
OPT_VERBOSE=0
OPT_NO_COLOR=0
OPT_NO_BANNER=0
OPT_OUTPUT_ONLY=""       # json | html | txt (empty = all)

# Wordlists (can be overridden via --wl-* flags)
WL_DIRS_SMALL="/usr/share/wordlists/dirb/common.txt"
WL_DIRS_BIG="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
WL_DNS="/usr/share/wordlists/dnsmap.txt"

# Finding counters
TOTAL_FINDINGS=0
COUNT_CRITICAL=0
COUNT_HIGH=0
COUNT_MEDIUM=0
COUNT_LOW=0
COUNT_INFO=0

# Timer
AUDIT_START_TIME=0

# ─────────────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────────────
print_banner() {
  [[ $OPT_NO_BANNER -eq 1 ]] && return
  echo -e "${C_CYAN}${C_BOLD}"
  cat << 'BANNER'
  ╦ ╦┌─┐┌┐ ╔═╗┌─┐┌─┐  ╔═╗┬ ┬┌┬┐┬┌┬┐
  ║║║├┤ ├┴┐╚═╗├┤ │    ╠═╣│ │ │││ │
  ╚╩╝└─┘└─┘╚═╝└─┘└─┘  ╩ ╩└─┘─┴┘┴ ┴
BANNER
  echo -e "${C_RESET}"
  printf "  Professional Web Security Audit Framework\n"
  printf "  Author: davidalvarezp      Version: 1.0.1\n"
  printf "  GH: github.com/davidalvarezp/websec-audit\n"
  echo -e "  ${C_DIM}─────────────────────────────────────────────────${C_RESET}"
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
#  HELP
# ─────────────────────────────────────────────────────────────────────────────
print_usage() {
  cat << USAGE
${C_BOLD}USAGE${C_RESET}
  $(basename "$0") -t <target> [options]

${C_BOLD}REQUIRED${C_RESET}
  -t, --target <url|ip>       Target URL or IP address
                              Examples: https://target.com | 192.168.1.1

${C_BOLD}OUTPUT${C_RESET}
  -o, --output <dir>          Output directory  (default: ./results_<domain>_<ts>)
  --format <fmt>              Report format: json | html | txt | all  (default: all)

${C_BOLD}SCAN OPTIONS${C_RESET}
  -T, --threads <n>           Concurrent threads        (default: 10)
  -p, --ports <profile>       Port profile: top-100 | top-1000 | full  (default: top-1000)
      --timeout <s>           Connection timeout in seconds  (default: 10)
      --depth <n>             Crawl depth                (default: 3)
      --proxy <url>           HTTP/HTTPS proxy  (e.g. http://127.0.0.1:8080)
      --aggressive            Aggressive mode — deeper scans, more noise
      --stealth               Stealth mode    — slower, lower detection footprint

${C_BOLD}MODULE CONTROL${C_RESET}
  --skip-recon                Skip reconnaissance (WHOIS, DNS, subdomains)
  --skip-portscan             Skip port scanning (nmap)
  --skip-fingerprint          Skip web fingerprinting
  --skip-ssl                  Skip SSL/TLS analysis
  --skip-headers              Skip HTTP security headers check
  --skip-dirbrute             Skip directory/file brute-forcing
  --skip-nikto                Skip Nikto web scanner
  --skip-sqli                 Skip SQL injection tests (sqlmap)
  --skip-xss                  Skip XSS tests (dalfox)
  --skip-cms                  Skip CMS detection and scanning
  --skip-cors                 Skip CORS misconfiguration tests
  --skip-redirect             Skip open redirect tests
  --skip-ssrf                 Skip SSRF tests
  --skip-subtakeover          Skip subdomain takeover checks
  --skip-nuclei               Skip Nuclei template scanning

${C_BOLD}WORDLISTS${C_RESET}
  --wl-dirs-small <file>      Small wordlist for directory brute-force
  --wl-dirs-big <file>        Large wordlist for directory brute-force
  --wl-dns <file>             Wordlist for DNS subdomain enumeration

${C_BOLD}MISC${C_RESET}
  -v, --verbose               Verbose output
      --no-color              Disable ANSI color output
      --no-banner             Suppress banner
  -h, --help                  Show this help message
  -V, --version               Show version information

${C_BOLD}EXAMPLES${C_RESET}
  $(basename "$0") -t https://target.com
  $(basename "$0") -t https://target.com --aggressive -T 20 -o /tmp/audit
  $(basename "$0") -t https://target.com --stealth --proxy http://127.0.0.1:8080
  $(basename "$0") -t https://target.com --skip-nikto --skip-sqli --format json
  $(basename "$0") -t https://target.com --ports full --depth 5 -v

USAGE
}

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING ENGINE
# ─────────────────────────────────────────────────────────────────────────────
_ts() { date '+%H:%M:%S'; }

log_info() {
  local msg="[$(_ts)] [INFO]     $1"
  [[ $OPT_NO_COLOR -eq 0 ]] && echo -e "${C_BLUE}${msg}${C_RESET}" || echo "$msg"
  echo "$msg" >> "$LOG_FILE"
}

log_ok() {
  local msg="[$(_ts)] [OK]       $1"
  [[ $OPT_NO_COLOR -eq 0 ]] && echo -e "${C_GREEN}${msg}${C_RESET}" || echo "$msg"
  echo "$msg" >> "$LOG_FILE"
}

log_warn() {
  local msg="[$(_ts)] [WARN]     $1"
  [[ $OPT_NO_COLOR -eq 0 ]] && echo -e "${C_YELLOW}${msg}${C_RESET}" || echo "$msg"
  echo "$msg" >> "$LOG_FILE"
}

log_error() {
  local msg="[$(_ts)] [ERROR]    $1"
  [[ $OPT_NO_COLOR -eq 0 ]] && echo -e "${C_RED}${msg}${C_RESET}" || echo "$msg"
  echo "$msg" >> "$LOG_FILE"
}

log_verbose() {
  [[ $OPT_VERBOSE -eq 0 ]] && return
  local msg="[$(_ts)] [VERBOSE]  $1"
  echo -e "${C_DIM}${msg}${C_RESET}"
  echo "$msg" >> "$LOG_FILE"
}

log_finding() {
  local severity="$1"; shift
  local msg="[$(_ts)] [${severity}]"
  # pad severity label
  case "${#severity}" in
    4) msg="[$(_ts)] [${severity}]     $1" ;;
    3) msg="[$(_ts)] [${severity}]      $1" ;;
    6) msg="[$(_ts)] [${severity}]   $1" ;;
    8) msg="[$(_ts)] [${severity}] $1" ;;
    *) msg="[$(_ts)] [${severity}]  $1" ;;
  esac

  local color="$C_RESET"
  case "$severity" in
    CRITICAL) color="${C_RED}${C_BOLD}" ;;
    HIGH)     color="${C_MAGENTA}${C_BOLD}" ;;
    MEDIUM)   color="$C_YELLOW" ;;
    LOW)      color="$C_CYAN" ;;
    INFO)     color="$C_DIM" ;;
  esac

  [[ $OPT_NO_COLOR -eq 0 ]] && echo -e "${color}${msg}${C_RESET}" || echo "$msg"
  echo "$msg" >> "$LOG_FILE"
}

log_section() {
  local title="$1"
  local line="══════════════════════════════════════════════════════════════"
  local inner="  ▸  ${title}"
  echo "" | tee -a "$LOG_FILE"
  if [[ $OPT_NO_COLOR -eq 0 ]]; then
    echo -e "${C_CYAN}${C_BOLD}${line}${C_RESET}" | tee -a "$LOG_FILE"
    echo -e "${C_CYAN}${C_BOLD}${inner}${C_RESET}" | tee -a "$LOG_FILE"
    echo -e "${C_CYAN}${C_BOLD}${line}${C_RESET}" | tee -a "$LOG_FILE"
  else
    echo "$line" | tee -a "$LOG_FILE"
    echo "$inner" | tee -a "$LOG_FILE"
    echo "$line" | tee -a "$LOG_FILE"
  fi
  echo "" | tee -a "$LOG_FILE"
}

log_subsection() {
  local title="$1"
  local line="  ────────────────────────────────────────"
  echo "" | tee -a "$LOG_FILE"
  if [[ $OPT_NO_COLOR -eq 0 ]]; then
    echo -e "${C_BLUE}${C_BOLD}${line}${C_RESET}" | tee -a "$LOG_FILE"
    echo -e "${C_BLUE}${C_BOLD}    ● ${title}${C_RESET}" | tee -a "$LOG_FILE"
    echo -e "${C_BLUE}${C_BOLD}${line}${C_RESET}" | tee -a "$LOG_FILE"
  else
    echo "$line" | tee -a "$LOG_FILE"
    echo "    [+] $title" | tee -a "$LOG_FILE"
    echo "$line" | tee -a "$LOG_FILE"
  fi
  echo "" | tee -a "$LOG_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
#  FINDING REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
# add_finding <SEVERITY> <MODULE> <TITLE> <DESCRIPTION> [EVIDENCE] [RECOMMENDATION]
add_finding() {
  local severity="${1:-INFO}"
  local module="${2:-UNKNOWN}"
  local title="${3:-Untitled finding}"
  local description="${4:-}"
  local evidence="${5:-}"
  local recommendation="${6:-}"

  # Increment counters
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
  case "$severity" in
    CRITICAL) COUNT_CRITICAL=$((COUNT_CRITICAL + 1)) ;;
    HIGH)     COUNT_HIGH=$((COUNT_HIGH + 1)) ;;
    MEDIUM)   COUNT_MEDIUM=$((COUNT_MEDIUM + 1)) ;;
    LOW)      COUNT_LOW=$((COUNT_LOW + 1)) ;;
    INFO)     COUNT_INFO=$((COUNT_INFO + 1)) ;;
  esac

  # Console output
  log_finding "$severity" "[${module}] ${title}"
  [[ -n "$description" ]]   && printf "             ↳ %s\n" "$description" | tee -a "$LOG_FILE"
  [[ -n "$evidence" ]]      && printf "             ↳ Evidence: %s\n" "$evidence" | tee -a "$LOG_FILE"
  [[ -n "$recommendation" ]] && printf "             ↳ Fix: %s\n" "$recommendation" | tee -a "$LOG_FILE"

  # Escape for JSON
  local j_title j_desc j_evid j_rec
  j_title=$(printf '%s' "$title"          | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g')
  j_desc=$(printf '%s'  "$description"   | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g')
  j_evid=$(printf '%s'  "$evidence"      | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g')
  j_rec=$(printf '%s'   "$recommendation" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g')

  printf '{"id":%d,"severity":"%s","module":"%s","title":"%s","description":"%s","evidence":"%s","recommendation":"%s","timestamp":"%s"}\n' \
    "$TOTAL_FINDINGS" "$severity" "$module" \
    "$j_title" "$j_desc" "$j_evid" "$j_rec" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >> "$FINDINGS_JSONL"
}

# ─────────────────────────────────────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
has_tool()    { command -v "$1" &>/dev/null; }
require_tool(){ has_tool "$1" && return 0; log_warn "Tool '$1' not found — skipping related checks."; return 1; }

strip_scheme()  { echo "$1" | sed -E 's|^https?://||' | cut -d'/' -f1; }
get_scheme()    { echo "$1" | grep -oP '^https?'; }
elapsed_secs()  { echo $(( $(date +%s) - AUDIT_START_TIME )); }
is_https()      { [[ "$TARGET_SCHEME" == "https" ]]; }

url_encode() {
  python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1" 2>/dev/null || \
  printf '%s' "$1" | od -An -tx1 | tr ' ' '%' | tr -d '\n'
}

resolve_ip() {
  host "$1" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}' || \
  dig +short A "$1" 2>/dev/null | head -1 || echo ""
}

# curl wrapper with audit-wide settings
_curl() {
  local args=(
    -sk
    --max-time "$OPT_TIMEOUT"
    -A "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
    --retry 2
    --retry-delay 1
  )
  [[ -n "$OPT_PROXY" ]] && args+=(-x "$OPT_PROXY")
  curl "${args[@]}" "$@"
}

# Run a command with timeout, capture output to file, return exit code
run_tool() {
  local label="$1" outfile="$2"; shift 2
  log_verbose "Running: $*"
  timeout "${OPT_TIMEOUT}s" "$@" > "$outfile" 2>&1
  local rc=$?
  [[ $rc -eq 0 ]] && log_verbose "Completed: $label" || log_verbose "Timeout/error ($rc): $label"
  return $rc
}

init_output_dir() {
  local safe_domain
  safe_domain=$(echo "$TARGET_DOMAIN" | tr '/:.' '_' | tr -cd '[:alnum:]_-')

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="${SCRIPT_DIR}/results_${safe_domain}_${TIMESTAMP}"
  fi

  mkdir -p "${OUTPUT_DIR}"/{logs,recon,portscan,ssl,headers,dirs,vulns,cms,misc,reports}

  LOG_FILE="${OUTPUT_DIR}/logs/audit_${TIMESTAMP}.log"
  REPORT_HTML="${OUTPUT_DIR}/reports/report_${TIMESTAMP}.html"
  REPORT_JSON="${OUTPUT_DIR}/reports/report_${TIMESTAMP}.json"
  REPORT_TXT="${OUTPUT_DIR}/reports/report_${TIMESTAMP}.txt"
  FINDINGS_JSONL="${OUTPUT_DIR}/logs/findings.jsonl"

  : > "$LOG_FILE"
  : > "$FINDINGS_JSONL"
}

# ─────────────────────────────────────────────────────────────────────────────
#  ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────
parse_args() {
  [[ $# -eq 0 ]] && { print_banner; print_usage; exit 1; }

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target)         TARGET="$2"; shift 2 ;;
      -o|--output)         OUTPUT_DIR="$2"; shift 2 ;;
      -T|--threads)        OPT_THREADS="$2"; shift 2 ;;
      -p|--ports)          OPT_PORTS="$2"; shift 2 ;;
      --format)            OPT_OUTPUT_ONLY="$2"; shift 2 ;;
      --timeout)           OPT_TIMEOUT="$2"; shift 2 ;;
      --depth)             OPT_DEPTH="$2"; shift 2 ;;
      --proxy)             OPT_PROXY="$2"; shift 2 ;;
      --aggressive)        OPT_AGGRESSIVE=1; shift ;;
      --stealth)           OPT_STEALTH=1; shift ;;
      --wl-dirs-small)     WL_DIRS_SMALL="$2"; shift 2 ;;
      --wl-dirs-big)       WL_DIRS_BIG="$2"; shift 2 ;;
      --wl-dns)            WL_DNS="$2"; shift 2 ;;
      --skip-recon)        MOD_RECON=0; shift ;;
      --skip-portscan)     MOD_PORTSCAN=0; shift ;;
      --skip-fingerprint)  MOD_FINGERPRINT=0; shift ;;
      --skip-ssl)          MOD_SSL=0; shift ;;
      --skip-headers)      MOD_HEADERS=0; shift ;;
      --skip-dirbrute)     MOD_DIRBRUTE=0; shift ;;
      --skip-nikto)        MOD_NIKTO=0; shift ;;
      --skip-sqli)         MOD_SQLI=0; shift ;;
      --skip-xss)          MOD_XSS=0; shift ;;
      --skip-cms)          MOD_CMS=0; shift ;;
      --skip-cors)         MOD_CORS=0; shift ;;
      --skip-redirect)     MOD_REDIRECT=0; shift ;;
      --skip-ssrf)         MOD_SSRF=0; shift ;;
      --skip-subtakeover)  MOD_SUBTAKEOVER=0; shift ;;
      --skip-nuclei)       MOD_NUCLEI=0; shift ;;
      -v|--verbose)        OPT_VERBOSE=1; shift ;;
      --no-color)          OPT_NO_COLOR=1; shift ;;
      --no-banner)         OPT_NO_BANNER=1; shift ;;
      -V|--version)
        echo "${TOOL_NAME} v${TOOL_VERSION} — ${TOOL_AUTHOR}"
        exit 0 ;;
      -h|--help)
        print_banner; print_usage; exit 0 ;;
      *)
        echo "Unknown option: $1" >&2; print_usage; exit 1 ;;
    esac
  done

  # Validate target
  [[ -z "$TARGET" ]] && { echo -e "${C_RED}[!] Error: --target is required.${C_RESET}"; exit 1; }

  # Normalise target
  [[ "$TARGET" =~ ^https?:// ]] || TARGET="https://${TARGET}"
  TARGET_SCHEME="$(get_scheme "$TARGET")"
  TARGET_DOMAIN="$(strip_scheme "$TARGET")"
  TARGET_IP="$(resolve_ip "$TARGET_DOMAIN")"

  # Validate conflicting modes
  if [[ $OPT_AGGRESSIVE -eq 1 && $OPT_STEALTH -eq 1 ]]; then
    echo -e "${C_YELLOW}[!] --aggressive and --stealth are mutually exclusive. Using --aggressive.${C_RESET}"
    OPT_STEALTH=0
  fi

  init_output_dir
}

# ─────────────────────────────────────────────────────────────────────────────
#  DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
module_check_deps() {
  log_section "DEPENDENCY CHECK"

  local required=(curl nmap)
  local optional=(
    nikto sqlmap whatweb wafw00f gobuster ffuf dirb
    wpscan droopescan sslscan "testssl.sh"
    dalfox subjack nuclei
    subfinder amass dnsrecon
    host whois dig jq python3
  )

  local missing_req=()

  for t in "${required[@]}"; do
    if has_tool "$t"; then
      log_ok "  [required] $t"
    else
      missing_req+=("$t")
      log_error "  [required] $t — NOT FOUND"
    fi
  done

  for t in "${optional[@]}"; do
    if has_tool "$t"; then
      log_ok "  [optional] $t"
    else
      log_warn "  [optional] $t — not found (reduced coverage)"
    fi
  done

  if [[ ${#missing_req[@]} -gt 0 ]]; then
    echo ""
    log_error "Missing required tools: ${missing_req[*]}"
    echo -e "  Install with: ${C_CYAN}sudo apt-get install -y ${missing_req[*]}${C_RESET}"
    exit 1
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 00 — TARGET INFORMATION
# ─────────────────────────────────────────────────────────────────────────────
module_target_info() {
  log_section "MODULE 00 — TARGET INFORMATION"
  log_info "Target URL    : $TARGET"
  log_info "Target Domain : $TARGET_DOMAIN"
  log_info "Resolved IP   : ${TARGET_IP:-<unresolved>}"
  log_info "Scheme        : $TARGET_SCHEME"
  log_info "Output Dir    : $OUTPUT_DIR"
  log_info "Timestamp     : $TIMESTAMP"
  log_info "Mode          : $( [[ $OPT_AGGRESSIVE -eq 1 ]] && echo AGGRESSIVE; \
                               [[ $OPT_STEALTH -eq 1 ]] && echo STEALTH; \
                               [[ $OPT_AGGRESSIVE -eq 0 && $OPT_STEALTH -eq 0 ]] && echo NORMAL )"
  [[ -n "$OPT_PROXY" ]] && log_info "Proxy         : $OPT_PROXY"

  add_finding "INFO" "INIT" "Audit started against ${TARGET}" \
    "Resolved IP: ${TARGET_IP:-<unresolved>} | Mode: $(
      [[ $OPT_AGGRESSIVE -eq 1 ]] && echo AGGRESSIVE || \
      [[ $OPT_STEALTH -eq 1 ]] && echo STEALTH || echo NORMAL)" "" ""
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 01 — RECONNAISSANCE
# ─────────────────────────────────────────────────────────────────────────────
module_recon() {
  [[ $MOD_RECON -eq 0 ]] && return
  log_section "MODULE 01 — RECONNAISSANCE"

  local recon_dir="${OUTPUT_DIR}/recon"

  # ── WHOIS ──────────────────────────────────────────────────────────────────
  log_subsection "WHOIS Lookup"
  if has_tool whois; then
    whois "$TARGET_DOMAIN" > "${recon_dir}/whois.txt" 2>&1 || true
    log_ok "WHOIS saved → ${recon_dir}/whois.txt"

    # Extract key registrant info
    local registrar expiry
    registrar=$(grep -iE "^registrar:" "${recon_dir}/whois.txt" | head -1 | sed 's/^[^:]*: *//' || true)
    expiry=$(grep -iE "expir" "${recon_dir}/whois.txt" | grep -oP '\d{4}-\d{2}-\d{2}' | head -1 || true)

    [[ -n "$registrar" ]] && log_info "Registrar : $registrar"
    [[ -n "$expiry" ]]    && log_info "Expiry    : $expiry"

    add_finding "INFO" "RECON" "WHOIS data collected for ${TARGET_DOMAIN}" \
      "Registrar: ${registrar:-N/A} | Expiry: ${expiry:-N/A}" "" ""
  else
    log_warn "whois not available"
  fi

  # ── DNS RECORDS ────────────────────────────────────────────────────────────
  log_subsection "DNS Record Enumeration"
  if has_tool dig; then
    local dns_file="${recon_dir}/dns_records.txt"
    {
      for rtype in A AAAA MX TXT NS SOA CNAME CAA; do
        printf "=== %s ===\n" "$rtype"
        dig +short "$rtype" "$TARGET_DOMAIN" 2>/dev/null || true
        echo ""
      done
      printf "=== DMARC ===\n"
      dig +short TXT "_dmarc.${TARGET_DOMAIN}" 2>/dev/null || true
      printf "\n=== SPF (raw TXT) ===\n"
      dig +short TXT "$TARGET_DOMAIN" 2>/dev/null | grep -i "v=spf" || true
    } > "$dns_file"

    log_ok "DNS records saved → $dns_file"

    # SPF / DMARC analysis
    local spf_record dmarc_record
    spf_record=$(dig +short TXT "$TARGET_DOMAIN" 2>/dev/null | grep -i "v=spf1" || true)
    dmarc_record=$(dig +short TXT "_dmarc.${TARGET_DOMAIN}" 2>/dev/null | head -1 || true)

    if [[ -z "$spf_record" ]]; then
      add_finding "MEDIUM" "RECON" "Missing SPF record on ${TARGET_DOMAIN}" \
        "No SPF TXT record found. Domain may be used for email spoofing." "" \
        "Add a TXT record: v=spf1 include:<provider> -all"
    else
      log_ok "SPF record present: ${spf_record:0:80}"
      # Check for +all (dangerous)
      if echo "$spf_record" | grep -q "+all"; then
        add_finding "HIGH" "RECON" "SPF record uses +all (permissive)" \
          "Any IP is allowed to send email on behalf of this domain." "$spf_record" \
          "Change +all to -all or ~all to restrict sending sources."
      fi
    fi

    if [[ -z "$dmarc_record" ]]; then
      add_finding "MEDIUM" "RECON" "Missing DMARC record on ${TARGET_DOMAIN}" \
        "No DMARC policy found. Email spoofing protection is absent." "" \
        "Add TXT record at _dmarc.${TARGET_DOMAIN}: v=DMARC1; p=reject; rua=mailto:dmarc@${TARGET_DOMAIN}"
    else
      log_ok "DMARC record present: ${dmarc_record:0:80}"
      if echo "$dmarc_record" | grep -qi "p=none"; then
        add_finding "LOW" "RECON" "DMARC policy set to p=none (monitoring only)" \
          "DMARC is in monitor mode and does not enforce rejection." "$dmarc_record" \
          "Upgrade DMARC policy to p=quarantine or p=reject."
      fi
    fi
  fi

  # ── DNS ZONE TRANSFER ──────────────────────────────────────────────────────
  log_subsection "DNS Zone Transfer (AXFR)"
  local ns_servers
  ns_servers=$(dig +short NS "$TARGET_DOMAIN" 2>/dev/null | head -5 || true)
  local axfr_file="${recon_dir}/axfr.txt"
  local axfr_found=0

  if [[ -n "$ns_servers" ]]; then
    while IFS= read -r ns; do
      ns="${ns%.}"
      log_verbose "Attempting AXFR from $ns"
      if dig AXFR "$TARGET_DOMAIN" "@${ns}" 2>/dev/null | \
         grep -v "^;;" | grep -v "^$" > "${axfr_file}.tmp" 2>&1; then
        local lines; lines=$(wc -l < "${axfr_file}.tmp" 2>/dev/null || echo 0)
        if [[ "$lines" -gt 5 ]]; then
          cat "${axfr_file}.tmp" >> "$axfr_file"
          axfr_found=1
          add_finding "CRITICAL" "RECON" "DNS Zone Transfer (AXFR) is permitted" \
            "Name server $ns allows AXFR — full DNS zone disclosed." \
            "$(head -5 "$axfr_file")" \
            "Restrict AXFR to authorized secondary name servers only."
        fi
      fi
      rm -f "${axfr_file}.tmp"
    done <<< "$ns_servers"
    [[ $axfr_found -eq 0 ]] && log_ok "AXFR not permitted (correct)"
  fi

  # ── SUBDOMAIN ENUMERATION ──────────────────────────────────────────────────
  log_subsection "Subdomain Enumeration"
  local subs_file="${recon_dir}/subdomains.txt"
  : > "$subs_file"

  if has_tool subfinder; then
    log_info "Running subfinder..."
    timeout 120s subfinder -d "$TARGET_DOMAIN" -silent \
      -o "${recon_dir}/subfinder.txt" 2>/dev/null || true
    [[ -f "${recon_dir}/subfinder.txt" ]] && \
      cat "${recon_dir}/subfinder.txt" >> "$subs_file"
  fi

  if has_tool amass; then
    log_info "Running amass (passive)..."
    timeout 180s amass enum -passive -d "$TARGET_DOMAIN" \
      -o "${recon_dir}/amass.txt" 2>/dev/null || true
    [[ -f "${recon_dir}/amass.txt" ]] && \
      cat "${recon_dir}/amass.txt" >> "$subs_file"
  fi

  if has_tool dnsrecon; then
    log_info "Running dnsrecon..."
    timeout 120s dnsrecon -d "$TARGET_DOMAIN" -t std \
      -j "${recon_dir}/dnsrecon.json" 2>/dev/null || true
  fi

  # Brute-force fallback if no enumeration tool found
  if ! has_tool subfinder && ! has_tool amass && [[ -f "$WL_DNS" ]]; then
    log_info "Brute-forcing subdomains via DNS (wordlist: $WL_DNS)..."
    local bf_count=0
    while IFS= read -r word && [[ $bf_count -lt 500 ]]; do
      [[ -z "$word" || "$word" == \#* ]] && continue
      local fqdn="${word}.${TARGET_DOMAIN}"
      if dig +short A "$fqdn" 2>/dev/null | grep -qP '^\d+\.\d+\.\d+\.\d+'; then
        echo "$fqdn" >> "$subs_file"
        log_verbose "Found: $fqdn"
      fi
      bf_count=$((bf_count + 1))
    done < "$WL_DNS"
  fi

  # Deduplicate
  if [[ -s "$subs_file" ]]; then
    sort -u "$subs_file" -o "$subs_file"
    local sub_count; sub_count=$(wc -l < "$subs_file")
    log_ok "Discovered $sub_count unique subdomains → $subs_file"
    add_finding "INFO" "RECON" "Subdomain enumeration: $sub_count hosts discovered" \
      "$(head -10 "$subs_file" | tr '\n' ' ')" "$subs_file" ""
  else
    log_info "No additional subdomains discovered"
  fi

  # ── GOOGLE DORKS (generated, not executed) ─────────────────────────────────
  log_subsection "Google Dork List"
  local dorks_file="${recon_dir}/google_dorks.txt"
  cat > "$dorks_file" << DORKS
# Google Dorks — ${TARGET_DOMAIN}
# Generated by ${TOOL_NAME} v${TOOL_VERSION} on ${DATE_HUMAN}
# Run these manually in Google / Bing / DuckDuckGo

## Information disclosure
site:${TARGET_DOMAIN}
site:${TARGET_DOMAIN} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:xlsx OR filetype:csv
site:${TARGET_DOMAIN} ext:php inurl:id=
site:${TARGET_DOMAIN} ext:asp OR ext:aspx
site:${TARGET_DOMAIN} "index of /"
site:${TARGET_DOMAIN} "index of /admin"
site:${TARGET_DOMAIN} "index of /backup"
site:${TARGET_DOMAIN} intext:"sql syntax" OR intext:"mysql_fetch_array" OR intext:"ORA-"

## Admin/login panels
site:${TARGET_DOMAIN} inurl:admin OR inurl:administrator
site:${TARGET_DOMAIN} inurl:login OR inurl:signin OR inurl:auth
site:${TARGET_DOMAIN} inurl:phpmyadmin OR inurl:adminer
site:${TARGET_DOMAIN} inurl:wp-admin OR inurl:wp-login.php

## Credentials & secrets
site:${TARGET_DOMAIN} intext:"password" filetype:log
site:${TARGET_DOMAIN} intext:"DB_PASSWORD" OR intext:"MYSQL_ROOT_PASSWORD"
site:${TARGET_DOMAIN} intext:"api_key" OR intext:"api_secret" OR intext:"client_secret"
"${TARGET_DOMAIN}" site:pastebin.com
"${TARGET_DOMAIN}" site:github.com password OR secret OR token OR credential

## Config files
site:${TARGET_DOMAIN} filetype:env OR filetype:conf OR filetype:cfg OR filetype:ini
site:${TARGET_DOMAIN} filetype:bak OR filetype:backup OR filetype:old OR filetype:orig

## Exposed panels & services
site:${TARGET_DOMAIN} inurl:swagger OR inurl:api-docs OR inurl:openapi
site:${TARGET_DOMAIN} inurl:console OR inurl:debug OR inurl:phpinfo
DORKS
  log_ok "Google Dorks generated → $dorks_file"
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 02 — PORT SCANNING
# ─────────────────────────────────────────────────────────────────────────────
module_portscan() {
  [[ $MOD_PORTSCAN -eq 0 ]] && return
  log_section "MODULE 02 — PORT SCANNING"
  require_tool nmap || return

  local scan_target="${TARGET_IP:-$TARGET_DOMAIN}"
  local nmap_base="${OUTPUT_DIR}/portscan/nmap"

  # Build nmap flags
  local ports_arg
  case "$OPT_PORTS" in
    top-100) ports_arg="--top-ports 100" ;;
    full)    ports_arg="-p-" ;;
    *)       ports_arg="--top-ports 1000" ;;
  esac

  local nmap_flags="-sV -sC --open"

  if [[ $OPT_AGGRESSIVE -eq 1 ]]; then
    nmap_flags="$nmap_flags -A -O --script=vuln,auth,default,discovery"
  elif [[ $OPT_STEALTH -eq 1 ]]; then
    nmap_flags="$nmap_flags -sS -T2 -f --data-length 32 --randomize-hosts"
  else
    nmap_flags="$nmap_flags -T4"
  fi

  [[ -n "$OPT_PROXY" ]] && nmap_flags="$nmap_flags --proxies $OPT_PROXY"

  log_info "Target : $scan_target"
  log_info "Profile: $OPT_PORTS"
  log_info "Flags  : $nmap_flags"
  echo ""

  # shellcheck disable=SC2086
  nmap $nmap_flags $ports_arg \
    -oN "${nmap_base}.txt" \
    -oX "${nmap_base}.xml" \
    -oG "${nmap_base}.gnmap" \
    "$scan_target" 2>&1 | tee -a "$LOG_FILE" || true

  [[ ! -f "${nmap_base}.txt" ]] && { log_error "nmap failed to produce output"; return; }

  log_ok "nmap completed → ${nmap_base}.txt"

  # Parse open ports and flag dangerous ones
  local open_ports
  open_ports=$(grep -P "^\d+/tcp\s+open" "${nmap_base}.txt" 2>/dev/null || true)

  if [[ -z "$open_ports" ]]; then
    log_info "No open ports found in scan range"
    return
  fi

  log_info "Open ports:"
  echo "$open_ports" | tee -a "$LOG_FILE"
  echo ""

  add_finding "INFO" "PORTSCAN" "Port scan results for $scan_target" \
    "$(echo "$open_ports" | wc -l) open port(s) found." \
    "$(echo "$open_ports" | head -5 | tr '\n' ' ')" ""

  # Risk-based analysis of open ports
  declare -A port_risks=(
    [21]="CRITICAL|FTP (port 21) — plaintext credentials|Close FTP; use SFTP (port 22) instead."
    [23]="CRITICAL|Telnet (port 23) — unencrypted remote shell|Disable Telnet; use SSH."
    [25]="MEDIUM|SMTP (port 25) exposed publicly|Restrict if not a mail relay."
    [110]="MEDIUM|POP3 (port 110) — plaintext email retrieval|Use POP3S (port 995)."
    [143]="MEDIUM|IMAP (port 143) — plaintext email access|Use IMAPS (port 993)."
    [389]="MEDIUM|LDAP (port 389) — unencrypted directory|Use LDAPS (port 636)."
    [445]="HIGH|SMB (port 445) exposed — risk of EternalBlue/ransomware|Block SMB at firewall; do not expose to internet."
    [1433]="HIGH|MSSQL (port 1433) exposed — database accessible|Block with firewall; allow local access only."
    [1521]="HIGH|Oracle DB (port 1521) exposed|Block with firewall; allow local access only."
    [2375]="CRITICAL|Docker API (port 2375) — unauthenticated exposure|Enable TLS on Docker socket; never expose to internet."
    [2376]="MEDIUM|Docker TLS API (port 2376) exposed|Restrict to authorized hosts only."
    [3306]="HIGH|MySQL (port 3306) exposed to internet|Block with firewall; bind to 127.0.0.1."
    [3389]="HIGH|RDP (port 3389) exposed — brute-force target|Use VPN gateway; disable direct RDP access."
    [5432]="HIGH|PostgreSQL (port 5432) exposed|Block with firewall; bind to 127.0.0.1."
    [5900]="HIGH|VNC (port 5900) exposed|Use VPN; require strong authentication."
    [6379]="HIGH|Redis (port 6379) — often unauthenticated|Require auth; bind to 127.0.0.1."
    [8080]="LOW|HTTP alternate port (8080) open|Verify intentional exposure; check for admin panels."
    [8443]="LOW|HTTPS alternate port (8443) open|Verify intentional exposure."
    [9200]="HIGH|Elasticsearch (port 9200) — often unauthenticated|Enable auth (X-Pack); do not expose publicly."
    [9300]="HIGH|Elasticsearch transport (port 9300) exposed|Block with firewall."
    [11211]="HIGH|Memcached (port 11211) — no auth by default|Block with firewall; bind to localhost."
    [27017]="HIGH|MongoDB (port 27017) — often unauthenticated|Enable auth; bind to localhost."
  )

  echo "$open_ports" | while IFS= read -r line; do
    local port; port=$(echo "$line" | awk '{print $1}' | cut -d/ -f1)
    local risk="${port_risks[$port]:-}"
    if [[ -n "$risk" ]]; then
      IFS='|' read -r sev title rec <<< "$risk"
      add_finding "$sev" "PORTSCAN" "$title" \
        "Service exposed: $line" "$line" "$rec"
    fi
  done
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 03 — WEB FINGERPRINTING
# ─────────────────────────────────────────────────────────────────────────────
module_fingerprint() {
  [[ $MOD_FINGERPRINT -eq 0 ]] && return
  log_section "MODULE 03 — WEB FINGERPRINTING"

  local recon_dir="${OUTPUT_DIR}/recon"

  # ── WhatWeb ────────────────────────────────────────────────────────────────
  log_subsection "Technology Detection"
  if has_tool whatweb; then
    local aggr_level=1
    [[ $OPT_AGGRESSIVE -eq 1 ]] && aggr_level=3

    whatweb -a $aggr_level "$TARGET" \
      --log-json="${recon_dir}/whatweb.json" \
      --log-brief="${recon_dir}/whatweb_brief.txt" \
      2>/dev/null | tee -a "$LOG_FILE" || true

    log_ok "WhatWeb → ${recon_dir}/whatweb.json"
  else
    # Fallback: header-based detection
    log_info "whatweb not available — performing header-based detection"
    local resp
    resp=$(_curl -I "$TARGET" 2>/dev/null || true)
    echo "$resp" > "${recon_dir}/basic_headers_raw.txt"

    local techs=("WordPress" "Drupal" "Joomla" "Magento" "Laravel" "Django"
                 "Rails" "Express" "nginx" "Apache" "IIS" "LiteSpeed"
                 "PHP" "ASP.NET" "ColdFusion" "Tomcat" "Jetty" "Cloudflare")
    for tech in "${techs[@]}"; do
      if echo "$resp" | grep -qi "$tech"; then
        log_info "Technology detected: $tech"
        add_finding "INFO" "FINGERPRINT" "Technology detected: $tech" \
          "Identified via response headers." "" ""
      fi
    done
  fi

  # ── WAF Detection ──────────────────────────────────────────────────────────
  log_subsection "WAF Detection"
  if has_tool wafw00f; then
    wafw00f "$TARGET" 2>/dev/null | tee -a "$LOG_FILE" | \
      tee "${recon_dir}/waf_detection.txt" > /dev/null || true

    if grep -qi "is behind" "${recon_dir}/waf_detection.txt" 2>/dev/null; then
      local waf_name
      waf_name=$(grep -i "is behind" "${recon_dir}/waf_detection.txt" | head -1 | sed 's/.*behind //')
      log_info "WAF detected: $waf_name"
      add_finding "INFO" "FINGERPRINT" "WAF detected: $waf_name" \
        "The target appears to be protected by a Web Application Firewall." "$waf_name" ""
    else
      add_finding "LOW" "FINGERPRINT" "No WAF detected" \
        "No known WAF signatures were identified in server responses." "" \
        "Consider deploying a WAF (Cloudflare, ModSecurity, AWS WAF, etc.)"
    fi
  else
    log_warn "wafw00f not available — WAF detection skipped"
  fi

  # ── Version-leaking headers ────────────────────────────────────────────────
  log_subsection "Server Version Disclosure"
  local headers
  headers=$(_curl -I "$TARGET" 2>/dev/null || true)
  echo "$headers" > "${OUTPUT_DIR}/headers/initial_response.txt"

  local leaking_headers=("Server" "X-Powered-By" "X-AspNet-Version"
                          "X-AspNetMvc-Version" "X-Generator" "X-Drupal-Cache"
                          "X-WordPress-Cache" "Via")
  for h in "${leaking_headers[@]}"; do
    local val
    val=$(echo "$headers" | grep -i "^${h}:" | head -1 || true)
    if [[ -n "$val" ]]; then
      log_warn "Version-leaking header: $val"
      add_finding "LOW" "FINGERPRINT" "Version disclosure via '$h' header" \
        "The server reveals technology/version info in response headers." \
        "$val" \
        "Remove or neutralise the '$h' header in your web server configuration."
    fi
  done
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 04 — SSL/TLS ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
module_ssl() {
  [[ $MOD_SSL -eq 0 ]] && return
  if ! is_https; then
    log_info "[SSL] Target is not HTTPS — skipping SSL/TLS analysis"
    add_finding "HIGH" "SSL" "Target is served over HTTP (no TLS)" \
      "All traffic between client and server is transmitted in plaintext." "" \
      "Deploy a TLS certificate (Let's Encrypt is free). Redirect all HTTP to HTTPS."
    return
  fi

  log_section "MODULE 04 — SSL/TLS ANALYSIS"
  local ssl_dir="${OUTPUT_DIR}/ssl"

  # ── testssl.sh (primary) ───────────────────────────────────────────────────
  if has_tool "testssl.sh"; then
    log_info "Running testssl.sh (full analysis)..."

    timeout 600s testssl.sh \
      --quiet \
      --severity LOW \
      --jsonfile "${ssl_dir}/testssl.json" \
      --logfile  "${ssl_dir}/testssl.log" \
      "$TARGET_DOMAIN" 2>/dev/null || true

    log_ok "testssl.sh → ${ssl_dir}/testssl.json"

    # Parse findings from JSON
    if has_tool jq && [[ -f "${ssl_dir}/testssl.json" ]]; then
      while IFS= read -r entry; do
        local sev finding_id finding_text
        sev=$(echo "$entry"         | jq -r '.severity // ""' 2>/dev/null)
        finding_id=$(echo "$entry"  | jq -r '.id // ""' 2>/dev/null)
        finding_text=$(echo "$entry"| jq -r '.finding // ""' 2>/dev/null)

        [[ -z "$sev" || -z "$finding_id" ]] && continue

        case "$sev" in
          CRITICAL|HIGH|MEDIUM|LOW)
            add_finding "$sev" "SSL" "testssl: [${finding_id}] ${finding_text:0:120}" \
              "" "" "Refer to testssl documentation for ${finding_id}" ;;
        esac
      done < <(jq -c '.[] | select(.severity != "OK" and .severity != "INFO" and .severity != "DEBUG" and .severity != "")' \
                "${ssl_dir}/testssl.json" 2>/dev/null || true)
    fi

  # ── sslscan (secondary) ────────────────────────────────────────────────────
  elif has_tool sslscan; then
    log_info "Running sslscan..."
    sslscan --no-colour "${TARGET_DOMAIN}:443" > "${ssl_dir}/sslscan.txt" 2>&1 || true
    log_ok "sslscan → ${ssl_dir}/sslscan.txt"

    local scan_output
    scan_output=$(cat "${ssl_dir}/sslscan.txt")

    # Deprecated protocols
    for proto in "SSLv2" "SSLv3" "TLSv1.0" "TLSv1.1"; do
      if echo "$scan_output" | grep -qP "^\s*${proto}\s+enabled"; then
        add_finding "HIGH" "SSL" "Insecure protocol enabled: $proto" \
          "$proto is deprecated and vulnerable to known attacks." "$proto" \
          "Disable $proto. Allow TLS 1.2 and TLS 1.3 only."
      fi
    done

    # Weak cipher suites
    if echo "$scan_output" | grep -qiE "RC4|NULL|EXPORT|anon|DES\b|3DES"; then
      add_finding "HIGH" "SSL" "Weak cipher suites detected" \
        "RC4, NULL, EXPORT or DES ciphers are enabled." \
        "$(echo "$scan_output" | grep -iE 'RC4|NULL|EXPORT|anon|DES' | head -3)" \
        "Disable weak ciphers. Prefer ECDHE+AESGCM and ChaCha20-Poly1305."
    fi

    # Self-signed or untrusted
    if echo "$scan_output" | grep -qi "self-signed\|not trusted"; then
      add_finding "HIGH" "SSL" "Untrusted or self-signed certificate" \
        "The certificate is not issued by a trusted CA." "" \
        "Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)"
    fi

  # ── openssl fallback ───────────────────────────────────────────────────────
  else
    log_info "testssl.sh/sslscan not available — using openssl fallback"
    local openssl_out="${ssl_dir}/openssl_info.txt"

    {
      echo "=== Certificate Info ==="
      echo | timeout "$OPT_TIMEOUT" openssl s_client \
        -connect "${TARGET_DOMAIN}:443" \
        -servername "$TARGET_DOMAIN" 2>/dev/null \
      | openssl x509 -noout -text 2>/dev/null || true

      echo ""
      echo "=== Protocol Support ==="
      for proto in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
        if echo | timeout 5s openssl s_client \
           -"$proto" -connect "${TARGET_DOMAIN}:443" \
           -servername "$TARGET_DOMAIN" 2>/dev/null \
           | grep -q "CONNECTED"; then
          echo "${proto}: ENABLED"
        else
          echo "${proto}: disabled"
        fi
      done
    } > "$openssl_out" 2>&1

    # Flag insecure protocols found
    grep "ENABLED" "$openssl_out" 2>/dev/null | while IFS= read -r line; do
      local proto; proto=$(echo "$line" | cut -d: -f1)
      case "$proto" in
        ssl2|ssl3|tls1|tls1_1)
          add_finding "HIGH" "SSL" "Insecure protocol enabled: $proto" \
            "$proto is deprecated and vulnerable." "$proto" \
            "Disable $proto. Use TLS 1.2+ only." ;;
      esac
    done

    log_ok "OpenSSL analysis → $openssl_out"
  fi

  # ── Certificate expiry check ───────────────────────────────────────────────
  log_subsection "Certificate Expiry Check"
  local expiry_raw
  expiry_raw=$(echo | timeout "$OPT_TIMEOUT" openssl s_client \
    -connect "${TARGET_DOMAIN}:443" \
    -servername "$TARGET_DOMAIN" 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null \
    | cut -d= -f2 || true)

  if [[ -n "$expiry_raw" ]]; then
    local exp_epoch now_epoch days_left
    exp_epoch=$(date -d "$expiry_raw" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    days_left=$(( (exp_epoch - now_epoch) / 86400 ))

    if [[ "$days_left" -lt 0 ]]; then
      add_finding "CRITICAL" "SSL" "Certificate has EXPIRED" \
        "Certificate expired $((days_left * -1)) days ago." "$expiry_raw" \
        "Renew the TLS certificate immediately."
    elif [[ "$days_left" -lt 14 ]]; then
      add_finding "CRITICAL" "SSL" "Certificate expires in $days_left days" \
        "Imminent certificate expiry will cause service disruption." "$expiry_raw" \
        "Renew the certificate immediately."
    elif [[ "$days_left" -lt 30 ]]; then
      add_finding "HIGH" "SSL" "Certificate expires in $days_left days" \
        "Certificate is close to expiry." "$expiry_raw" \
        "Renew the certificate urgently."
    elif [[ "$days_left" -lt 90 ]]; then
      add_finding "MEDIUM" "SSL" "Certificate expires in $days_left days" \
        "" "$expiry_raw" "Plan certificate renewal."
    else
      log_ok "Certificate valid — $days_left days remaining (${expiry_raw})"
    fi
  fi

  # ── HSTS ──────────────────────────────────────────────────────────────────
  log_subsection "HSTS (HTTP Strict Transport Security)"
  local hsts_header
  hsts_header=$(_curl -I "$TARGET" 2>/dev/null | grep -i "^strict-transport-security:" || true)

  if [[ -z "$hsts_header" ]]; then
    add_finding "MEDIUM" "SSL" "HSTS header not configured" \
      "Strict-Transport-Security is absent — browsers may access the site over HTTP." "" \
      "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
  else
    local maxage
    maxage=$(echo "$hsts_header" | grep -oP 'max-age=\K\d+' || echo 0)
    if [[ "$maxage" -lt 15552000 ]]; then
      add_finding "LOW" "SSL" "HSTS max-age is too short ($maxage seconds)" \
        "Recommended minimum is 6 months (15552000 seconds)." "$hsts_header" \
        "Increase HSTS max-age to at least 15552000."
    else
      log_ok "HSTS configured: $hsts_header"
    fi
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 05 — HTTP SECURITY HEADERS
# ─────────────────────────────────────────────────────────────────────────────
module_headers() {
  [[ $MOD_HEADERS -eq 0 ]] && return
  log_section "MODULE 05 — HTTP SECURITY HEADERS"

  local hdrs_dir="${OUTPUT_DIR}/headers"
  local hdr_file="${hdrs_dir}/response_headers.txt"

  _curl -I -L --max-redirs 5 "$TARGET" 2>/dev/null > "$hdr_file" || true
  log_info "Response headers captured → $hdr_file"
  cat "$hdr_file" | tee -a "$LOG_FILE"
  echo ""

  # ── Security headers that MUST be present ──────────────────────────────────
  declare -A REQUIRED_HEADERS=(
    ["content-security-policy"]="MEDIUM|Content-Security-Policy (CSP) missing|Implement a strict CSP to mitigate XSS and data injection attacks."
    ["x-frame-options"]="MEDIUM|X-Frame-Options missing — clickjacking risk|Add: X-Frame-Options: SAMEORIGIN"
    ["x-content-type-options"]="LOW|X-Content-Type-Options missing — MIME sniffing risk|Add: X-Content-Type-Options: nosniff"
    ["referrer-policy"]="LOW|Referrer-Policy missing|Add: Referrer-Policy: strict-origin-when-cross-origin"
    ["permissions-policy"]="LOW|Permissions-Policy missing|Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    ["cross-origin-opener-policy"]="LOW|Cross-Origin-Opener-Policy (COOP) missing|Add: Cross-Origin-Opener-Policy: same-origin"
    ["cross-origin-resource-policy"]="LOW|Cross-Origin-Resource-Policy (CORP) missing|Add: Cross-Origin-Resource-Policy: same-origin"
  )

  for header in "${!REQUIRED_HEADERS[@]}"; do
    IFS='|' read -r sev title rec <<< "${REQUIRED_HEADERS[$header]}"
    if ! grep -qi "^${header}:" "$hdr_file" 2>/dev/null; then
      add_finding "$sev" "HEADERS" "$title" \
        "The response is missing the '${header}' security header." "" "$rec"
    else
      log_ok "Present: $(grep -i "^${header}:" "$hdr_file" | head -1)"

      # CSP audit — flag dangerous directives
      if [[ "$header" == "content-security-policy" ]]; then
        local csp_val
        csp_val=$(grep -i "^content-security-policy:" "$hdr_file" | head -1)
        if echo "$csp_val" | grep -qi "unsafe-inline\|unsafe-eval"; then
          add_finding "MEDIUM" "HEADERS" "CSP contains 'unsafe-inline' or 'unsafe-eval'" \
            "Overly permissive CSP directive undermines XSS protection." "$csp_val" \
            "Remove 'unsafe-inline'/'unsafe-eval'. Use nonces or hashes instead."
        fi
        if echo "$csp_val" | grep -qi "default-src \*\|script-src \*"; then
          add_finding "HIGH" "HEADERS" "CSP uses wildcard (*) for script-src or default-src" \
            "A wildcard CSP directive provides no protection against XSS." "$csp_val" \
            "Specify explicit allowed origins in Content-Security-Policy."
        fi
      fi
    fi
  done

  # ── Headers that should NOT be present ─────────────────────────────────────
  log_subsection "Sensitive Header Exposure"
  local forbidden_headers=("Server" "X-Powered-By" "X-AspNet-Version"
                            "X-AspNetMvc-Version" "X-Generator" "X-CF-Powered-By")
  for h in "${forbidden_headers[@]}"; do
    local val; val=$(grep -i "^${h}:" "$hdr_file" 2>/dev/null | head -1 || true)
    if [[ -n "$val" ]]; then
      add_finding "LOW" "HEADERS" "Informative header exposed: $h" \
        "Server reveals technology details via '$h' header." "$val" \
        "Remove or anonymise the '$h' header in your server configuration."
    fi
  done

  # ── Cookie flags ────────────────────────────────────────────────────────────
  log_subsection "Cookie Security Flags"
  local cookies
  cookies=$(_curl -I "$TARGET" 2>/dev/null | grep -i "^set-cookie:" || true)

  if [[ -n "$cookies" ]]; then
    echo "$cookies" | while IFS= read -r cookie; do
      local cookie_name; cookie_name=$(echo "$cookie" | grep -oP 'Set-Cookie:\s*\K[^=]+' || echo "?")

      if ! echo "$cookie" | grep -qi "httponly"; then
        add_finding "MEDIUM" "HEADERS" "Cookie '$cookie_name' missing HttpOnly flag" \
          "Cookie is accessible via JavaScript — XSS can steal session tokens." \
          "$cookie" "Add 'HttpOnly' flag to all session cookies."
      fi
      if ! echo "$cookie" | grep -qi "secure"; then
        add_finding "MEDIUM" "HEADERS" "Cookie '$cookie_name' missing Secure flag" \
          "Cookie may be transmitted over unencrypted HTTP connections." \
          "$cookie" "Add 'Secure' flag to all session cookies."
      fi
      if ! echo "$cookie" | grep -qi "samesite"; then
        add_finding "LOW" "HEADERS" "Cookie '$cookie_name' missing SameSite attribute" \
          "Absence of SameSite exposes the cookie to CSRF risks." \
          "$cookie" "Add 'SameSite=Strict' or 'SameSite=Lax' to session cookies."
      fi
      if echo "$cookie" | grep -qiP "samesite=none(?!.*secure)" ; then
        add_finding "MEDIUM" "HEADERS" "Cookie '$cookie_name' uses SameSite=None without Secure" \
          "SameSite=None requires the Secure flag." \
          "$cookie" "Add 'Secure' flag when using 'SameSite=None'."
      fi
    done
  else
    log_info "No Set-Cookie headers found in initial response"
  fi

  # ── HTTP → HTTPS redirect ───────────────────────────────────────────────────
  log_subsection "HTTP to HTTPS Redirect"
  local http_url="${TARGET/https:\/\//http://}"
  local redirect_code
  redirect_code=$(_curl -sI -o /dev/null -w "%{http_code}" \
    --max-redirs 0 "$http_url" 2>/dev/null || echo "000")

  if echo "$redirect_code" | grep -qP "^30[1-8]$"; then
    log_ok "HTTP → HTTPS redirect in place (HTTP $redirect_code)"
  else
    add_finding "MEDIUM" "HEADERS" "HTTP does not redirect to HTTPS (HTTP $redirect_code)" \
      "Requests over HTTP are not automatically upgraded to HTTPS." "$http_url → $redirect_code" \
      "Configure a permanent 301 redirect from HTTP to HTTPS."
  fi

  # ── Cache-Control on sensitive pages ───────────────────────────────────────
  local cache_ctrl
  cache_ctrl=$(_curl -I "$TARGET" 2>/dev/null | grep -i "^cache-control:" || true)
  if [[ -z "$cache_ctrl" ]]; then
    add_finding "LOW" "HEADERS" "Cache-Control header missing" \
      "Without Cache-Control, sensitive pages may be cached by intermediaries." "" \
      "Add: Cache-Control: no-store, no-cache on authenticated/sensitive pages."
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 06 — DIRECTORY & FILE BRUTE-FORCING
# ─────────────────────────────────────────────────────────────────────────────
module_dirbrute() {
  [[ $MOD_DIRBRUTE -eq 0 ]] && return
  log_section "MODULE 06 — DIRECTORY & FILE ENUMERATION"

  local dirs_dir="${OUTPUT_DIR}/dirs"
  local wordlist="$WL_DIRS_SMALL"
  [[ $OPT_AGGRESSIVE -eq 1 ]] && wordlist="$WL_DIRS_BIG"

  if [[ ! -f "$wordlist" ]]; then
    log_warn "Wordlist not found: $wordlist"
    log_warn "Install wordlists: sudo apt-get install wordlists"
    log_info "Skipping brute-force, running sensitive file checks only"
  else
    # ── gobuster ──────────────────────────────────────────────────────────────
    if has_tool gobuster; then
      log_subsection "gobuster (directory)"
      gobuster dir \
        -u "$TARGET" \
        -w "$wordlist" \
        -t "$OPT_THREADS" \
        --timeout "${OPT_TIMEOUT}s" \
        -q \
        -o "${dirs_dir}/gobuster_dirs.txt" \
        $( [[ -n "$OPT_PROXY" ]] && printf -- "--proxy %s" "$OPT_PROXY" ) \
        2>/dev/null || true

      if [[ -f "${dirs_dir}/gobuster_dirs.txt" ]]; then
        local found; found=$(wc -l < "${dirs_dir}/gobuster_dirs.txt")
        log_ok "$found paths found → ${dirs_dir}/gobuster_dirs.txt"
        [[ $found -gt 0 ]] && add_finding "INFO" "DIRBRUTE" \
          "$found directories/files discovered" \
          "$(head -10 "${dirs_dir}/gobuster_dirs.txt" | tr '\n' ' ')" \
          "${dirs_dir}/gobuster_dirs.txt" ""
      fi

      # DNS subdomain brute-force
      if [[ -f "$WL_DNS" ]]; then
        log_subsection "gobuster (DNS)"
        gobuster dns \
          --do "$TARGET_DOMAIN" \
          -w "$WL_DNS" \
          -t "$OPT_THREADS" \
          -q \
          -o "${dirs_dir}/gobuster_dns.txt" \
          2>/dev/null || true
      fi

    # ── ffuf fallback ──────────────────────────────────────────────────────────
    elif has_tool ffuf; then
      log_subsection "ffuf"
      ffuf -u "${TARGET}/FUZZ" \
           -w "$wordlist" \
           -t "$OPT_THREADS" \
           -timeout "$OPT_TIMEOUT" \
           -mc 200,201,204,301,302,307,401,403 \
           -of json \
           -o "${dirs_dir}/ffuf_results.json" \
           -s 2>/dev/null || true
      log_ok "ffuf → ${dirs_dir}/ffuf_results.json"

    # ── dirb fallback ──────────────────────────────────────────────────────────
    elif has_tool dirb; then
      log_subsection "dirb"
      dirb "$TARGET" "$wordlist" -S -r \
        -o "${dirs_dir}/dirb_results.txt" 2>/dev/null || true
      log_ok "dirb → ${dirs_dir}/dirb_results.txt"

    else
      log_warn "No directory brute-force tool found (gobuster/ffuf/dirb)"
    fi
  fi

  # ── Sensitive file/path probing ────────────────────────────────────────────
  log_subsection "Sensitive File Probing"
  declare -A SENSITIVE_PATHS=(
    # Format: PATH="SEVERITY|short description"
    ["/.git/HEAD"]="CRITICAL|Git repository exposed — source code may be accessible"
    ["/.git/config"]="CRITICAL|Git config file exposed"
    ["/.env"]="CRITICAL|Environment file exposed — may contain credentials"
    ["/.env.local"]="CRITICAL|Local env file exposed"
    ["/.env.production"]="CRITICAL|Production env file exposed"
    ["/wp-config.php"]="CRITICAL|WordPress config file accessible — DB credentials exposed"
    ["/wp-config.php.bak"]="CRITICAL|WordPress config backup exposed"
    ["/configuration.php"]="CRITICAL|Joomla config file exposed"
    ["/config/database.yml"]="CRITICAL|Rails database config exposed"
    ["/.aws/credentials"]="CRITICAL|AWS credentials file exposed"
    ["/db.sql"]="CRITICAL|Database dump accessible"
    ["/dump.sql"]="CRITICAL|SQL dump accessible"
    ["/backup.sql"]="CRITICAL|SQL backup accessible"
    ["/backup.zip"]="HIGH|Backup archive accessible"
    ["/backup.tar.gz"]="HIGH|Backup archive accessible"
    ["/phpinfo.php"]="HIGH|phpinfo() page accessible — full PHP/server info exposed"
    ["/info.php"]="HIGH|PHP info page accessible"
    ["/test.php"]="MEDIUM|Test PHP file accessible"
    ["/phpmyadmin/"]="HIGH|phpMyAdmin interface exposed"
    ["/adminer.php"]="HIGH|Adminer database interface exposed"
    ["/adminer/"]="HIGH|Adminer database interface exposed"
    ["/admin/"]="MEDIUM|Admin panel accessible"
    ["/administrator/"]="MEDIUM|Administrator panel accessible"
    ["/.htaccess"]="MEDIUM|.htaccess file readable — server config exposed"
    ["/web.config"]="HIGH|web.config exposed — IIS config/credentials may be disclosed"
    ["/server-status"]="MEDIUM|Apache server-status page accessible"
    ["/server-info"]="MEDIUM|Apache server-info page accessible"
    ["/_profiler/"]="MEDIUM|Symfony profiler exposed"
    ["/_debugbar"]="MEDIUM|DebugBar exposed"
    ["/api/swagger.json"]="LOW|Swagger API spec accessible"
    ["/api/openapi.json"]="LOW|OpenAPI spec accessible"
    ["/swagger-ui.html"]="LOW|Swagger UI exposed"
    ["/api-docs"]="LOW|API documentation exposed"
    ["/graphql"]="LOW|GraphQL endpoint accessible"
    ["/graphiql"]="MEDIUM|GraphiQL IDE exposed"
    ["/console"]="HIGH|Interactive console exposed"
    ["/robots.txt"]="INFO|robots.txt accessible — may reveal hidden paths"
    ["/sitemap.xml"]="INFO|sitemap.xml accessible"
    ["/.well-known/security.txt"]="INFO|security.txt present — check responsible disclosure policy"
    ["/crossdomain.xml"]="LOW|crossdomain.xml present"
    ["/clientaccesspolicy.xml"]="LOW|clientaccesspolicy.xml present"
    ["/.DS_Store"]="MEDIUM|.DS_Store file exposed — directory structure leaked"
    ["/package.json"]="MEDIUM|package.json exposed — dependency list revealed"
    ["/composer.json"]="MEDIUM|composer.json exposed"
    ["/Dockerfile"]="HIGH|Dockerfile exposed"
    ["/docker-compose.yml"]="HIGH|docker-compose.yml exposed — may contain credentials"
    ["/Makefile"]="LOW|Makefile accessible"
    ["/.travis.yml"]="LOW|CI config exposed"
    ["/.circleci/config.yml"]="LOW|CircleCI config exposed"
  )

  local sensitive_found="${dirs_dir}/sensitive_paths_found.txt"
  : > "$sensitive_found"

  for path in "${!SENSITIVE_PATHS[@]}"; do
    IFS='|' read -r sev description <<< "${SENSITIVE_PATHS[$path]}"
    local url="${TARGET}${path}"
    local status
    status=$(_curl -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

    if [[ "$status" =~ ^(200|206|301|302)$ ]]; then
      echo "[HTTP ${status}] ${url}" | tee -a "$sensitive_found" | tee -a "$LOG_FILE"
      add_finding "$sev" "DIRBRUTE" "Sensitive path accessible: ${path}" \
        "$description" "HTTP ${status} — ${url}" \
        "Restrict access, remove the file, or block the path at the web server level."
    fi
  done

  if [[ -s "$sensitive_found" ]]; then
    log_warn "$(wc -l < "$sensitive_found") sensitive path(s) found — review $sensitive_found"
  else
    log_ok "No high-priority sensitive files detected"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 07 — NIKTO
# ─────────────────────────────────────────────────────────────────────────────
module_nikto() {
  [[ $MOD_NIKTO -eq 0 ]] && return
  log_section "MODULE 07 — NIKTO WEB SERVER SCAN"
  require_tool nikto || return

  local nikto_base="${OUTPUT_DIR}/vulns/nikto"
  local nikto_flags="-host $TARGET -nointeractive -maxtime 600"

  [[ $OPT_AGGRESSIVE -eq 1 ]] && nikto_flags="$nikto_flags -Plugins @@ALL"
  [[ -n "$OPT_PROXY" ]]       && nikto_flags="$nikto_flags -useproxy $OPT_PROXY"

  log_info "Running Nikto (may take several minutes)..."

  # shellcheck disable=SC2086
  timeout 650s nikto $nikto_flags \
    -output "${nikto_base}.txt" -Format txt 2>/dev/null | tee -a "$LOG_FILE" || true

  # shellcheck disable=SC2086
  timeout 650s nikto $nikto_flags \
    -output "${nikto_base}.json" -Format json 2>/dev/null || true

  if [[ ! -f "${nikto_base}.txt" ]]; then
    log_warn "Nikto did not produce output"
    return
  fi

  log_ok "Nikto → ${nikto_base}.txt"

  # Parse findings
  grep -E "^\+ " "${nikto_base}.txt" 2>/dev/null | while IFS= read -r line; do
    local sev="LOW"
    echo "$line" | grep -qiE "vuln|exploit|inject|XSS|SQL|CVE|OSVDB-[0-9]{4,}" && sev="HIGH"
    echo "$line" | grep -qiE "outdated|version|disclose|found|enabled"          && sev="MEDIUM"

    add_finding "$sev" "NIKTO" "${line:2:120}" \
      "" "$line" "Investigate Nikto finding and apply the appropriate remediation."
  done
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 08 — SQL INJECTION
# ─────────────────────────────────────────────────────────────────────────────
module_sqli() {
  [[ $MOD_SQLI -eq 0 ]] && return
  log_section "MODULE 08 — SQL INJECTION (sqlmap)"
  require_tool sqlmap || return

  local sqli_dir="${OUTPUT_DIR}/vulns/sqlmap"
  mkdir -p "$sqli_dir"

  local sqlmap_flags="--batch --random-agent --timeout=$OPT_TIMEOUT --threads=$OPT_THREADS"
  sqlmap_flags="$sqlmap_flags --level=3 --risk=2"

  if [[ $OPT_AGGRESSIVE -eq 1 ]]; then
    sqlmap_flags="$sqlmap_flags --level=5 --risk=3 --forms --crawl=${OPT_DEPTH} --dbs --tamper=space2comment"
  fi
  [[ $OPT_STEALTH -eq 1 ]] && sqlmap_flags="$sqlmap_flags --delay=2 --safe-freq=3 --smart"
  [[ -n "$OPT_PROXY" ]]    && sqlmap_flags="$sqlmap_flags --proxy=$OPT_PROXY"

  log_info "Running sqlmap on $TARGET"
  log_verbose "Flags: $sqlmap_flags"

  # shellcheck disable=SC2086
  timeout 600s sqlmap -u "$TARGET" $sqlmap_flags \
    --output-dir="$sqli_dir" \
    2>/dev/null | tee "${sqli_dir}/sqlmap_console.txt" || true

  local output_file="${sqli_dir}/sqlmap_console.txt"
  if grep -qiE "is vulnerable|sqlmap identified|injectable" "$output_file" 2>/dev/null; then
    add_finding "CRITICAL" "SQLI" "SQL Injection confirmed on ${TARGET}" \
      "sqlmap identified injectable parameter(s)." \
      "$(grep -iE 'Parameter:|Type:|Title:' "$output_file" | head -5 | tr '\n' ' ')" \
      "Use parameterised queries / prepared statements. Never concatenate user input into SQL."
  else
    log_ok "No SQL injection detected on the main target URL"
    add_finding "INFO" "SQLI" "No obvious SQLi on primary URL" \
      "Manual testing with specific parameters recommended." "" ""
  fi

  log_info "sqlmap results → $sqli_dir"
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 09 — CROSS-SITE SCRIPTING (XSS)
# ─────────────────────────────────────────────────────────────────────────────
module_xss() {
  [[ $MOD_XSS -eq 0 ]] && return
  log_section "MODULE 09 — CROSS-SITE SCRIPTING (XSS)"

  local xss_dir="${OUTPUT_DIR}/vulns/xss"
  mkdir -p "$xss_dir"

  # ── dalfox ────────────────────────────────────────────────────────────────
  if has_tool dalfox; then
    log_subsection "dalfox XSS Scanner"
    local dalfox_flags="--silence --timeout $OPT_TIMEOUT"
    [[ $OPT_AGGRESSIVE -eq 1 ]] && dalfox_flags="$dalfox_flags --deep-domxss --follow-redirects"
    [[ -n "$OPT_PROXY" ]]       && dalfox_flags="$dalfox_flags --proxy $OPT_PROXY"

    # shellcheck disable=SC2086
    timeout 300s dalfox url "$TARGET" $dalfox_flags \
      --output "${xss_dir}/dalfox_results.txt" 2>/dev/null || true

    if [[ -s "${xss_dir}/dalfox_results.txt" ]] && \
       grep -qiE "\[V\]|WEAK|MEDIUM|HIGH|CRITICAL" "${xss_dir}/dalfox_results.txt" 2>/dev/null; then
      add_finding "HIGH" "XSS" "XSS vulnerability confirmed by dalfox" \
        "dalfox identified reflected or DOM-based XSS." \
        "$(head -3 "${xss_dir}/dalfox_results.txt")" \
        "Escape all HTML output. Implement a strict Content-Security-Policy."
    fi
  fi

  # ── Reflected XSS — manual probe ──────────────────────────────────────────
  log_subsection "Reflected XSS Probe"
  local xss_payloads=(
    "<script>alert(1)</script>"
    "'><img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "\"><script>alert(1)</script>"
    "javascript:alert(1)"
    "';alert(1);//"
    "<details open ontoggle=alert(1)>"
    "<iframe srcdoc='<script>alert(1)</script>'>"
  )

  local xss_params=("q" "s" "search" "query" "keyword" "id" "name" "page"
                    "url" "ref" "return" "redirect" "next" "view" "lang")

  local xss_found="${xss_dir}/reflected_xss.txt"
  : > "$xss_found"

  for param in "${xss_params[@]}"; do
    for payload in "${xss_payloads[@]}"; do
      local enc; enc=$(url_encode "$payload")
      local test_url="${TARGET}?${param}=${enc}"
      local response
      response=$(_curl "$test_url" 2>/dev/null | head -100 || true)

      if echo "$response" | grep -qF "$payload"; then
        echo "[REFLECTED XSS] param=$param payload=$payload" | tee -a "$xss_found" | tee -a "$LOG_FILE"
        add_finding "HIGH" "XSS" "Reflected XSS in parameter '$param'" \
          "Payload is reflected verbatim in the response without encoding." \
          "${test_url:0:200}" \
          "Encode all user-supplied output. Add Content-Security-Policy."
        break  # One confirmed finding per param is enough
      fi
    done
  done

  if [[ ! -s "$xss_found" ]]; then
    log_ok "No reflected XSS detected in common parameters"
  fi
  log_info "XSS tests → $xss_dir"
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 10 — CMS SCANNING
# ─────────────────────────────────────────────────────────────────────────────
module_cms() {
  [[ $MOD_CMS -eq 0 ]] && return
  log_section "MODULE 10 — CMS DETECTION & SCANNING"

  local cms_dir="${OUTPUT_DIR}/cms"

  # Detect CMS
  local page
  page=$(_curl "$TARGET" 2>/dev/null || true)
  local headers
  headers=$(_curl -I "$TARGET" 2>/dev/null || true)
  local combined="${page}${headers}"
  local detected_cms="unknown"

  if echo "$combined" | grep -qi "wp-content\|wp-includes\|wordpress"; then
    detected_cms="wordpress"
  elif echo "$combined" | grep -qi "sites/all/modules\|Drupal.settings\|X-Generator: Drupal"; then
    detected_cms="drupal"
  elif echo "$combined" | grep -qi "Joomla\|/media/jui\|generator.*joomla"; then
    detected_cms="joomla"
  elif echo "$combined" | grep -qi "Mage.Cookies\|magento\|/skin/frontend"; then
    detected_cms="magento"
  fi

  log_info "Detected CMS: $detected_cms"
  add_finding "INFO" "CMS" "CMS detected: $detected_cms" "" "" ""

  # ── WordPress ──────────────────────────────────────────────────────────────
  if [[ "$detected_cms" == "wordpress" ]]; then
    log_subsection "WordPress — wpscan"

    if has_tool wpscan; then
      local wpscan_flags="--url $TARGET --no-banner"
      [[ $OPT_AGGRESSIVE -eq 1 ]] && \
        wpscan_flags="$wpscan_flags --enumerate ap,at,cb,dbe,u --plugins-detection aggressive"
      [[ -n "$OPT_PROXY" ]] && wpscan_flags="$wpscan_flags --proxy $OPT_PROXY"

      # shellcheck disable=SC2086
      timeout 600s wpscan $wpscan_flags \
        --format json \
        --output "${cms_dir}/wpscan_results.json" \
        2>/dev/null | tee "${cms_dir}/wpscan_console.txt" || true

      log_ok "wpscan → ${cms_dir}/wpscan_results.json"

      if has_tool jq && [[ -f "${cms_dir}/wpscan_results.json" ]]; then
        local wp_version
        wp_version=$(jq -r '.version.number // "unknown"' \
          "${cms_dir}/wpscan_results.json" 2>/dev/null || echo "unknown")
        log_info "WordPress version: $wp_version"

        local plugin_vulns
        plugin_vulns=$(jq '[.plugins[]?.vulnerabilities[]?] | length' \
          "${cms_dir}/wpscan_results.json" 2>/dev/null || echo 0)
        [[ "$plugin_vulns" -gt 0 ]] && add_finding "HIGH" "CMS" \
          "WordPress: $plugin_vulns plugin vulnerability/vulnerabilities found" \
          "wpscan identified vulnerable plugins." \
          "See ${cms_dir}/wpscan_results.json" \
          "Update all plugins to the latest version immediately."

        local theme_vulns
        theme_vulns=$(jq '[.themes[]?.vulnerabilities[]?] | length' \
          "${cms_dir}/wpscan_results.json" 2>/dev/null || echo 0)
        [[ "$theme_vulns" -gt 0 ]] && add_finding "MEDIUM" "CMS" \
          "WordPress: $theme_vulns theme vulnerability/vulnerabilities found" \
          "" "See ${cms_dir}/wpscan_results.json" \
          "Update all themes. Remove inactive/unused themes."

        local wp_users
        wp_users=$(jq '.users | length' \
          "${cms_dir}/wpscan_results.json" 2>/dev/null || echo 0)
        [[ "$wp_users" -gt 0 ]] && add_finding "MEDIUM" "CMS" \
          "WordPress: $wp_users user(s) enumerable via the API" \
          "Username enumeration can aid brute-force attacks." \
          "$(jq -r '.users | keys[]' "${cms_dir}/wpscan_results.json" 2>/dev/null | head -5 | tr '\n' ' ')" \
          "Add 'remove_action(\"template_redirect\",\"redirect_canonical\")' and restrict REST API user endpoint."
      fi
    fi

    # WordPress-specific path probes
    declare -A WP_PATHS=(
      ["/xmlrpc.php"]="MEDIUM|WordPress XML-RPC enabled — brute-force amplification risk|Disable xmlrpc.php if not required."
      ["/wp-json/wp/v2/users"]="MEDIUM|REST API exposes user list|Restrict REST API user endpoint."
      ["/wp-content/debug.log"]="HIGH|WordPress debug.log accessible|Delete file; disable WP_DEBUG_LOG in production."
      ["/?author=1"]="LOW|Author enumeration via ?author= parameter|Add redirect to prevent author slug leakage."
      ["/wp-login.php"]="INFO|WordPress login page accessible|Enable two-factor authentication; limit login attempts."
    )

    for wpath in "${!WP_PATHS[@]}"; do
      IFS='|' read -r sev desc rec <<< "${WP_PATHS[$wpath]}"
      local status
      status=$(_curl -o /dev/null -w "%{http_code}" "${TARGET}${wpath}" 2>/dev/null || echo "000")
      [[ "$status" =~ ^(200|301|302)$ ]] && add_finding "$sev" "CMS" "$desc" \
        "" "${TARGET}${wpath} (HTTP $status)" "$rec"
    done

  # ── Drupal / Joomla ────────────────────────────────────────────────────────
  elif [[ "$detected_cms" =~ ^(drupal|joomla)$ ]] && has_tool droopescan; then
    log_subsection "droopescan — $detected_cms"
    droopescan scan "$detected_cms" -u "$TARGET" \
      --output-format json \
      > "${cms_dir}/droopescan_${detected_cms}.json" 2>/dev/null || true
    log_ok "droopescan → ${cms_dir}/droopescan_${detected_cms}.json"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 11 — CORS MISCONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
module_cors() {
  [[ $MOD_CORS -eq 0 ]] && return
  log_section "MODULE 11 — CORS MISCONFIGURATION"

  local cors_file="${OUTPUT_DIR}/misc/cors_tests.txt"
  : > "$cors_file"

  local test_origins=(
    "https://evil.com"
    "https://${TARGET_DOMAIN}.evil.com"
    "https://evil.${TARGET_DOMAIN}"
    "null"
    "https://attacker.io"
    "http://localhost"
    "https://not${TARGET_DOMAIN}"
  )

  log_info "Testing ${#test_origins[@]} adversarial origins..."

  for origin in "${test_origins[@]}"; do
    local response
    response=$(_curl \
      -H "Origin: ${origin}" \
      -H "Access-Control-Request-Method: GET" \
      -H "Access-Control-Request-Headers: Authorization" \
      -I "$TARGET" 2>/dev/null || true)

    local acao acac acam
    acao=$(echo "$response" | grep -i "access-control-allow-origin:"  | head -1 | tr -d '\r' || true)
    acac=$(echo "$response" | grep -i "access-control-allow-credentials:" | head -1 | tr -d '\r' || true)
    acam=$(echo "$response" | grep -i "access-control-allow-methods:" | head -1 | tr -d '\r' || true)

    printf "Origin: %s\n  ACAO: %s\n  ACAC: %s\n\n" "$origin" "$acao" "$acac" >> "$cors_file"

    # Origin reflected back
    if echo "$acao" | grep -qi "$(echo "$origin" | sed 's|https://||')"; then
      local sev="MEDIUM"
      echo "$acac" | grep -qi "true" && sev="CRITICAL"

      add_finding "$sev" "CORS" "CORS: arbitrary origin reflected — Origin: $origin" \
        "The server reflects the attacker's origin in Access-Control-Allow-Origin.$(
          echo "$acac" | grep -qi 'true' && echo ' ACAC: true permits credentialed cross-origin requests.')" \
        "ACAO: $acao | ACAC: $acac" \
        "Validate origins against an explicit allowlist. Never reflect the Origin header directly."
    fi

    # Wildcard
    if echo "$acao" | grep -qP ":\s*\*\s*$"; then
      add_finding "MEDIUM" "CORS" "CORS wildcard (*) in Access-Control-Allow-Origin" \
        "Any origin can make cross-origin requests to this endpoint." "$acao" \
        "Specify allowed origins explicitly. Wildcard is unsafe for authenticated endpoints."
    fi

    # null origin accepted
    if [[ "$origin" == "null" ]] && echo "$acao" | grep -qi "null"; then
      add_finding "HIGH" "CORS" "CORS: 'null' origin accepted" \
        "'null' origin can be triggered from sandboxed iframes — allows cross-origin attacks." \
        "$acao" "Never allow 'null' origin in CORS policy."
    fi
  done

  log_info "CORS tests → $cors_file"
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 12 — OPEN REDIRECT
# ─────────────────────────────────────────────────────────────────────────────
module_open_redirect() {
  [[ $MOD_REDIRECT -eq 0 ]] && return
  log_section "MODULE 12 — OPEN REDIRECT"

  local redirect_file="${OUTPUT_DIR}/misc/open_redirect.txt"
  : > "$redirect_file"

  local payloads=(
    "https://evil.com"
    "//evil.com"
    "///evil.com"
    "https:evil.com"
    "/\\evil.com"
    "https://evil.com%2F%2E%2E"
    "%2F%2Fevil.com"
    "https:///evil.com"
    "/%5Cevil.com"
    "https://evil.com@${TARGET_DOMAIN}"
  )

  local params=(
    "next" "url" "redirect" "redirect_uri" "redirect_url"
    "return" "return_url" "returnUrl" "returnTo"
    "go" "goto" "dest" "destination" "target"
    "forward" "redir" "link" "to" "r" "out" "ref"
    "continue" "callback" "successUrl" "failureUrl"
  )

  log_info "Testing ${#params[@]} params × ${#payloads[@]} payloads..."
  local found=0

  for param in "${params[@]}"; do
    for payload in "${payloads[@]}"; do
      local enc; enc=$(url_encode "$payload")
      local test_url="${TARGET}?${param}=${enc}"
      local location
      location=$(_curl -sI -o /dev/null -w "%{redirect_url}" \
        --max-redirs 0 "$test_url" 2>/dev/null || true)

      if echo "$location" | grep -qi "evil\.com"; then
        found=$((found + 1))
        echo "[OPEN REDIRECT] param=${param} payload=${payload} → ${location}" | \
          tee -a "$redirect_file" | tee -a "$LOG_FILE"
        add_finding "MEDIUM" "REDIRECT" "Open Redirect via parameter '$param'" \
          "Unvalidated redirect to external domain." \
          "${test_url:0:200} → $location" \
          "Validate redirect targets against an allowlist of internal paths/domains."
        break  # One finding per parameter
      fi
    done
  done

  if [[ $found -eq 0 ]]; then
    log_ok "No open redirects detected in common parameters"
  else
    log_warn "$found open redirect(s) confirmed — see $redirect_file"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 13 — SERVER-SIDE REQUEST FORGERY (SSRF)
# ─────────────────────────────────────────────────────────────────────────────
module_ssrf() {
  [[ $MOD_SSRF -eq 0 ]] && return
  log_section "MODULE 13 — SERVER-SIDE REQUEST FORGERY (SSRF)"

  local ssrf_file="${OUTPUT_DIR}/misc/ssrf_tests.txt"
  : > "$ssrf_file"

  local payloads=(
    "http://127.0.0.1/"
    "http://127.0.0.1:22/"
    "http://127.0.0.1:8080/"
    "http://localhost/"
    "http://[::1]/"
    "http://0.0.0.0/"
    "http://2130706433/"          # 127.0.0.1 decimal
    "http://0x7f000001/"          # 127.0.0.1 hex
    "http://169.254.169.254/"     # IMDS (AWS/Azure/GCP shared)
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://metadata.google.internal/"
    "http://metadata.google.internal/computeMetadata/v1/"
    "http://169.254.169.254/metadata/v1/"
    "http://192.168.0.1/"
    "http://10.0.0.1/"
  )

  local params=(
    "url" "uri" "src" "href" "path" "dest" "redirect"
    "image" "img" "load" "fetch" "proxy" "resource"
    "data" "continue" "file" "page" "feed" "host"
    "api" "callback" "endpoint" "target" "domain"
  )

  # Cloud SSRF indicator patterns
  local indicators=("ami-id" "instance-id" "availability-zone" "instance-type"
                     "iam" "security-credentials" "computeMetadata"
                     "root:" "daemon:" "mysql:" "postgres:"  # /etc/passwd fragments
                     "127.0.0.1" "localhost" "internal")

  log_info "Testing ${#params[@]} params × ${#payloads[@]} SSRF payloads..."
  local found=0

  for param in "${params[@]}"; do
    for payload in "${payloads[@]}"; do
      local enc; enc=$(url_encode "$payload")
      local test_url="${TARGET}?${param}=${enc}"
      local response
      response=$(_curl "$test_url" 2>/dev/null | head -30 || true)

      for indicator in "${indicators[@]}"; do
        if echo "$response" | grep -qi "$indicator"; then
          found=$((found + 1))
          echo "[SSRF CONFIRMED] param=$param payload=$payload indicator=$indicator" | \
            tee -a "$ssrf_file" | tee -a "$LOG_FILE"
          add_finding "CRITICAL" "SSRF" "SSRF confirmed via parameter '$param'" \
            "Response contains internal/cloud-metadata content ('$indicator')." \
            "${test_url:0:200}" \
            "Validate and allowlist outbound URLs. Block IMDS access (e.g. IMDSv2 on AWS). Use egress firewalling."
          break 2  # Next param
        fi
      done
    done
  done

  if [[ $found -eq 0 ]]; then
    log_ok "No in-band SSRF detected"
    add_finding "INFO" "SSRF" "No in-band SSRF detected on common parameters" \
      "Out-of-band (OOB) SSRF may still exist. Use Burp Collaborator or Interactsh for blind testing." "" ""
  fi
  log_info "SSRF tests → $ssrf_file"
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 14 — SUBDOMAIN TAKEOVER
# ─────────────────────────────────────────────────────────────────────────────
module_subtakeover() {
  [[ $MOD_SUBTAKEOVER -eq 0 ]] && return
  log_section "MODULE 14 — SUBDOMAIN TAKEOVER"

  local subs_file="${OUTPUT_DIR}/recon/subdomains.txt"
  local takeover_file="${OUTPUT_DIR}/misc/subtakeover.txt"
  : > "$takeover_file"

  if [[ ! -s "$subs_file" ]]; then
    log_info "No subdomain list available — run with MOD_RECON enabled first"
    return
  fi

  # ── subjack ────────────────────────────────────────────────────────────────
  if has_tool subjack; then
    log_subsection "subjack"
    subjack \
      -w "$subs_file" \
      -t "$OPT_THREADS" \
      -timeout "$OPT_TIMEOUT" \
      -o "$takeover_file" \
      -ssl 2>/dev/null || true

    if [[ -s "$takeover_file" ]]; then
      add_finding "HIGH" "SUBTAKEOVER" "Potential subdomain takeover(s) detected by subjack" \
        "$(cat "$takeover_file")" "$takeover_file" \
        "Remove stale DNS records pointing to deprovisioned external services."
    fi
  fi

  # ── Nuclei takeover templates ──────────────────────────────────────────────
  if has_tool nuclei && [[ $MOD_NUCLEI -eq 1 ]]; then
    log_subsection "Nuclei — takeover templates"
    timeout 300s nuclei \
      -l "$subs_file" \
      -tags takeover \
      -o "${OUTPUT_DIR}/misc/nuclei_takeover.txt" \
      -silent 2>/dev/null || true

    if [[ -s "${OUTPUT_DIR}/misc/nuclei_takeover.txt" ]]; then
      add_finding "HIGH" "SUBTAKEOVER" "Nuclei: subdomain takeover template matched" \
        "$(cat "${OUTPUT_DIR}/misc/nuclei_takeover.txt")" \
        "${OUTPUT_DIR}/misc/nuclei_takeover.txt" \
        "Remove the stale DNS record immediately."
    fi
  fi

  # ── Manual CNAME → dangling-service check ──────────────────────────────────
  log_subsection "Dangling CNAME analysis"
  declare -A TAKEOVER_SERVICES=(
    ["amazonaws.com"]="AWS S3 / Elastic Beanstalk"
    ["elasticbeanstalk.com"]="AWS Elastic Beanstalk"
    ["cloudfront.net"]="AWS CloudFront"
    ["github.io"]="GitHub Pages"
    ["heroku.com"]="Heroku"
    ["herokussl.com"]="Heroku"
    ["zendesk.com"]="Zendesk"
    ["freshdesk.com"]="Freshdesk"
    ["helpscoutdocs.com"]="HelpScout"
    ["surge.sh"]="Surge.sh"
    ["netlify.app"]="Netlify"
    ["render.com"]="Render"
    ["azurewebsites.net"]="Azure Web Apps"
    ["azure-api.net"]="Azure API Management"
    ["myshopify.com"]="Shopify"
    ["squarespace.com"]="Squarespace"
    ["tumblr.com"]="Tumblr"
    ["ghost.io"]="Ghost"
    ["webflow.io"]="Webflow"
    ["fly.dev"]="Fly.io"
    ["pages.dev"]="Cloudflare Pages"
  )

  local sub_count; sub_count=$(wc -l < "$subs_file")
  log_info "Analysing $sub_count subdomain(s) for dangling CNAMEs..."

  while IFS= read -r sub; do
    [[ -z "$sub" ]] && continue
    local cname
    cname=$(dig +short CNAME "$sub" 2>/dev/null | sed 's/\.$//' || true)
    [[ -z "$cname" ]] && continue

    for svc_domain in "${!TAKEOVER_SERVICES[@]}"; do
      if echo "$cname" | grep -qi "$svc_domain"; then
        local http_code
        http_code=$(_curl -o /dev/null -w "%{http_code}" "https://${sub}" 2>/dev/null || echo "000")
        if [[ "$http_code" =~ ^(404|410|403|503)$ ]]; then
          echo "[TAKEOVER RISK] ${sub} → CNAME ${cname} (${TAKEOVER_SERVICES[$svc_domain]}) HTTP ${http_code}" | \
            tee -a "$takeover_file" | tee -a "$LOG_FILE"
          add_finding "HIGH" "SUBTAKEOVER" \
            "Dangling CNAME: ${sub} → ${TAKEOVER_SERVICES[$svc_domain]}" \
            "CNAME points to $cname but the resource returns HTTP $http_code — takeover may be possible." \
            "${sub} → ${cname} (HTTP ${http_code})" \
            "Remove the CNAME record for ${sub} or reclaim the resource at ${TAKEOVER_SERVICES[$svc_domain]}."
        fi
        break
      fi
    done
  done < "$subs_file"

  if [[ -s "$takeover_file" ]]; then
    log_warn "Takeover findings → $takeover_file"
  else
    log_ok "No subdomain takeover candidates found"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 15 — NUCLEI TEMPLATE SCAN
# ─────────────────────────────────────────────────────────────────────────────
module_nuclei() {
  [[ $MOD_NUCLEI -eq 0 ]] && return
  require_tool nuclei || return
  log_section "MODULE 15 — NUCLEI TEMPLATE SCAN"

  local nuclei_dir="${OUTPUT_DIR}/vulns/nuclei"
  mkdir -p "$nuclei_dir"

  local severity_filter="medium,high,critical"
  [[ $OPT_AGGRESSIVE -eq 1 ]] && severity_filter="low,medium,high,critical"

  local nuclei_flags="-silent -no-interactsh"
  [[ -n "$OPT_PROXY" ]] && nuclei_flags="$nuclei_flags -proxy $OPT_PROXY"

  log_info "Running Nuclei (severity: $severity_filter)..."

  # shellcheck disable=SC2086
  timeout 600s nuclei \
    -u "$TARGET" \
    -severity "$severity_filter" \
    -o "${nuclei_dir}/nuclei_results.txt" \
    -json -o "${nuclei_dir}/nuclei_results.json" \
    $nuclei_flags \
    2>/dev/null || true

  if [[ -s "${nuclei_dir}/nuclei_results.txt" ]]; then
    local ncount; ncount=$(wc -l < "${nuclei_dir}/nuclei_results.txt")
    log_ok "Nuclei: $ncount finding(s) → ${nuclei_dir}/nuclei_results.txt"

    grep -oP '\[.*?\]\s+\[.*?\]\s+\[.*?\]\s+.*' "${nuclei_dir}/nuclei_results.txt" 2>/dev/null | \
    head -50 | while IFS= read -r finding; do
      local sev="MEDIUM"
      echo "$finding" | grep -qi "\[critical\]" && sev="CRITICAL"
      echo "$finding" | grep -qi "\[high\]"     && sev="HIGH"
      echo "$finding" | grep -qi "\[low\]"      && sev="LOW"
      echo "$finding" | grep -qi "\[info\]"     && sev="INFO"

      add_finding "$sev" "NUCLEI" "${finding:0:120}" \
        "" "$finding" "Review Nuclei finding and apply corresponding remediation."
    done
  else
    log_ok "No Nuclei findings for severity level: $severity_filter"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────


generate_reports() {
  log_section "GENERATING REPORTS"
 
  local elapsed
  elapsed=$(elapsed_secs)
 
  # ── Determine which formats to produce ──────────────────────────────────────
  local do_json=1 do_html=1 do_txt=1
  case "${OPT_OUTPUT_ONLY:-all}" in
    json) do_html=0; do_txt=0 ;;
    html) do_json=0; do_txt=0 ;;
    txt)  do_json=0; do_html=0 ;;
  esac
 
  # ── Helpers ─────────────────────────────────────────────────────────────────
 
  # Parse a field from a JSONL line — works with jq OR python3 OR grep fallback
  _get_field() {
    local line="$1" field="$2" default="${3:-}"
    local val=""
 
    if has_tool jq; then
      val=$(printf '%s' "$line" | jq -r ".${field} // empty" 2>/dev/null || true)
    fi
 
    if [[ -z "$val" ]] && has_tool python3; then
      val=$(printf '%s' "$line" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('${field}',''))" 2>/dev/null || true)
    fi
 
    if [[ -z "$val" ]]; then
      # grep fallback — extracts "field":"value"
      val=$(printf '%s' "$line" | grep -oP "\"${field}\":\s*\"?\K[^\",}]+" | head -1 || true)
    fi
 
    printf '%s' "${val:-$default}"
  }
 
  # HTML-escape a string
  _hesc() {
    printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'
  }
 
  # ────────────────────────────────────────────────────────────────────────────
  # TXT REPORT
  # ────────────────────────────────────────────────────────────────────────────
  if [[ $do_txt -eq 1 ]]; then
    {
      local sep="════════════════════════════════════════════════════════════════"
      echo "$sep"
      echo "  WEBSEC-AUDIT v${TOOL_VERSION}  —  Security Audit Report"
      echo "$sep"
      printf "  Target    : %s\n" "$TARGET"
      printf "  IP        : %s\n" "${TARGET_IP:-N/A}"
      printf "  Date      : %s\n" "$DATE_HUMAN"
      printf "  Duration  : %ds\n" "$elapsed"
      printf "  Auditor   : %s@%s\n" "$(whoami)" "$(hostname)"
      echo "$sep"
      echo ""
      echo "  RISK SUMMARY"
      echo "  ──────────────────────────────────────────────────"
      printf "  %-12s %d\n" "CRITICAL"  "$COUNT_CRITICAL"
      printf "  %-12s %d\n" "HIGH"      "$COUNT_HIGH"
      printf "  %-12s %d\n" "MEDIUM"    "$COUNT_MEDIUM"
      printf "  %-12s %d\n" "LOW"       "$COUNT_LOW"
      printf "  %-12s %d\n" "INFO"      "$COUNT_INFO"
      printf "  %-12s %d\n" "TOTAL"     "$TOTAL_FINDINGS"
      echo ""
      echo "$sep"
      echo "  FINDINGS"
      echo "$sep"
      echo ""
 
      if [[ -s "$FINDINGS_JSONL" ]]; then
        local n=0
        while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          n=$((n + 1))
          local sev mod title desc evid rec ts
          sev=$(_get_field  "$line" "severity"       "INFO")
          mod=$(_get_field  "$line" "module"          "-")
          title=$(_get_field "$line" "title"          "Untitled")
          desc=$(_get_field  "$line" "description"   "")
          evid=$(_get_field  "$line" "evidence"       "")
          rec=$(_get_field   "$line" "recommendation" "")
          ts=$(_get_field    "$line" "timestamp"      "")
 
          printf "  [%03d] [%-8s] [%s] %s\n" "$n" "$sev" "$mod" "$title"
          [[ -n "$desc" ]] && printf "        Description  : %s\n" "$desc"
          [[ -n "$evid" ]] && printf "        Evidence     : %s\n" "$evid"
          [[ -n "$rec"  ]] && printf "        Remediation  : %s\n" "$rec"
          [[ -n "$ts"   ]] && printf "        Timestamp    : %s\n" "$ts"
          echo ""
        done < "$FINDINGS_JSONL"
      else
        echo "  No findings recorded."
      fi
 
      echo ""
      echo "$sep"
      echo "  FULL AUDIT LOG"
      echo "$sep"
      echo ""
      cat "$LOG_FILE"
    } > "$REPORT_TXT"
    log_ok "TXT report  → $REPORT_TXT"
  fi
 
  # ────────────────────────────────────────────────────────────────────────────
  # JSON REPORT
  # ────────────────────────────────────────────────────────────────────────────
  if [[ $do_json -eq 1 ]]; then
    {
      printf '{\n'
      printf '  "metadata": {\n'
      printf '    "tool": "%s",\n'          "$TOOL_NAME"
      printf '    "version": "%s",\n'       "$TOOL_VERSION"
      printf '    "author": "%s",\n'        "$TOOL_AUTHOR"
      printf '    "target": "%s",\n'        "$TARGET"
      printf '    "domain": "%s",\n'        "$TARGET_DOMAIN"
      printf '    "ip": "%s",\n'            "${TARGET_IP:-}"
      printf '    "start_time": "%s",\n'    "$DATE_HUMAN"
      printf '    "duration_secs": %d\n'    "$elapsed"
      printf '  },\n'
      printf '  "summary": {\n'
      printf '    "total": %d,\n'      "$TOTAL_FINDINGS"
      printf '    "critical": %d,\n'   "$COUNT_CRITICAL"
      printf '    "high": %d,\n'       "$COUNT_HIGH"
      printf '    "medium": %d,\n'     "$COUNT_MEDIUM"
      printf '    "low": %d,\n'        "$COUNT_LOW"
      printf '    "info": %d\n'        "$COUNT_INFO"
      printf '  },\n'
      printf '  "findings": [\n'
 
      local first=1
      if [[ -s "$FINDINGS_JSONL" ]]; then
        while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          [[ $first -eq 0 ]] && printf ',\n'
          printf '    %s' "$line"
          first=0
        done < "$FINDINGS_JSONL"
        printf '\n'
      fi
 
      printf '  ]\n'
      printf '}\n'
    } > "$REPORT_JSON"
    log_ok "JSON report → $REPORT_JSON"
  fi
 
  # ────────────────────────────────────────────────────────────────────────────
  # HTML REPORT
  # ────────────────────────────────────────────────────────────────────────────
  if [[ $do_html -eq 1 ]]; then
 
    # Risk colour
    local risk_label="INFO ONLY" risk_color="#78909c"
    [[ $COUNT_LOW -gt 0 ]]      && { risk_label="LOW RISK";      risk_color="#42a5f5"; }
    [[ $COUNT_MEDIUM -gt 0 ]]   && { risk_label="MEDIUM RISK";   risk_color="#ffb300"; }
    [[ $COUNT_HIGH -gt 0 ]]     && { risk_label="HIGH RISK";     risk_color="#f0883e"; }
    [[ $COUNT_CRITICAL -gt 0 ]] && { risk_label="CRITICAL RISK"; risk_color="#f44336"; }
 
    # Risk bar percentages
    local total_bar=$(( COUNT_CRITICAL + COUNT_HIGH + COUNT_MEDIUM + COUNT_LOW ))
    [[ $total_bar -eq 0 ]] && total_bar=1
    local bc=$(( COUNT_CRITICAL * 100 / total_bar ))
    local bh=$(( COUNT_HIGH     * 100 / total_bar ))
    local bm=$(( COUNT_MEDIUM   * 100 / total_bar ))
    local bl=$(( COUNT_LOW      * 100 / total_bar ))
 
    # Write HTML header
    cat > "$REPORT_HTML" << HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>websec-audit — ${TARGET_DOMAIN}</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--br:#30363d;
  --tx:#c9d1d9;--mu:#8b949e;--gn:#3fb950;--bl:#58a6ff;
  --yw:#d29922;--or:#f0883e;--rd:#f85149;
  --cc:#f44336;--ch:#f0883e;--cm:#d29922;--cl:#42a5f5;--ci:#78909c;
  --fn:'Segoe UI',system-ui,sans-serif;--fc:'Consolas','Courier New',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--fn);background:var(--bg);color:var(--tx);font-size:14px;line-height:1.6}
a{color:var(--bl);text-decoration:none}
header{background:var(--bg2);border-bottom:1px solid var(--br);
  padding:18px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
header h1{font-size:20px;color:var(--bl);font-weight:600}
header .sub{color:var(--mu);font-size:12px;margin-top:3px}
.risk{padding:6px 16px;border-radius:5px;font-size:12px;font-weight:700;letter-spacing:.6px;
  background:${risk_color}22;color:${risk_color};border:1px solid ${risk_color}}
main{max-width:1200px;margin:0 auto;padding:28px 32px}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
.card{background:var(--bg2);border:1px solid var(--br);border-radius:8px;padding:16px;text-align:center}
.card .n{font-size:36px;font-weight:700;line-height:1}
.card .l{font-size:11px;color:var(--mu);margin-top:5px;text-transform:uppercase;letter-spacing:1px}
.card.cc{border-color:var(--cc)}.card.cc .n{color:var(--cc)}
.card.ch{border-color:var(--ch)}.card.ch .n{color:var(--ch)}
.card.cm{border-color:var(--cm)}.card.cm .n{color:var(--cm)}
.card.cl{border-color:var(--cl)}.card.cl .n{color:var(--cl)}
.card.ci .n{color:var(--ci)}
.rbar{height:5px;background:var(--bg3);border-radius:3px;overflow:hidden;display:flex;margin-bottom:24px}
.rc{background:var(--cc)}.rh{background:var(--ch)}.rm{background:var(--cm)}.rl{background:var(--cl)}
.meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:24px}
.meta-box{background:var(--bg2);border:1px solid var(--br);border-radius:8px;padding:14px 16px}
.meta-box h2{font-size:13px;color:var(--mu);margin-bottom:10px;font-weight:500;text-transform:uppercase;letter-spacing:.6px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;font-size:12px}
.kv .k{color:var(--mu)}.kv .v{font-family:var(--fc);color:var(--tx);word-break:break-all}
h2.sh{font-size:15px;font-weight:600;margin-bottom:12px;padding-left:10px;border-left:3px solid var(--bl)}
.filter-bar{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:14px;align-items:center}
.fb{padding:4px 12px;border-radius:5px;cursor:pointer;font-size:12px;border:1px solid var(--br);
  background:var(--bg2);color:var(--mu);transition:all .15s}
.fb:hover,.fb.active{border-color:var(--bl);color:var(--bl);background:#58a6ff11}
.sb{margin-left:auto;padding:5px 11px;border-radius:5px;border:1px solid var(--br);
  background:var(--bg3);color:var(--tx);font-size:12px;width:200px}
.sb:focus{outline:none;border-color:var(--bl)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--bg3);color:var(--mu);text-align:left;padding:9px 12px;
  font-weight:500;border-bottom:1px solid var(--br);white-space:nowrap;
  position:sticky;top:0;z-index:5}
td{padding:9px 12px;border-bottom:1px solid var(--br);vertical-align:top}
tr:hover td{background:#ffffff08}
tr[hidden]{display:none}
.badge{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700;
  letter-spacing:.4px;white-space:nowrap}
.bcc{background:#f4433618;color:var(--cc);border:1px solid var(--cc)}
.bch{background:#f0883e18;color:var(--ch);border:1px solid var(--ch)}
.bcm{background:#d2992218;color:var(--cm);border:1px solid var(--cm)}
.bcl{background:#42a5f518;color:var(--cl);border:1px solid var(--cl)}
.bci{background:#78909c18;color:var(--ci);border:1px solid var(--ci)}
.mtag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;
  background:var(--bg3);color:var(--mu);border:1px solid var(--br);font-family:var(--fc)}
.ev{font-family:var(--fc);font-size:11px;color:var(--mu);background:var(--bg3);
  padding:3px 7px;border-radius:3px;margin-top:4px;word-break:break-all;border-left:2px solid var(--br)}
.fix{font-size:11px;color:var(--gn);margin-top:4px}
.fix::before{content:"💡 "}
#empty{text-align:center;padding:40px;color:var(--mu);display:none}
footer{text-align:center;color:var(--mu);font-size:11px;padding:20px;
  border-top:1px solid var(--br);margin-top:32px}
@media(max-width:700px){.cards{grid-template-columns:repeat(3,1fr)}.meta-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <div>
    <h1>🔐 websec-audit — Security Report</h1>
    <div class="sub">${TARGET} &nbsp;|&nbsp; ${DATE_HUMAN} &nbsp;|&nbsp; v${TOOL_VERSION} by ${TOOL_AUTHOR}</div>
  </div>
  <div class="risk">${risk_label}</div>
</header>
<main>
 
<div class="cards">
  <div class="card cc"><div class="n">${COUNT_CRITICAL}</div><div class="l">Critical</div></div>
  <div class="card ch"><div class="n">${COUNT_HIGH}</div><div class="l">High</div></div>
  <div class="card cm"><div class="n">${COUNT_MEDIUM}</div><div class="l">Medium</div></div>
  <div class="card cl"><div class="n">${COUNT_LOW}</div><div class="l">Low</div></div>
  <div class="card ci"><div class="n">${COUNT_INFO}</div><div class="l">Info</div></div>
</div>
 
<div class="rbar">
  <div class="rc" style="width:${bc}%"></div>
  <div class="rh" style="width:${bh}%"></div>
  <div class="rm" style="width:${bm}%"></div>
  <div class="rl" style="width:${bl}%"></div>
</div>
 
<div class="meta-grid">
  <div class="meta-box">
    <h2>Scan Metadata</h2>
    <div class="kv">
      <span class="k">Target</span>   <span class="v">${TARGET}</span>
      <span class="k">Domain</span>   <span class="v">${TARGET_DOMAIN}</span>
      <span class="k">IP</span>       <span class="v">${TARGET_IP:-N/A}</span>
      <span class="k">Date</span>     <span class="v">${DATE_HUMAN}</span>
      <span class="k">Duration</span> <span class="v">${elapsed}s</span>
      <span class="k">Auditor</span>  <span class="v">$(whoami)@$(hostname)</span>
      <span class="k">Mode</span>     <span class="v">$( [[ ${OPT_AGGRESSIVE:-0} -eq 1 ]] && echo AGGRESSIVE || [[ ${OPT_STEALTH:-0} -eq 1 ]] && echo STEALTH || echo NORMAL)</span>
    </div>
  </div>
  <div class="meta-box">
    <h2>Module Status</h2>
    <div class="kv">
      <span class="k">Recon</span>       <span class="v">$( [[ ${MOD_RECON:-1} -eq 1 ]]        && echo "✔ enabled" || echo "— skipped")</span>
      <span class="k">Port Scan</span>   <span class="v">$( [[ ${MOD_PORTSCAN:-1} -eq 1 ]]     && echo "✔ enabled" || echo "— skipped")</span>
      <span class="k">SSL/TLS</span>     <span class="v">$( [[ ${MOD_SSL:-1} -eq 1 ]]          && echo "✔ enabled" || echo "— skipped")</span>
      <span class="k">Headers</span>     <span class="v">$( [[ ${MOD_HEADERS:-1} -eq 1 ]]      && echo "✔ enabled" || echo "— skipped")</span>
      <span class="k">Dir Brute</span>   <span class="v">$( [[ ${MOD_DIRBRUTE:-1} -eq 1 ]]     && echo "✔ enabled" || echo "— skipped")</span>
      <span class="k">SQLi / XSS</span> <span class="v">$( [[ ${MOD_SQLI:-1} -eq 1 ]]  && echo "✔" || echo "—") / $( [[ ${MOD_XSS:-1} -eq 1 ]] && echo "✔" || echo "—")</span>
      <span class="k">CMS</span>         <span class="v">$( [[ ${MOD_CMS:-1} -eq 1 ]]          && echo "✔ enabled" || echo "— skipped")</span>
      <span class="k">Nuclei</span>      <span class="v">$( [[ ${MOD_NUCLEI:-1} -eq 1 ]]       && echo "✔ enabled" || echo "— skipped")</span>
    </div>
  </div>
</div>
 
<h2 class="sh">Security Findings (${TOTAL_FINDINGS})</h2>
<div class="filter-bar">
  <button class="fb active" onclick="filt('ALL',this)">All (${TOTAL_FINDINGS})</button>
  <button class="fb" onclick="filt('CRITICAL',this)" style="color:var(--cc)">Critical (${COUNT_CRITICAL})</button>
  <button class="fb" onclick="filt('HIGH',this)"     style="color:var(--ch)">High (${COUNT_HIGH})</button>
  <button class="fb" onclick="filt('MEDIUM',this)"   style="color:var(--cm)">Medium (${COUNT_MEDIUM})</button>
  <button class="fb" onclick="filt('LOW',this)"      style="color:var(--cl)">Low (${COUNT_LOW})</button>
  <button class="fb" onclick="filt('INFO',this)">Info (${COUNT_INFO})</button>
  <input class="sb" type="text" placeholder="Search…" oninput="srch(this.value)">
</div>
 
<div id="empty">No findings match the current filter.</div>
<table><thead><tr>
  <th style="width:36px">#</th>
  <th style="width:90px">Severity</th>
  <th style="width:100px">Module</th>
  <th>Finding</th>
  <th style="width:130px">Timestamp</th>
</tr></thead><tbody id="tbody">
HTMLHEAD
 
    # Write table rows
    local row=0
    if [[ -s "$FINDINGS_JSONL" ]]; then
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        row=$((row + 1))
 
        local sev mod title desc evid rec ts
        sev=$(_get_field   "$line" "severity"       "INFO")
        mod=$(_get_field   "$line" "module"         "-")
        title=$(_get_field  "$line" "title"         "Untitled")
        desc=$(_get_field   "$line" "description"   "")
        evid=$(_get_field   "$line" "evidence"      "")
        rec=$(_get_field    "$line" "recommendation" "")
        ts=$(_get_field     "$line" "timestamp"      "")
 
        # Escape for HTML
        local htitle hmod hdesc hevid hrec
        htitle=$(_hesc "$title")
        hmod=$(_hesc "$mod")
        hdesc=$(_hesc "$desc")
        hevid=$(_hesc "$evid")
        hrec=$(_hesc "$rec")
 
        # Badge class
        local bcls="bci"
        case "$sev" in
          CRITICAL) bcls="bcc" ;; HIGH) bcls="bch" ;;
          MEDIUM)   bcls="bcm" ;; LOW)  bcls="bcl" ;;
        esac
 
        local srchdata
        srchdata=$(printf '%s %s %s %s' "$sev" "$mod" "$title" "$desc" | tr '[:upper:]' '[:lower:]')
 
        {
          printf '<tr data-sev="%s" data-q="%s">\n' "$sev" "$srchdata"
          printf '<td>%d</td>\n' "$row"
          printf '<td><span class="badge %s">%s</span></td>\n' "$bcls" "$sev"
          printf '<td><span class="mtag">%s</span></td>\n' "$hmod"
          printf '<td><strong>%s</strong>' "$htitle"
          [[ -n "$hdesc" ]] && printf '<br><small style="color:var(--mu)">%s</small>' "$hdesc"
          [[ -n "$hevid" ]] && printf '<div class="ev">%s</div>' "$hevid"
          [[ -n "$hrec"  ]] && printf '<div class="fix">%s</div>' "$hrec"
          printf '</td>\n'
          printf '<td style="font-family:var(--fc);font-size:11px;color:var(--mu);white-space:nowrap">%s</td>\n' "$ts"
          printf '</tr>\n'
        } >> "$REPORT_HTML"
 
      done < "$FINDINGS_JSONL"
    fi
 
    # Write HTML footer
    cat >> "$REPORT_HTML" << HTMLFOOT
</tbody></table>
</main>
<footer>Generated by <strong>websec-audit</strong> v${TOOL_VERSION} — <a href="${TOOL_URL}">${TOOL_URL}</a> — Authorised use only</footer>
<script>
var cur='ALL',srchTerm='';
function filt(s,btn){
  cur=s;
  document.querySelectorAll('.fb').forEach(function(b){b.classList.remove('active')});
  btn.classList.add('active');
  update();
}
function srch(v){srchTerm=v.toLowerCase();update();}
function update(){
  var rows=document.querySelectorAll('#tbody tr'),vis=0;
  rows.forEach(function(r){
    var sm=cur==='ALL'||r.dataset.sev===cur;
    var qm=!srchTerm||(r.dataset.q||'').includes(srchTerm);
    r.hidden=!(sm&&qm);
    if(sm&&qm)vis++;
  });
  document.getElementById('empty').style.display=vis===0?'':'none';
}
</script>
</body></html>
HTMLFOOT
 
    log_ok "HTML report → $REPORT_HTML"
  fi
}


# ─────────────────────────────────────────────────────────────────────────────
#  FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print_summary() {
  log_section "AUDIT COMPLETE"

  local elapsed; elapsed=$(elapsed_secs)
  local risk="LOW"
  [[ $COUNT_MEDIUM -gt 0 ]] && risk="MEDIUM"
  [[ $COUNT_HIGH -gt 0 ]]   && risk="HIGH"
  [[ $COUNT_CRITICAL -gt 0 ]] && risk="CRITICAL"

  local risk_color="$C_CYAN"
  case "$risk" in
    CRITICAL) risk_color="$C_RED" ;;
    HIGH)     risk_color="$C_MAGENTA" ;;
    MEDIUM)   risk_color="$C_YELLOW" ;;
  esac

  echo ""
  echo -e "${C_BOLD}"
  printf "  ┌───────────────────────────────────────────────────┐\n"
  printf "  │  %-49s│\n" "TARGET : $TARGET"
  printf "  │  %-49s│\n" "IP     : ${TARGET_IP:-N/A}"
  printf "  │  ${risk_color}%-49s${C_RESET}${C_BOLD}│\n" "RISK   : $risk"
  printf "  ├───────────────────────────────────────────────────┤\n"
  printf "  │  ${C_RED}%-49s${C_RESET}${C_BOLD}│\n" "CRITICAL  : $COUNT_CRITICAL"
  printf "  │  ${C_MAGENTA}%-49s${C_RESET}${C_BOLD}│\n" "HIGH      : $COUNT_HIGH"
  printf "  │  ${C_YELLOW}%-49s${C_RESET}${C_BOLD}│\n" "MEDIUM    : $COUNT_MEDIUM"
  printf "  │  ${C_CYAN}%-49s${C_RESET}${C_BOLD}│\n" "LOW       : $COUNT_LOW"
  printf "  │  ${C_DIM}%-49s${C_RESET}${C_BOLD}│\n" "INFO      : $COUNT_INFO"
  printf "  ├───────────────────────────────────────────────────┤\n"
  printf "  │  %-49s│\n" "TOTAL     : $TOTAL_FINDINGS finding(s)"
  printf "  │  %-49s│\n" "DURATION  : ${elapsed}s"
  printf "  └───────────────────────────────────────────────────┘\n"
  echo -e "${C_RESET}"

  echo ""
  log_ok "Output directory : $OUTPUT_DIR"
  log_ok "HTML report      : $REPORT_HTML"
  log_ok "JSON report      : $REPORT_JSON"
  log_ok "TXT report       : $REPORT_TXT"
  log_ok "Audit log        : $LOG_FILE"
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
#  SIGNAL HANDLING & CLEANUP
# ─────────────────────────────────────────────────────────────────────────────
handle_interrupt() {
  echo ""
  log_warn "Audit interrupted by user (SIGINT/SIGTERM)"
  [[ -f "$LOG_FILE" ]] && echo "[INTERRUPTED] PID=$AUDIT_PID" >> "$LOG_FILE"
  # Try to generate partial reports
  generate_reports 2>/dev/null || true
  print_summary    2>/dev/null || true
  exit 130
}

trap 'handle_interrupt' INT TERM

# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
main() {
  AUDIT_START_TIME=$(date +%s)

  parse_args "$@"
  print_banner

  # Legal notice
  echo -e "${C_RED}${C_BOLD}"
  printf "  ╔═══════════════════════════════════════════════════╗\n"
  printf "  ║  ⚠  LEGAL NOTICE                                 ║\n"
  printf "  ║  This tool may only be used against systems you  ║\n"
  printf "  ║  own or have explicit written authorisation to   ║\n"
  printf "  ║  test. Unauthorised use is illegal.              ║\n"
  printf "  ╚═══════════════════════════════════════════════════╝\n"
  echo -e "${C_RESET}"
  read -r -t 5 -p "  Press ENTER to continue (auto-continues in 5s)..." 2>/dev/null || true
  echo ""
  echo ""

  log_info "Starting ${TOOL_NAME} v${TOOL_VERSION} | PID: ${AUDIT_PID}"

  module_check_deps
  module_target_info
  module_recon
  module_portscan
  module_fingerprint
  module_ssl
  module_headers
  module_dirbrute
  module_nikto
  module_sqli
  module_xss
  module_cms
  module_cors
  module_open_redirect
  module_ssrf
  module_subtakeover
  module_nuclei
  generate_reports
  print_summary
}

main "$@"
