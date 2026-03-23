#!/usr/bin/env bash
# =============================================================================
#   install.sh — Dependency installer for websec-audit
#   Debian 10/../13 · Ubuntu 20.04/../26.04 · Kali
#   Author  : davidalvarezp
#   License : MIT
# =============================================================================
set -euo pipefail

INSTALL_LOG="/tmp/websec_install_$(date +%Y%m%d_%H%M%S).log"

C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'; C_BLUE='\033[0;34m'; C_BOLD='\033[1m'; C_RESET='\033[0m'

ok()   { echo -e "${C_GREEN}  [✔]${C_RESET} $1" | tee -a "$INSTALL_LOG"; }
info() { echo -e "${C_BLUE}  [i]${C_RESET} $1" | tee -a "$INSTALL_LOG"; }
warn() { echo -e "${C_YELLOW}  [!]${C_RESET} $1" | tee -a "$INSTALL_LOG"; }
err()  { echo -e "${C_RED}  [✘]${C_RESET} $1" | tee -a "$INSTALL_LOG" >&2; }
step() { echo -e "\n${C_BOLD}${C_CYAN}  ── $1 ──${C_RESET}" | tee -a "$INSTALL_LOG"; }
has_tool() { command -v "$1" &>/dev/null; }

[[ $EUID -ne 0 ]] && { err "Run as root: sudo $0"; exit 1; }

echo -e "${C_BOLD}${C_CYAN}"
cat << 'BANNER'
  ╔═══════════════════════════════════════════╗
  ║   WebSec-Audit — Dependency Installer     ║
  ╚═══════════════════════════════════════════╝
BANNER
echo -e "${C_RESET}"
echo "  Install log: $INSTALL_LOG"
echo ""

# ── System check ──────────────────────────────────────────────────────────────
step "System Verification"
OS_ID=$(grep "^ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
OS_VER=$(grep "^VERSION_ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "?")
ARCH=$(uname -m)
BIN_ARCH="amd64"
[[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && BIN_ARCH="arm64"

info "OS: $OS_ID $OS_VER | Arch: $ARCH ($BIN_ARCH)"

# ── APT packages ──────────────────────────────────────────────────────────────
step "APT Package Installation"
info "Updating package lists..."
apt-get update -qq 2>>"$INSTALL_LOG"

APT_PACKAGES=(
  curl wget git nmap
  sqlmap dirb gobuster
  dnsutils bind9-dnsutils whois dnsmap
  whatweb wafw00f
  sslscan openssl
  python3 python3-pip jq
  ruby ruby-dev build-essential libssl-dev libffi-dev
)

for pkg in "${APT_PACKAGES[@]}"; do
  if apt-get install -y -qq "$pkg" >>"$INSTALL_LOG" 2>&1; then
    ok "$pkg"
  else
    warn "$pkg — not available via APT"
  fi
done

# ── Nikto (install from GitHub — not in Debian 12 main repos) ─────────────────
step "Nikto"
if has_tool nikto; then
  ok "nikto already installed"
else
  info "Installing nikto from GitHub..."
  if [[ -d /opt/nikto ]]; then
    git -C /opt/nikto pull -q >>"$INSTALL_LOG" 2>&1 || true
  else
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto >>"$INSTALL_LOG" 2>&1
  fi

  # Create wrapper script
  cat > /usr/local/bin/nikto << 'NIKTO_WRAPPER'
#!/usr/bin/env bash
exec perl /opt/nikto/program/nikto.pl "$@"
NIKTO_WRAPPER
  chmod +x /usr/local/bin/nikto

  # Ensure perl and required modules are installed
  apt-get install -y -qq perl libnet-ssleay-perl >>"$INSTALL_LOG" 2>&1 || true

  if has_tool nikto; then
    ok "nikto installed → /usr/local/bin/nikto"
  else
    warn "nikto installation failed — check $INSTALL_LOG"
  fi
fi

# ── Wordlists ─────────────────────────────────────────────────────────────────
step "Wordlists"
# dirb wordlists (always available with dirb)
if [[ -f /usr/share/dirb/wordlists/common.txt ]]; then
  ok "dirb wordlists present"
elif [[ -f /usr/share/wordlists/dirb/common.txt ]]; then
  ok "dirb wordlists present"
fi

# Try wordlists package (may require contrib/non-free on some systems)
if [[ ! -f /usr/share/wordlists/rockyou.txt ]] && \
   [[ ! -f /usr/share/wordlists/rockyou.txt.gz ]]; then
  apt-get install -y -qq wordlists >>"$INSTALL_LOG" 2>&1 || true
fi

# Decompress rockyou if needed
if [[ -f /usr/share/wordlists/rockyou.txt.gz && \
      ! -f /usr/share/wordlists/rockyou.txt ]]; then
  gunzip /usr/share/wordlists/rockyou.txt.gz && ok "rockyou.txt decompressed"
fi

# Ensure the websec-audit default wordlist paths exist
# Create symlinks from dirb paths if needed
WL_DIR="/usr/share/wordlists"
mkdir -p "$WL_DIR"

if [[ ! -f "${WL_DIR}/dirb/common.txt" ]]; then
  mkdir -p "${WL_DIR}/dirb"
  if [[ -f /usr/share/dirb/wordlists/common.txt ]]; then
    ln -sf /usr/share/dirb/wordlists/common.txt "${WL_DIR}/dirb/common.txt"
    ok "Symlinked dirb wordlist → ${WL_DIR}/dirb/common.txt"
  fi
fi

ok "Wordlists ready"

# ── Go binary installer helper ────────────────────────────────────────────────
# NOTE: No 'local' here — this is a top-level function, all vars are local inside it
install_go_binary() {
  local name="$1"
  local url="$2"
  local binary="${3:-$1}"
  local tmp_file

  if has_tool "$name"; then
    ok "$name already installed"
    return 0
  fi

  info "Downloading $name from GitHub..."
  tmp_file=$(mktemp)

  if wget -q --timeout=30 "$url" -O "$tmp_file" >>"$INSTALL_LOG" 2>&1; then
    local ext="${url##*.}"
    if [[ "$ext" == "gz" || "$url" == *".tar.gz" ]]; then
      tar -xzf "$tmp_file" -C /usr/local/bin/ "$binary" >>"$INSTALL_LOG" 2>&1 \
        && chmod +x "/usr/local/bin/$binary" \
        && ok "$name installed" \
        || { warn "$name: extraction failed"; rm -f "$tmp_file"; return 1; }
    elif [[ "$ext" == "zip" ]]; then
      apt-get install -y -qq unzip >>"$INSTALL_LOG" 2>&1 || true
      unzip -q -o "$tmp_file" "$binary" -d /usr/local/bin/ >>"$INSTALL_LOG" 2>&1 \
        && chmod +x "/usr/local/bin/$binary" \
        && ok "$name installed" \
        || { warn "$name: extraction failed"; rm -f "$tmp_file"; return 1; }
    else
      mv "$tmp_file" "/usr/local/bin/$binary"
      chmod +x "/usr/local/bin/$binary"
      ok "$name installed"
    fi
  else
    warn "$name: download failed (check internet connection)"
  fi

  rm -f "$tmp_file"
}

# Get latest tag from GitHub API (no local outside function)
get_latest_tag() {
  curl -s --max-time 10 \
    "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
  | grep -oP '"tag_name":\s*"v?\K[^"]+' | head -1 || echo "$2"
}

# ── gobuster (already installed via APT, skip if present) ─────────────────────
step "gobuster"
if has_tool gobuster; then
  ok "gobuster already installed (APT)"
else
  install_go_binary "gobuster" \
    "https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_${BIN_ARCH}.tar.gz" \
    "gobuster"
fi

# ── ffuf ─────────────────────────────────────────────────────────────────────
step "ffuf"
if has_tool ffuf; then
  ok "ffuf already installed"
else
  FFUF_VER=$(get_latest_tag "ffuf/ffuf" "2.1.0")
  install_go_binary "ffuf" \
    "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_${BIN_ARCH}.tar.gz" \
    "ffuf"
fi

# ── subfinder ─────────────────────────────────────────────────────────────────
step "subfinder"
if has_tool subfinder; then
  ok "subfinder already installed"
else
  SUBFINDER_VER=$(get_latest_tag "projectdiscovery/subfinder" "2.6.3")
  install_go_binary "subfinder" \
    "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VER}/subfinder_${SUBFINDER_VER}_linux_${BIN_ARCH}.zip" \
    "subfinder"
fi

# ── dalfox ────────────────────────────────────────────────────────────────────
step "dalfox (XSS scanner)"
if has_tool dalfox; then
  ok "dalfox already installed"
else
  DALFOX_VER=$(get_latest_tag "hahwul/dalfox" "2.9.2")
  install_go_binary "dalfox" \
    "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VER}/dalfox_linux_${BIN_ARCH}.tar.gz" \
    "dalfox"
fi

# ── subjack ───────────────────────────────────────────────────────────────────
step "subjack"
if has_tool subjack; then
  ok "subjack already installed"
else
  info "Downloading subjack..."
  SUBJACK_URL="https://github.com/haccer/subjack/releases/latest/download/subjack-linux-${BIN_ARCH}"
  if wget -q --timeout=30 "$SUBJACK_URL" -O /usr/local/bin/subjack >>"$INSTALL_LOG" 2>&1; then
    chmod +x /usr/local/bin/subjack
    ok "subjack installed"
  else
    warn "subjack download failed"
  fi
fi

# ── nuclei ────────────────────────────────────────────────────────────────────
step "nuclei"
if has_tool nuclei; then
  ok "nuclei already installed"
else
  NUCLEI_VER=$(get_latest_tag "projectdiscovery/nuclei" "3.2.0")
  install_go_binary "nuclei" \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${BIN_ARCH}.zip" \
    "nuclei"
fi

if has_tool nuclei; then
  info "Updating Nuclei templates..."
  nuclei -update-templates -silent >>"$INSTALL_LOG" 2>&1 \
    && ok "Nuclei templates updated" \
    || warn "Template update failed — run: nuclei -update-templates"
fi

# ── amass ─────────────────────────────────────────────────────────────────────
step "amass"
if has_tool amass; then
  ok "amass already installed"
else
  if apt-get install -y -qq amass >>"$INSTALL_LOG" 2>&1; then
    ok "amass installed via APT"
  else
    AMASS_VER=$(get_latest_tag "owasp-amass/amass" "4.2.0")
    install_go_binary "amass" \
      "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VER}/amass_Linux_${BIN_ARCH}.zip" \
      "amass"
  fi
fi

# ── dnsrecon ──────────────────────────────────────────────────────────────────
step "dnsrecon"
if has_tool dnsrecon; then
  ok "dnsrecon already installed"
else
  apt-get install -y -qq dnsrecon >>"$INSTALL_LOG" 2>&1 \
    || pip3 install dnsrecon --quiet >>"$INSTALL_LOG" 2>&1 \
    || warn "dnsrecon not installed"
  has_tool dnsrecon && ok "dnsrecon installed"
fi

# ── droopescan ────────────────────────────────────────────────────────────────
step "droopescan"
if has_tool droopescan; then
  ok "droopescan already installed"
else
  if pip3 install droopescan --quiet >>"$INSTALL_LOG" 2>&1; then
    ok "droopescan installed"
  else
    warn "droopescan installation failed"
  fi
fi

# ── WPScan ────────────────────────────────────────────────────────────────────
step "WPScan"
if has_tool wpscan; then
  ok "wpscan already installed"
else
  info "Installing wpscan via gem..."
  gem install wpscan --no-document >>"$INSTALL_LOG" 2>&1 \
    && ok "wpscan installed" \
    || warn "wpscan installation failed"
fi

# ── testssl.sh ────────────────────────────────────────────────────────────────
step "testssl.sh"
if has_tool testssl.sh; then
  ok "testssl.sh already installed"
else
  info "Installing testssl.sh from GitHub..."
  if [[ -d /opt/testssl.sh ]]; then
    git -C /opt/testssl.sh pull -q >>"$INSTALL_LOG" 2>&1 || true
  else
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git \
      /opt/testssl.sh >>"$INSTALL_LOG" 2>&1
  fi
  ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
  chmod +x /opt/testssl.sh/testssl.sh
  ok "testssl.sh installed"
fi

# ── SecLists ──────────────────────────────────────────────────────────────────
step "SecLists"
if [[ -d /usr/share/seclists ]]; then
  ok "SecLists already present"
else
  if apt-get install -y -qq seclists >>"$INSTALL_LOG" 2>&1; then
    ok "SecLists installed via APT"
  else
    info "Cloning SecLists (this may take a while)..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
      /usr/share/seclists >>"$INSTALL_LOG" 2>&1 \
      && ok "SecLists installed" \
      || warn "SecLists clone failed — install manually"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${C_BOLD}${C_CYAN}  ═══════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}  Installation Summary${C_RESET}"
echo ""

TOOLS=(
  curl nmap nikto sqlmap gobuster ffuf dirb
  whatweb wafw00f sslscan testssl.sh wpscan
  subfinder amass dnsrecon dalfox subjack nuclei
  droopescan dig host whois jq python3 ruby
)

installed=0; missing=0
for t in "${TOOLS[@]}"; do
  if has_tool "$t"; then
    printf "  ${C_GREEN}✔${C_RESET} %-20s\n" "$t"
    installed=$((installed + 1))
  else
    printf "  ${C_YELLOW}○${C_RESET} %-20s %s\n" "$t" "(not found)"
    missing=$((missing + 1))
  fi
done

echo ""
echo -e "  ${C_BOLD}Installed: ${C_GREEN}${installed}${C_RESET}  |  Missing: ${C_YELLOW}${missing}${C_RESET}"
echo ""
echo -e "  ${C_DIM}Full log: ${INSTALL_LOG}${C_RESET}"
echo ""
echo -e "  ${C_BOLD}Usage:${C_RESET}"
echo "  chmod +x websec-audit.sh"
echo "  ./websec-audit.sh -t https://target.com"
echo ""