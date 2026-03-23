#!/usr/bin/env bash
# =============================================================================
#
#   install.sh — Dependency installer for websec-audit
#   Supported: Debian 11/12/13, Ubuntu 20.04/22.04/24.04
#
#   Author  : davidalvarezp
#   Version : 1.0.1
#   License : MIT
#   GitHub  : https://github.com/davidalvarezp/websec-audit
#
# =============================================================================

set -euo pipefail

readonly SCRIPT_VERSION="1.0.1"
readonly INSTALL_LOG="/tmp/websec_install_$(date +%Y%m%d_%H%M%S).log"

# ── Colors ────────────────────────────────────────────────────────────────────
C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'; C_BLUE='\033[0;34m'; C_BOLD='\033[1m'; C_RESET='\033[0m'

ok()   { echo -e "${C_GREEN}  [✔]${C_RESET} $1" | tee -a "$INSTALL_LOG"; }
info() { echo -e "${C_BLUE}  [i]${C_RESET} $1" | tee -a "$INSTALL_LOG"; }
warn() { echo -e "${C_YELLOW}  [!]${C_RESET} $1" | tee -a "$INSTALL_LOG"; }
err()  { echo -e "${C_RED}  [✘]${C_RESET} $1" | tee -a "$INSTALL_LOG" >&2; }
step() { echo -e "\n${C_BOLD}${C_CYAN}  ── $1 ──${C_RESET}" | tee -a "$INSTALL_LOG"; }

has_tool() { command -v "$1" &>/dev/null; }

# ── Privilege check ───────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { err "Run as root: sudo $0"; exit 1; }

echo -e "${C_BOLD}${C_CYAN}"
cat << 'BANNER'
  ╔═════════════════════════════════════════════════╗
  ║   websec-audit — Dependency Installer           ║
  ║   Debian / Ubuntu                               ║
  ╚═════════════════════════════════════════════════╝
BANNER
echo -e "${C_RESET}"
echo "  Install log: $INSTALL_LOG"
echo ""

# ── System check ──────────────────────────────────────────────────────────────
step "System Verification"
OS_ID=$(grep "^ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
OS_VER=$(grep "^VERSION_ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "?")
ARCH=$(uname -m)

info "OS: $OS_ID $OS_VER | Arch: $ARCH"
[[ "$OS_ID" =~ ^(debian|ubuntu|kali|parrot)$ ]] || warn "Untested OS: $OS_ID — proceeding anyway"

# ── APT packages ──────────────────────────────────────────────────────────────
step "APT Package Installation"
info "Updating package lists..."
apt-get update -qq 2>>"$INSTALL_LOG"

APT_PACKAGES=(
  # Core tools
  curl wget git nmap
  # Web scanners
  nikto sqlmap dirb
  # DNS & network
  dnsutils bind9-dnsutils whois dnsmap
  # Fingerprinting & WAF
  whatweb wafw00f
  # SSL
  sslscan openssl
  # Wordlists
  wordlists
  # Languages & build deps
  python3 python3-pip jq
  ruby ruby-dev build-essential libssl-dev libffi-dev
  # gobuster (if packaged)
  gobuster
)

for pkg in "${APT_PACKAGES[@]}"; do
  if apt-get install -y -qq "$pkg" >>"$INSTALL_LOG" 2>&1; then
    ok "$pkg"
  else
    warn "$pkg — install failed or not available (will try alternative)"
  fi
done

# ── WPScan (gem) ──────────────────────────────────────────────────────────────
step "WPScan"
if has_tool wpscan; then
  ok "wpscan already installed ($(wpscan --version 2>/dev/null | head -1))"
else
  info "Installing wpscan via gem..."
  if gem install wpscan --no-document >>"$INSTALL_LOG" 2>&1; then
    ok "wpscan installed"
  else
    warn "wpscan installation failed"
  fi
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
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
      >>"$INSTALL_LOG" 2>&1
  fi
  ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
  chmod +x /opt/testssl.sh/testssl.sh
  ok "testssl.sh installed → /usr/local/bin/testssl.sh"
fi

# ── Go binary installer helper ────────────────────────────────────────────────
install_go_binary() {
  local name="$1" url="$2" binary="${3:-$1}"
  if has_tool "$name"; then
    ok "$name already installed"
    return 0
  fi
  info "Downloading $name..."
  local tmp; tmp=$(mktemp)
  local ext="${url##*.}"

  if wget -q "$url" -O "$tmp" >>"$INSTALL_LOG" 2>&1; then
    case "$ext" in
      gz)
        tar -xzf "$tmp" -C /usr/local/bin/ "$binary" >>"$INSTALL_LOG" 2>&1 && \
          chmod +x "/usr/local/bin/$binary" && ok "$name installed" || warn "$name: extraction failed" ;;
      zip)
        unzip -q -o "$tmp" "$binary" -d /usr/local/bin/ >>"$INSTALL_LOG" 2>&1 && \
          chmod +x "/usr/local/bin/$binary" && ok "$name installed" || warn "$name: extraction failed" ;;
      *)
        mv "$tmp" "/usr/local/bin/$binary"
        chmod +x "/usr/local/bin/$binary" && ok "$name installed" || warn "$name: install failed" ;;
    esac
  else
    warn "$name: download failed"
  fi
  rm -f "$tmp"
}

# Detect arch for Go binaries
case "$ARCH" in
  x86_64|amd64) BIN_ARCH="amd64" ;;
  aarch64|arm64) BIN_ARCH="arm64" ;;
  armv7*) BIN_ARCH="arm" ;;
  *) BIN_ARCH="amd64"; warn "Unknown arch $ARCH — assuming amd64" ;;
esac

# ── gobuster ──────────────────────────────────────────────────────────────────
step "gobuster"
if ! has_tool gobuster; then
  install_go_binary "gobuster" \
    "https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_${BIN_ARCH}.tar.gz" \
    "gobuster"
fi

# ── ffuf ─────────────────────────────────────────────────────────────────────
step "ffuf"
if ! has_tool ffuf; then
  install_go_binary "ffuf" \
    "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest 2>/dev/null | grep -oP '"tag_name": "v\K[^"]+' | head -1 || echo '2.1.0')_linux_${BIN_ARCH}.tar.gz" \
    "ffuf"
fi

# ── subfinder ─────────────────────────────────────────────────────────────────
step "subfinder"
if ! has_tool subfinder; then
  install_go_binary "subfinder" \
    "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_${BIN_ARCH}.zip" \
    "subfinder"
fi

# ── dalfox ────────────────────────────────────────────────────────────────────
step "dalfox (XSS scanner)"
if ! has_tool dalfox; then
  local DALFOX_VER
  DALFOX_VER=$(curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest 2>/dev/null | grep -oP '"tag_name": "v\K[^"]+' | head -1 || echo "2.9.1")
  install_go_binary "dalfox" \
    "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VER}/dalfox_linux_${BIN_ARCH}.tar.gz" \
    "dalfox"
fi

# ── subjack ───────────────────────────────────────────────────────────────────
step "subjack (subdomain takeover)"
if ! has_tool subjack; then
  if wget -q "https://github.com/haccer/subjack/releases/latest/download/subjack-linux-${BIN_ARCH}" \
     -O /usr/local/bin/subjack >>"$INSTALL_LOG" 2>&1; then
    chmod +x /usr/local/bin/subjack
    ok "subjack installed"
  else
    warn "subjack download failed"
  fi
fi

# ── nuclei ────────────────────────────────────────────────────────────────────
step "nuclei"
if ! has_tool nuclei; then
  install_go_binary "nuclei" \
    "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${BIN_ARCH}.zip" \
    "nuclei"
fi

if has_tool nuclei; then
  info "Updating Nuclei templates..."
  nuclei -update-templates -silent >>"$INSTALL_LOG" 2>&1 || warn "Template update failed (try: nuclei -update-templates)"
  ok "Nuclei templates updated"
fi

# ── amass ─────────────────────────────────────────────────────────────────────
step "amass"
if ! has_tool amass; then
  if apt-get install -y -qq amass >>"$INSTALL_LOG" 2>&1; then
    ok "amass installed via apt"
  else
    local AMASS_VER
    AMASS_VER=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest 2>/dev/null | grep -oP '"tag_name": "v\K[^"]+' | head -1 || echo "4.2.0")
    install_go_binary "amass" \
      "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VER}/amass_Linux_${BIN_ARCH}.zip" \
      "amass"
  fi
fi

# ── droopescan ────────────────────────────────────────────────────────────────
step "droopescan (Drupal/Joomla scanner)"
if ! has_tool droopescan; then
  if pip3 install droopescan --quiet >>"$INSTALL_LOG" 2>&1; then
    ok "droopescan installed"
  else
    warn "droopescan installation failed"
  fi
fi

# ── SecLists wordlists ────────────────────────────────────────────────────────
step "SecLists Wordlists"
if [[ -d /usr/share/seclists ]]; then
  ok "SecLists already present at /usr/share/seclists"
else
  # Try apt first
  if apt-get install -y -qq seclists >>"$INSTALL_LOG" 2>&1; then
    ok "SecLists installed via apt"
  else
    info "Cloning SecLists from GitHub (this may take a while)..."
    if git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
       /usr/share/seclists >>"$INSTALL_LOG" 2>&1; then
      ok "SecLists installed at /usr/share/seclists"
    else
      warn "SecLists clone failed — install manually"
    fi
  fi
fi

# Decompress rockyou if needed
[[ -f /usr/share/wordlists/rockyou.txt.gz && ! -f /usr/share/wordlists/rockyou.txt ]] && \
  gunzip /usr/share/wordlists/rockyou.txt.gz && ok "rockyou.txt decompressed"

# ── dnsrecon ──────────────────────────────────────────────────────────────────
step "dnsrecon"
if ! has_tool dnsrecon; then
  apt-get install -y -qq dnsrecon >>"$INSTALL_LOG" 2>&1 || \
    pip3 install dnsrecon --quiet >>"$INSTALL_LOG" 2>&1 || \
    warn "dnsrecon not installed"
  has_tool dnsrecon && ok "dnsrecon installed"
fi

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${C_BOLD}${C_CYAN}  ═══════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}  Installation Summary${C_RESET}"
echo ""

TOOLS=(
  "curl" "nmap" "nikto" "sqlmap" "gobuster" "ffuf" "dirb"
  "whatweb" "wafw00f" "sslscan" "testssl.sh" "wpscan"
  "subfinder" "amass" "dnsrecon" "dalfox" "subjack" "nuclei"
  "droopescan" "dig" "host" "whois" "jq" "python3" "ruby"
)

installed=0; missing=0
for t in "${TOOLS[@]}"; do
  if has_tool "$t"; then
    printf "  ${C_GREEN}✔${C_RESET} %-20s %s\n" "$t" "($(command -v "$t"))"
    installed=$((installed + 1))
  else
    printf "  ${C_YELLOW}○${C_RESET} %-20s %s\n" "$t" "(not found)"
    missing=$((missing + 1))
  fi
done

echo ""
echo -e "  ${C_BOLD}Installed: ${C_GREEN}${installed}${C_RESET}  |  ${C_BOLD}Missing: ${C_YELLOW}${missing}${C_RESET}"
echo ""
echo -e "  ${C_DIM}Full log: ${INSTALL_LOG}${C_RESET}"
echo ""
echo -e "  ${C_BOLD}Usage:${C_RESET}"
echo "  chmod +x websec-audit.sh"
echo "  ./websec-audit.sh -t https://target.com"
echo "  ./websec-audit.sh -t https://target.com --aggressive -T 20"
echo ""
