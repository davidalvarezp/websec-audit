<div align="center">

# WebSec-Audit

**Professional Web Security Audit Framework**

[![Version](https://img.shields.io/badge/version-1.0.1-blue?style=flat-square)](https://github.com/davidalvarezp/websec-audit/releases)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-5.0%2B-orange?style=flat-square)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Kali-lightgrey?style=flat-square)](https://github.com/davidalvarezp/websec-audit)
[![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen?style=flat-square)](https://github.com/davidalvarezp/websec-audit/commits/main)

A modular, extensible Bash framework for **comprehensive web application security assessments**.  
Automates 15+ attack surface modules, generates structured logs, and produces professional reports in HTML, JSON and TXT.

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Modules](#-modules) · [Output](#-output-structure) · [Contributing](#-contributing)

---
![WebSec-Audit Start](https://raw.githubusercontent.com/davidalvarezp/websec-audit/main/demo/1_start.png)

![WebSec-Audit End](https://raw.githubusercontent.com/davidalvarezp/websec-audit/main/demo/2_end.png)

</div>

---

## ⚠️ Legal Disclaimer

> **This tool is intended exclusively for authorised security assessments.**  
> Only run it against systems you own or have **explicit written permission** to test.  
> Unauthorised use against third-party systems is illegal and may result in criminal prosecution.  
> The author assumes **no liability** whatsoever for misuse of this software.

---

## ✨ Features

- **15+ security modules** — recon, port scanning, SSL/TLS, headers, SQLi, XSS, CMS, CORS, SSRF, subdomain takeover, and more
- **Modular architecture** — enable or disable any module independently via `--skip-<module>`
- **Three scan modes** — Normal, Aggressive (`--aggressive`), Stealth (`--stealth`)
- **Professional reporting** — interactive HTML dashboard, structured JSON, and plain-text log
- **Tool-agnostic** — gracefully degrades to fallbacks when optional tools are absent
- **Smart finding engine** — findings stored as JSONL with severity, module, evidence, and remediation
- **Proxy support** — route all traffic through Burp Suite or any HTTP proxy
- **CVSS-aligned severities** — CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Zero external dependencies** — core scan works with only `curl` and `nmap`

---

## 📦 Installation

### Quick Install (recommended)

```bash
git clone https://github.com/davidalvarezp/websec-audit.git
cd websec-audit
chmod +x install.sh websec-audit.sh
sudo ./install.sh
```

### Manual (Debian/Ubuntu)

```bash
# Required
sudo apt-get install -y curl nmap

# Recommended
sudo apt-get install -y nikto sqlmap gobuster whatweb wafw00f sslscan \
    python3 python3-pip jq ruby dirb dnsutils whois wordlists

# Optional (improves coverage significantly)
pip3 install droopescan
gem install wpscan --no-document
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
sudo ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
```

### Kali Linux

Most tools are pre-installed. Run:
```bash
sudo apt-get install -y gobuster dalfox subjack nuclei subfinder
./install.sh   # handles remaining gaps
```

---

## 🚀 Usage

### Basic

```bash
./websec-audit.sh -t https://target.com
```

### Aggressive (deeper, noisier)

```bash
./websec-audit.sh -t https://target.com --aggressive -T 20
```

### Stealth (slower, lower detection footprint)

```bash
./websec-audit.sh -t https://target.com --stealth
```

### Through a proxy (Burp Suite)

```bash
./websec-audit.sh -t https://target.com --proxy http://127.0.0.1:8080
```

### Custom output directory and JSON-only report

```bash
./websec-audit.sh -t https://target.com -o /tmp/audit --format json
```

### Skip specific modules

```bash
./websec-audit.sh -t https://target.com --skip-nikto --skip-sqli --skip-cms -v
```

### Full port scan with aggressive mode

```bash
./websec-audit.sh -t https://target.com --ports full --aggressive --depth 5
```

---

## 📋 Full Options Reference

```
REQUIRED
  -t, --target <url|ip>       Target URL or IP address

OUTPUT
  -o, --output <dir>          Output directory
      --format <fmt>          json | html | txt | all  (default: all)

SCAN OPTIONS
  -T, --threads <n>           Concurrent threads  (default: 10)
  -p, --ports <profile>       top-100 | top-1000 | full  (default: top-1000)
      --timeout <s>           Connection timeout  (default: 10)
      --depth <n>             Crawl depth  (default: 3)
      --proxy <url>           HTTP/HTTPS proxy
      --aggressive            Aggressive mode
      --stealth               Stealth mode

MODULE CONTROL (--skip-<module>)
  --skip-recon                WHOIS, DNS, subdomain enumeration
  --skip-portscan             nmap port scanning
  --skip-fingerprint          WhatWeb, WAF detection
  --skip-ssl                  SSL/TLS analysis
  --skip-headers              HTTP security headers
  --skip-dirbrute             Directory/file brute-forcing
  --skip-nikto                Nikto web scanner
  --skip-sqli                 SQL injection (sqlmap)
  --skip-xss                  XSS (dalfox + manual)
  --skip-cms                  CMS detection & scanning
  --skip-cors                 CORS misconfiguration
  --skip-redirect             Open redirect
  --skip-ssrf                 SSRF
  --skip-subtakeover          Subdomain takeover
  --skip-nuclei               Nuclei template scan

WORDLISTS
  --wl-dirs-small <file>      Small wordlist for directory brute-force
  --wl-dirs-big <file>        Large wordlist for directory brute-force
  --wl-dns <file>             DNS subdomain wordlist

MISC
  -v, --verbose               Verbose output
      --no-color              Disable ANSI colors
      --no-banner             Suppress banner
  -V, --version               Version info
  -h, --help                  Help
```

---

## 🔍 Modules

| # | Module | Description | Key Tools |
|---|--------|-------------|-----------|
| 00 | **Target Info** | Resolve IP, initialise directories | `dig`, `host` |
| 01 | **Reconnaissance** | WHOIS, DNS records, AXFR, subdomain enum, SPF/DMARC, dorks | `whois`, `dig`, `subfinder`, `amass`, `dnsrecon` |
| 02 | **Port Scanning** | Full service/version detection, risk-based port analysis | `nmap` |
| 03 | **Fingerprinting** | Technology stack, WAF detection, version leakage | `whatweb`, `wafw00f` |
| 04 | **SSL/TLS** | Protocol support, ciphers, cert expiry, HSTS, CAA | `testssl.sh`, `sslscan`, `openssl` |
| 05 | **HTTP Headers** | 7+ security headers, cookie flags, CSP audit, HTTPS redirect | `curl` |
| 06 | **Dir & File Enum** | Directory brute-force + 40 sensitive path probes | `gobuster`, `ffuf`, `dirb` |
| 07 | **Nikto** | Web server misconfigurations, known CVEs | `nikto` |
| 08 | **SQL Injection** | Automated SQLi detection and exploitation | `sqlmap` |
| 09 | **XSS** | Reflected XSS probe across common parameters + DOM XSS | `dalfox`, `curl` |
| 10 | **CMS Scanning** | WordPress, Drupal, Joomla, Magento detection and scanning | `wpscan`, `droopescan` |
| 11 | **CORS** | Misconfigured CORS, wildcard origins, credentialed CORS | `curl` |
| 12 | **Open Redirect** | 20+ params × 10 redirect payloads | `curl` |
| 13 | **SSRF** | Cloud IMDS (AWS/GCP/Azure), internal IP probing | `curl` |
| 14 | **Subdomain Takeover** | Dangling CNAME detection for 20+ services | `subjack`, `nuclei`, `dig` |
| 15 | **Nuclei** | Community CVE/misconfiguration templates | `nuclei` |

---

## 📁 Output Structure

```
results_target_YYYYMMDD_HHMMSS/
├── logs/
│   ├── audit_YYYYMMDD_HHMMSS.log     # Full timestamped audit log
│   └── findings.jsonl                # One JSON object per finding
├── recon/
│   ├── whois.txt
│   ├── dns_records.txt
│   ├── subdomains.txt
│   ├── axfr.txt
│   ├── whatweb.json
│   ├── waf_detection.txt
│   └── google_dorks.txt
├── portscan/
│   ├── nmap.txt
│   ├── nmap.xml
│   └── nmap.gnmap
├── ssl/
│   ├── testssl.json
│   └── testssl.log
├── headers/
│   └── response_headers.txt
├── dirs/
│   ├── gobuster_dirs.txt
│   └── sensitive_paths_found.txt
├── vulns/
│   ├── sqlmap/
│   ├── xss/
│   └── nuclei/
├── cms/
│   ├── wpscan_results.json
│   └── droopescan_*.json
├── misc/
│   ├── cors_tests.txt
│   ├── open_redirect.txt
│   ├── ssrf_tests.txt
│   └── subtakeover.txt
└── reports/
    ├── report_YYYYMMDD_HHMMSS.html   # Interactive dashboard
    ├── report_YYYYMMDD_HHMMSS.json   # Structured JSON
    └── report_YYYYMMDD_HHMMSS.txt    # Plain text
```

---

## 📊 Report Examples

### HTML Report
- Interactive severity filter (Critical / High / Medium / Low / Info)
- Live search across all findings
- Risk bar and scan metadata panel
- Evidence and remediation per finding
- Dark theme, responsive layout

### JSON Report
```json
{
  "metadata": {
    "tool": "websec-audit",
    "version": "1.0.1",
    "target": "https://davidalvarezp.com",
    "start_time": "2026-01-01 12:00:00",
    "duration_secs": 342
  },
  "summary": {
    "total": 18,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 3,
    "info": 2
  },
  "findings": [
    {
      "id": 1,
      "severity": "CRITICAL",
      "module": "RECON",
      "title": "DNS Zone Transfer (AXFR) is permitted",
      "description": "Name server ns1.davidalvarezp.com allows AXFR — full DNS zone disclosed.",
      "evidence": "...",
      "recommendation": "Restrict AXFR to authorised secondary name servers only.",
      "timestamp": "2026-01-01T12:00:12Z"
    }
  ]
}
```

---

## 🔧 Requirements

### Required
| Tool | Purpose | Install |
|------|---------|---------|
| `bash` 5.0+ | Shell interpreter | `apt-get install bash` |
| `curl` | HTTP requests | `apt-get install curl` |
| `nmap` | Port scanning | `apt-get install nmap` |

### Recommended (significantly improves coverage)
| Tool | Module | Install |
|------|--------|---------|
| `nikto` | Web vuln scan | `apt-get install nikto` |
| `sqlmap` | SQL injection | `apt-get install sqlmap` |
| `gobuster` / `ffuf` | Dir brute-force | `apt-get install gobuster` |
| `whatweb` | Fingerprinting | `apt-get install whatweb` |
| `wafw00f` | WAF detection | `apt-get install wafw00f` |
| `sslscan` / `testssl.sh` | SSL/TLS | `apt-get install sslscan` |
| `wpscan` | WordPress | `gem install wpscan` |
| `dalfox` | XSS | [GitHub releases](https://github.com/hahwul/dalfox) |
| `nuclei` | CVE templates | [GitHub releases](https://github.com/projectdiscovery/nuclei) |
| `subfinder` | Subdomain enum | [GitHub releases](https://github.com/projectdiscovery/subfinder) |
| `jq` | JSON parsing | `apt-get install jq` |
| `python3` | Utilities | `apt-get install python3` |

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-module`
3. Commit your changes: `git commit -m 'feat: add new-module'`
4. Push to your branch: `git push origin feature/new-module`
5. Open a Pull Request

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

---

## 📜 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made with ❤️ by [davidalvarezp](https://davidalvarezp.com)

⭐ **Star this repo** if you find it useful!

</div>
