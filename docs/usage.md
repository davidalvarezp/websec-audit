---
title: All Options
description: Complete reference for all websec-audit flags, options and module controls.
---

# All Options

Complete CLI reference for WebSec-Audit.

```
./websec-audit.sh -t <target> [options]
```

---

## Required

| Flag | Description |
|---|---|
| `-t`, `--target <url\|ip>` | Target URL or IP address. If no scheme is provided, `https://` is assumed. |

---

## Output

| Flag | Default | Description |
|---|---|---|
| `-o`, `--output <dir>` | `./results_<domain>_<ts>` | Directory where all results are saved |
| `--format <fmt>` | `all` | Report format: `json` \| `html` \| `txt` \| `all` |

---

## Scan options

| Flag | Default | Description |
|---|---|---|
| `-T`, `--threads <n>` | `10` | Concurrent threads passed to brute-force tools |
| `-p`, `--ports <profile>` | `top-1000` | Port profile: `top-100` \| `top-1000` \| `full` |
| `--timeout <s>` | `10` | Connection timeout in seconds for all HTTP/TCP operations |
| `--depth <n>` | `3` | Crawl depth used in aggressive sqlmap and CMS scans |
| `--proxy <url>` | _(none)_ | Route all traffic through this proxy (e.g. `http://127.0.0.1:8080`) |
| `--aggressive` | off | Aggressive mode — deeper scans, higher noise, more findings |
| `--stealth` | off | Stealth mode — slower, lower detection footprint |

!!! warning
    `--aggressive` and `--stealth` are mutually exclusive. If both are provided, `--aggressive` takes precedence.

---

## Module control

Every module can be individually disabled. Useful for scoping an audit or skipping slow/noisy tools.

| Flag | Module disabled |
|---|---|
| `--skip-recon` | Reconnaissance (WHOIS, DNS, subdomain enum) |
| `--skip-portscan` | Port scanning (nmap) |
| `--skip-fingerprint` | Web fingerprinting (WhatWeb, WAF) |
| `--skip-ssl` | SSL/TLS analysis |
| `--skip-headers` | HTTP security headers |
| `--skip-dirbrute` | Directory & file brute-forcing |
| `--skip-nikto` | Nikto web scanner |
| `--skip-sqli` | SQL injection (sqlmap) |
| `--skip-xss` | XSS testing (dalfox + manual) |
| `--skip-cms` | CMS detection & scanning |
| `--skip-cors` | CORS misconfiguration tests |
| `--skip-redirect` | Open redirect tests |
| `--skip-ssrf` | SSRF tests |
| `--skip-subtakeover` | Subdomain takeover checks |
| `--skip-nuclei` | Nuclei template scan |

---

## Wordlists

| Flag | Default | Description |
|---|---|---|
| `--wl-dirs-small <file>` | `/usr/share/wordlists/dirb/common.txt` | Small wordlist for directory brute-force (normal mode) |
| `--wl-dirs-big <file>` | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Large wordlist (aggressive mode) |
| `--wl-dns <file>` | `/usr/share/wordlists/dnsmap.txt` | DNS subdomain brute-force wordlist |

---

## Misc

| Flag | Description |
|---|---|
| `-v`, `--verbose` | Print verbose debug output to stdout |
| `--no-color` | Disable ANSI colour output (useful for piping / CI) |
| `--no-banner` | Suppress the ASCII banner (useful for scripting) |
| `-V`, `--version` | Print version and exit |
| `-h`, `--help` | Print usage and exit |

---

## Examples

```bash
# Basic scan
./websec-audit.sh -t https://target.com

# Aggressive with 20 threads, custom output dir
./websec-audit.sh -t https://target.com --aggressive -T 20 -o /tmp/audit

# Stealth through Burp Suite
./websec-audit.sh -t https://target.com --stealth --proxy http://127.0.0.1:8080

# Skip slow modules, verbose, JSON only
./websec-audit.sh -t https://target.com --skip-nikto --skip-sqli -v --format json

# Full port scan, deep crawl
./websec-audit.sh -t https://target.com --ports full --depth 5 --aggressive

# Headers and SSL audit only (everything else skipped)
./websec-audit.sh -t https://target.com \
  --skip-recon --skip-portscan --skip-fingerprint \
  --skip-dirbrute --skip-nikto --skip-sqli --skip-xss \
  --skip-cms --skip-cors --skip-redirect --skip-ssrf \
  --skip-subtakeover --skip-nuclei

# No colour, no banner — clean output for CI/logging
./websec-audit.sh -t https://target.com --no-color --no-banner
```
