---
title: Web Security Audit Framework
description: Professional Web Security Audit Framework — modular, extensible, Bash-native.
hide:
  - navigation
  - toc
---

<div class="ws-hero">
  <h1>WebSec-Audit</h1>
  <p class="ws-tagline">Professional Web Security Audit Framework — modular, extensible, Bash-native</p>
</div>

!!! danger "Legal Notice"
    This tool is intended **exclusively for authorised security assessments**.
    Only run it against systems you own or have **explicit written permission** to test.
    Unauthorised use is illegal. The author assumes no liability for misuse.

---

## What is WebSec-Audit?

**WebSec-Audit** is a Bash framework that automates comprehensive web application security audits.
It integrates **15+ independent modules** — from passive reconnaissance to active exploitation —
and produces professional findings reports in three formats.

Designed to run on **Debian, Ubuntu and Kali Linux** with zero mandatory dependencies beyond
`curl` and `nmap`.

---

## Feature highlights

<div class="grid cards" markdown>

- :material-puzzle: **Modular architecture**

    Enable or disable any of the 15+ modules with a single `--skip-<module>` flag.

- :material-speedometer: **Three scan modes**

    Normal, Aggressive and Stealth — adapt the scan depth to each engagement.

- :material-file-chart: **Rich reports**

    Interactive HTML dashboard, structured JSON and plain-text log — generated automatically.

- :material-shield-search: **Broad coverage**

    Recon · Port scan · SSL/TLS · Headers · SQLi · XSS · SSRF · CORS · CMS · Takeover · Nuclei

- :material-bug-play: **Proxy support**

    Route all traffic through Burp Suite or any HTTP proxy with `--proxy`.

- :material-tools: **Tool-agnostic**

    Graceful fallback when optional tools are absent. Core scan works with only `curl` + `nmap`.

</div>

---

## Modules at a glance

<div class="module-grid">
  <a class="module-card" href="modules/recon/">
    <div class="mc-num">Module 01</div>
    <div class="mc-name">Reconnaissance</div>
    <div class="mc-desc">WHOIS · DNS · AXFR · Subdomains · SPF/DMARC · Dorks</div>
  </a>
  <a class="module-card" href="modules/portscan/">
    <div class="mc-num">Module 02</div>
    <div class="mc-name">Port Scanning</div>
    <div class="mc-desc">nmap · service detection · risk analysis</div>
  </a>
  <a class="module-card" href="modules/fingerprint/">
    <div class="mc-num">Module 03</div>
    <div class="mc-name">Fingerprinting</div>
    <div class="mc-desc">WhatWeb · WAF detection · version leakage</div>
  </a>
  <a class="module-card" href="modules/ssl/">
    <div class="mc-num">Module 04</div>
    <div class="mc-name">SSL/TLS</div>
    <div class="mc-desc">testssl.sh · ciphers · cert expiry · HSTS</div>
  </a>
  <a class="module-card" href="modules/headers/">
    <div class="mc-num">Module 05</div>
    <div class="mc-name">HTTP Headers</div>
    <div class="mc-desc">CSP · cookies · clickjacking · redirects</div>
  </a>
  <a class="module-card" href="modules/dirbrute/">
    <div class="mc-num">Module 06</div>
    <div class="mc-name">Dir & File Enum</div>
    <div class="mc-desc">gobuster · ffuf · 40+ sensitive paths</div>
  </a>
  <a class="module-card" href="modules/nikto/">
    <div class="mc-num">Module 07</div>
    <div class="mc-name">Nikto</div>
    <div class="mc-desc">Web server CVEs · misconfigurations</div>
  </a>
  <a class="module-card" href="modules/sqli/">
    <div class="mc-num">Module 08</div>
    <div class="mc-name">SQL Injection</div>
    <div class="mc-desc">sqlmap · auto + aggressive mode</div>
  </a>
  <a class="module-card" href="modules/xss/">
    <div class="mc-num">Module 09</div>
    <div class="mc-name">XSS</div>
    <div class="mc-desc">dalfox · reflected · DOM-based</div>
  </a>
  <a class="module-card" href="modules/cms/">
    <div class="mc-num">Module 10</div>
    <div class="mc-name">CMS Scanning</div>
    <div class="mc-desc">WordPress · Drupal · Joomla · Magento</div>
  </a>
  <a class="module-card" href="modules/cors/">
    <div class="mc-num">Module 11</div>
    <div class="mc-name">CORS</div>
    <div class="mc-desc">wildcard · reflected origin · null origin</div>
  </a>
  <a class="module-card" href="modules/redirect/">
    <div class="mc-num">Module 12</div>
    <div class="mc-name">Open Redirect</div>
    <div class="mc-desc">20 params × 10 payloads</div>
  </a>
  <a class="module-card" href="modules/ssrf/">
    <div class="mc-num">Module 13</div>
    <div class="mc-name">SSRF</div>
    <div class="mc-desc">AWS · GCP · Azure IMDS · internal IPs</div>
  </a>
  <a class="module-card" href="modules/subtakeover/">
    <div class="mc-num">Module 14</div>
    <div class="mc-name">Subdomain Takeover</div>
    <div class="mc-desc">subjack · nuclei · 20+ services</div>
  </a>
  <a class="module-card" href="modules/nuclei/">
    <div class="mc-num">Module 15</div>
    <div class="mc-name">Nuclei</div>
    <div class="mc-desc">CVE templates · misconfiguration scan</div>
  </a>
</div>

---

## Quick start

```bash
git clone https://github.com/davidalvarezp/websec-audit.git
cd websec-audit
chmod +x install.sh websec-audit.sh
sudo ./install.sh
./websec-audit.sh -t https://target.com
```

:material-arrow-right: See [Installation](installation.md) and [Quick Start](quickstart.md) for details.

---

## Author

Built by **[davidalvarezp](https://davidalvarezp.com)**.

:material-github: [github.com/davidalvarezp](https://github.com/davidalvarezp) ·
:material-linkedin: [linkedin.com/in/davidalvarezp](https://www.linkedin.com/in/davidalvarezp)
