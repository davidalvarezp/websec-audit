---
title: Quick Start
description: Run your first websec-audit scan in under 2 minutes.
---

# Quick Start

Get up and running in under 2 minutes.

!!! warning "Authorised targets only"
    Only scan systems you own or have explicit written permission to test.
    For practice, use [DVWA](https://github.com/digininja/DVWA), [WebGoat](https://github.com/WebGoat/WebGoat),
    or a [HackTheBox](https://hackthebox.com) / [TryHackMe](https://tryhackme.com) machine.

---

## 1. Clone and install

```bash
git clone https://github.com/davidalvarezp/websec-audit.git
cd websec-audit
chmod +x install.sh websec-audit.sh
sudo ./install.sh
```

---

## 2. Run your first scan

```bash
./websec-audit.sh -t https://target.com
```

The scan runs all 15 modules sequentially. Depending on the target and available tools,
a standard scan takes **5–20 minutes**.

---

## 3. Review the results

When the scan finishes you will see a summary like this:

```
  ┌───────────────────────────────────────────────────┐
  │  TARGET   : https://target.com                    │
  │  IP       : 93.184.216.34                         │
  │  RISK     : HIGH                                  │
  ├───────────────────────────────────────────────────┤
  │  CRITICAL : 2                                     │
  │  HIGH     : 5                                     │
  │  MEDIUM   : 7                                     │
  │  LOW      : 4                                     │
  │  INFO     : 3                                     │
  ├───────────────────────────────────────────────────┤
  │  TOTAL    : 21 finding(s)                         │
  │  DURATION : 487s                                  │
  └───────────────────────────────────────────────────┘

  HTML report : results_target_YYYYMMDD_HHMMSS/reports/report_*.html
  JSON report : results_target_YYYYMMDD_HHMMSS/reports/report_*.json
  Audit log   : results_target_YYYYMMDD_HHMMSS/logs/audit_*.log
```

Open the HTML report in your browser for the interactive dashboard.

---

## Common usage patterns

=== "Standard scan"
    ```bash
    ./websec-audit.sh -t https://target.com
    ```

=== "Aggressive (deeper)"
    ```bash
    ./websec-audit.sh -t https://target.com --aggressive -T 20
    ```

=== "Stealth (low noise)"
    ```bash
    ./websec-audit.sh -t https://target.com --stealth
    ```

=== "Through Burp Suite"
    ```bash
    ./websec-audit.sh -t https://target.com --proxy http://127.0.0.1:8080
    ```

=== "Skip slow modules"
    ```bash
    ./websec-audit.sh -t https://target.com --skip-nikto --skip-sqli
    ```

=== "JSON output only"
    ```bash
    ./websec-audit.sh -t https://target.com --format json -o /tmp/audit
    ```

=== "Full port scan"
    ```bash
    ./websec-audit.sh -t https://target.com --ports full --aggressive
    ```

---

## Output directory structure

```
results_target_20240101_120000/
├── logs/
│   ├── audit_20240101_120000.log     # full timestamped log
│   └── findings.jsonl                # one JSON object per finding
├── recon/          WHOIS, DNS records, subdomains, WhatWeb, WAF, dorks
├── portscan/       nmap (.txt .xml .gnmap)
├── ssl/            testssl.json / sslscan.txt
├── headers/        response headers
├── dirs/           gobuster results, sensitive paths found
├── vulns/          sqlmap/, xss/, nuclei/
├── cms/            wpscan_results.json, droopescan_*.json
├── misc/           cors_tests.txt, open_redirect.txt, ssrf_tests.txt, subtakeover.txt
└── reports/
    ├── report_*.html   ← open this in your browser
    ├── report_*.json
    └── report_*.txt
```

---

## Next steps

- Read the full [Usage reference](usage.md) for all flags and options
- Understand [Scan Modes](modes.md) to choose the right intensity
- Browse the [Module docs](modules/index.md) to learn what each module checks
- Review [Reports & Output](reports.md) to understand the report format
