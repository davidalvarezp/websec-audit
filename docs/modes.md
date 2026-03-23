---
title: Scan Modes
description: Normal, Aggressive and Stealth scan modes explained.
---

# Scan Modes

WebSec-Audit supports three scan modes that control depth, noise and speed across all modules.

---

## Normal (default)

Balanced scan suitable for most engagements. Moderate threads, mid-level tool aggression.

```bash
./websec-audit.sh -t https://target.com
```

| Aspect | Behaviour |
|---|---|
| nmap | `-sV -sC --open -T4 --top-ports 1000` |
| sqlmap | `--level=3 --risk=2` |
| gobuster | Small wordlist, 10 threads |
| dalfox | Standard mode |
| WhatWeb | Aggression level 1 |
| Nikto | Default plugins |

---

## Aggressive

Deepest scan. More findings, significantly more network noise. Use only when the scope explicitly permits it.

```bash
./websec-audit.sh -t https://target.com --aggressive
./websec-audit.sh -t https://target.com --aggressive -T 20 --ports full
```

| Aspect | Behaviour |
|---|---|
| nmap | Adds `-A -O --script=vuln,auth,default,discovery` |
| sqlmap | `--level=5 --risk=3 --forms --crawl=<depth> --dbs --tamper=space2comment` |
| gobuster | Large wordlist (`dirbuster medium`) |
| dalfox | `--deep-domxss --follow-redirects` |
| WhatWeb | Aggression level 3 |
| Nikto | `--Plugins @@ALL` |
| Nuclei | Includes `low` severity templates |
| Port profile | Can be combined with `--ports full` for `-p-` scan |

!!! warning "Noise warning"
    Aggressive mode will almost certainly trigger IDS/IPS alerts and WAF blocks.
    Always confirm with the client that this level of noise is within scope.

---

## Stealth

Slower scan designed to minimise the detection footprint. Useful for red team engagements or
environments with sensitive monitoring.

```bash
./websec-audit.sh -t https://target.com --stealth
```

| Aspect | Behaviour |
|---|---|
| nmap | `-sS -T2 -f --data-length 32 --randomize-hosts` |
| sqlmap | `--delay=2 --safe-freq=3 --smart` |
| gobuster | Small wordlist, reduced threads |
| HTTP requests | Longer intervals between requests |

!!! info "Stealth limitations"
    Stealth mode reduces noise but does not guarantee evasion. A determined blue team will
    still detect the scan. For full covert operations, consider manual testing with specific
    targeted checks only.

---

## Mode comparison

| Feature | Normal | Aggressive | Stealth |
|---|:---:|:---:|:---:|
| nmap scripts | default | vuln + auth + discovery | SYN + fragmented |
| sqlmap level | 3 | 5 | 3 |
| sqlmap risk | 2 | 3 | 2 |
| Crawling | No | Yes (--depth) | No |
| Full port scan | Optional | Recommended | Not recommended |
| WAF evasion | None | None | Partial |
| Speed | Medium | Fast | Slow |
| Noise | Medium | High | Low |
| Detection risk | Medium | High | Low-Medium |

---

## Combining flags

Modes can be combined with any module or output flag:

```bash
# Aggressive + custom threads + JSON only + proxy
./websec-audit.sh -t https://target.com \
  --aggressive -T 20 \
  --proxy http://127.0.0.1:8080 \
  --format json \
  -o /tmp/red-team-audit
```
