---
title: "Module 02 · Port Scanning"
description: nmap service/version detection with automated risk-based analysis of open ports.
---

# Module 02 · Port Scanning

**Flag:** `--skip-portscan`

Runs nmap against the target and performs automated risk analysis on every open port.

---

## Port profiles

| `--ports` value | nmap flag | Use case |
|---|---|---|
| `top-100` | `--top-ports 100` | Quick check |
| `top-1000` _(default)_ | `--top-ports 1000` | Standard |
| `full` | `-p-` | Full coverage (slow) |

---

## Mode behaviour

| Mode | Extra flags |
|---|---|
| Normal | `-sV -sC --open -T4` |
| Aggressive | Adds `-A -O --script=vuln,auth,default,discovery` |
| Stealth | `-sS -T2 -f --data-length 32 --randomize-hosts` |

---

## Automated risk analysis

Every open port is evaluated against a built-in risk table:

| Port | Service | Severity | Reason |
|---|---|:---:|---|
| 21 | FTP | <span class="sev sev-critical">CRITICAL</span> | Plaintext credentials |
| 23 | Telnet | <span class="sev sev-critical">CRITICAL</span> | Unencrypted remote shell |
| 2375 | Docker API | <span class="sev sev-critical">CRITICAL</span> | Unauthenticated container access |
| 445 | SMB | <span class="sev sev-high">HIGH</span> | EternalBlue / ransomware risk |
| 3306 | MySQL | <span class="sev sev-high">HIGH</span> | DB exposed to internet |
| 3389 | RDP | <span class="sev sev-high">HIGH</span> | Brute-force target |
| 5432 | PostgreSQL | <span class="sev sev-high">HIGH</span> | DB exposed to internet |
| 6379 | Redis | <span class="sev sev-high">HIGH</span> | Often unauthenticated |
| 9200 | Elasticsearch | <span class="sev sev-high">HIGH</span> | Often unauthenticated |
| 27017 | MongoDB | <span class="sev sev-high">HIGH</span> | Often unauthenticated |
| 25 | SMTP | <span class="sev sev-medium">MEDIUM</span> | Open relay risk |
| 8080/8443 | HTTP alt | <span class="sev sev-low">LOW</span> | Admin panel exposure |

---

## Output files

```
portscan/
├── nmap.txt      # human-readable
├── nmap.xml      # machine-readable, compatible with Metasploit
└── nmap.gnmap    # grepable format
```
