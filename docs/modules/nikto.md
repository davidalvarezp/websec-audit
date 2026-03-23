---
title: "Module 07 · Nikto"
description: Nikto web server vulnerability scanner integration.
---

# Module 07 · Nikto

**Flag:** `--skip-nikto`

Runs Nikto against the target and classifies findings by severity.

---

## What Nikto checks

- Outdated server software with known CVEs
- Default files and scripts (admin panels, test pages, install scripts)
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- Server misconfigurations
- Cookie and header issues not covered by Module 05
- Common web application vulnerabilities

---

## Mode behaviour

| Mode | Nikto flags |
|---|---|
| Normal | Default plugins, 10-minute max |
| Aggressive | `--Plugins @@ALL` — runs every available plugin |

---

## Severity classification

Nikto findings are auto-classified:

| Pattern in output | Assigned severity |
|---|:---:|
| `vuln`, `exploit`, `inject`, `XSS`, `CVE`, `OSVDB-XXXX` | <span class="sev sev-high">HIGH</span> |
| `outdated`, `version`, `disclose`, `found`, `enabled` | <span class="sev sev-medium">MEDIUM</span> |
| Everything else | <span class="sev sev-low">LOW</span> |

---

## Output files

```
vulns/
├── nikto.txt
└── nikto.json
```

!!! tip "Nikto can be noisy"
    Nikto generates many false positives. Review each finding manually before including it in a formal report.
    Use `--skip-nikto` in quick assessments where time is limited.
