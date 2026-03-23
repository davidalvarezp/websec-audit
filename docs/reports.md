---
title: Reports & Output
description: HTML dashboard, JSON report and TXT log formats explained.
---

# Reports & Output

After every scan, WebSec-Audit generates three report formats automatically inside the output directory.

---

## Output directory

```
results_<domain>_<timestamp>/
├── logs/
│   ├── audit_<timestamp>.log     # live timestamped console log
│   └── findings.jsonl            # one JSON line per finding (written as discovered)
├── recon/
├── portscan/
├── ssl/
├── headers/
├── dirs/
├── vulns/
├── cms/
├── misc/
└── reports/
    ├── report_<timestamp>.html
    ├── report_<timestamp>.json
    └── report_<timestamp>.txt
```

You can override the base directory with `-o /path/to/dir`.

---

## HTML report

The most human-friendly format. Open it in any browser — no server needed.

### Features

- **Risk badge** — top-level risk rating (CRITICAL / HIGH / MEDIUM / LOW / INFO ONLY)
- **Summary cards** — count per severity level with a visual risk bar
- **Scan metadata panel** — target, IP, duration, mode, modules executed
- **Interactive findings table**:
    - Filter by severity with one click
    - Live full-text search across all fields
    - Each row shows: severity badge, module, title, description, evidence and remediation
- **Dark theme** — easy on the eyes during long review sessions

### Severity colour coding

| Badge | Severity | Meaning |
|---|---|---|
| <span class="sev sev-critical">CRITICAL</span> | Critical | Immediate exploitation risk. Fix before going live. |
| <span class="sev sev-high">HIGH</span> | High | Significant security risk. Fix urgently. |
| <span class="sev sev-medium">MEDIUM</span> | Medium | Notable risk. Fix in next release cycle. |
| <span class="sev sev-low">LOW</span> | Low | Minor risk or best-practice violation. |
| <span class="sev sev-info">INFO</span> | Info | Informational only. No direct security impact. |

---

## JSON report

Fully structured, machine-readable report. Ideal for:

- Integration with ticketing systems (Jira, Linear, etc.)
- Feeding into a SIEM or vulnerability management platform
- Programmatic post-processing with `jq`

### Schema

```json
{
  "metadata": {
    "tool": "websec-audit",
    "version": "1.0.1",
    "author": "davidalvarezp",
    "target": "https://target.com",
    "domain": "target.com",
    "ip": "93.184.216.34",
    "start_time": "2026-03-23 12:00:00",
    "duration_secs": 487
  },
  "summary": {
    "total": 21,
    "critical": 2,
    "high": 5,
    "medium": 7,
    "low": 4,
    "info": 3
  },
  "findings": [
    {
      "id": 1,
      "severity": "CRITICAL",
      "module": "RECON",
      "title": "DNS Zone Transfer (AXFR) is permitted",
      "description": "Name server ns1.target.com allows AXFR — full DNS zone disclosed.",
      "evidence": "dig AXFR target.com @ns1.target.com",
      "recommendation": "Restrict AXFR to authorised secondary name servers only.",
      "timestamp": "2024-01-01T12:00:12Z"
    }
  ]
}
```

### Useful `jq` queries

```bash
# Count by severity
jq '.summary' report_*.json

# List all critical findings
jq '.findings[] | select(.severity=="CRITICAL") | .title' report_*.json

# Export findings as CSV
jq -r '.findings[] | [.id,.severity,.module,.title] | @csv' report_*.json

# Filter by module
jq '.findings[] | select(.module=="HEADERS")' report_*.json
```

---

## TXT report

Full timestamped plain-text log. Contains:

- Scan metadata header
- Risk summary table
- Complete audit log with all module output

Ideal for formal deliverables that require a plaintext audit trail.

---

## JSONL findings file

`findings.jsonl` is written **as findings are discovered** — one JSON object per line.
This means if the scan is interrupted (Ctrl-C), you still have a valid, processable findings file.

```bash
# Count findings in a partial scan
wc -l findings.jsonl

# Pretty-print the last finding
tail -1 findings.jsonl | jq .
```

---

## Controlling report format

```bash
# Generate all formats (default)
./websec-audit.sh -t https://target.com

# JSON only
./websec-audit.sh -t https://target.com --format json

# HTML only
./websec-audit.sh -t https://target.com --format html

# TXT only
./websec-audit.sh -t https://target.com --format txt
```
