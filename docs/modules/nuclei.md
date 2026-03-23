---
title: "Module 15 · Nuclei"
description: CVE and misconfiguration template scanning with Nuclei.
---

# Module 15 · Nuclei

**Flag:** `--skip-nuclei`

Runs the [Nuclei](https://github.com/projectdiscovery/nuclei) engine against the target using the community template library.

---

## Severity filter

| Mode | Templates included |
|---|---|
| Normal | `medium`, `high`, `critical` |
| Aggressive | `low`, `medium`, `high`, `critical` |

---

## Template categories covered

- CVE templates (known software vulnerabilities)
- Default credentials
- Exposed panels and dashboards
- Misconfiguration (cloud, server, application)
- Technology detection
- Network exposure
- Fuzzing templates (aggressive mode)

---

## Template updates

Templates are updated automatically during `install.sh`. To manually update:

```bash
nuclei -update-templates
```

---

## Findings

Each Nuclei match is imported as a finding with its native severity (`critical`, `high`, `medium`, `low`, `info`).

---

## Output files

```
vulns/nuclei/
├── nuclei_results.txt
└── nuclei_results.json
```

!!! tip
    Nuclei is also used internally by Module 14 (Subdomain Takeover) with the `takeovers/` template tag.
