---
title: "Module 09 · XSS"
description: Cross-Site Scripting detection using dalfox and manual reflected XSS probing.
---

# Module 09 · XSS

**Flag:** `--skip-xss`

Tests for reflected and DOM-based XSS using dalfox and a manual parameter probe.

---

## dalfox scan

dalfox is run against the target URL with automatic parameter discovery.

| Mode | Extra flags |
|---|---|
| Normal | `--silence --timeout <n>` |
| Aggressive | `--deep-domxss --follow-redirects` |

dalfox tests for:

- Reflected XSS in URL parameters
- DOM-based XSS
- Blind XSS (with callback)
- Header injection

---

## Manual reflected XSS probe

In addition to dalfox, the module probes common GET parameters with 8 payloads:

```
<script>alert(1)</script>
'><img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
';alert(1);//
<details open ontoggle=alert(1)>
<iframe srcdoc='<script>alert(1)</script>'>
```

Parameters tested: `q`, `s`, `search`, `query`, `keyword`, `id`, `name`, `page`, `url`, `ref`, `return`, `redirect`, `next`, `view`, `lang`

If the payload is reflected verbatim in the response body, the finding is confirmed.

---

## Findings

| Condition | Severity |
|---|:---:|
| XSS confirmed (dalfox or manual) | <span class="sev sev-high">HIGH</span> |

---

## Remediation

- **Encode all user-controlled output** before inserting it into HTML (use framework-native escaping)
- Implement a **strict Content-Security-Policy** that disallows inline scripts
- Set `X-Content-Type-Options: nosniff`

---

## Output files

```
vulns/xss/
├── dalfox_results.txt
└── reflected_xss.txt
```
