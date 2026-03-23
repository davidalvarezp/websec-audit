---
title: "Module 12 · Open Redirect"
description: Open redirect detection across 20 parameters and 10 payload variants.
---

# Module 12 · Open Redirect

**Flag:** `--skip-redirect`

Tests 20 common redirect parameters with 10 payload variants.

---

## Parameters tested

`next`, `url`, `redirect`, `redirect_uri`, `redirect_url`, `return`, `return_url`, `returnUrl`, `returnTo`, `go`, `goto`, `dest`, `destination`, `target`, `forward`, `redir`, `link`, `to`, `r`, `out`, `ref`, `continue`, `callback`, `successUrl`, `failureUrl`

---

## Payloads

```
https://evil.com
//evil.com
///evil.com
https:evil.com
/\evil.com
https://evil.com%2F%2E%2E
%2F%2Fevil.com
https:///evil.com
/%5Cevil.com
https://evil.com@<target-domain>
```

---

## Findings

| Condition | Severity |
|---|:---:|
| Redirect to external domain confirmed | <span class="sev sev-medium">MEDIUM</span> |

---

## Remediation

Validate redirect targets against an allowlist of known-safe internal paths or domains. If the application must redirect to external URLs, use an intermediate confirmation page.

---

## Output files

```
misc/
└── open_redirect.txt
```
