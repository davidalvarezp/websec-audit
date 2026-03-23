---
title: "Module 11 · CORS Misconfiguration"
description: CORS policy testing — wildcard, reflected origin, null origin and credentialed cross-origin requests.
---

# Module 11 · CORS Misconfiguration

**Flag:** `--skip-cors`

Tests the target's CORS policy against 7 adversarial origins.

---

## Test origins

```
https://evil.com
https://<domain>.evil.com
https://evil.<domain>
null
https://attacker.io
http://localhost
https://not<domain>
```

Each origin is sent in an `Origin` header with `Access-Control-Request-Method: GET` and
`Access-Control-Request-Headers: Authorization`.

---

## Checks and findings

| Condition | Severity |
|---|:---:|
| Attacker origin reflected in `ACAO` + `ACAC: true` | <span class="sev sev-critical">CRITICAL</span> |
| Attacker origin reflected in `ACAO` (no credentials) | <span class="sev sev-medium">MEDIUM</span> |
| Wildcard `*` in `Access-Control-Allow-Origin` | <span class="sev sev-medium">MEDIUM</span> |
| `null` origin accepted | <span class="sev sev-high">HIGH</span> |

---

## Why CORS matters

A misconfigured CORS policy allows an attacker's website to make authenticated cross-origin requests on behalf of a victim user — reading sensitive API responses, exfiltrating data, or performing actions under their session.

The most critical case is:

```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

This combination allows a malicious site to make credentialed requests and read the responses.

---

## Remediation

- Validate `Origin` against an **explicit allowlist** — never reflect it back directly
- Never use `Access-Control-Allow-Origin: *` on endpoints that handle authenticated data
- Never combine `ACAO: *` with `ACAC: true` (browsers block this, but other clients do not)
- Never trust the `null` origin

---

## Output files

```
misc/
└── cors_tests.txt
```
