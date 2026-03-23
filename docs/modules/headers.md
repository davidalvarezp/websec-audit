---
title: "Module 05 · HTTP Headers"
description: HTTP security header analysis, cookie flags and HTTP-to-HTTPS redirect verification.
---

# Module 05 · HTTP Headers

**Flag:** `--skip-headers`

Audits HTTP response headers for security misconfigurations.

---

## Required security headers

| Header | Severity if absent | Notes |
|---|:---:|---|
| `Content-Security-Policy` | <span class="sev sev-medium">MEDIUM</span> | Also audits CSP value for `unsafe-inline`, `unsafe-eval`, wildcards |
| `X-Frame-Options` | <span class="sev sev-medium">MEDIUM</span> | Clickjacking protection |
| `X-Content-Type-Options` | <span class="sev sev-low">LOW</span> | MIME sniffing prevention |
| `Referrer-Policy` | <span class="sev sev-low">LOW</span> | URL leakage control |
| `Permissions-Policy` | <span class="sev sev-low">LOW</span> | Browser API restrictions |
| `Cross-Origin-Opener-Policy` | <span class="sev sev-low">LOW</span> | Cross-origin isolation |
| `Cross-Origin-Resource-Policy` | <span class="sev sev-low">LOW</span> | Resource access control |

### CSP deep audit
When CSP is present, the module further checks:

| CSP Condition | Severity |
|---|:---:|
| `unsafe-inline` or `unsafe-eval` present | <span class="sev sev-medium">MEDIUM</span> |
| Wildcard (`*`) in `script-src` or `default-src` | <span class="sev sev-high">HIGH</span> |

---

## Version-leaking headers

Headers that should **not** be present in production:

`Server` · `X-Powered-By` · `X-AspNet-Version` · `X-AspNetMvc-Version` · `X-Generator` · `X-CF-Powered-By`

Each flagged as <span class="sev sev-low">LOW</span>.

---

## Cookie security flags

Every `Set-Cookie` response header is analysed for:

| Missing flag | Severity |
|---|:---:|
| `HttpOnly` | <span class="sev sev-medium">MEDIUM</span> |
| `Secure` | <span class="sev sev-medium">MEDIUM</span> |
| `SameSite` | <span class="sev sev-low">LOW</span> |
| `SameSite=None` without `Secure` | <span class="sev sev-medium">MEDIUM</span> |

---

## HTTP → HTTPS redirect

Checks whether HTTP requests are automatically upgraded to HTTPS.

| Condition | Severity |
|---|:---:|
| HTTP does not redirect to HTTPS | <span class="sev sev-medium">MEDIUM</span> |

---

## Cache-Control

| Condition | Severity |
|---|:---:|
| `Cache-Control` header absent | <span class="sev sev-low">LOW</span> |

---

## Output files

```
headers/
├── response_headers.txt
└── initial_response.txt
```
