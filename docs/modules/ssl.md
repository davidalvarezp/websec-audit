---
title: "Module 04 · SSL/TLS"
description: Full SSL/TLS analysis — deprecated protocols, weak ciphers, certificate expiry and HSTS.
---

# Module 04 · SSL/TLS

**Flag:** `--skip-ssl`

!!! info
    This module is automatically skipped if the target is served over plain HTTP.
    In that case, a **HIGH** finding is raised: *"Target is served over HTTP (no TLS)"*.

---

## Checks performed

### Protocol support
Flags deprecated and vulnerable protocols:

| Protocol | Severity |
|---|:---:|
| SSLv2 | <span class="sev sev-high">HIGH</span> |
| SSLv3 | <span class="sev sev-high">HIGH</span> |
| TLS 1.0 | <span class="sev sev-high">HIGH</span> |
| TLS 1.1 | <span class="sev sev-high">HIGH</span> |
| TLS 1.2 | ✅ Acceptable |
| TLS 1.3 | ✅ Preferred |

### Cipher suites
Flags weak or broken ciphers:

- RC4, NULL, EXPORT, anonymous (anon), DES, 3DES → <span class="sev sev-high">HIGH</span>

### Certificate validity

| Condition | Severity |
|---|:---:|
| Certificate expired | <span class="sev sev-critical">CRITICAL</span> |
| Expires in < 14 days | <span class="sev sev-critical">CRITICAL</span> |
| Expires in < 30 days | <span class="sev sev-high">HIGH</span> |
| Expires in < 90 days | <span class="sev sev-medium">MEDIUM</span> |
| Self-signed / untrusted | <span class="sev sev-high">HIGH</span> |

### HSTS

| Condition | Severity |
|---|:---:|
| HSTS header absent | <span class="sev sev-medium">MEDIUM</span> |
| `max-age` < 15552000 (6 months) | <span class="sev sev-low">LOW</span> |

---

## Tool priority

1. **testssl.sh** — comprehensive analysis, JSON output parsed automatically
2. **sslscan** — protocol and cipher enumeration
3. **openssl** — fallback, manual protocol checks

---

## Output files

```
ssl/
├── testssl.json      # if testssl.sh available
├── testssl.log
├── sslscan.txt       # if sslscan available
└── openssl_info.txt  # fallback
```
