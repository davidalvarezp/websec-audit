---
title: "Module 03 · Fingerprinting"
description: Technology stack detection, WAF identification and version-leaking header analysis.
---

# Module 03 · Fingerprinting

**Flag:** `--skip-fingerprint`

Identifies the technology stack, detects WAFs, and flags response headers that leak version information.

---

## Technology detection

Uses **WhatWeb** (aggression level 1 in normal mode, 3 in aggressive) to identify:

- Web server (nginx, Apache, IIS, LiteSpeed, Caddy)
- Programming language and framework (PHP, Django, Rails, Laravel, ASP.NET, Express)
- CMS (WordPress, Drupal, Joomla, Magento)
- JavaScript libraries and versions
- Analytics and tracking tools
- CDN and cloud provider

Output saved to `recon/whatweb.json` and `recon/whatweb_brief.txt`.

---

## WAF detection

Uses **wafw00f** to identify the presence and type of Web Application Firewall.

| Condition | Severity |
|---|:---:|
| No WAF detected | <span class="sev sev-low">LOW</span> |
| WAF identified | <span class="sev sev-info">INFO</span> |

A missing WAF is flagged as Low because it means there is no automatic filtering layer between the internet and the application.

---

## Version-leaking headers

The following response headers are checked. Any that disclose technology names or version numbers are flagged:

`Server` · `X-Powered-By` · `X-AspNet-Version` · `X-AspNetMvc-Version` · `X-Generator` · `X-CF-Powered-By` · `Via`

| Condition | Severity |
|---|:---:|
| Version-leaking header present | <span class="sev sev-low">LOW</span> |

---

## Fallback

If `whatweb` is not installed, the module falls back to header-based detection using `curl`, scanning for technology names in the response headers and body.

---

## Output files

```
recon/
├── whatweb.json
├── whatweb_brief.txt
├── waf_detection.txt
└── basic_headers_raw.txt     # fallback only
```
