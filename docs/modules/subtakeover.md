---
title: "Module 14 · Subdomain Takeover"
description: Dangling CNAME detection across 20+ known external services.
---

# Module 14 · Subdomain Takeover

**Flag:** `--skip-subtakeover`

Analyses the subdomain list produced by Module 01 for dangling CNAMEs pointing to deprovisioned external services.

!!! note "Dependency"
    This module requires the subdomain list from Module 01 (`recon/subdomains.txt`).
    Run with `--skip-recon` only if you provide a pre-existing subdomain list.

---

## Method 1 — subjack

subjack scans the subdomain list and checks each entry against its fingerprint database of known takeover-vulnerable services.

## Method 2 — Nuclei takeover templates

Nuclei runs against the subdomain list using the built-in `takeovers/` template category.

## Method 3 — Manual CNAME analysis

For each subdomain with a CNAME record, the module checks whether the CNAME points to a known external service and whether the resource returns a 404/410/403/503 (indicating the resource no longer exists).

**Monitored services (20+):**

AWS S3 · Elastic Beanstalk · CloudFront · GitHub Pages · Heroku · Zendesk · Freshdesk · HelpScout · Surge.sh · Netlify · Render · Azure Web Apps · Azure API Management · Shopify · Squarespace · Tumblr · Ghost · Webflow · Fly.io · Cloudflare Pages

---

## Findings

| Condition | Severity |
|---|:---:|
| Takeover confirmed (subjack / Nuclei) | <span class="sev sev-high">HIGH</span> |
| Dangling CNAME to known service + 404/410 | <span class="sev sev-high">HIGH</span> |

---

## Remediation

Remove the DNS CNAME record for the affected subdomain, or reclaim the resource at the external service before an attacker does.

---

## Output files

```
misc/
├── subtakeover.txt
└── nuclei_takeover.txt
```
