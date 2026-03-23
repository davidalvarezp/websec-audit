---
title: "Module 10 · CMS Scanning"
description: WordPress, Drupal, Joomla and Magento detection and security scanning.
---

# Module 10 · CMS Scanning

**Flag:** `--skip-cms`

Detects the CMS powering the target and runs the appropriate scanner.

---

## Detection

The module detects CMS by analysing the response body and headers for known fingerprints:

| CMS | Detection signals |
|---|---|
| WordPress | `wp-content`, `wp-includes`, `wordpress` in body/headers |
| Drupal | `sites/all/modules`, `Drupal.settings`, `X-Generator: Drupal` |
| Joomla | `/media/jui`, `generator: Joomla`, cookie names |
| Magento | `Mage.Cookies`, `/skin/frontend`, `magento` |

---

## WordPress (wpscan)

wpscan is run with:

| Mode | Flags |
|---|---|
| Normal | `--url <target> --no-banner --format json` |
| Aggressive | `--enumerate ap,at,cb,dbe,u --plugins-detection aggressive` |

**Parsed results:**

| Condition | Severity |
|---|:---:|
| Plugin vulnerabilities found | <span class="sev sev-high">HIGH</span> |
| Theme vulnerabilities found | <span class="sev sev-medium">MEDIUM</span> |
| Users enumerable via REST API | <span class="sev sev-medium">MEDIUM</span> |

**WordPress-specific path probes:**

| Path | Condition | Severity |
|---|---|:---:|
| `/xmlrpc.php` | Accessible | <span class="sev sev-medium">MEDIUM</span> |
| `/wp-json/wp/v2/users` | Returns user list | <span class="sev sev-medium">MEDIUM</span> |
| `/wp-content/debug.log` | Accessible | <span class="sev sev-high">HIGH</span> |
| `/?author=1` | Author enumeration works | <span class="sev sev-low">LOW</span> |
| `/wp-login.php` | Accessible | <span class="sev sev-info">INFO</span> |

## Drupal / Joomla (droopescan)

droopescan is used for Drupal and Joomla targets, detecting:

- Core version and known vulnerabilities
- Installed plugins/modules with known CVEs
- Themes

---

## Output files

```
cms/
├── wpscan_results.json
├── wpscan_console.txt
├── droopescan_drupal.json
└── droopescan_joomla.json
```
