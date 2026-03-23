---
title: Changelog
description: Version history for websec-audit.
---

# Changelog

All notable changes are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.1] — 2026-03-23

### Added

- **Module 15 — Nuclei** template scan integration
- **Module 14 — Subdomain Takeover**: subjack + Nuclei + CNAME analysis for 20+ services
- **Module 13 — SSRF**: cloud IMDS probing (AWS/GCP/Azure), decimal/hex IP encoding
- **Module 12 — Open Redirect**: 20 params × 10 payloads
- **Module 11 — CORS**: null origin, credentialed, wildcard detection
- **Module 10 — CMS**: WordPress REST API user enumeration, debug.log, xmlrpc.php
- **Module 09 — XSS**: dalfox integration + 8 reflected payloads × 15 parameters
- **Module 08 — SQLi**: sqlmap with forms crawl and tamper scripts in aggressive mode
- **Module 07 — Nikto**: severity-based finding classification
- **Module 06 — Dir Enum**: 40 sensitive path probes (`.git`, `.env`, AWS credentials, Dockerfiles)
- **Module 05 — HTTP Headers**: CSP deep audit, SameSite=None, Cache-Control
- **Module 04 — SSL/TLS**: HSTS preload, cert expiry thresholds (14/30/90 days)
- **Module 03 — Fingerprint**: WAF detection, version-leaking header enumeration
- **Module 02 — Port Scan**: risk analysis for 20+ dangerous ports
- **Module 01 — Recon**: SPF `+all` detection, DMARC `p=none`, 700+ Google Dorks
- Interactive HTML report with severity filter, live search and risk bar
- JSON report with full metadata envelope
- `--format json|html|txt|all` flag
- `--no-banner` and `--version` flags
- Graceful interrupt — partial reports generated on SIGINT/SIGTERM
- `findings.jsonl` written as-discovered for resilient partial runs
- Aggressive mode: nmap `-A -O --script=vuln,auth`, sqlmap level 5 + tamper, deep DOM XSS
- Stealth mode: nmap `-sS -T2 -f`, sqlmap delay, safe-freq

### Changed

- Fully rewritten in English
- Modular `module_*()` function architecture
- `add_finding()` emits structured JSONL with id, severity, module, title, description, evidence, recommendation, timestamp
- Output directory reorganised into 9 subdirectories

### Fixed

- SPF detection now handles multi-TXT records
- HSTS check handles missing header without error
- JSON report correctly escapes multi-line evidence strings

---

## [1.0.0] — 2026-01-13

### Added

- Initial release
- Core modules: recon, port scan, SSL, headers, dir brute-force, nikto, sqlmap
- Basic HTML report
- Spanish-language interface

---

[1.0.1]: https://github.com/davidalvarezp/websec-audit/releases/tag/v1.0.1
[1.0.0]: https://github.com/davidalvarezp/websec-audit/releases/tag/v1.0.0
