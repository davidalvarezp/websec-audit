# Changelog

All notable changes to **websec-audit** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] — 2026-03-23

### Added
- **Module 15 — Nuclei** template scan integration (severity-filtered)
- **Module 14 — Subdomain Takeover**: `subjack` + Nuclei + manual CNAME analysis for 20+ services
- **Module 13 — SSRF**: cloud IMDS probing (AWS, GCP, Azure), decimal/hex IP encoding
- **Module 12 — Open Redirect**: 20 parameters × 10 redirect payloads
- **Module 11 — CORS**: null origin, credentialed cross-origin, wildcard detection
- **Module 10 — CMS**: WordPress REST API user enumeration, debug.log, xmlrpc.php checks
- **Module 09 — XSS**: dalfox integration + 8 reflected XSS payloads × 15 parameters
- **Module 08 — SQLi**: sqlmap with forms crawl in aggressive mode, tamper scripts
- **Module 07 — Nikto**: severity-based finding classification
- **Module 06 — Dir Enum**: 40 sensitive path probes (`.git`, `.env`, AWS credentials, Dockerfiles, etc.)
- **Module 05 — HTTP Headers**: CSP audit (unsafe-inline, wildcards), SameSite=None+Secure, Cache-Control
- **Module 04 — SSL/TLS**: CAA records, HSTS preload, cert expiry thresholds (14/30/90 days)
- **Module 03 — Fingerprint**: WAF detection via wafw00f, version-leaking header enumeration
- **Module 02 — Port Scan**: risk-based analysis for 20+ dangerous ports
- **Module 01 — Recon**: SPF `+all` detection, DMARC `p=none` warning, 700+ Google Dorks
- Interactive HTML report with severity filter, live search, and risk bar
- JSON report with full metadata envelope
- `--format json|html|txt|all` flag
- `--no-banner` flag for scripting/CI use
- `--version` / `-V` flag
- Graceful interrupt handling — generates partial reports on SIGINT/SIGTERM
- Signal trap generates partial report on Ctrl-C
- `findings.jsonl` raw log for programmatic processing
- Aggressive mode: nmap `-A -O --script=vuln,auth`, sqlmap level 5 + tamper, deep DOM XSS
- Stealth mode: nmap `-sS -T2 -f`, sqlmap delay, randomised ordering
- Tool availability graceful degradation — all modules have fallbacks

### Changed
- Fully rewritten in English for international audience
- Modular `module_*()` function architecture — each module independently skippable
- `add_finding()` now emits structured JSONL with id, severity, module, title, description, evidence, recommendation, and RFC3339 timestamp
- `_curl()` wrapper with retry, consistent UA, proxy, and timeout
- Output directory structure reorganised into `recon/`, `portscan/`, `ssl/`, `headers/`, `dirs/`, `vulns/`, `cms/`, `misc/`, `reports/`, `logs/`
- HTML report: dark theme, sticky table headers, responsive grid

### Fixed
- SPF record detection now handles multi-TXT records correctly
- HSTS max-age check handles missing header without error
- nmap output parsing compatible with both GNU and BSD grep
- JSON report correctly handles multi-line evidence strings

---

## [1.0.0] — 2026-01-13

### Added
- Initial release
- Core modules: recon, port scan, SSL, headers, dir brute-force, nikto, sqlmap
- Basic HTML report
- Spanish-language interface

---

[1.0.1]: https://github.com/davidalvarezp/websec-audit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/davidalvarezp/websec-audit/releases/tag/v1.0.0
