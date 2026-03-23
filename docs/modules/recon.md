---
title: "Module 01 · Reconnaissance"
description: WHOIS, DNS records, zone transfer, subdomain enumeration, SPF/DMARC and Google Dorks.
---

# Module 01 · Reconnaissance

**Flag:** `--skip-recon`

The reconnaissance module performs passive and semi-passive information gathering before any active scanning begins.

---

## Sub-checks

### WHOIS lookup
Queries the WHOIS database for registrar, registrant, expiry date and nameservers.
Output saved to `recon/whois.txt`.

### DNS record enumeration
Queries all major record types: `A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA`, `CNAME`, `CAA`, `DMARC`.
Output saved to `recon/dns_records.txt`.

**SPF analysis** — flags missing SPF records and dangerous `+all` policies:

| Condition | Severity |
|---|:---:|
| No SPF record | <span class="sev sev-medium">MEDIUM</span> |
| SPF uses `+all` | <span class="sev sev-high">HIGH</span> |
| No DMARC record | <span class="sev sev-medium">MEDIUM</span> |
| DMARC `p=none` | <span class="sev sev-low">LOW</span> |

### DNS Zone Transfer (AXFR)
Attempts AXFR against all discovered nameservers. A successful transfer exposes the entire DNS zone.

| Condition | Severity |
|---|:---:|
| AXFR permitted | <span class="sev sev-critical">CRITICAL</span> |

### Subdomain enumeration
Uses multiple tools in parallel and deduplicates results into `recon/subdomains.txt`:

- **subfinder** — passive DNS sources (certificate transparency, DNS databases)
- **amass** — passive enumeration
- **dnsrecon** — standard DNS queries
- **Fallback** — wordlist-based DNS brute-force (first 500 entries) if no enumeration tool is available

### Google Dorks
Generates a curated list of Google Dorks for manual research — not executed automatically.
Saved to `recon/google_dorks.txt`. Categories include: information disclosure, admin panels, credentials, config files, exposed APIs.

---

## Tools used

| Tool | Role | Fallback |
|---|---|---|
| `whois` | WHOIS lookup | None |
| `dig` | DNS queries | `host` |
| `subfinder` | Passive subdomain enum | Wordlist brute-force |
| `amass` | Extended passive enum | Optional |
| `dnsrecon` | DNS standard checks | Optional |

---

## Skip this module

```bash
./websec-audit.sh -t https://target.com --skip-recon
```

---

## Output files

```
recon/
├── whois.txt
├── dns_records.txt
├── axfr.txt
├── subfinder.txt
├── amass.txt
├── dnsrecon.json
├── subdomains.txt          # deduplicated, used by Module 14
├── whatweb.json
├── waf_detection.txt
└── google_dorks.txt
```
