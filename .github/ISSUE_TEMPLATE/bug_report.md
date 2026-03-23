---
name: Bug Report
about: Report a bug or unexpected behaviour in websec-audit
title: "[BUG] "
labels: bug
assignees: davidalvarezp
---

## Description

<!-- A clear and concise description of the bug -->

## Steps to Reproduce

```bash
# Exact command you ran (redact the target)
./websec-audit.sh -t https://REDACTED --option
```

1. Run the above command
2. See error / unexpected behaviour in module: **[MODULE NAME]**

## Expected Behaviour

<!-- What you expected to happen -->

## Actual Behaviour

<!-- What actually happened. Include relevant log output below -->

<details>
<summary>Log output (redact sensitive data)</summary>

```
paste relevant log lines here
```

</details>

## Environment

| Item | Details |
|------|---------|
| websec-audit version | `./websec-audit.sh -V` |
| OS / Distro | e.g. Debian 12, Ubuntu 22.04, Kali 2024.1 |
| Bash version | `bash --version` |
| Affected tool | e.g. nmap, sqlmap, gobuster |
| Tool version | e.g. `nmap --version` |

## Module

- [ ] Recon
- [ ] Port Scan
- [ ] Fingerprint
- [ ] SSL/TLS
- [ ] HTTP Headers
- [ ] Dir/File Enum
- [ ] Nikto
- [ ] SQLi
- [ ] XSS
- [ ] CMS
- [ ] CORS
- [ ] Open Redirect
- [ ] SSRF
- [ ] Subdomain Takeover
- [ ] Nuclei
- [ ] Reporting
- [ ] Install / Dependencies
- [ ] Other

## Additional Context

<!-- Any other context, screenshots, or information that might help -->
