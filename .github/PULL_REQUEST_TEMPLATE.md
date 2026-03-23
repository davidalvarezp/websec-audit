## Summary

<!-- One paragraph describing what this PR does and why -->

## Type of Change

- [ ] 🐛 Bug fix
- [ ] ✨ New feature / module
- [ ] 📝 Documentation update
- [ ] ♻️  Refactor (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🔧 Chore / maintenance

## Related Issue(s)

<!-- Closes #XXX | Fixes #XXX | Resolves #XXX -->

## Changes Made

<!-- List the key changes in bullet points -->
- 
- 
- 

## Module(s) Affected

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
- [ ] Reporting / Output
- [ ] Install script
- [ ] Documentation

## Testing

<!-- Describe how you tested this PR -->

```bash
# Commands used to test
./websec-audit.sh -t https://REDACTED --your-new-option
```

- [ ] Tested on Debian / Ubuntu
- [ ] Tested with `--aggressive` mode
- [ ] Tested with `--stealth` mode
- [ ] Tested with `--skip-<module>` to ensure skip works
- [ ] `shellcheck -S warning websec-audit.sh` passes with zero warnings

## Checklist

- [ ] Code follows the style guidelines in [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] Self-review completed
- [ ] New module added to `README.md` module table
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] No hardcoded credentials, IPs, or sensitive data
- [ ] All findings go through `add_finding()` — not written directly to files
