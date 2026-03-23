---
title: Contributing
description: How to contribute to websec-audit — bug reports, new modules, code style and commit conventions.
---

# Contributing

Contributions are welcome. This page covers everything you need to know before opening a PR.

---

## Getting started

1. **Fork** the repository on GitHub
2. **Clone** your fork: `git clone https://github.com/YOUR_USER/websec-audit.git`
3. Create a **feature branch**: `git checkout -b feature/your-feature`
4. Make your changes
5. Run `shellcheck -S warning websec-audit.sh` — zero warnings required
6. **Commit** using conventional commits (see below)
7. **Push** and open a Pull Request against `main`

---

## Code style

- Target **bash 5.0+**
- Use `set -euo pipefail` at the top of every script
- Quote all variable expansions: `"$var"` not `$var`
- Use `[[ ]]` for conditions
- Declare local variables with `local var` then assign separately (avoids SC2155)
- Run `shellcheck` before every commit

---

## Adding a new module

1. Add a toggle: `MOD_MYMODULE=1`
2. Add `--skip-mymodule` to `parse_args()`
3. Write the function:

```bash
module_mymodule() {
  [[ $MOD_MYMODULE -eq 0 ]] && return
  log_section "MODULE XX — NAME"

  # your logic

  add_finding "HIGH" "MYMODULE" "Title" "Description" "evidence" "Remediation."
}
```

4. Call it in `main()` before `generate_reports`
5. Add to the module table in `README.md` and these docs
6. Add a `CHANGELOG.md` entry

---

## Commit conventions

```
feat(module): add GraphQL introspection detection
fix(ssl): handle certificates with no expiry date
docs(readme): add Kali installation instructions
refactor(headers): extract cookie analysis into helper
```

**Types:** `feat` · `fix` · `docs` · `refactor` · `perf` · `test` · `chore`

---

## Issue templates

Use the GitHub issue templates:

- **Bug report** — for unexpected behaviour or errors
- **Feature request** — for new modules or improvements

---

## Full guide

The complete contributing guide is in the repository:
[CONTRIBUTING.md :material-github:](https://github.com/davidalvarezp/websec-audit/blob/main/CONTRIBUTING.md)
