# Contributing to websec-audit

Thank you for your interest in contributing to **websec-audit**!   
All contributions are welcome — bug reports, feature requests, documentation improvements, new modules, and code fixes.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Guidelines](#development-guidelines)
- [Adding a New Module](#adding-a-new-module)
- [Commit Conventions](#commit-conventions)
- [Pull Request Process](#pull-request-process)

---

## Code of Conduct

By participating in this project, you agree to:

- Be respectful and constructive in all communications
- Only contribute code intended for **authorised security testing**
- Not submit payloads, exploits, or code designed to harm systems without consent

---

## How to Contribute

### Reporting Bugs

1. Search [existing issues](https://github.com/davidalvarezp/websec-audit/issues) first
2. Open a new issue using the **Bug Report** template
3. Include: OS version, tool versions, reproduction steps, expected vs actual behaviour

### Requesting Features

1. Open an issue using the **Feature Request** template
2. Describe the use case and expected output clearly

### Code Contributions

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USER/websec-audit.git`
3. Create a **feature branch**: `git checkout -b feature/your-feature-name`
4. Make your changes following the guidelines below
5. **Test** your changes
6. **Commit** using conventional commits (see below)
7. **Push**: `git push origin feature/your-feature-name`
8. Open a **Pull Request** against `main`

---

## Development Guidelines

### Shell Style

- Target **bash 5.0+** — no POSIX-only constraints, but avoid bash 5.1+ exclusive syntax
- Use `set -euo pipefail` and `IFS=$'\n\t'` at the top of every script
- Quote all variable expansions: `"$var"` not `$var`
- Use `[[ ]]` for conditions, not `[ ]`
- Prefer `local` variables inside functions
- Run `shellcheck` on your changes before submitting:
  ```bash
  shellcheck -S warning websec-audit.sh
  ```

### Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Functions | `snake_case` | `module_sqli()` |
| Constants | `UPPER_SNAKE` | `readonly TOOL_VERSION` |
| Global vars | `UPPER_SNAKE` | `OPT_AGGRESSIVE` |
| Local vars | `lower_snake` | `local scan_target` |
| Module flags | `MOD_NAME` | `MOD_SQLI` |
| Option flags | `OPT_NAME` | `OPT_THREADS` |

### Error Handling

- Never silently ignore errors — use `|| true` only when failure is genuinely acceptable
- Use `log_warn` when a tool is missing; the script must continue
- Use `log_error` + `exit 1` only for unrecoverable conditions (missing required tool, invalid target)
- All findings must go through `add_finding()` — never write directly to reports

### Performance

- Respect `OPT_THREADS` and `OPT_TIMEOUT` in all external tool calls
- Use `timeout` around all network operations
- Avoid unnecessary subshells in tight loops

---

## Adding a New Module

1. Add a toggle variable in the global section:
   ```bash
   MOD_MYMODULE=1
   ```

2. Add a `--skip-mymodule` argument in `parse_args()`:
   ```bash
   --skip-mymodule) MOD_MYMODULE=0; shift ;;
   ```

3. Add the `--skip-mymodule` entry to the help text in `print_usage()`.

4. Write the module function following this template:
   ```bash
   # ─────────────────────────────────────────────────────────────────────────────
   #  MODULE XX — YOUR MODULE NAME
   # ─────────────────────────────────────────────────────────────────────────────
   module_mymodule() {
     [[ $MOD_MYMODULE -eq 0 ]] && return
     log_section "MODULE XX — YOUR MODULE NAME"

     local out_dir="${OUTPUT_DIR}/misc"

     # Check for optional tools
     if ! has_tool mytool; then
       log_warn "mytool not available — skipping related checks"
     fi

     # ... your logic ...

     # Register findings
     add_finding "HIGH" "MYMODULE" "Short finding title" \
       "Detailed description of what was found." \
       "evidence string" \
       "Remediation recommendation."

     log_info "Module results → $out_dir"
   }
   ```

5. Call the module in `main()` after `module_cms` and before `generate_reports`.

6. Add the module to the table in `README.md`.

7. Add an entry to `CHANGELOG.md` under `[Unreleased]`.

---

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

### Types

| Type | When to use |
|------|------------|
| `feat` | New feature or module |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `chore` | Build process, dependency updates |

### Examples

```bash
feat(module): add GraphQL introspection detection
fix(ssl): handle certificates with no expiry date gracefully
docs(readme): add Kali Linux installation instructions
refactor(headers): extract cookie analysis into helper function
```

---

## Pull Request Process

1. **One PR per feature/fix** — keep changes focused and reviewable
2. **Update documentation** — README, CHANGELOG, and inline comments
3. **Describe your PR** — fill in the PR template completely
4. **Pass shellcheck** — zero warnings on `websec-audit.sh` and `install.sh`
5. **Test manually** — run the affected module(s) against a test target (DVWA, HackTheBox, your own lab)

PRs will be reviewed within 5 business days. Feedback will be given constructively.  
Once approved, a maintainer will merge it into `main`.

---

Thank you for helping make **websec-audit** better! 🔐
