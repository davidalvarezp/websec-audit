---
title: "Module 08 · SQL Injection"
description: Automated SQL injection detection and exploitation using sqlmap.
---

# Module 08 · SQL Injection

**Flag:** `--skip-sqli`

Uses sqlmap to detect and confirm SQL injection vulnerabilities in the target URL.

---

## sqlmap configuration

| Mode | sqlmap flags |
|---|---|
| Normal | `--batch --random-agent --level=3 --risk=2 --timeout=<n> --threads=<n>` |
| Aggressive | `--level=5 --risk=3 --forms --crawl=<depth> --dbs --tamper=space2comment` |
| Stealth | Adds `--delay=2 --safe-freq=3 --smart` |

---

## What is checked

- **GET parameters** in the target URL
- **POST forms** (aggressive mode via `--forms`)
- **Crawled pages** (aggressive mode via `--crawl`)

sqlmap tests for:

- Boolean-based blind SQLi
- Error-based SQLi
- Time-based blind SQLi
- UNION-based SQLi
- Stacked queries

---

## Findings

| Condition | Severity |
|---|:---:|
| SQL injection confirmed | <span class="sev sev-critical">CRITICAL</span> |
| No SQLi on primary URL | <span class="sev sev-info">INFO</span> |

---

## Remediation

> Use **parameterised queries** (prepared statements) in every database interaction. Never concatenate user-supplied input directly into SQL strings.

=== "PHP (PDO)"
    ```php
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_GET['id']]);
    ```

=== "Python (psycopg2)"
    ```python
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    ```

=== "Node.js (pg)"
    ```js
    const res = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
    ```

---

## Output files

```
vulns/sqlmap/
├── sqlmap_console.txt
└── <target>/           # sqlmap output directory per target
```
