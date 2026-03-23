---
title: "Module 06 · Dir & File Enumeration"
description: Directory brute-forcing and sensitive file path probing.
---

# Module 06 · Dir & File Enumeration

**Flag:** `--skip-dirbrute`

Combines wordlist-based directory brute-forcing with targeted probing of 40+ known sensitive paths.

---

## Directory brute-force

| Mode | Wordlist used |
|---|---|
| Normal | `--wl-dirs-small` (default: dirb/common.txt) |
| Aggressive | `--wl-dirs-big` (default: dirbuster/directory-list-2.3-medium.txt) |

**Tool priority:** gobuster → ffuf → dirb

```bash
# Use a custom wordlist
./websec-audit.sh -t https://target.com --wl-dirs-small /path/to/custom.txt
```

---

## Sensitive path probing

40+ paths are probed directly with `curl` regardless of the brute-force wordlist.
Findings are severity-classified automatically:

=== "Critical"
    | Path | Why |
    |---|---|
    | `/.git/HEAD` | Git repository exposed |
    | `/.git/config` | Git config exposed |
    | `/.env` | Environment file with credentials |
    | `/.env.local` | Local environment file |
    | `/.env.production` | Production secrets |
    | `/wp-config.php` | WordPress database credentials |
    | `/wp-config.php.bak` | Backup of WP config |
    | `/configuration.php` | Joomla config |
    | `/config/database.yml` | Rails DB config |
    | `/.aws/credentials` | AWS credentials file |
    | `/db.sql`, `/dump.sql`, `/backup.sql` | Database dumps |

=== "High"
    | Path | Why |
    |---|---|
    | `/phpinfo.php`, `/info.php` | PHP environment disclosure |
    | `/phpmyadmin/`, `/adminer.php` | Database admin interfaces |
    | `/web.config` | IIS config / credentials |
    | `/backup.zip`, `/backup.tar.gz` | Backup archives |
    | `/console` | Interactive console (RCE risk) |
    | `/Dockerfile`, `/docker-compose.yml` | Infrastructure secrets |

=== "Medium"
    | Path | Why |
    |---|---|
    | `/admin/`, `/administrator/` | Admin panels |
    | `/.htaccess` | Apache config |
    | `/server-status`, `/server-info` | Apache status pages |
    | `/_profiler/`, `/_debugbar` | Framework debug panels |
    | `/graphiql` | GraphQL IDE |
    | `/.DS_Store` | Directory structure leak |
    | `/package.json`, `/composer.json` | Dependency exposure |

=== "Low / Info"
    | Path | Why |
    |---|---|
    | `/robots.txt` | May disclose hidden paths |
    | `/sitemap.xml` | Site structure |
    | `/api/swagger.json`, `/swagger-ui.html` | API docs |
    | `/graphql` | GraphQL endpoint |
    | `/.well-known/security.txt` | Security contact policy |

---

## Output files

```
dirs/
├── gobuster_dirs.txt
├── gobuster_dns.txt
├── ffuf_results.json
├── dirb_results.txt
└── sensitive_paths_found.txt   # only paths that returned 200/301/302
```
