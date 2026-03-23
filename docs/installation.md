---
title: Installation
description: How to install websec-audit and its dependencies on Debian, Ubuntu and Kali Linux.
---

# Installation

WebSec-Audit runs on **Debian 11/12/13**, **Ubuntu 20.04/22.04/24.04** and **Kali Linux 2023+**.

---

## Automatic install (recommended)

The bundled `install.sh` script handles everything: APT packages, Go binaries, Ruby gems, Python packages and wordlists.

```bash
git clone https://github.com/davidalvarezp/websec-audit.git
cd websec-audit
chmod +x install.sh websec-audit.sh
sudo ./install.sh
```

The installer detects your architecture (`amd64` / `arm64`) and downloads the correct pre-compiled binaries for tools not available via APT.

!!! tip "Install log"
    The installer writes a full log to `/tmp/websec_install_<timestamp>.log`.
    Check it if anything fails.

---

## Manual install

### Required (core functionality)

```bash
sudo apt-get install -y curl nmap
```

### Recommended (significantly improves coverage)

```bash
sudo apt-get install -y \
  nikto sqlmap gobuster dirb \
  whatweb wafw00f sslscan \
  python3 python3-pip jq ruby \
  dnsutils whois wordlists
```

### Optional tools (install individually)

=== "testssl.sh"
    ```bash
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
    sudo ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
    ```

=== "wpscan"
    ```bash
    sudo gem install wpscan --no-document
    ```

=== "dalfox"
    ```bash
    # Download latest release for your arch
    wget https://github.com/hahwul/dalfox/releases/latest/download/dalfox_linux_amd64.tar.gz
    tar -xzf dalfox_linux_amd64.tar.gz
    sudo mv dalfox /usr/local/bin/
    ```

=== "subfinder"
    ```bash
    wget https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip
    unzip subfinder_linux_amd64.zip
    sudo mv subfinder /usr/local/bin/
    ```

=== "nuclei"
    ```bash
    wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
    unzip nuclei_linux_amd64.zip
    sudo mv nuclei /usr/local/bin/
    nuclei -update-templates
    ```

=== "droopescan"
    ```bash
    pip3 install droopescan
    ```

---

## Kali Linux

Most tools are pre-installed. Run the installer to fill any remaining gaps:

```bash
sudo ./install.sh
```

---

## Verifying the installation

```bash
./websec-audit.sh --version
```

Expected output:

```
websec-audit v1.0.1 — davidalvarezp
```

The tool also performs a dependency check at the start of every scan, listing which tools are available and which are missing.

---

## Dependency matrix

| Tool | Required | Module(s) |
|---|:---:|---|
| `curl` | ✅ | All HTTP modules |
| `nmap` | ✅ | Port Scanning |
| `nikto` | optional | Nikto |
| `sqlmap` | optional | SQL Injection |
| `gobuster` | optional | Dir & File Enum |
| `ffuf` | optional | Dir & File Enum (fallback) |
| `dirb` | optional | Dir & File Enum (fallback) |
| `whatweb` | optional | Fingerprinting |
| `wafw00f` | optional | Fingerprinting |
| `sslscan` | optional | SSL/TLS |
| `testssl.sh` | optional | SSL/TLS (preferred) |
| `wpscan` | optional | CMS — WordPress |
| `droopescan` | optional | CMS — Drupal/Joomla |
| `dalfox` | optional | XSS |
| `subfinder` | optional | Reconnaissance |
| `amass` | optional | Reconnaissance |
| `dnsrecon` | optional | Reconnaissance |
| `subjack` | optional | Subdomain Takeover |
| `nuclei` | optional | Nuclei + Takeover |
| `jq` | optional | JSON report parsing |
| `python3` | optional | URL encoding, HTML reports |
| `whois` | optional | Reconnaissance |
| `dig` | optional | DNS analysis |
