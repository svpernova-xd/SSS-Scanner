<div align="center">

```
 _____ _____ _____    ___
|   __|   __|   __|  / __| ___  __ _ _ _  _ _  ___ _ _
|__   |__   |__   |  \__ \/ __// _` | ' \| ' \/ -_) '_|
|_____|_____|_____|  |___/\___/\__,_|_||_|_||_\___|_|
```

**SSS-Scanner — Sensitive Service Scanner**

![Python](https://img.shields.io/badge/Python-3.6%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0-f59e0b?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-22c55e?style=flat-square)

*A fast, evasive port scanner purpose-built for authorized penetration testing and bug bounty recon.*

</div>

---

> **⚠ Legal Notice**
> SSS-Scanner is intended **exclusively** for use on systems you own or have explicit written permission to test.
> Unauthorized scanning may violate local laws. The author accepts no liability for misuse.

---

## ✦ Overview

SSS-Scanner is a multi-threaded sensitive-service port scanner with built-in evasion capabilities. It resolves hostnames, scans 66 pre-defined sensitive ports across all targets concurrently, and outputs clean results both to the terminal and a timestamped report file.

Designed for:
- **Bug bounty recon** — quickly surface exposed services across a large scope
- **Internal pentest** — identify sensitive services before deep exploitation
- **Asset discovery** — map what's actually listening across a network

---

## ✦ Features

| Feature | Details |
|---|---|
| 🔍 **66 built-in ports** | Covers databases, remote access, APIs, message queues, and more |
| 🧠 **3 scan modes** | `human`, `fast`, `stealth` — tune speed vs. detectability |
| 🎲 **Evasion engine** | Randomized scan order, per-connection jitter, rate limiting |
| 🌐 **DNS resolution** | Concurrent multi-threaded DNS with failure logging |
| ➕ **Custom ports** | Add ports inline or via file — supports ranges and labels |
| 💾 **Auto-save results** | Timestamped `.txt` report generated after every scan |
| ⚡ **Concurrent scanning** | ThreadPoolExecutor with configurable CPS and thread cap |
| 🛑 **Graceful interrupt** | `Ctrl+C` finishes current tasks cleanly; second press force-quits |

---

## ✦ Built-in Port Coverage

<details>
<summary>Click to expand — all 66 sensitive ports</summary>

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 3306 | MySQL / MariaDB |
| 22 | SSH / SFTP | 3389 | RDP |
| 23 | Telnet | 5432 | PostgreSQL |
| 25 | SMTP | 5601 | Kibana |
| 53 | DNS | 5800 | VNC-HTTP |
| 69 | TFTP | 5900–5901 | VNC |
| 80 | HTTP | 5938 | TeamViewer |
| 110 | POP3 | 5984 | CouchDB |
| 135 | MSRPC | 5985–5986 | WinRM |
| 139 | NetBIOS-SSN | 6379 | Redis |
| 143 | IMAP | 7443 | VMware vCenter |
| 161–162 | SNMP | 8000 / 8080 | HTTP-alt |
| 389 | LDAP | 8086 | InfluxDB |
| 443 | HTTPS | 8443 | HTTPS-alt |
| 445 | SMB | 9042 | Cassandra |
| 465 | SMTPS | 9090 | Web Management |
| 514 | Syslog | 9100 | Node Exporter |
| 587 | SMTP Submission | 9200 | Elasticsearch |
| 636 | LDAPS | 9300 | Elasticsearch Transport |
| 873 | Rsync | 10000 | Webmin |
| 989–990 | FTPS | 11211 | Memcached |
| 993 | IMAPS | 27017–27018 | MongoDB |
| 995 | POP3S | 2375–2376 | Docker API |
| 1433–1434 | MSSQL | 3000 | Grafana / Prometheus |
| 1521 | OracleDB | 3268–3269 | GC-LDAP |
| 2049 | NFS | — | — |

</details>

---

## ✦ Installation

### Quick install (Kali Linux)

```bash
git clone https://github.com/svpernova/sss-scanner
cd sss-scanner
sudo bash install.sh
```

The installer will:
1. Verify Python 3 is present (installs it if not)
2. Copy `sss-scanner.py` to `/usr/local/lib/sss-scanner/`
3. Create a launcher at `/usr/local/bin/sss-scanner`
4. Run a smoke test to confirm everything works

**After install, use `sss-scanner` from anywhere — no `python3` prefix needed.**

### Manual install (without installer)

```bash
git clone https://github.com/svpernova/sss-scanner
cd sss-scanner
chmod +x sss-scanner.py
python3 sss-scanner.py hosts.txt
```

### Requirements

- Python 3.6+
- Standard library only — **no pip dependencies**
- Kali Linux (tested), any Debian-based distro should work

---

## ✦ Usage

```
sss-scanner <hosts_file> [options]
```

### Arguments

| Argument | Short | Default | Description |
|---|---|---|---|
| `hosts_file` | — | required | Path to file with hostnames/IPs (one per line) |
| `--ports` | `-p` | — | Extra ports: `8080`, `8080,9090`, or `8000-8050` |
| `--ports-file` | `-pf` | — | File with custom ports (see format below) |
| `--mode` | — | `human` | Scan mode: `human` · `fast` · `stealth` |
| `--cps` | — | `50` | Max connections per second |
| `--timeout` | — | `3.0` | TCP connect timeout in seconds |
| `--threads` | — | `50` | Max concurrent threads |
| `--preserve-labels` | — | off | Keep built-in labels; don't override with custom ones |

---

## ✦ Scan Modes

| Mode | Speed | Jitter | Max CPS | Max Threads | Use Case |
|---|---|---|---|---|---|
| `human` | Medium | 0.05–0.5s | 50 | 50 | Default — balanced evasion |
| `fast` | High | 0.01–0.1s | unlimited | 100 | Speed over stealth |
| `stealth` | Low | 0.2–1.5s | 20 | 20 | Minimal footprint |

---

## ✦ Examples

```bash
# Basic scan with default settings
sss-scanner alive_hosts.txt

# Stealth scan with slower rate
sss-scanner alive_hosts.txt --mode stealth --cps 10

# Add custom ports inline
sss-scanner alive_hosts.txt --ports 8080,8443,10250

# Add a port range
sss-scanner alive_hosts.txt --ports 8000-8100

# Load extra ports from file
sss-scanner alive_hosts.txt --ports-file my_ports.txt

# Combine inline and file-based ports
sss-scanner alive_hosts.txt --ports 9999 --ports-file extra_ports.txt

# Fast scan with more threads
sss-scanner alive_hosts.txt --mode fast --threads 100 --timeout 1.5
```

---

## ✦ Custom Ports File Format (`--ports-file`)

```
# Lines starting with # are ignored

# Single port (uses built-in label if available)
8443

# Port with custom label
9999:MyCustomAPI

# Port range (all ports labelled as custom-N)
8000-8010

# Comma-separated ports
8080,9090,10000

# Range with label (label applies to first port; rest get custom-N)
8050-8060:InternalServices
```

---

## ✦ Hosts File Format

```
# One host per line — domains, IPs, or URLs (scheme and path are stripped)
192.168.1.1
10.0.0.0/24
example.com
https://target.com/path    ← scheme and path auto-stripped
```

---

## ✦ Output

### Terminal

```
Phase 1: DNS Resolution
────────────────────────────────────────
  [✓] Resolved: 28/32
  [!] Failed:   4 (internal/split-DNS)
  [*] DNS failures saved: sss_dns_fails_20260508_235709.txt

Phase 2: Port Scanning (Evasion Mode)
────────────────────────────────────────
  [*] Probes:   1,848 (~0.9m estimated)

  [~] 5/28 hosts checked (0 with open ports) — 1s
  ...

  ── target.example.com (10.10.1.5)
     ├─    22/tcp  →  SSH/SFTP
     ├─   443/tcp  →  HTTPS
     ├─  3306/tcp  →  MySQL/MariaDB
     ├─  6379/tcp  →  Redis
```

### Report file

Auto-saved as `sss_scanner_results_YYYYMMDD_HHMMSS.txt` in the current directory:

```
# ═══════════════════════════════════════════════════════════════
# SSS-Scanner v1.0 — svpernova
# Scan Results — 20260508_235709
# Mode: Human | Duration: 54s
# Ports scanned: 66
# ═══════════════════════════════════════════════════════════════

# target.example.com
target.example.com:22  (SSH/SFTP)
target.example.com:443  (HTTPS)
target.example.com:3306  (MySQL/MariaDB)
```

---

## ✦ Uninstall

```bash
sudo rm /usr/local/bin/sss-scanner && sudo rm -rf /usr/local/lib/sss-scanner
```

---

## ✦ Project Structure

```
sss-scanner/
├── sss-scanner.py   ← main scanner
├── install.sh       ← Kali Linux installer
└── README.md        ← this file
```

---

## ✦ License

MIT — see [LICENSE](LICENSE).
Use only on systems you own or have written authorization to test.

---

<div align="center">

Made by **svpernova** · [GitHub](https://github.com/svpernova/sss-scanner)

</div>
