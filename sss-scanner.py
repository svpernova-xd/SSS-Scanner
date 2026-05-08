#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     SSS-Scanner v1.0                                         ║
║              Sensitive Service Scanner — Evasion Mode                        ║
║                                                                              ║
║   ███████  ██████  ███████  ███████  ██████   █████  ███    ██               ║
║   ██      ██      ██      ██      ██      ██   ██  ████   ██                 ║
║   ███████ ██      ███████ ███████ ██      ███████ ██ ██  ██                  ║
║        ██ ██      ██           ██ ██      ██   ██ ██  ██ ██                  ║
║   ███████  ██████  ███████ ███████  ██████ ██   ██ ██   ████                 ║
║                                                                              ║
║   Author:  svpernova                                                         ║
║   License: MIT — Authorized Penetration Testing Only                         ║
║   GitHub:  https://github.com/svpernova/sss-scanner                          ║
║                                                                              ║
║   [!] USE ONLY ON SYSTEMS YOU OWN OR HAVE WRITTEN PERMISSION TO TEST         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import socket
import sys
import os
import time
import random
import threading
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse
import re

# ─── ANSI COLORS ────────────────────────────────────────────────────────────
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    
    RED_BG    = "\033[101m"
    GREEN_BG  = "\033[102m"
    BLUE_BG   = "\033[104m"
    CYAN_BG   = "\033[106m"
    
    # Status indicators
    OK    = f"{GREEN}[+]{RESET}"
    INFO  = f"{BLUE}[*]{RESET}"
    WARN  = f"{YELLOW}[!]{RESET}"
    FAIL  = f"{RED}[-]{RESET}"
    HEAD  = f"{CYAN}[=]{RESET}"


# ─── BANNER ─────────────────────────────────────────────────────────────────
def print_banner():
    """Print Metasploit-style clean banner using plain print() for correct alignment"""
    C = Colors
    W = 66  # visible box width (inner)

    ascii_lines = [
        f"  {C.CYAN} _____ _____ _____    ___                                 {C.RESET}",
        f"  {C.CYAN}|   __|   __|   __|  / __| ___  __ _ _ _  _ _  ___ _ _   {C.RESET}",
        f"  {C.CYAN}|__   |__   |__   |  \\__ \\/ __|/ _` | ' \\| ' \\/ -_) '_|  {C.RESET}",
        f"  {C.CYAN}|_____|_____|_____|  |___/\\___/\\__,_|_||_|_||_\\___|_|    {C.RESET}",
    ]

    sep   = f"{C.CYAN}{C.BOLD}{'─' * (W + 2)}{C.RESET}"
    blank = ""

    print()
    print(sep)
    print(blank)
    for line in ascii_lines:
        print(line)
    print(blank)
    print(f"  {C.BOLD}{C.WHITE}SSS-Scanner{C.RESET}  {C.DIM}v1.0{C.RESET}   {C.DIM}·{C.RESET}   {C.YELLOW}Sensitive Service Scanner{C.RESET}")
    print(blank)
    print(sep)
    print(f"  {C.DIM}Author   {C.RESET}  {C.WHITE}svpernova{C.RESET}")
    print(f"  {C.DIM}GitHub   {C.RESET}  {C.BLUE}https://github.com/svpernova/sss-scanner{C.RESET}")
    print(f"  {C.DIM}License  {C.RESET}  {C.GREEN}MIT — Authorized Penetration Testing Only{C.RESET}")
    print(sep)
    print(f"  {C.YELLOW}{C.BOLD}⚠  USE ONLY ON SYSTEMS YOU OWN OR HAVE WRITTEN PERMISSION TO TEST{C.RESET}")
    print(sep)
    print()

# Keep BANNER as empty string for backward compat (print_banner() replaces it)
BANNER = ""


# ─── SENSITIVE PORTS (built-in) ─────────────────────────────────────────────
SENSITIVE_PORTS_BASE = {
    21:   "FTP",
    22:   "SSH/SFTP",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    115:  "SFTP",
    135:  "MSRPC",
    139:  "NetBIOS-SSN",
    143:  "IMAP",
    161:  "SNMP",
    162:  "SNMP-trap",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    514:  "Syslog",
    587:  "SMTP-submission",
    636:  "LDAPS",
    873:  "Rsync",
    989:  "FTPS-data",
    990:  "FTPS-control",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1434: "MSSQL-monitor",
    1521: "OracleDB",
    2049: "NFS",
    2375: "Docker-API",
    2376: "Docker-API-TLS",
    2483: "OracleDB-alt",
    2484: "OracleDB-alt2",
    3000: "Grafana/Prometheus",
    3268: "GC-LDAP",
    3269: "GC-LDAPS",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5800: "VNC-HTTP",
    5900: "VNC",
    5901: "VNC-1",
    5938: "TeamViewer",
    5984: "CouchDB",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    7443: "VMware-vCenter",
    8000: "HTTP-alt",
    8080: "HTTP-alt",
    8086: "InfluxDB",
    8090: "API-Alt",
    8443: "HTTPS-alt",
    9042: "Cassandra",
    9090: "WebManagement",
    9100: "Node-Exporter",
    9160: "Cassandra-THRIFT",
    9200: "Elasticsearch",
    9300: "Elasticsearch-transport",
    9443: "HTTPS-alt2",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-web",
}

# ─── EVASION CONFIG ──────────────────────────────────────────────────────────
class EvasionConfig:
    def __init__(self):
        self.jitter_min = 0.05
        self.jitter_max = 0.5
        self.host_group_delay_min = 1.0
        self.host_group_delay_max = 5.0
        self.ports_per_batch = 5
        self.max_cps = 50
        self.src_port_min = 10000
        self.src_port_max = 65000
        self.timeout = 3.0
        self.max_threads = 50
        self.shuffle_hosts = True
        self.shuffle_ports = True
        self.randomize_order = True
        self.human_mode = True

conf = EvasionConfig()


# ─── CTRL+C HANDLER ─────────────────────────────────────────────────────────
shutdown_flag = threading.Event()

def signal_handler(sig, frame):
    """Graceful shutdown on Ctrl+C"""
    if shutdown_flag.is_set():
        print(f"\n{Colors.RED}{Colors.BOLD}[!] Force quitting...{Colors.RESET}")
        sys.exit(1)
    
    shutdown_flag.set()
    print(f"\n{Colors.YELLOW}{Colors.BOLD}[!] INTERRUPT RECEIVED{Colors.RESET}")
    print(f"{Colors.YELLOW}[!] Finishing current scans and shutting down gracefully...{Colors.RESET}")
    print(f"{Colors.YELLOW}[!] Press Ctrl+C again to force quit{Colors.RESET}")

signal.signal(signal.SIGINT, signal_handler)


# ─── CUSTOM PORTS ────────────────────────────────────────────────────────────
def parse_custom_ports(port_spec):
    custom_ports = {}
    if not port_spec:
        return custom_ports
    
    parts = [p.strip() for p in port_spec.split(',') if p.strip()]
    
    for part in parts:
        if '-' in part:
            range_match = re.match(r'^(\d+)-(\d+)$', part)
            if range_match:
                start = int(range_match.group(1))
                end = int(range_match.group(2))
                if start > end:
                    start, end = end, start
                if start < 1 or end > 65535:
                    print(f"{Colors.WARN} Invalid port range: {part} (must be 1-65535){Colors.RESET}")
                    continue
                for p in range(start, end + 1):
                    label = SENSITIVE_PORTS_BASE.get(p, f"custom-{p}")
                    custom_ports[p] = label
            else:
                print(f"{Colors.WARN} Invalid range format: {part} (use: start-end){Colors.RESET}")
        else:
            try:
                p = int(part)
                if p < 1 or p > 65535:
                    print(f"{Colors.WARN} Invalid port: {p} (must be 1-65535){Colors.RESET}")
                    continue
                label = SENSITIVE_PORTS_BASE.get(p, f"custom-{p}")
                custom_ports[p] = label
            except ValueError:
                print(f"{Colors.WARN} Invalid port value: '{part}'{Colors.RESET}")
    
    return custom_ports


def parse_custom_ports_file(filepath):
    custom_ports = {}
    if not filepath or not os.path.exists(filepath):
        return custom_ports
    
    with open(filepath) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if ':' in line and not line.startswith('http'):
                parts = line.split(':', 1)
                try:
                    left = parts[0].strip()
                    label = parts[1].strip()
                    
                    if '-' in left:
                        range_match = re.match(r'^(\d+)-(\d+)$', left)
                        if range_match:
                            start = int(range_match.group(1))
                            end = int(range_match.group(2))
                            if start > end:
                                start, end = end, start
                            for p in range(start, end + 1):
                                custom_ports[p] = f"{label}-{p}" if p != start else label
                        else:
                            print(f"{Colors.WARN} File line {line_num}: Invalid '{line}'{Colors.RESET}")
                    else:
                        p = int(left)
                        custom_ports[p] = label
                except (ValueError, IndexError):
                    line_ports = parse_custom_ports(line)
                    custom_ports.update(line_ports)
            else:
                line_ports = parse_custom_ports(line)
                custom_ports.update(line_ports)
    
    return custom_ports


def merge_ports(base_ports, custom_ports, overwrite=True):
    merged = dict(base_ports)
    for p, label in custom_ports.items():
        if overwrite:
            merged[p] = label
        else:
            merged.setdefault(p, label)
    return merged


def build_port_list(args):
    custom_ports = {}
    
    if args.ports:
        cli_ports = parse_custom_ports(args.ports)
        custom_ports.update(cli_ports)
        if cli_ports:
            port_list_str = ', '.join(str(p) for p in sorted(cli_ports.keys()))
            print(f"{Colors.INFO} Custom ports from --ports: {port_list_str}{Colors.RESET}")
    
    if args.ports_file:
        file_ports = parse_custom_ports_file(args.ports_file)
        custom_ports.update(file_ports)
        if file_ports:
            print(f"{Colors.INFO} Custom ports from file ({args.ports_file}): {len(file_ports)} ports{Colors.RESET}")
    
    final_ports = merge_ports(SENSITIVE_PORTS_BASE, custom_ports, overwrite=not args.preserve_labels)
    
    if custom_ports:
        new_ports = [p for p in custom_ports if p not in SENSITIVE_PORTS_BASE]
        if new_ports:
            print(f"{Colors.INFO} New ports added: {', '.join(str(p) for p in sorted(new_ports))}{Colors.RESET}")
    
    return final_ports


# ─── SOCKET WITH EVASION ─────────────────────────────────────────────────────
def create_evasion_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        src_port = random.randint(conf.src_port_min, conf.src_port_max)
        s.bind(('0.0.0.0', src_port))
    except Exception:
        pass
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 0)
    buf_size = random.choice([4096, 8192, 16384, 32768, 65535])
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buf_size)
    s.settimeout(conf.timeout)
    return s


# ─── GLOBAL STATE ────────────────────────────────────────────────────────────
results_lock = threading.Lock()
found_hosts = {}
scan_progress = {"total": 0, "done": 0, "alive": 0}
progress_lock = threading.Lock()
start_time = None
rate_limit_lock = threading.Lock()
probe_counter = 0
probe_start = 0
resolved_cache = {}


# ─── RATE LIMITER ──────────────────────────────────────────────────────────
def rate_limit():
    global probe_counter, probe_start
    if shutdown_flag.is_set():
        return
    with rate_limit_lock:
        now = time.time()
        if probe_start == 0:
            probe_start = now
            probe_counter = 1
            return
        elapsed = now - probe_start
        if elapsed < 1.0:
            probe_counter += 1
            if probe_counter >= conf.max_cps:
                sleep_time = 1.0 - elapsed + random.uniform(0.01, 0.1)
                time.sleep(sleep_time)
                probe_start = time.time()
                probe_counter = 0
        else:
            probe_start = now
            probe_counter = 0


# ─── HUMAN DELAY ─────────────────────────────────────────────────────────
def human_delay():
    if not conf.human_mode:
        return
    if random.random() < 0.01:
        time.sleep(random.uniform(0.5, 2.0))
    delay = random.uniform(conf.jitter_min, conf.jitter_max)
    if random.random() < 0.05:
        delay += random.uniform(0.1, 0.3)
    time.sleep(delay)


# ─── RESOLVE ───────────────────────────────────────────────────────────
def resolve_host(hostname):
    try:
        ip = socket.getaddrinfo(hostname.strip(), 80, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        return hostname.strip(), ip
    except Exception:
        return hostname.strip(), None


# ─── SCAN PORT ─────────────────────────────────────────────────────────
def scan_port(hostname, ip, port, service_name):
    if shutdown_flag.is_set():
        return False
    rate_limit()
    s = None
    try:
        s = create_evasion_socket()
        result = s.connect_ex((ip, port))
        if result == 0:
            with results_lock:
                if hostname not in found_hosts:
                    found_hosts[hostname] = {}
                found_hosts[hostname][port] = service_name
            print(f"{Colors.GREEN}{Colors.BOLD}[+] {hostname}:{port}  →  {service_name}  ({ip}){Colors.RESET}", flush=True)
            return True
    except Exception:
        pass
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return False


# ─── SCAN HOST ─────────────────────────────────────────────────────────
def scan_host(hostname, ip, ports_dict):
    with progress_lock:
        scan_progress["done"] += 1
        done = scan_progress["done"]
        total = scan_progress["total"]
        alive = scan_progress["alive"]
        elapsed = time.time() - start_time
        if done % 5 == 0 or done == total:
            print(f"{Colors.DIM}[~] {done}/{total} hosts checked ({alive} with open ports) — {elapsed:.0f}s{Colors.RESET}", flush=True)
    
    port_items = list(ports_dict.items())
    if conf.randomize_order:
        random.shuffle(port_items)
    
    for i in range(0, len(port_items), conf.ports_per_batch):
        if shutdown_flag.is_set():
            return
        batch = port_items[i:i + conf.ports_per_batch]
        for port, service in batch:
            if shutdown_flag.is_set():
                return
            human_delay()
            open_found = scan_port(hostname, ip, port, service)
            if open_found:
                with progress_lock:
                    scan_progress["alive"] += 1
        time.sleep(random.uniform(0.1, 0.5))


# ─── DISPLAY ───────────────────────────────────────────────────────────
def print_header(ports_dict):
    os.system('clear' if os.name == 'posix' else 'cls')
    print_banner()
    print(f"{Colors.CYAN}{Colors.BOLD}{'─' * 72}{Colors.RESET}")
    print(f"  {Colors.WHITE}{Colors.BOLD}Configuration{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'─' * 72}{Colors.RESET}")
    print(f"  {Colors.INFO} Ports:     {Colors.WHITE}{len(ports_dict)} total{Colors.RESET}")
    print(f"  {Colors.INFO} Built-in:  {Colors.WHITE}{len(SENSITIVE_PORTS_BASE)} sensitive ports{Colors.RESET}")
    custom_count = len(ports_dict) - len(SENSITIVE_PORTS_BASE)
    if custom_count > 0:
        print(f"  {Colors.INFO} Custom:    {Colors.YELLOW}+{custom_count} user-added ports{Colors.RESET}")
    print(f"  {Colors.INFO} Jitter:    {Colors.WHITE}{conf.jitter_min}s — {conf.jitter_max}s{Colors.RESET}")
    print(f"  {Colors.INFO} Max CPS:   {Colors.WHITE}{conf.max_cps} connections/sec{Colors.RESET}")
    print(f"  {Colors.INFO} Mode:      {Colors.GREEN if conf.human_mode else Colors.YELLOW}{'HUMAN' if conf.human_mode else 'FAST'}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'─' * 72}{Colors.RESET}")
    print()


def print_summary(ports_dict):
    elapsed = time.time() - start_time
    
    print()
    print(f"{Colors.CYAN}{Colors.BOLD}{'═' * 72}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}  ╔══ SCAN COMPLETE ══╗{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'═' * 72}{Colors.RESET}")
    print(f"  {Colors.INFO} Duration:  {Colors.WHITE}{elapsed:.1f}s ({elapsed/60:.1f}m){Colors.RESET}")
    with progress_lock:
        print(f"  {Colors.INFO} Checked:   {Colors.WHITE}{scan_progress['done']} hosts{Colors.RESET}")
        print(f"  {Colors.INFO} Found:     {Colors.GREEN}{scan_progress['alive']} hosts with open ports{Colors.RESET}")
    
    with results_lock:
        if not found_hosts:
            print(f"\n  {Colors.YELLOW}No open ports found on any host.{Colors.RESET}")
        else:
            total_ports = sum(len(ports) for ports in found_hosts.values())
            print(f"\n  {Colors.INFO} Total open ports found: {Colors.GREEN}{Colors.BOLD}{total_ports}{Colors.RESET}")
            print()
            for hostname in sorted(found_hosts.keys()):
                ports_info = found_hosts[hostname]
                ip_str = f" ({Colors.DIM}{resolved_cache.get(hostname, '?')}{Colors.RESET})" if hostname in resolved_cache else ""
                print(f"  {Colors.CYAN}{Colors.BOLD}── {Colors.WHITE}{hostname}{Colors.RESET}{ip_str}")
                for port in sorted(ports_info.keys()):
                    print(f"     {Colors.GREEN}├─{Colors.RESET} {Colors.YELLOW}{port:>5}{Colors.RESET}{Colors.DIM}/tcp{Colors.RESET}  {Colors.CYAN}→{Colors.RESET}  {Colors.WHITE}{ports_info[port]}{Colors.RESET}")
            print()
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"sss_scanner_results_{timestamp}.txt"
            with open(filename, 'w') as f:
                f.write("# ═══════════════════════════════════════════════════════════════\n")
                f.write(f"# SSS-Scanner v1.0 — svpernova\n")
                f.write(f"# Scan Results — {timestamp}\n")
                f.write(f"# Mode: {'Human' if conf.human_mode else 'Fast'} | Duration: {elapsed:.0f}s\n")
                f.write(f"# Ports scanned: {len(ports_dict)}\n")
                f.write("# ═══════════════════════════════════════════════════════════════\n\n")
                for hostname in sorted(found_hosts.keys()):
                    ports_info = found_hosts[hostname]
                    f.write(f"# {hostname}\n")
                    for port in sorted(ports_info.keys()):
                        f.write(f"{hostname}:{port}  ({ports_info[port]})\n")
                    f.write("\n")
            print(f"  {Colors.GREEN}{Colors.BOLD}[✓]{Colors.RESET} Results saved: {Colors.WHITE}{filename}{Colors.RESET}")


# ─── MAIN ──────────────────────────────────────────────────────────────
def main():
    global start_time, resolved_cache, conf
    
    parser = argparse.ArgumentParser(
        description="SSS-Scanner v1.0 — Sensitive Service Scanner with Evasion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}{Colors.BOLD}Examples:{Colors.RESET}
  {Colors.WHITE}%(prog)s alive_hosts.txt{Colors.RESET}
  {Colors.WHITE}%(prog)s alive_hosts.txt --cps 30 --timeout 3.0 --mode stealth{Colors.RESET}
  {Colors.WHITE}%(prog)s alive_hosts.txt --ports 8080,9090,10000{Colors.RESET}
  {Colors.WHITE}%(prog)s alive_hosts.txt --ports 8000-8050{Colors.RESET}
  {Colors.WHITE}%(prog)s alive_hosts.txt --ports-file my_ports.txt{Colors.RESET}
  {Colors.WHITE}%(prog)s alive_hosts.txt --ports 8443,9999 --ports-file extra_ports.txt{Colors.RESET}
        
{Colors.YELLOW}{Colors.BOLD}Port File Format (--ports-file):{Colors.RESET}
  8443              Single port
  9999:MyService    Port with label
  8000-8010         Port range
  8080,9090,10000   Comma-separated
  # Comment lines  Ignored
        """
    )
    
    parser.add_argument("hosts_file", help="File containing hostnames/IPs (one per line)")
    parser.add_argument("--ports", "-p", help="Additional ports to scan (e.g., 8080,9090 or 8000-8050)")
    parser.add_argument("--ports-file", "-pf", help="File with custom ports (one per line, supports port:label)")
    parser.add_argument("--cps", type=int, default=50, help="Max connections per second (default: 50)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Connection timeout in seconds (default: 3.0)")
    parser.add_argument("--mode", choices=["human", "fast", "stealth"], default="human",
                        help="Scan mode: human (default), fast, or stealth")
    parser.add_argument("--threads", type=int, default=50, help="Max threads (default: 50)")
    parser.add_argument("--preserve-labels", action="store_true",
                        help="Don't override built-in port labels with custom ones")
    
    args = parser.parse_args()
    
    # Build port list
    ports_dict = build_port_list(args)
    
    # Deduplicate
    final_ports = {}
    for p in sorted(ports_dict.keys()):
        final_ports[p] = ports_dict[p]
    
    # Config
    conf.max_cps = args.cps
    conf.timeout = args.timeout
    conf.max_threads = args.threads
    
    if args.mode == "fast":
        conf.human_mode = False
        conf.jitter_min = 0.01
        conf.jitter_max = 0.1
        conf.max_threads = min(args.threads, 100)
    elif args.mode == "stealth":
        conf.human_mode = True
        conf.jitter_min = 0.2
        conf.jitter_max = 1.5
        conf.max_cps = min(conf.max_cps, 20)
        conf.max_threads = min(args.threads, 20)
    else:
        conf.human_mode = True
        conf.jitter_min = 0.05
        conf.jitter_max = 0.5
    
    # Load hosts
    if not os.path.exists(args.hosts_file):
        print(f"{Colors.FAIL} File not found: {args.hosts_file}{Colors.RESET}")
        sys.exit(1)
    
    with open(args.hosts_file) as f:
        raw_hosts = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    hosts = []
    for h in raw_hosts:
        h = h.split('://')[-1]
        h = h.split('/')[0]
        h = h.split(':')[0]
        if h:
            hosts.append(h)
    
    if conf.shuffle_hosts:
        random.shuffle(hosts)
    
    print_header(final_ports)
    
    print(f"{Colors.CYAN}{Colors.BOLD}{'─' * 72}{Colors.RESET}")
    print(f"  {Colors.WHITE}{Colors.BOLD}Targets{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'─' * 72}{Colors.RESET}")
    print(f"  {Colors.INFO} Hosts:    {Colors.WHITE}{len(hosts)} loaded from {args.hosts_file}{Colors.RESET}")
    print(f"  {Colors.INFO} Ports:    {Colors.WHITE}{len(final_ports)} total to scan{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'─' * 72}{Colors.RESET}")
    print()
    
    start_time = time.time()
    
    # Phase 1: DNS Resolution
    print(f"{Colors.CYAN}{Colors.BOLD}Phase 1: DNS Resolution{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 40}{Colors.RESET}")
    resolved = {}
    dns_fails = []
    
    dns_threads = min(conf.max_threads, 50)
    with ThreadPoolExecutor(max_workers=dns_threads) as executor:
        futures = {executor.submit(resolve_host, h): h for h in hosts}
        for future in as_completed(futures):
            if shutdown_flag.is_set():
                break
            hostname, ip = future.result()
            if ip:
                resolved[hostname] = ip
            else:
                dns_fails.append(hostname)
    
    if shutdown_flag.is_set():
        print(f"\n{Colors.YELLOW}[!] Scan interrupted during DNS resolution{Colors.RESET}")
        sys.exit(0)
    
    resolved_cache = dict(resolved)
    
    print(f"  {Colors.GREEN}[✓]{Colors.RESET} Resolved: {Colors.WHITE}{len(resolved)}/{len(hosts)}{Colors.RESET}")
    if dns_fails:
        print(f"  {Colors.YELLOW}[!]{Colors.RESET} Failed:   {Colors.WHITE}{len(dns_fails)}{Colors.RESET} (internal/split-DNS)")
        fail_file = f"sss_dns_fails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fail_file, 'w') as f:
            for h in dns_fails:
                f.write(h + "\n")
        print(f"  {Colors.INFO} DNS failures saved: {Colors.WHITE}{fail_file}{Colors.RESET}")
    
    resolved_items = list(resolved.items())
    if conf.shuffle_hosts:
        random.shuffle(resolved_items)
    
    print()
    
    # Phase 2: Scanning
    print(f"{Colors.CYAN}{Colors.BOLD}Phase 2: Port Scanning (Evasion Mode){Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 40}{Colors.RESET}")
    total_probes = len(resolved) * len(final_ports)
    est_seconds = (total_probes / conf.max_cps) * 1.5
    mins = est_seconds / 60
    print(f"  {Colors.INFO} Probes:   {Colors.WHITE}{total_probes:,}{Colors.RESET} (~{Colors.WHITE}{mins:.1f}m{Colors.RESET} estimated)")
    if conf.human_mode:
        print(f"  {Colors.YELLOW}[!] Human evasion mode active — scan will be slower{Colors.RESET}")
    print()
    
    with progress_lock:
        scan_progress["total"] = len(resolved)
    
    with ThreadPoolExecutor(max_workers=conf.max_threads) as executor:
        futures = {}
        for hostname, ip in resolved_items:
            if shutdown_flag.is_set():
                break
            future = executor.submit(scan_host, hostname, ip, final_ports)
            futures[future] = hostname
        for future in as_completed(futures):
            if shutdown_flag.is_set():
                break
            pass
    
    if shutdown_flag.is_set():
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Partial results below{Colors.RESET}")
    
    # Summary
    print_summary(final_ports)
    
    if shutdown_flag.is_set():
        print(f"\n{Colors.RED}[!] Scan interrupted — results may be incomplete{Colors.RESET}")
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}[✓] SSS-Scanner v1.0 finished{Colors.RESET}")


if __name__ == "__main__":
    main()
