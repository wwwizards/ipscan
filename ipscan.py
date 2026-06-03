#!/usr/bin/env python3
#------------------------------------------------------------------------------
# SCRIPT: ipscan.py
#------------------------------------------------------------------------------
#  PURPOSE: Poor Man's parallel IP & standard-port scanner (stdlib-only).
# ABSTRACT: Brute-force scans a list of CIDR subnets for ICMP-responsive hosts,
#           then probes a curated set of standard TCP ports on the live ones.
#           Pure stdlib — no pip dependencies. Cross-platform: Windows / Linux
#           / macOS. Outputs human-readable text or JSON (-q).
# REQUIRES: Python 3.9+ (tested on 3.10 / 3.12 / 3.14). No external packages.
#
# WARNING: Unauthorized scanning can be illegal. Get written permission from
#     the network owner (or somebody of competent jurisdiction empowering you
#     to do so) before scanning IP ranges you do not own. See:
#         https://nmap.org/book/legal-issues.html
#     Network probing / port scanning tools are only permitted on your own
#     residential home network, or on networks where you have explicit
#     authorization from the destination host and/or network administrator.
#
#  CREATED: 2023-07-13 BY: Joe Negron <github.com/wwwizards>
#  COMPANY: LogicWizards.NYC <LogicWizards.NYC>
#  VERSION: 0.9.1
#  LICENSE: MIT
#  USAGE:
#     python ipscan.py "192.168.0.0/24 10.0.0.0/16"
#     python ipscan.py 10.0.0.0/24 -t 128 -q > scan.json
#
# CHANGELOG (v0.9.1 — 2026-06-03, Py3.14 + cross-platform fixes):
#   - FIX: socket.timeout removed in Py3.14 → use TimeoutError
#   - FIX: ping flags branched by platform (Windows -n/-w-ms, Linux -c/-W-sec,
#          macOS -c/-W-ms). Previously Linux-only flags broke Win + Mac.
#   - FIX: catch OSError on ping subprocess (ping binary missing in minimal
#          Python 3.12+ container/runtime images)
#   - FIX: spinner UnicodeEncodeError on legacy Windows codepages → ASCII
#          fallback when stdout encoding can't render the glyph
#   - FIX: duplicate FG_RED definition; duplicate 5896 in windows_tcp
#   - CHORE: platform import is now actually used
#------------------------------------------------------------------------------

import argparse
import ipaddress
import itertools
import json
import platform
import socket
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor

# Default Configuration
standard_ports = [21, 22, 25, 53, 80, 110, 135, 143, 443, 445, 1433, 3306,
                  3389, 5671, 5672, 5985, 5986, 8009, 8080, 8443]
windows_tcp = [135, 137, 138, 139, 445, 5896]   # de-duped
windows_udp = [137, 138]
max_threads = 64

# Platform detection (used for ping flag selection)
IS_WINDOWS = platform.system() == "Windows"
IS_DARWIN  = platform.system() == "Darwin"

# Text Formatting (ANSI)
FG_BLD = "\033[1m"
FG_BLU = "\033[94m"
FG_REV = "\033[7m"
FG_RED = "\033[91m"
FG_ORN = "\033[38;5;208m"
FG_GRN = "\033[92m"
FG_GRY = "\033[90m"
FG_YEL = "\033[93m"
RESET  = "\033[0m"
SPACES = '     '
CLOBBER = '\r' + ' ' * 80 + '\r'

# Enable ANSI on legacy Windows consoles (no-op on modern Terminal/PowerShell 7)
if IS_WINDOWS:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _safe_write(text):
    """Write to stdout, falling back to ASCII if the console can't encode it."""
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        sys.stdout.write(text.encode('ascii', 'replace').decode('ascii'))
    sys.stdout.flush()


def spinner():
    """Lightweight progress spinner; ASCII-safe fallback on dumb consoles."""
    glyphs = ['         ', '    .    ', '    o    ', '    O    ',
              '   (*)   ', '  (( ))  ', ' ((( ))) ', '(((   )))',
              '((     ))', '(       )', '         ']
    spinner_cycle = itertools.cycle(glyphs)
    while True:
        current = next(spinner_cycle)
        _safe_write(f'\r{CLOBBER}{SPACES}{FG_YEL}{current}{SPACES}{RESET}')
        time.sleep(0.15)


def is_port_active(ip, port, timeout=1):
    """Check if a given TCP port on an IP is actively listening."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except (TimeoutError, ConnectionRefusedError, OSError):
        # NOTE: socket.timeout was removed in Py3.14; TimeoutError is its
        # canonical replacement (alias since 3.3, sole name from 3.14).
        return False


def get_reverse_dns(ip):
    """Perform a reverse DNS lookup for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _ping_cmd(ip, timeout):
    """Build the platform-correct ping command.

    Windows: ping -n 1 -w <ms>     (Microsoft ping, -w is ms)
    Linux:   ping -c 1 -W <sec>    (iputils ping, -W is seconds)
    macOS:   ping -c 1 -W <ms>     (BSD ping, -W is ms — NOT seconds)
    """
    if IS_WINDOWS:
        return ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
    if IS_DARWIN:
        return ['ping', '-c', '1', '-W', str(int(timeout * 1000)), ip]
    return ['ping', '-c', '1', '-W', str(int(timeout)), ip]


def is_pingable(ip, timeout=1):
    """Check if an IP responds to ICMP echo. Cross-platform, tolerant of
    missing ping binary (minimal container images, locked-down hosts)."""
    try:
        subprocess.check_output(
            _ping_cmd(ip, timeout),
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    except (FileNotFoundError, OSError):
        # ping binary missing or unexecutable — treat as unreachable rather
        # than crashing the whole scan
        return False


def infer_os(ports):
    """Infer OS family from open-port fingerprint."""
    if 3389 in ports and 22 not in ports:
        return "Windows"
    if 22 in ports and 3389 not in ports:
        return "Linux"
    if 22 in ports and 3389 in ports:
        return "Hybrid"
    return "Unknown"


def scan_ip_ping(ip_str, pingable_ips, unresponsive_ips, lock, total_ips, progress):
    """Ping an IP address and categorize it as responsive or unresponsive."""
    with lock:
        scanned_ips = progress[0]
        progress[0] += 1
        progress_percentage = (progress[0] / total_ips) * 100

    if not quiet:
        _safe_write(
            f"\r{CLOBBER}Progress: {FG_GRN}{progress_percentage:.2f}% {RESET}"
            f"Pinging IP: {FG_GRN}{ip_str} "
            f"{FG_RED}[{RESET}{scanned_ips + 1}/{total_ips}{FG_RED}]{RESET}..."
        )

    if is_pingable(ip_str):
        with lock:
            pingable_ips.append(ip_str)
    else:
        with lock:
            unresponsive_ips.append(ip_str)


def scan_ip_ports(ip_str, active_ports, lock):
    """Scan standard ports on a pingable IP and stash results."""
    hostname = get_reverse_dns(ip_str) or "NO IN-ADDR.ARPA or PTR RECORD"
    ports = [port for port in standard_ports if is_port_active(ip_str, port)]
    with lock:
        active_ports[ip_str] = ports
        data[ip_str] = {
            "DNS": hostname,
            "OS": infer_os(ports),
            "LISTENERS": ports,
        }


def scan_ips(ip_range, threads, quiet):
    """Scan a list of IP addresses for active ports."""
    active_ports = {}
    unresponsive_ips = []
    pingable_ips = []
    lock = threading.Lock()
    progress = [0]
    total_ips = sum(
        len(list(ipaddress.IPv4Network(subnet, strict=False)))
        for subnet in ip_range
    )

    if not quiet:
        print(f"\n{FG_YEL}{FG_REV} - INFO: Scanning {total_ips} IP addresses "
              f"with {threads} threads on {platform.system()}...{RESET}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        # PHASE 1: PING SWEEP
        for subnet in ip_range:
            network = ipaddress.IPv4Network(subnet, strict=False)
            for ip in network:
                ip_str = str(ip)
                futures.append(executor.submit(
                    scan_ip_ping, ip_str, pingable_ips, unresponsive_ips,
                    lock, total_ips, progress
                ))
        for future in futures:
            future.result()

        # Display unresponsive IPs immediately after ping phase
        if not quiet:
            print(f"\n\n{FG_REV} - INFO: List of IPs Unresponsive to ICMP "
                  f"Echo (ping) {RESET}")
        for ip in unresponsive_ips:
            padding = max(15, len(ip) + 4)
            hostname = get_reverse_dns(ip) or "NO IN-ADDR.ARPA or PTR RECORD"
            COLOR = FG_ORN if "IN-ADDR.ARPA" not in hostname else FG_GRY
            if not quiet:
                print(f"IP: {FG_GRY}{ip:<{padding}}{RESET}\tDNS: "
                      f"{COLOR}{hostname}{RESET}")
            data[ip] = {"DNS": hostname, "OS": "NULL", "LISTENERS": []}

        # PHASE 2: PORT SWEEP on pingable hosts
        progress[0] = 0
        if not quiet:
            print(f"\n{FG_REV} - INFO: ICMP Tests Complete; BEGIN: TCP Port "
                  f"Scans... {RESET}", flush=True)
            print(f"\n - {FG_BLD}PORTS BEING TESTED: "
                  f"{FG_YEL}{standard_ports}{RESET}", flush=True)
            spinner_thread = threading.Thread(target=spinner, daemon=True)
            spinner_thread.start()

        futures = []
        for ip_str in pingable_ips:
            active_ports[ip_str] = []
            futures.append(executor.submit(
                scan_ip_ports, ip_str, active_ports, lock
            ))
        for future in futures:
            future.result()

    return active_ports


def format_results(active_ports):
    """Print the human-readable results of the scan."""
    if not quiet:
        print(f"{CLOBBER}\n\n{FG_REV} - INFO: Async-Scan Responses "
              f"(From: PING-ABLE IPs)... {RESET}")
    for ip, ports in active_ports.items():
        if ports:
            hostname = get_reverse_dns(ip) or "NO IN-ADDR.ARPA or PTR RECORD"
            os_type = infer_os(ports)
            if not quiet:
                DNS_COLOR = FG_BLU if "IN-ADDR.ARPA" not in hostname else FG_ORN
                OS_COLOR = (FG_GRN if "Windows" in os_type
                            else FG_BLU if "Linux" in os_type
                            else FG_RED)
                p1 = max(15, len(ip) + 4)
                p2 = max(33, len(hostname) + 2)
                print(f"{CLOBBER}IP: {FG_GRN}{ip:<{p1}}{RESET} \tDNS: "
                      f"{DNS_COLOR}{hostname:<{p2}}{RESET} \tOS: "
                      f"{OS_COLOR}{os_type}{RESET} \tLISTENERS: "
                      f"{FG_RED}{', '.join(map(str, ports))}{RESET}")


#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parallel IP Scanner")
    parser.add_argument("ip_range", nargs="+",
                        help="Space-separated list of subnet/CIDR addresses "
                             "(e.g., '192.168.0.0/24 10.0.0.0/16')")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress progress indicators & emit JSON only")
    parser.add_argument("-t", "--threads", type=int, default=max_threads,
                        help="Number of threads for parallel scanning")

    args = parser.parse_args()
    ip_range = args.ip_range
    threads = args.threads
    quiet = args.quiet

    data = {}

    report = scan_ips(ip_range, threads, quiet)
    format_results(report)

    if quiet:
        print(json.dumps(data, indent=4))
