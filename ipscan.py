#!/usr/bin/env python3
# --------------------------------------------------------------------------
# Script: ipscan.py
# --------------------------------------------------------------------------
# ABSTRACT: Poor Man's Simple IP & Standard Port Scanner - This script does brute force
#     scan(s) of a specified list of IPs within a specified subnets for active
#     listeners on standard ports. The list of ports includes commonly used ports
#     such as 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP),
#     and database ports like 1433 (SQL Server) and 3306 (MySQL) - among others.
#     It takes a space-separated list of CIDR blocks subnets as parameters - and
#     assumes /32 if not specified. If the ping fails it will just continue. Results
#     include active IPs with responsive ports and those that were unresponsive.
#     you can also specify a different number of threads
#     using the `--threads` argument when executing the script.
#
# WARNING: Unauthorized scanning can be illegal, and users should be reminded to
#     obtain permission (in writing) by the owner, or from somebody of competent
#     jurisdiction empowering you to do so, before scanning IP ranges you do not own.
#     for more information on this see: --> https://nmap.org/book/legal-issues.html
#     Network probing or port scanning tools are only permitted when used in
#     conjunction with your own residential home network, or for other networks
#     when explicitly authorized by the destination host and/or network administrator.
#     Unauthorized port scanning, using this tool for any reason, is strictly prohibited.
#
# CREATED: 23-0713 - BY: Joe Negron <github.com/wwwizards>
# UPDATED: 23-0905 - BY: Joe Negron <github.com/wwwizards> - refactored for modularity, last-hop, & spinner
# UPDATED: 23-0911 - BY: Joe Negron <github.com/wwwizards> - add windows ports; flagged last-hop for removal
# UPDATED: 23-0912 - BY: Joe Negron <github.com/wwwizards> - --output json feature
# UPDATED: 23-1218 - BY: Joe Negron <github.com/wwwizards> - multi-threaded for speed
# UPDATED: 26-0506 - BY: wwwizards <github.com/wwwizards> - liberated to wwwizards/ipscan
# VERSION: v0.9
# AUTODOC: https://github.com/wwwizards/pickaxe
#
# LICENSE: MIT - https://opensource.org/licenses/MIT
# COPYRIGHT: (c) 2023-2026 wwwizards (Joe Negron) <github.com/wwwizards>
#
# USAGE:
#     python ipscan.py "subnet1/CIDR1 subnet2/CIDR2 ..." - and then just wait for results...
#
# EXAMPLE:
#     python ipscan.py "192.168.0.0/24 10.0.0.0/16"
# --------------------------------------------------------------------------


import argparse
import ipaddress
import itertools
import json
import platform
import re
import socket
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor


# Default Configuration
standard_ports = [21, 22, 25, 53, 80, 8080, 8009, 110, 135, 143, 443, 445, 8443, 3389, 1433, 3306, 5671, 5672, 5985, 5986]
windows_tcp = [135, 137, 138, 139, 445, 5896, 5896]
windows_udp = [137, 138]
max_threads = 64

# Text Formatting (quick & dirty - purdificationators)
FG_BLD = "\033[1m"
FG_BLU = "\033[94m"
FG_REV = "\033[7m"
FG_RED = "\033[91m"
FG_RED = "\033[91m"
FG_ORN = "\033[38;5;208m"
FG_GRN = "\033[92m"
FG_GRY = "\033[90m"
FG_YEL = "\033[93m"
RESET = "\033[0m"
LF_KEY = ""
RT_KEY = ""
UP_KEY = '\x1b[1A'
DN_KEY = ""
CR_CLR = '\x1b[2K'
SPACES ='     '
CLOBBER = '\r' + ' ' * 80 + '\r' # wipes out any text on the previous line
# Simple spinner function to show progress during waiting periods
def spinner():
    # Define a multi-character spinner cycle
    spinner_cycle = itertools.cycle(['         ','    ◟    ','    ◜    ','    ◝    ','    ◞    ','    ⋆    ','    𖦹    ','    ✧    ','    ✩    ','    o    ','    0    ','    O    ','    ☾☽   ','   (*)   ','  (( ))  ',' ((( ))) ','(((   )))','((     ))','(       )','         ' ])
    while True:
        current_spinner = next(spinner_cycle)  # Get the next spinner state
        padding = max(9, len(SPACES)*2+1, len(current_spinner))
        sys.stdout.write(f'\r{CLOBBER}{SPACES}{FG_YEL}{current_spinner}{SPACES:<{padding}}{RESET}')  # Use '\r' to return to the beginning of the line
        sys.stdout.flush()  # Flush the stdout buffer to ensure the spinner is displayed
        time.sleep(0.15)  # Small delay between spinner updates

def is_port_active(ip, port, timeout=1):
    """Check if a given port on an IP address is actively listening."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def get_reverse_dns(ip):
    """Perform a reverse DNS lookup for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None

def is_pingable(ip, timeout=1):
    """Check if an IP address is pingable."""
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', str(timeout), ip], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def infer_os(ports):
    """Infers the OS type based on open port assumptions."""
    if 3389 in ports and 22 not in ports:
        return f"Windows"
    elif 22 in ports and 3389 not in ports:
        return f"Linux"
    elif 22 in ports and 3389 in ports:
        return f"Hybrid" # Hybrid= both Windows & Linux
    else:
        return f"Unknown"

def scan_ip_ping(ip_str, pingable_ips, unresponsive_ips, lock, total_ips, progress):
    """Ping an IP address and categorize it as responsive or unresponsive."""
    with lock:
        scanned_ips = progress[0]
        progress[0] += 1
        progress_percentage = (progress[0] / total_ips) * 100
    if not quiet:
        print(f"\r{CLOBBER}Progress: {FG_GRN}{progress_percentage:.2f}% {RESET}Pinging IP: {FG_GRN}{ip_str} {FG_RED}[{RESET}{scanned_ips + 1}/{total_ips}{FG_RED}]{RESET}...", end="", flush=True)

    if is_pingable(ip_str):
        with lock:
            pingable_ips.append(ip_str)
    else:
        with lock:
            unresponsive_ips.append(ip_str)

def scan_ip_ports(ip_str, active_ports, lock):
    """Scan active ports and perform traceroute on pingable IPs."""
    hostname = get_reverse_dns(ip_str) or "NO IN-ADDR.ARPA or PTR RECORD"
    ports = [port for port in standard_ports if is_port_active(ip_str, port)]
    with lock:
        active_ports[ip_str] = ports
        # Add additional data to our structure for potential JSON export
        data[ip_str] = {
            "DNS": hostname,
            "OS": infer_os(ports),
            "LISTENERS": ports,
        }

def scan_ips(ip_range, threads, quiet):
    """Scan a list of IP addresses for active ports."""
    # Data structures to hold scan results
    active_ports = {}
    unresponsive_ips = []
    pingable_ips = []
    lock = threading.Lock()
    progress = [0]
    total_ips = sum(len(list(ipaddress.IPv4Network(subnet, strict=False))) for subnet in ip_range)

    if not quiet:
        print(f"\n{FG_YEL}{FG_REV} - INFO: Scanning {total_ips} IP addresses with {threads} threads...{RESET}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        # PHASE-1: PING EVERYTHING
        for subnet in ip_range:
            network = ipaddress.IPv4Network(subnet, strict=False)
            for ip in network:
                ip_str = str(ip)
                future = executor.submit(scan_ip_ping, ip_str, pingable_ips, unresponsive_ips, lock, total_ips, progress)
                futures.append(future)

        # Wait for ping phase to complete
        for future in futures:
            future.result()

        # Display unresponsive IPs immediately after ping phase
        if not quiet:
            print(f"\n\n{FG_REV} - INFO: List of IPs Unresponsive to ICMP Echo (ping) {RESET}")
        for ip in unresponsive_ips:
            # Calculate padding based on the length of the IP
            padding = max(15, len(ip) + 4)  # Minimum padding to ensure readability
            hostname = get_reverse_dns(ip) or "NO IN-ADDR.ARPA or PTR RECORD"
            # Format and print the line with aligned columns
            COLOR = FG_ORN if "IN-ADDR.ARPA" not in hostname else FG_GRY
            if not quiet:
                print(f"IP: {FG_GRY}{ip:<{padding}}{RESET}\tDNS: {COLOR}{hostname}{RESET}")
            # update array for json output feature
            data[ip] = {
                "DNS": hostname,
                "OS": "NULL",
                "LISTENERS": [],
            }

        # Reset progress for port scanning phase
        progress[0] = 0
        if not quiet:
            print(f"\n{FG_REV} - INFO: ICMP Tests Complete; BEGIN: TCP Port Scans... {RESET}", flush=True)
            print(f"\n - {FG_BLD}PORTS BEING TESTED: {FG_YEL}{standard_ports}{RESET}", flush=True)
            # invoke simple spinner for visual feedback during the scanning phase
            spinner_thread = threading.Thread(target=spinner, daemon=True)
            spinner_thread.start()

        # Port scanning phase
        futures = []
        for ip_str in pingable_ips:
            active_ports[ip_str] = []
            future = executor.submit(scan_ip_ports, ip_str, active_ports, lock)
            futures.append(future)

        # Wait for port scanning phase to complete
        for future in futures:
            future.result()

    return active_ports

def format_results(active_ports):
    """Print the results of the scan."""
    # Print the list of IPs with active ports
    if not quiet:
            print(f"{CLOBBER}\n\n{FG_REV} - INFO: Async-Scan Responses (From: PING-ABLE IPs)... {RESET}")
    for ip, ports in active_ports.items():
        if ports:
            hostname = get_reverse_dns(ip) or "NO IN-ADDR.ARPA or PTR RECORD"
            os_type = infer_os(ports)
            if not quiet:
                # 24-0911JN-MOD: Dark-Deprecation Last-Hop - too slow & not much value
                # last_hop = get_last_hop(ip) if ports else "UNKNOWN"
                # Format and print the line with aligned columns
                DNS_COLOR = FG_BLU if "IN-ADDR.ARPA" not in hostname else FG_ORN
                OS_COLOR = FG_GRN if "Windows" in os_type else FG_BLU if "Linux" in os_type else FG_RED
                # Calculate padding based on the length of the IP & DNS
                padding1 = max(15, len(ip) + 4)  # Minimum padding to ensure readability
                padding2 = max(33, len(hostname) + 2)  # Minimum padding to ensure readability
                padding3 = max(15, len(ip) + 4)  # Minimum padding to ensure readability
                # 24-0911JN-MOD: Dark-Deprecation Last-Hop - too slow & not much value
                # print(f"{CLOBBER}IP: {FG_GRN}{ip:<{padding1}}{RESET} \tDNS: {COLOR}{hostname:<{padding2}}{RESET} \tOS: {os_type} \tLastHop: {last_hop:<{padding3}} \tLISTENERS: {FG_RED}{', '.join(map(str, ports))}{RESET}")
                print(f"{CLOBBER}IP: {FG_GRN}{ip:<{padding1}}{RESET} \tDNS: {DNS_COLOR}{hostname:<{padding2}}{RESET} \tOS: {OS_COLOR}{os_type}{RESET} \tLISTENERS: {FG_RED}{', '.join(map(str, ports))}{RESET}")

#------------------------------------------------------------------------------------------------------------
#  MAIN
#------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parallel IP Scanner")
    parser.add_argument("ip_range", nargs="+", help="Space-separated list of subnet/CIDR addresses (e.g., '192.168.0.0/24 10.0.0.0/16')")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress Progress Indicators & Output Data as JSON")  # Changed here
    parser.add_argument("-t", "--threads", type=int, default=max_threads, help="Number of threads to use for parallel scanning")

    args = parser.parse_args()
    ip_range = args.ip_range
    threads = args.threads
    quiet = args.quiet

    # Data structure to hold scan results
    data = {}

    # Initiate the scan and identify ping-able IP's & Active Ports
    report = scan_ips(ip_range, threads, quiet)

    # display the results for humans (default) or json for further processing
    format_results(report)
    if quiet:
        # Print the data as formatted JSON
        print(json.dumps(data, indent=4))
