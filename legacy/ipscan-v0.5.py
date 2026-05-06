"""
ABSTRACT: Simple IP & Standard Ports Scanner - This script does a brute force 
    scan of a specified list of IPs within a specified subnets for active 
    listeners on standard ports. The list of ports includes commonly used ports 
    such as 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP), 
    and database ports like 1433 (SQL Server) and 3306 (MySQL) - among others. 
    It takes a space-separated list of CIDR blocks subnets as parameters - it 
    assumes /32 if not specified. If the ping fails it will just continue. Results 
    include active IPs with responsive ports and those that were unresponsive.

WARNING: Unauthorized scanning can be illegal, and users should be reminded to 
    obtain permission (in writing) by the owner, or from somebody of competent 
    jurisdiction empowering you to do so, before scanning IP ranges you do not own. 
    for more information on this see: --> https://nmap.org/book/legal-issues.html
    Network probing or port scanning tools are only permitted when used in 
    conjunction with your own residential home network, or for other networks 
    when explicitly authorized by the destination host and/or network administrator. 
    Unauthorized port scanning, using this tool for any reason, is strictly prohibited.   
   
CREATED: 2023-0713 - by: Joe Negron <jnegron9@fordham.edu> 
    Version: v.01 - initial try - quick & dirty - but slow to execute 
UPDATED: 2023-0718 - by: Joe Negron <jnegron9@fordham.edu> 
VERSION: v0.5 - Brute-Force took a while to run and I am impatient - so, I 
    added concurrent threading. With this, the number of threads is now set 
    to 4 by default, but you can still specify a different number of threads 
    using the `--threads` argument when executing the script.

Usage:
    python ipscan.py "subnet1/CIDR1 subnet2/CIDR2 ..." - and then just wait for results... 

Example:
    python ipscan.py "192.168.0.0/24 10.0.0.0/16"
"""
## IMPORT HELPER LIBRARIES ###
import socket       # https://docs.python.org/3/library/socket.html
import ipaddress    # https://docs.python.org/3/library/ipaddress.html 
import argparse     # https://docs.python.org/3/library/argparse.html
import sys          # https://docs.python.org/3/library/sys.html

# IMPORT ASYNC-IO: Executor subclass that uses a pool of threads to execute calls asynchronously. 
# https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.ThreadPoolExecutor
from concurrent.futures import ThreadPoolExecutor 
import threading    # https://docs.python.org/3/library/threading.html
import subprocess   # https://docs.python.org/3/library/subprocess.html

### CONFIGURABLE SETTINGS ###
standard_ports = [21, 22, 25, 53, 80, 8080, 8009, 110, 143, 443, 8443, 3389, 1433, 3306, 5671, 5672 ] # Defines standard ports to scan
max_threads = 64 # Defines the number of asynch-io threads to run concurrently - for performance

# Define the most popular foreground and background colors as string variables
FG_BLD = "\033[1m"
FG_BLU = "\033[94m"
FG_REV = "\033[7m"
FG_RED = "\033[91m"
FG_ORN = "\033[38;5;208m"
FG_GRN = "\033[92m"
FG_GRY = "\033[90m"
FG_YEL = "\033[93m"
BG_RED = "\033[101m"
BG_ORN = "\033[48;5;208m"
BG_GRY = "\033[100m"
RESET = "\033[0m"  # Reset all colors and formatting


def is_port_active(ip, port, timeout=1):
    """
    Checks if a given port on an IP address is actively listening.

    Args:
        ip (str): IP address to check.
        port (int): Port number to check.
        timeout (int, optional): Connection timeout in seconds. Defaults to 1.

    Returns:
        bool: True if the port is actively listening, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def get_reverse_dns(ip):
    """
    Performs a reverse DNS lookup for an IP address.

    Args:
        ip (str): IP address to lookup.

    Returns:
        str or None: The hostname associated with the IP address, or None if not found.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None

def is_pingable(ip, timeout=1):
    """
    Checks if an IP address is pingable.

    Args:
        ip (str): IP address to ping.
        timeout (int, optional): Timeout for the ping command in seconds. Defaults to 1.

    Returns:
        bool: True if the IP address is pingable, False otherwise.
    """
    try:
        output = subprocess.check_output(['ping', '-c', '1', '-W', str(timeout), ip])
        return "1 packets transmitted, 1 received" in output.decode()
    except subprocess.CalledProcessError:
        return False

def print_result(ip_str, hostname, active_ports, no_listeners_ips=None, is_active_scan=True):
    """
    Prints the results for a scanned IP address.

    Args:
        ip_str (str): IP address.
        hostname (str): Hostname associated with the IP address.
        active_ports (list): List of active ports for the IP address.
        no_listeners_ips (list, optional): List of IP addresses with no active ports. Defaults to None.
        is_active_scan (bool, optional): Indicates if the scan was for active ports. Defaults to True.

    Returns:
        None: The function prints the results to the console.
    """
    if hostname:
        print(f"{FG_GRN}IP: {ip_str} {RESET}(FQDN: {FG_BLU}{hostname}{RESET})", end=' ')
    else:
        print(f"{FG_GRY}IP: {ip_str}", end=' ')

    if is_active_scan:
        if active_ports:
            print(f"- {FG_RED}ACTIVE PORTS: {', '.join(map(str, active_ports))}")
        else:
            print(f"- {FG_ORN}NO RESPONSE ON STANDARD PORTS.")
    else:
        print(f"- {FG_GRY}UNRESPONSIVE TO PING.")

    # Reset colors after printing the result
    print(RESET, end=' ')


def scan_ip_ports(ip_str, active_ports, lock, total_ips, progress, no_listeners_ips):
    """
    Scans active ports on a given IP address.

    Args:
        ip_str (str): IP address to scan.
        active_ports (dict): Dictionary to store active ports for each IP address.
        lock (threading.Lock): Lock to synchronize thread access.
        total_ips (int): Total number of IP addresses to scan.
        progress (list): List to track scan progress.
        no_listeners_ips (list): List to store IPs with no active ports.

    Returns:
        None: The function updates the active_ports dictionary with the results.
    """
    inactive = True
    with lock:
        scanned_ips = progress[0]
        progress[0] += 1
        progress_percentage = (progress[0] / total_ips) * 100
    print(f"Scanning IP:{FG_BLU} {ip_str} [{scanned_ips + 1}/{total_ips}]... Progress: {FG_YEL}{progress_percentage:.2f}% {RESET}", end="")

    for port in standard_ports:
        if is_port_active(ip_str, port):
            active_ports[ip_str].append(port)
            inactive = False

    with lock:
        if inactive:
            inactive_ips.append(ip_str)
        else:
            no_listeners_ips.append(ip_str)

    print_result(ip_str, get_reverse_dns(ip_str), active_ports[ip_str], no_listeners_ips)




def scan_ips(ip_range, threads):
    """
    Scans a list of IP addresses for active ports on standard ports.

    Args:
        ip_range (list): List of subnet/CIDR addresses to scan.
        threads (int): Number of threads to use for parallel scanning.

    Returns:
        tuple: A tuple containing two dictionaries - the first containing IP addresses with active ports,
               and the second containing IP addresses with no active ports.
    """
    active_ports = {}
    global inactive_ips
    inactive_ips = []
    no_listeners_ips = []
    total_ips = sum(len(list(ipaddress.IPv4Network(subnet, strict=False))) for subnet in ip_range)

    lock = threading.Lock()
    progress = [0]

    print(f"{FG_REV} - INFO: Scanning {total_ips} IP addresses with {threads} threads...{RESET}")
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for subnet in ip_range:
                network = ipaddress.IPv4Network(subnet, strict=False)
                for ip in network:
                    ip_str = str(ip)
                    active_ports[ip_str] = []
                    future = executor.submit(scan_ip_ports, ip_str, active_ports, lock, total_ips, progress, no_listeners_ips)
                    futures.append(future)

            for future in futures:
                future.result()

    except KeyboardInterrupt:
        print("\n{FG_RED}{FG_REV} - KILL: Scanning interrupted by user.{RESET}")
        sys.exit(1)

    print(f"\n{FG_REV} - DONE: Scanning completed. {RESET}")
    return active_ports, no_listeners_ips

if __name__ == "__main__":
    # INITIALIZE CLI-ARG PARSER
    parser = argparse.ArgumentParser(description="Parallel IP Scanner")
    parser.add_argument("ip_range", nargs="+", help="Space-separated list of subnet/CIDR addresses (e.g., '192.168.0.0/24 10.0.0.0/16')")
    parser.add_argument("-t", "--threads", type=int, default=max_threads, help="Number of threads to use for parallel scanning (default: set in config options)")
    # INITIALIZE VARS
    args = parser.parse_args()
    ip_range = args.ip_range
    threads = args.threads

    # SCAN IPs & DISPLAY PROGRESS
    active_ports, no_listeners_ips = scan_ips(ip_range, threads)
    
    # REPORT THE RESULTS
    if active_ports:
        print(f"\n {FG_REV}List of IPs with Active Ports:{RESET}")
        for ip, ports in active_ports.items():
            print_result(ip, get_reverse_dns(ip), ports)

    if no_listeners_ips:
        
        print(f"\n {FG_REV}List of IPs Unresponsive to ICMP Echo (ping) Test: {RESET}")
        for ip in no_listeners_ips:
            print(f"{FG_GRN}", end=' ')
            print_result(ip, get_reverse_dns(ip), [], is_active_scan=False)
        print (RESET)
