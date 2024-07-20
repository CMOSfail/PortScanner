"""
PortScanner by CMOSFail | All Rights Reserved 2024

This script uses the nmap library to scan a given IP address and port (or all ports if not specified)
and outputs the scan results to a nicely formatted text file.

Requirements:
    - python-nmap library (install using 'pip install python-nmap')
    - nmap command-line tool (install from https://nmap.org/download.html)

Usage:
    python nmap_scan.py <IP_ADDRESS> [--ports <PORTS>]

    Example:
        python nmap_scan.py 192.168.1.1
        python nmap_scan.py 192.168.1.1 --ports "80,443,27017"
"""

import subprocess
import sys
import shutil
import platform
import nmap
import argparse
import datetime

def install_package(package):
    """
    Installs the given package using pip.

    Args:
        package (str): The package to install.
    """
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def check_nmap_installed():
    """
    Checks if the nmap command-line tool is installed and available in the PATH.
    
    Raises:
        EnvironmentError: If nmap is not found in the PATH with instructions to install based on OS.
    """
    if not shutil.which("nmap"):
        os_type = platform.system()
        if os_type == "Windows":
            instructions = "Please download and install Nmap from https://nmap.org/download.html and ensure it's available in the PATH."
        elif os_type == "Linux":
            instructions = "Please install Nmap using your package manager (e.g., 'sudo apt-get install nmap' for Debian-based systems or 'sudo yum install nmap' for Red Hat-based systems)."
        elif os_type == "Darwin":  # macOS
            instructions = "Please install Nmap using Homebrew (e.g., 'brew install nmap')."
        else:
            instructions = "Please install Nmap from https://nmap.org/download.html."

        raise EnvironmentError(f"nmap command-line tool is not found in PATH. {instructions}")

def scan_ports(ip, tcp_ports, udp_ports):
    """
    Scans the given IP address for specified TCP and UDP ports.

    Args:
        ip (str): The IP address to scan.
        tcp_ports (str): Comma-separated list of TCP ports to scan.
        udp_ports (str): Comma-separated list of UDP ports to scan.

    Returns:
        dict: The scan result.
    """
    nm = nmap.PortScanner()
    port_args = ""
    if tcp_ports:
        port_args += f"T:{tcp_ports}"
    if udp_ports:
        if port_args:
            port_args += ","
        port_args += f"U:{udp_ports}"
    scan_result = nm.scan(ip, arguments=f'-sS -sU -p {port_args}')
    return scan_result

def format_scan_result(scan_result):
    """
    Formats the scan result into a readable string.

    Args:
        scan_result (dict): The scan result from nmap.

    Returns:
        str: The formatted scan result.
    """
    header = "PortScanner by CMOSFail | All Rights Reserved 2024"
    footer = "PortScanner by CMOSFail | All Rights Reserved 2024"
    formatted_result = [header, "PORT      STATE SERVICE"]
    scanned_ports = {}

    for host in scan_result['scan']:
        host_info = scan_result['scan'][host]
        for proto in host_info.keys():
            if proto in ['tcp', 'udp']:
                for port in host_info[proto].keys():
                    port_info = host_info[proto][port]
                    scanned_ports[f"{port}/{proto}"] = f"{port_info['state']:>7} {port_info['name']}"

    if scanned_ports:
        for port_proto, state_service in scanned_ports.items():
            formatted_result.append(f"{port_proto:<9} {state_service}")
        formatted_result.append(footer)
    else:
        formatted_result.append("No ports found.")

    return '\n'.join(formatted_result)

def save_to_file(data, filename):
    """
    Saves the provided data to a file.

    Args:
        data (str): The data to save.
        filename (str): The name of the file to save the data to.
    """
    with open(filename, 'w') as file:
        file.write(data)

def parse_ports(ports):
    """
    Parses the port string and returns lists of TCP and UDP ports.

    Args:
        ports (str): The port string to parse.

    Returns:
        tuple: A tuple containing two strings: a comma-separated list of TCP ports and a comma-separated list of UDP ports.
    """
    tcp_ports = []
    udp_ports = []
    for port in ports.split(','):
        port = port.strip()
        if 'both' in port:
            port_num = port.split()[0]
            tcp_ports.append(port_num)
            udp_ports.append(port_num)
        elif 'tcp' in port:
            port_num = port.split()[0]
            tcp_ports.append(port_num)
        elif 'udp' in port:
            port_num = port.split()[0]
            udp_ports.append(port_num)
        else:
            tcp_ports.append(port)
            udp_ports.append(port)
    return ','.join(tcp_ports), ','.join(udp_ports)

def main():
    """
    Main function to parse arguments, prompt for missing input, perform the scan, and save the results to a file.
    """
    check_nmap_installed()
    
    parser = argparse.ArgumentParser(description='Scan an IP address and port using nmap')
    parser.add_argument('--ip', help='IP address to scan')
    parser.add_argument('--ports', help='Ports to scan (optional). Example: "80,443,27017 tcp, 28017 udp" or "all"')
    args = parser.parse_args()

    ip = args.ip
    ports = args.ports

    if not ip:
        ip = input("Please enter the IP address to scan: ")

    if not ports:
        ports = input("Please enter the ports to scan (or 'all' for all ports): ")

    if ports.lower() == "all":
        tcp_ports = "1-65535"
        udp_ports = "1-65535"
    else:
        tcp_ports, udp_ports = parse_ports(ports)

    scan_result = scan_ports(ip, tcp_ports, udp_ports)
    formatted_result = format_scan_result(scan_result)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"scan_result_{ip}_{timestamp}.txt"
    save_to_file(formatted_result, filename)

    print(f"Scan results saved to {filename}")

if __name__ == "__main__":
    main()
