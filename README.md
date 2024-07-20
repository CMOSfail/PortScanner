
# PortScanner by CMOSFail

## Description

PortScanner by CMOSFail is a Python tool that uses the `nmap` library to scan a given IP address and specified ports, outputting the results to a nicely formatted text file. This tool can scan both TCP and UDP ports and is designed to be flexible and easy to use.

## Features

- Scan specified TCP and UDP ports or all ports
- Outputs scan results to a formatted text file
- Handles both open and closed ports
- Includes header and footer in the output for branding

## Requirements

- Python 3.x
- `python-nmap` library (install using `pip install python-nmap`)
- Nmap command-line tool (install from https://nmap.org/download.html)

## Installation

1. Ensure that Python 3.x is installed on your system.
2. Install the required Python package:
    ```bash
    pip install python-nmap
    ```
3. Download and install the Nmap command-line tool from [Nmap's official site](https://nmap.org/download.html).

## Usage

You can run the script either by providing command-line arguments or interactively.

### Command-Line Arguments

```bash
python nmap_scan.py --ip <IP_ADDRESS> --ports "<PORTS>"
```

Example:
```bash
python nmap_scan.py --ip 192.168.1.1 --ports "80,443,27017 tcp, 28017 udp, 27018"
```

### Interactive Mode

If you run the script without arguments, it will prompt you for the required information:

```bash
python nmap_scan.py
```

## Example Output

```
PortScanner by CMOSFail | All Rights Reserved 2024
PORT      STATE SERVICE
80/tcp       open http
443/tcp      open https
27017/tcp    open mongod
27018/tcp  closed mongod
80/udp    filtered http
443/udp   filtered https
27018/udp filtered 
28017/udp filtered 
PortScanner by CMOSFail | All Rights Reserved 2024
```

## License

This project is licensed under the MIT License.

## Author

Created by Itamar Itzhaki (CMOSfail) - [GitHub](https://github.com/CMOSfail)
