# System Inventory Scanner

A Bash script for automatically collecting system information from local and remote Linux servers.

## Overview

The System Inventory Scanner is a versatile tool that gathers detailed system information including:

- Hardware details (CPU, memory, disk space)
- Network information (IP addresses, MAC addresses)
- Operating system details
- Serial numbers and UUIDs
- Server function detection (Web server, Database server)
- Installed software packages

The script automatically detects if a system is running on VMware, AWS EC2, or physical hardware, and collects platform-specific information accordingly.

## Requirements

- Bash 4.0 or higher
- Linux-based system for the scanner and target systems
- For remote scanning: SSH key-based authentication set up between scanner and targets
- For CIDR range scanning: `nmap` installed
- `sudo` access on target systems (for hardware information)

## Installation

1. Download the script:
   ```bash
   wget https://example.com/system_inventory_scanner.sh
   ```

2. Make it executable:
   ```bash
   chmod +x system_inventory_scanner.sh
   ```

3. Run directly - no installation required!

## Usage

The script can be run in several modes:

```
Usage: ./system_inventory_scanner.sh [-l | -r CIDR_RANGE | -f IP_LIST_FILE | IP_ADDRESS]
Options:
  -l              Run locally (no SSH)
  -r CIDR_RANGE   Scan a CIDR range (e.g., 192.168.1.0/24)
  -f IP_LIST_FILE Read IPs from a file (one IP per line)
  IP_ADDRESS      Scan a single IP address
```

### Examples

1. **Scan the local machine**:
   ```bash
   ./system_inventory_scanner.sh -l
   ```

2. **Scan a remote server**:
   ```bash
   ./system_inventory_scanner.sh 192.168.1.100
   ```

3. **Scan multiple servers from a file**:
   ```bash
   echo "192.168.1.101" > servers.txt
   echo "192.168.1.102" >> servers.txt
   ./system_inventory_scanner.sh -f servers.txt
   ```

4. **Scan a network range**:
   ```bash
   ./system_inventory_scanner.sh -r 192.168.1.0/24
   ```

## Output

The script generates two CSV files:

1. **system_inventory.csv**: Contains system hardware and configuration details
2. **software_inventory.csv**: Contains information about installed software packages

These files can be opened in any spreadsheet application like Excel or LibreOffice Calc.

## Special Features

- **Platform Detection**: Automatically identifies VMware VMs, AWS EC2 instances, and physical servers
- **Self-contained**: No external configuration files needed
- **Serial Number Generation**: If a proper serial number cannot be determined, one will be generated
- **Web Server Detection**: For web servers, the script collects information about configured websites
- **Database Server Detection**: Identifies if the system is running a database server

## Troubleshooting

- **SSH Issues**: Ensure SSH key-based authentication is set up correctly between the scanner and target systems
- **Permission Errors**: The script requires sudo access on target systems to collect hardware information
- **Missing Information**: Some fields may appear empty if the corresponding information couldn't be collected

## License

This script is released under the MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
