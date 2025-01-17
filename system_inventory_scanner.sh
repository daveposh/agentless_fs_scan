#!/bin/bash
#
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'./
NC='\033[0m' # No Color

# Output CSV file
OUTPUT_FILE="system_inventory.csv"

# Function to sanitize CSV values
sanitize_csv() {
    echo "$1" | sed 's/,/;/g' | sed 's/"/'"'"'/g'
}

# Function to collect system information for a single host
collect_system_info() {
    local ip=$1
    echo -e "${GREEN}Collecting information for $ip...${NC}"
    
    if ! ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
        echo -e "${RED}Host $ip is not reachable${NC}"
        return 1
    fi

    # Try SSH connection with key-based auth
    if ! ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" true 2>/dev/null; then
        echo -e "${RED}Cannot SSH to $ip${NC}"
        return 1
    fi

    # Collect system information via SSH
    local system_info=$(ssh "$ip" "
        hostname=\$(hostname)
        os=\$(cat /etc/os-release | grep 'PRETTY_NAME' | cut -d '=' -f 2 | tr -d '\"')
        os_version=\$(cat /etc/os-release | grep 'VERSION_ID' | cut -d '=' -f 2 | tr -d '\"')
        kernel=\$(uname -r)
        memory=\$(free -g | awk '/^Mem:/{print \$2}')
        disk_space=\$(df -BG / | awk 'NR==2 {print \$2}' | tr -d 'G')
        cpu_speed=\$(lscpu | grep 'CPU MHz' | awk '{print \$3/1000}')
        cpu_cores=\$(nproc)
        mac_addresses=\$(ip link | awk '/link\/ether/{print \$2}' | paste -sd ';' -)
        ip_addresses=\$(ip -4 addr show | grep inet | awk '{print \$2}' | cut -d '/' -f 1 | paste -sd ';' -)
        serial_number=\$(dmidecode -s system-serial-number 2>/dev/null || echo 'N/A')
        uuid=\$(dmidecode -s system-uuid 2>/dev/null || echo 'N/A')
        last_login=\$(last -1 -R | head -1 | awk '{print \$1}')
        asset_type='Server'
        discovery_date=\$(date '+%Y-%m-%d %H:%M:%S')
        domain=\$(dnsdomainname 2>/dev/null || echo 'N/A')
        asset_state='Active'
        region=''
        az=''
        
        echo \"\$hostname,\$asset_type,,\$hostname,Linux Server,,true,Production,scan_agent,system,\$discovery_date,scan_agent,system,\$discovery_date,automated_scan,,,system,,,\$discovery_date,,,,,,,\$domain,\$asset_state,\$serial_number,\$discovery_date,Physical,Server,,\${region},\${az},\$os,\$os_version,\$kernel,\$memory,\$disk_space,\$cpu_speed,\$cpu_cores,\$mac_addresses,\$uuid,\$hostname,\$ip_addresses,,false,\$last_login,,,,,,,,,\$discovery_date,Server,Production,Production,,system,system\"
    ")

    # Append to CSV file
    echo "$system_info" >> "$OUTPUT_FILE"
}

# Create CSV file with header
cp header.csv "$OUTPUT_FILE"

# Check if no arguments provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 [-r CIDR_RANGE | -f IP_LIST_FILE | IP_ADDRESS]"
    exit 1
fi

# Check if first argument is an option or IP address
if [[ $1 == -* ]]; then
    # Parse command line arguments and process hosts
    while getopts "r:f:h" opt; do
        case $opt in
            r)
                CIDR_RANGE=$OPTARG
                if command -v nmap >/dev/null 2>&1; then
                    echo -e "${GREEN}Scanning CIDR range: $CIDR_RANGE${NC}"
                    nmap -sL -n "$CIDR_RANGE" | grep "Nmap scan report" | cut -d ' ' -f 5 | while read -r ip; do
                        collect_system_info "$ip"
                    done
                else
                    echo -e "${RED}Error: nmap is required for CIDR range scanning${NC}"
                    exit 1
                fi
                ;;
            f)
                IP_FILE=$OPTARG
                if [ ! -f "$IP_FILE" ]; then
                    echo -e "${RED}Error: File $IP_FILE not found${NC}"
                    exit 1
                fi
                echo -e "${GREEN}Reading IPs from file: $IP_FILE${NC}"
                
                # Create CSV file with header if it doesn't exist
                if [ ! -f "$OUTPUT_FILE" ]; then
                    cp header.csv "$OUTPUT_FILE"
                fi
                
                # Read the file and process each IP
                while IFS= read -r line || [ -n "$line" ]; do
                    # Skip empty lines and comments
                    if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                        # Trim whitespace
                        ip=$(echo "$line" | tr -d '[:space:]')
                        if [[ -n "$ip" ]]; then
                            echo -e "${GREEN}Processing IP: $ip${NC}"
                            collect_system_info "$ip"
                        fi
                    fi
                done < <(grep -v '^[[:space:]]*$' "$IP_FILE" | grep -v '^[[:space:]]*#')
                ;;
            h|*)
                echo "Usage: $0 [-r CIDR_RANGE | -f IP_LIST_FILE | IP_ADDRESS]"
                echo "Options:"
                echo "  -r CIDR_RANGE    Scan a CIDR range (e.g., 192.168.1.0/24)"
                echo "  -f IP_LIST_FILE  Read IPs from a file (one IP per line)"
                echo "  IP_ADDRESS       Scan a single IP address"
                exit 1
                ;;
        esac
    done
else
    # Treat first argument as single IP address
    if [ ! -f "$OUTPUT_FILE" ]; then
        cp header.csv "$OUTPUT_FILE"
    fi
    collect_system_info "$1"
fi 