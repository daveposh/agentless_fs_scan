#!/bin/bash
#
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Output CSV file
OUTPUT_FILE="system_inventory.csv"

# At the start of the script, after the shebang
# Ensure bash version >= 4 for associative arrays
if ((BASH_VERSINFO[0] < 4)); then
   echo "This script requires bash version 4 or higher"
   exit 1
fi

# Declare global associative array at script level
declare -A STATIC_DATA
declare -a BLOCKLIST

# Function to sanitize CSV values
sanitize_csv() {
    echo "$1" | sed 's/,/;/g' | sed 's/"/'"'"'/g'
}

# Function to read static data from config file
read_static_data() {
    if [ ! -f "static_data.conf" ]; then
        echo -e "${RED}Error: static_data.conf file not found${NC}"
        return 1
    fi
    
    # Clear any existing data
    unset STATIC_DATA
    declare -A STATIC_DATA
    
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ $key =~ ^[[:space:]]*# ]] && continue
        [[ -z $key ]] && continue
        
        # Remove quotes and trim whitespace
        key=$(echo "$key" | tr -d "'" | tr -d '"' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(echo "$value" | tr -d '"' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Convert spaces in key to underscores for easier handling
        key=$(echo "$key" | tr ' ' '_')
        
        # Only set if key is not empty
        if [ ! -z "$key" ]; then
            STATIC_DATA[$key]="$value"
        fi
    done < "static_data.conf"
    
    return 0
}

# Function to read blocklist
read_blocklist() {
    if [ ! -f "linux.csv" ]; then
        echo -e "${RED}Warning: linux.csv (blocklist) not found${NC}"
        return 0
    fi
    
    # Clear existing blocklist
    BLOCKLIST=()
    
    # Read linux.csv and populate the blocklist array
    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^#.*$ ]] && continue
        
        # Add software name to blocklist
        BLOCKLIST+=("$line")
    done < "linux.csv"
}

# Function to check if software is in blocklist
is_blocked() {
    local check_software="$1"
    
    # Loop through blocklist
    for blocked_software in "${BLOCKLIST[@]}"; do
        if [[ "$check_software" == "$blocked_software" ]]; then
            return 0  # software is blocked
        fi
    done
    return 1  # software is not blocked
}

# Function to collect system information for a single host
collect_system_info() {
    local ip=$1

    # Check for localhost/127.0.0.1
    if [[ "$ip" == "127.0.0.1" ]] || [[ "$ip" == "localhost" ]]; then
        echo -e "${RED}Error: Cannot use localhost/127.0.0.1. Please provide a remote IP address${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Collecting information for $ip...${NC}"
    
    # Read static data and blocklist
    read_static_data || return 1
    read_blocklist
    
    # Get hostname first to check against blocklist
    remote_hostname=$(ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" "hostname" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        if is_blocked "$remote_hostname"; then
            echo -e "${GREEN}Skipping blocked hostname: $remote_hostname${NC}"
            return 0
        fi
    else
        echo -e "${RED}Failed to get remote hostname${NC}"
    fi
    
    # Get absolute paths for files
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    OUTPUT_FILE="$SCRIPT_DIR/system_inventory.csv"
    SOFTWARE_OUTPUT_FILE="$SCRIPT_DIR/software_inventory.csv"
    
    # Create software inventory CSV header if it doesn't exist
    if [ ! -f "$SOFTWARE_OUTPUT_FILE" ]; then
        echo "hostname,product,version,location" > "$SOFTWARE_OUTPUT_FILE"
    fi

    if ! ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
        echo -e "${RED}Host $ip is not reachable${NC}"
        return 1
    fi

    # Try SSH connection with key-based auth
    if ! ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" true 2>/dev/null; then
        echo -e "${RED}Cannot SSH to $ip${NC}"
        return 1
    fi

    # Create a temporary directory for output
    TMP_DIR=$(mktemp -d)
    LOCAL_SYSTEM_TMP="$TMP_DIR/system.csv"

    # Collect system information and software inventory in a single SSH connection
    ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" "
        hostname=\$(hostname)
        os=\$(cat /etc/os-release | grep 'PRETTY_NAME' | cut -d '=' -f 2 | tr -d '\"')
        os_version=\$(cat /etc/os-release | grep 'VERSION_ID' | cut -d '=' -f 2 | tr -d '\"')
        kernel=\$(uname -r)
        memory=\$(free -g | awk '/^Mem:/{print \$2}')
        disk_space=\$(df -BG / | awk 'NR==2 {print \$2}' | tr -d 'G')
        cpu_speed=\$(lscpu | grep 'CPU MHz' | awk '{print \$3/1000}')
        cpu_cores=\$(nproc)
        mac_addresses=\$(ip link | awk '/link\/ether/{print \$2}' | paste -sd ';' -)
        ip_addresses=\$(ip -4 addr show | grep inet | awk '{print \$2}' | cut -d '/' -f 1 | grep -v '^127\.' | paste -sd ';' -)
        
        # Check if sudo is available and can be used without password
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            serial_number=\$(sudo dmidecode -s system-serial-number 2>/dev/null || echo 'N/A')
            uuid=\$(sudo dmidecode -s system-uuid 2>/dev/null || echo 'N/A')
        else
            echo \"Warning: sudo access not available for dmidecode commands\" >&2
            serial_number='No sudo access'
            uuid='No sudo access'
        fi
        
        last_login=\$(last -1 -R | head -1 | awk '{print \$1}')
        discovery_date=\$(date '+%Y-%m-%d %H:%M:%S')
        domain=\$(dnsdomainname 2>/dev/null || echo 'N/A')
        
        # Get system age from root filesystem creation date
        system_age=\$(date -d @\$(stat -c %W /) \"+%m-%d-%Y\" 2>/dev/null || date -d @\$(stat -c %Y /) \"+%m-%d-%Y\")
        
        # Output system information
        echo \"SYSINFO:\$hostname,\
${STATIC_DATA[Asset_Type]:-Server},\
\$os,\
\$os_version,\
\$kernel,\
\$memory,\
\$disk_space,\
\$cpu_speed,\
\$cpu_cores,\
\$mac_addresses,\
\$ip_addresses,\
\$serial_number,\
\$uuid,\
\$last_login,\
\$discovery_date,\
\$domain,\
${STATIC_DATA[Asset_State]:-Active},\
${STATIC_DATA[Impact]:-High},\
${STATIC_DATA[Usage_Type]:-permanent},\
${STATIC_DATA[Created_by_-_Source]:-System Inventory Scanner},\
${STATIC_DATA[Department]:-IT},\
${STATIC_DATA[Workspace]:-My Workspace},\
${STATIC_DATA[Environment]:-Production},\
\$system_age\"

        # Output software information
        echo \"SOFTWARE_START\"
        dpkg-query -W -f='\${Package},\${Version},\${Status}\n' | while IFS=',' read -r pkg version status; do
            if [[ \$status == *\"installed\"* ]]; then
                location=\$(dpkg -L \"\$pkg\" 2>/dev/null | grep -m 1 '/usr/bin\|/usr/sbin\|/usr/local/bin' || echo 'N/A')
                echo \"\$hostname,\$pkg,\$version,\$location\"
            fi
        done
        echo \"SOFTWARE_END\"
    " | while IFS= read -r line; do
        if [[ "$line" == SYSINFO:* ]]; then
            # Extract system information (remove SYSINFO: prefix)
            echo "${line#SYSINFO:}" > "$LOCAL_SYSTEM_TMP"
        elif [[ "$line" == SOFTWARE_START ]]; then
            # Start collecting software information
            collecting_software=1
        elif [[ "$line" == SOFTWARE_END ]]; then
            # Stop collecting software information
            collecting_software=0
        elif [ "$collecting_software" = "1" ]; then
            # Process software line
            pkg_name=$(echo "$line" | cut -d',' -f2)
            if ! is_blocked "$pkg_name"; then
                echo "$line" >> "$SOFTWARE_OUTPUT_FILE"
            fi
        fi
    done

    # Create header if file doesn't exist or is empty
    if [ ! -f "$OUTPUT_FILE" ] || [ ! -s "$OUTPUT_FILE" ]; then
        echo "hostname,asset_type,os,os_version,kernel,memory,disk_space,cpu_speed,cpu_cores,mac_addresses,ip_addresses,serial_number,uuid,last_login,discovery_date,domain,asset_state,impact,usage_type,created_by,department,workspace,environment,system_age" > "$OUTPUT_FILE"
    fi

    # Append system information if collected
    if [ -s "$LOCAL_SYSTEM_TMP" ]; then
        cat "$LOCAL_SYSTEM_TMP" >> "$OUTPUT_FILE"
        echo -e "${GREEN}Successfully collected information from $ip${NC}"
    else
        echo -e "${RED}Failed to collect information from $ip${NC}"
        rm -rf "$TMP_DIR"
        return 1
    fi

    # Cleanup
    rm -rf "$TMP_DIR"
}

# Ensure header.csv exists and has content
if [ ! -f "header.csv" ]; then
    echo "hostname,asset_type,os,os_version,kernel,memory,disk_space,cpu_speed,cpu_cores,mac_addresses,ip_addresses,serial_number,uuid,last_login,discovery_date,domain,asset_state,impact,usage_type,created_by,department,workspace,environment" > "header.csv"
fi

# Create CSV file with header if it doesn't exist
if [ ! -f "$OUTPUT_FILE" ]; then
    cp header.csv "$OUTPUT_FILE"
elif [ ! -s "$OUTPUT_FILE" ]; then
    cp header.csv "$OUTPUT_FILE"
fi

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
                        # Skip localhost/127.0.0.1
                        if [[ "$ip" != "127.0.0.1" ]] && [[ "$ip" != "localhost" ]]; then
                            collect_system_info "$ip"
                        fi
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
                
                # Read all IPs into an array
                IPS=()
                while IFS= read -r line || [ -n "$line" ]; do
                    # Clean the line: remove trailing %, spaces, and other special characters
                    ip=$(echo "$line" | sed 's/%//g' | tr -d '[:space:]')
                    # Skip empty lines, comments, and localhost
                    if [[ -n "$ip" && ! "$ip" =~ ^# && "$ip" != "127.0.0.1" && "$ip" != "localhost" ]]; then
                        IPS+=("$ip")
                    fi
                done < "$IP_FILE"
                
                # Process each IP
                for ip in "${IPS[@]}"; do
                    echo -e "${GREEN}Processing IP: $ip${NC}"
                    collect_system_info "$ip"
                done
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
    collect_system_info "$1"
fi 