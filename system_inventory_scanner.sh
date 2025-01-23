#!/bin/bash
#
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Output CSV file
OUTPUT_FILE="system_inventory.csv"

# Static values
declare -A STATIC_DATA=(
    ["Impact"]="High"
    ["Asset_Type"]="Server"
    ["End_of_Life"]=""
    ["Physical_Subtype"]=""
    ["Usage_Type"]="permanent"
    ["Created_by_-_Source"]="System Inventory Scanner"
    ["Department"]="IT"
    ["Workspace"]="My Team"
    ["Environment"]="PROD"
)

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
    
    # Debug output to verify static data
    echo "Debug: Static Data Values:"
    echo "Workspace = ${STATIC_DATA[Workspace]}"
    echo "Asset Type = ${STATIC_DATA[Asset_Type]}"
    echo "Impact = ${STATIC_DATA[Impact]}"
    echo "Environment = ${STATIC_DATA[Environment]}"
    
    # Get absolute paths for files
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    OUTPUT_FILE="$SCRIPT_DIR/system_inventory.csv"
    SOFTWARE_OUTPUT_FILE="$SCRIPT_DIR/software_inventory.csv"
    
    # Create CSV files with headers if they don't exist
    if [ ! -f "$OUTPUT_FILE" ]; then
        echo "Name,Asset Type,Asset Tag,Impact,Description,End of Life,Discovery Enabled,Usage Type,Created by - Source,Created by - User,Created At,Last updated by - Source,Last updated by - User,Updated At,Sources,Location,Department,Managed By,Used By,Group,Assigned on,Workspace,Product,Vendor,Cost,Warranty,Acquisition Date,Warranty Expiry Date,Domain,Asset State,Serial Number,Last Audit Date,Type,Physical Subtype,Virtual Subtype,Region,Availability Zone,OS,OS Version,OS Service Pack,Memory(GB),Disk Space(GB),CPU Speed(GHz),CPU Core Count,MAC Address,UUID,Hostname,IP Address,IP Address 2,Shared IP,Last login by,Item ID,Item Name,Public Address,State,Instance Type,Provider,Creation Timestamp,Server Function,Environment,Usage Type,Book Value($),Used by (Name),Managed by (Name),system age" > "$OUTPUT_FILE"
    fi
    
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

    # Pass static data values to SSH command
    export WORKSPACE_VALUE="${STATIC_DATA[Workspace]}"
    export ASSET_TYPE="${STATIC_DATA[Asset_Type]}"
    export IMPACT="${STATIC_DATA[Impact]}"
    export END_OF_LIFE="${STATIC_DATA[End_of_Life]}"
    export USAGE_TYPE="${STATIC_DATA[Usage_Type]}"
    export CREATED_BY="${STATIC_DATA[Created_by_-_Source]}"
    export DEPARTMENT="${STATIC_DATA[Department]}"
    
    # Ensure Environment is set to PROD if not defined
    if [ -z "${STATIC_DATA[Environment]}" ]; then
        export ENVIRONMENT="PROD"
        echo "Debug: Setting default Environment = PROD"
    else
        export ENVIRONMENT="${STATIC_DATA[Environment]}"
        echo "Debug: Using configured Environment = ${ENVIRONMENT}"
    fi

    ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$ip" "
        hostname=\$(hostname)
        os=\$(cat /etc/os-release | grep 'PRETTY_NAME' | cut -d '=' -f 2 | tr -d '\"')
        os_version=\$(cat /etc/os-release | grep 'VERSION_ID' | cut -d '=' -f 2 | tr -d '\"')
        kernel=\$(uname -r)
        memory_mb=\$(free -m | awk '/^Mem:/{print \$2}')
        memory=\$(( (memory_mb + 1023) / 1024 ))
        disk_space=\$(df -BG / | awk 'NR==2 {print \$2}' | tr -d 'G')
        cpu_speed=\$(lscpu | grep 'CPU MHz' | awk '{print \$3/1000}')
        cpu_cores=\$(nproc)
        mac_addresses=\$(ip link | awk '/link\/ether/{print \$2}' | paste -sd ';' -)
        ip_addresses=\$(ip -4 addr show | grep inet | awk '{print \$2}' | cut -d '/' -f 1 | grep -v '^127\.' | paste -sd ';' -)
        
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            serial_number=\$(sudo dmidecode -s system-serial-number 2>/dev/null || echo 'N/A')
            uuid=\$(sudo dmidecode -s system-uuid 2>/dev/null || echo 'N/A')
        else
            echo \"Warning: sudo access not available for dmidecode commands\" >&2
            serial_number='No sudo access'
            uuid='No sudo access'
        fi
        
        last_login=\$(last -1 -R | head -1 | awk '{print \$1}')
        discovery_date=\$(date '+%Y-%m-%d %H:%M')
        domain=\$(dnsdomainname 2>/dev/null || echo 'N/A')
        
        system_age=\$(date -d @\$(stat -c %W /) \"+%Y-%m-%d %H:%M\" 2>/dev/null || date -d @\$(stat -c %Y /) \"+%Y-%m-%d %H:%M\")

        if [[ \"\$serial_number\" == *\"VMware\"* ]]; then
            product=\"VMware Vcenter VM\"
            virtual_subtype=\"VMware\"
        else
            product=\"SERVER\"
            virtual_subtype=\"\"
        fi

        if pgrep -f \"nginx\" >/dev/null; then
            server_function=\"Webserver\"
            description=\"<p>Server Info: \$hostname (\$ip_addresses) - \$server_function</p>\"
            if [ -d \"/etc/nginx/sites-enabled\" ]; then
                description+=\"<p>Enabled Sites:</p><ul>\"
                for site in /etc/nginx/sites-enabled/*; do
                    if [ -f \"\$site\" ]; then
                        site_name=\$(basename \"\$site\")
                        server_name=\$(grep -h \"server_name\" \"\$site\" 2>/dev/null | head -1 | sed 's/server_name//g' | tr -d ';' | xargs)
                        description+=\"<li>\$site_name (\$server_name)</li>\"
                    fi
                done
                description+=\"</ul>\"
            else
                description+=\"<p>No sites-enabled directory found</p>\"
            fi
        elif pgrep -f \"mysqld\" >/dev/null || pgrep -f \"mariadbd\" >/dev/null; then
            server_function=\"Database\"
            description=\"<p>Server Info: \$hostname (\$ip_addresses) - \$server_function</p>\"
        else
            server_function=\"\"
            description=\"<p>Server Info: \$hostname (\$ip_addresses)</p>\"
        fi
        
        echo \"SYSINFO:\$hostname,\
${STATIC_DATA[Asset_Type]},\
\$serial_number,\
${STATIC_DATA[Impact]},\
\$description,\
${STATIC_DATA[End_of_Life]},\
yes,\
${STATIC_DATA[Usage_Type]},\
${STATIC_DATA[Created_by_-_Source]},\
,\
\$discovery_date,\
${STATIC_DATA[Created_by_-_Source]},\
,\
\$discovery_date,\
${STATIC_DATA[Created_by_-_Source]},\
,\
${STATIC_DATA[Department]},\
,\
,\
,\
,\
${STATIC_DATA[Workspace]},\
\$product,\
,\
,\
,\
,\
,\
\$domain,\
Active,\
\$serial_number,\
\$discovery_date,\
Server,\
${STATIC_DATA[Physical_Subtype]},\
\$virtual_subtype,\
,\
,\
\$os,\
\$os_version,\
,\
\$memory,\
\$disk_space,\
\$cpu_speed,\
\$cpu_cores,\
\$mac_addresses,\
\$uuid,\
\$hostname,\
\$ip_addresses,\
,\
,\
\$last_login,\
,\
,\
,\
Active,\
,\
,\
\$discovery_date,\
\$server_function,\
${STATIC_DATA[Environment]},\
${STATIC_DATA[Usage_Type]},\
,\
,\
,\
\$system_age\"

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