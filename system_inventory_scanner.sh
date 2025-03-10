#!/bin/bash
#
# At the start of the script, after the shebang
# Ensure bash version >= 4 for associative arrays
if ((BASH_VERSINFO[0] < 4)); then
   echo "This script requires bash version 4 or higher"
   exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Output CSV file
OUTPUT_FILE="system_inventory.csv"
SOFTWARE_OUTPUT_FILE="software_inventory.csv"

# Built-in static values - no external file needed
WORKSPACE_VALUE="My Team"
ASSET_TYPE="Server"
IMPACT="High"
END_OF_LIFE=""
USAGE_TYPE="permanent"
CREATED_BY="System Inventory Scanner"
DEPARTMENT="IT"
ENVIRONMENT="PROD"

# Built-in blocklist - no external file needed
declare -a BLOCKLIST=(
    "systemd"
    "linux-headers"
    "linux-image"
    "linux-modules"
    "grub"
    "initramfs"
)

# Function to sanitize CSV values
sanitize_csv() {
    # Simple CSV value escaping
    echo "$1" | sed 's/,/;/g' | sed 's/"/'"'"'/g'
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
    local is_local=$2

    if [ "$is_local" != "true" ]; then
        # Check for localhost/127.0.0.1
        if [[ "$ip" == "127.0.0.1" ]] || [[ "$ip" == "localhost" ]]; then
            echo -e "${RED}Error: For local execution, please use the -l flag${NC}" >&2
            return 1
        fi
        
        echo -e "${GREEN}Collecting information for $ip...${NC}" >&2

        # Try SSH connection with key-based auth
        echo -e "${GREEN}Testing SSH connection to $ip...${NC}" >&2
        if ! ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no "$ip" "echo 'SSH test successful'" >/dev/null 2>&1; then
            echo -e "${RED}Cannot SSH to $ip - Please check SSH key authentication is set up${NC}" >&2
            return 1
        fi
    else
        echo -e "${GREEN}Collecting local system information...${NC}" >&2
    fi

    # Create a temporary directory for output
    TMP_DIR=$(mktemp -d)
    LOCAL_SYSTEM_TMP="$TMP_DIR/system.csv"

    # Function containing the commands to execute
    collect_commands() {
        # Export variables for use in the command
        WORKSPACE_VALUE="My Team"
        ASSET_TYPE="Server"
        IMPACT="High"
        END_OF_LIFE=""
        USAGE_TYPE="permanent"
        CREATED_BY="System Inventory Scanner"
        DEPARTMENT="IT"
        ENVIRONMENT="PROD"

        hostname=$(hostname)
        os=$(cat /etc/os-release | grep 'PRETTY_NAME' | cut -d '=' -f 2 | tr -d '"')
        os_version=$(cat /etc/os-release | grep 'VERSION_ID' | cut -d '=' -f 2 | tr -d '"')
        kernel=$(uname -r)
        memory_mb=$(free -m | awk '/^Mem:/{print $2}')
        memory=$(( (memory_mb + 500) / 1000 ))
        disk_space=$(df -BG / | awk 'NR==2 {print $2}' | tr -d 'G')
        cpu_speed=$(lscpu | grep 'CPU MHz' | awk '{print $3/1000}')
        cpu_cores=$(nproc)
        mac_addresses=$(ip link | awk '/link\/ether/{print $2}' | paste -sd ';' -)
        ip_addresses=$(ip -4 addr show | grep inet | awk '{print $2}' | cut -d '/' -f 1 | grep -v '^127\.' | paste -sd ';' -)
        public_ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "N/A")
        
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            serial_number=$(sudo dmidecode -s system-serial-number 2>/dev/null || echo '')
            uuid=$(sudo dmidecode -s system-uuid 2>/dev/null || echo 'N/A')
            
            # Clean up the serial number
            serial_number=$(echo "$serial_number" | tr -d '\r\n\t')
        else
            echo "Warning: sudo access not available for dmidecode commands" >&2
            timestamp=$(date '+%Y%m%d%H%M%S')
            serial_number="CXI-$timestamp"
            uuid='No sudo access'
        fi
        
        # Initialize variables
        region=""
        availability_zone=""
        location=""
        vendor=""
        instance_type=""
        virtual_subtype=""
        product="SERVER"

        # First determine if this is a VMware VM
        if echo "$serial_number" | grep -q "VMware"; then
            # This is a VMware VM
            product='VMware Virtual Machine'
            virtual_subtype='VMware'
            instance_type='Virtual'
            vendor='VMware'
            # Keep the VMware serial number as is - it's the asset tag
        elif echo "$serial_number" | grep -q "^ec2"; then
            # This is an AWS EC2 instance
            TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
            if [ -n "$TOKEN" ]; then
                availability_zone=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null)
                region=$(echo "$availability_zone" | sed 's/[a-z]$//')
                ec2_instance_type=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null)
                
                location="AWS $region"
                vendor='Amazon EC2'
                instance_type='Virtual'
                virtual_subtype="Amazon EC2 instance - $ec2_instance_type"
                product='EC2 Instance'
            fi
        else
            # Physical server or unknown type
            if [ -z "$serial_number" ] || [ "$serial_number" = "Not Specified" ] || [ "$serial_number" = "N/A" ] || [ "$serial_number" = "None" ]; then
                timestamp=$(date '+%Y%m%d%H%M%S')
                serial_number="CXI-$timestamp"
            fi
            instance_type=''
            virtual_subtype=''
            product='SERVER'
            vendor=''
        fi
        
        # Set asset tag to be the same as serial number
        asset_tag=$serial_number
        
        last_login=$(last -1 -R | head -1 | awk '{print $1}')
        discovery_date=$(date '+%Y-%m-%d %H:%M')
        domain=$(dnsdomainname 2>/dev/null || echo 'N/A')
        
        # Format system age date consistently
        system_age=$(date -d @$(stat -c %W / 2>/dev/null || stat -c %Y /) '+%Y-%m-%d %H:%M' 2>/dev/null || echo 'N/A')

        # Format last login date if available
        if [ x"$last_login" != x"" ]; then
            last_login_date=$(last -1 -R $last_login | head -1 | awk '{print $5,$6,$7,$8}' | xargs -I{} date -d "{}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo $last_login)
        else
            last_login_date=""
        fi

        if pgrep -f "nginx" >/dev/null; then
            server_function="Webserver"
            description="<p>Server Info: $hostname ($ip_addresses) - $server_function</p>"
            if [ -d "/etc/nginx/sites-enabled" ]; then
                description+="<p>Enabled Sites:</p><ul>"
                for site in /etc/nginx/sites-enabled/*; do
                    if [ -f "$site" ]; then
                        site_name=$(basename "$site")
                        
                        # Extract server block content
                        server_blocks=$(awk '/server[[:space:]]*{/,/}/' "$site")
                        
                        # Process each server block
                        echo "$server_blocks" | while IFS= read -r line; do
                            if [[ "$line" =~ server_name[[:space:]]+(.*)\; ]]; then
                                server_names=${BASH_REMATCH[1]}
                            elif [[ "$line" =~ listen[[:space:]]+(.*)\; ]]; then
                                listen_port=$(echo "${BASH_REMATCH[1]}" | grep -o '[0-9]\+' | head -1)
                                if [[ "$line" = *ssl* ]]; then
                                    ssl="true"
                                fi
                            elif [[ "$line" =~ root[[:space:]]+(.*)\; ]]; then
                                root_dir=${BASH_REMATCH[1]}
                            fi
                        done
                        
                        # Default to port 80 if not specified
                        if [ x"$listen_port" = x"" ]; then
                            listen_port="80"
                        fi
                        
                        # If no server_name found or it's _, use IP address
                        if [ x"$server_names" = x"" ] || [ x"$server_names" = x"_" ]; then
                            server_names="$ip_addresses"
                        fi
                        
                        # Determine protocol based on SSL directive and port
                        protocol="http"
                        if [ x"$ssl" = x"true" ] || [ x"$listen_port" = x"443" ]; then
                            protocol="https"
                        fi
                        
                        # For each server name, create a URL
                        for server_name in $server_names; do
                            # Clean up server name
                            server_name=$(echo "$server_name" | tr -d ' ')
                            
                            # Create URL based on port
                            if [ "$listen_port" = "80" ] && [ "$protocol" = "http" ]; then
                                url="<a href=\"http://$server_name\">$server_name</a>"
                            elif [ "$listen_port" = "443" ] && [ "$protocol" = "https" ]; then
                                url="<a href=\"https://$server_name\">$server_name</a>"
                            else
                                url="<a href=\"$protocol://$server_name:$listen_port\">$server_name:$listen_port</a>"
                            fi
                            
                            # Add root directory if available
                            if [ -n "$root_dir" ]; then
                                root_info=" (Document Root: $root_dir)"
                            else
                                root_info=""
                            fi
                            
                            description+="<li>$site_name - $url$root_info</li>"
                        done
                    fi
                done
                description+="</ul>"
            else
                description+="<p>No sites-enabled directory found</p>"
            fi
        elif pgrep -f "mysqld" >/dev/null || pgrep -f "mariadbd" >/dev/null; then
            server_function="Database"
            description="<p>Server Info: $hostname ($ip_addresses) - $server_function</p>"
        else
            server_function=""
            description="<p>Server Info: $hostname ($ip_addresses)</p>"
        fi
        
        {
            echo "SYSINFO:$hostname,\
$ASSET_TYPE,\
$asset_tag,\
$IMPACT,\
$description,\
$END_OF_LIFE,\
yes,\
$USAGE_TYPE,\
$CREATED_BY,\
,\
$discovery_date,\
$CREATED_BY,\
,\
$discovery_date,\
$CREATED_BY,\
$location,\
$DEPARTMENT,\
,\
,\
,\
,\
$WORKSPACE_VALUE,\
$product,\
$vendor,\
,\
,\
,\
,\
$domain,\
Active,\
$serial_number,\
$discovery_date,\
$instance_type,\
,\
$virtual_subtype,\
$region,\
$availability_zone,\
$os,\
$os_version,\
,\
$memory,\
$disk_space,\
$cpu_speed,\
$cpu_cores,\
$mac_addresses,\
$uuid,\
$hostname,\
$ip_addresses,\
,\
,\
$last_login_date,\
,\
,\
$public_ip,\
Active,\
,\
,\
$discovery_date,\
$server_function,\
$ENVIRONMENT,\
$USAGE_TYPE,\
,\
,\
,\
$system_age"

            echo "SOFTWARE_START"
            # Get installed packages and their versions
            dpkg-query -W -f='${Package},${Version},${Status}\n' 2>/dev/null | while IFS=',' read -r pkg version status; do
                if [[ "$status" == *"installed"* ]]; then
                    # Get the package location (first executable found)
                    location=$(dpkg -L "$pkg" 2>/dev/null | grep -m 1 '^/usr/s?bin/[^/]*$' || echo 'N/A')
                    
                    # Get package description
                    description=$(dpkg-query -W -f='${Description}' "$pkg" 2>/dev/null | head -n1 || echo 'N/A')
                    
                    # Clean and format the version
                    clean_version=$(echo "$version" | tr -d ' ' | sed 's/[[:space:]]//g')
                    
                    # Output in CSV format with proper escaping
                    echo "$hostname,$pkg,$clean_version,$location"
                fi
            done
            echo "SOFTWARE_END"
        } 2>/dev/null
    }

    if [ "$is_local" = "true" ]; then
        # Execute commands locally
        collect_commands > "$TMP_DIR/output.txt"
    else
        # Execute commands via SSH
        ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no "$ip" "$(declare -f collect_commands); collect_commands" > "$TMP_DIR/output.txt"
    fi

    # Create CSV files with headers if they don't exist
    if [ "$is_local" = "true" ] || [ ! -f "$OUTPUT_FILE" ]; then
        # Always create header for local execution or if file doesn't exist
        echo "Name,Asset Type,Asset Tag,Impact,Description,End of Life,Discovery Enabled,Usage Type,Created by - Source,Created by - User,Created At,Last updated by - Source,Last updated by - User,Updated At,Sources,Location,Department,Managed By,Used By,Group,Assigned on,Workspace,Product,Vendor,Cost,Warranty,Acquisition Date,Warranty Expiry Date,Domain,Asset State,Serial Number,Last Audit Date,Type,Physical Subtype,Virtual Subtype,Region,Availability Zone,OS,OS Version,OS Service Pack,Memory(GB),Disk Space(GB),CPU Speed(GHz),CPU Core Count,MAC Address,UUID,Hostname,IP Address,IP Address 2,Shared IP,Last login by,Item ID,Item Name,Public Address,State,Instance Type,Provider,Creation Timestamp,Server Function,Environment,Usage Type,Book Value($),Used by (Name),Managed by (Name),system age" > "$OUTPUT_FILE"
    fi

    if [ "$is_local" = "true" ] || [ ! -f "$SOFTWARE_OUTPUT_FILE" ]; then
        # Always create header for local execution or if file doesn't exist
        echo "hostname,product,version,location" > "$SOFTWARE_OUTPUT_FILE"
    fi

    # Process the output file
    collecting_software=0
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" == SYSINFO:* ]]; then
            # Extract system information (remove SYSINFO: prefix)
            echo "${line#SYSINFO:}" > "$LOCAL_SYSTEM_TMP"
        elif [[ "$line" == SOFTWARE_START ]]; then
            # Start collecting software information
            collecting_software=1
        elif [[ "$line" == SOFTWARE_END ]]; then
            # Stop collecting software information
            collecting_software=0
        elif [ "$collecting_software" = "1" ] && [ -n "$line" ]; then
            # Process software line if not empty
            echo "$line" >> "$SOFTWARE_OUTPUT_FILE"
        fi
    done < "$TMP_DIR/output.txt"

    # Append system information if collected
    if [ -s "$LOCAL_SYSTEM_TMP" ]; then
        if [ "$is_local" = "true" ]; then
            # For local execution, overwrite the file
            cat "$LOCAL_SYSTEM_TMP" > "$OUTPUT_FILE"
        else
            # For remote execution, append to the file
            cat "$LOCAL_SYSTEM_TMP" >> "$OUTPUT_FILE"
        fi
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
    echo "Usage: $0 [-l | -r CIDR_RANGE | -f IP_LIST_FILE | IP_ADDRESS]"
    exit 1
fi

# Check if first argument is an option or IP address
if [[ $1 == -* ]]; then
    # Parse command line arguments and process hosts
    while getopts "lr:f:h" opt; do
        case $opt in
            l)
                echo -e "${GREEN}Running local system scan...${NC}"
                collect_system_info "localhost" "true"
                ;;
            r)
                CIDR_RANGE=$OPTARG
                if command -v nmap >/dev/null 2>&1; then
                    echo -e "${GREEN}Scanning CIDR range: $CIDR_RANGE${NC}"
                    nmap -sL -n "$CIDR_RANGE" | grep "Nmap scan report" | cut -d ' ' -f 5 | while read -r ip; do
                        # Skip localhost/127.0.0.1
                        if [[ "$ip" != "127.0.0.1" ]] && [[ "$ip" != "localhost" ]]; then
                            collect_system_info "$ip" "false"
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
                while IFS= read -r ip || [ -n "$ip" ]; do
                    # Skip empty lines, comments, and localhost
                    if [[ -n "$ip" && ! "$ip" =~ ^# && "$ip" != "127.0.0.1" && "$ip" != "localhost" ]]; then
                        collect_system_info "$ip" "false"
                    fi
                done < "$IP_FILE"
                ;;
            h|*)
                echo "Usage: $0 [-l | -r CIDR_RANGE | -f IP_LIST_FILE | IP_ADDRESS]"
                echo "Options:"
                echo "  -l              Run locally (no SSH)"
                echo "  -r CIDR_RANGE   Scan a CIDR range (e.g., 192.168.1.0/24)"
                echo "  -f IP_LIST_FILE Read IPs from a file (one IP per line)"
                echo "  IP_ADDRESS      Scan a single IP address"
                exit 1
                ;;
        esac
    done
else
    # Treat first argument as single IP address
    collect_system_info "$1" "false"
fi 