#!/bin/bash
# setup_tools.sh - Consolidated setup script for vulnerability analysis tools
# This script is designed for Kali Linux and Debian-based systems

set -e

# Colors for better output
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

echo -e "${BLUE}===== Vulnerability Analysis Toolkit Setup =====${NC}"
echo "This script will install and configure all necessary tools for security scanning."
echo -e "${YELLOW}Note: This script is for Linux systems. Windows is not supported.${NC}"

# Function to check for root/sudo access
check_sudo() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${YELLOW}This script requires sudo for some operations.${NC}"
        # Check if user can use sudo
        if sudo -v 2>/dev/null; then
            echo -e "${GREEN}Sudo access confirmed.${NC}"
        else
            echo -e "${RED}Warning: You don't have sudo privileges. Some operations may fail.${NC}"
        fi
    else
        echo -e "${GREEN}Running as root.${NC}"
    fi
}

# Function to fix repository key issues
fix_repo_keys() {
    echo -e "\n${BLUE}Fixing repository key issues...${NC}"
    bash ./fix_repo_keys.sh  # Call the reusable script
}

# Function to fix any dpkg issues with better error handling
fix_dpkg() {
    echo -e "\n${BLUE}[1/7] Checking for and fixing any package manager issues...${NC}"
    
    # Kill any running apt/dpkg processes that might be holding locks
    for proc in apt apt-get dpkg; do
        if pgrep -f $proc >/dev/null; then
            echo "Killing running $proc processes..."
            sudo killall -9 $proc 2>/dev/null || true
        fi
    done
    
    # Remove lock files
    for lock_file in /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
        if [ -f "$lock_file" ]; then
            echo "Removing lock file: $lock_file"
            sudo rm -f "$lock_file"
        fi
    done
    
    # Configure dpkg if interrupted
    sudo dpkg --configure -a || echo "Failed to configure dpkg. Continuing anyway."
    
    # Fix broken packages
    sudo apt-get install -f -y || echo "Failed to fix broken packages. Continuing anyway."
    
    # Clean apt cache to start fresh
    sudo apt-get clean || echo "Failed to clean package cache. Continuing anyway."
}

# Function to install apt packages with fallback repositories
install_apt_packages() {
    echo -e "\n${BLUE}[2/7] Installing required system packages...${NC}"
    
    # First try to fix repository issues
    fix_repo_keys
    
    # Try multiple Kali mirrors if the default fails
    MIRRORS=("http://http.kali.org/kali" "http://kali.download/kali" "http://mirror.ufro.cl/kali")
    
    updated=false
    for mirror in "${MIRRORS[@]}"; do
        echo "Trying repository mirror: $mirror"
        # Create temporary sources.list with the current mirror
        echo "deb $mirror kali-rolling main contrib non-free" | sudo tee /etc/apt/sources.list.d/temp-mirror.list
        
        if sudo apt-get update -o Acquire::AllowInsecureRepositories=true; then
            echo -e "${GREEN}Successfully updated package lists using mirror: $mirror${NC}"
            updated=true
            break
        else
            echo -e "${YELLOW}Failed to update with mirror: $mirror${NC}"
            sudo rm -f /etc/apt/sources.list.d/temp-mirror.list
        fi
    done
    
    # If all mirrors failed, try offline installation
    if [ "$updated" = false ]; then
        echo -e "${YELLOW}Could not update from any repository. Trying offline installation...${NC}"
        check_offline_installation
    fi
    
    # List of essential packages
    PACKAGES=("curl" "wget" "git" "python3" "python3-pip" "libpcap-dev" "build-essential")
    
    # Try to install each package individually with better error handling
    for pkg in "${PACKAGES[@]}"; do
        echo -e "\nInstalling $pkg..."
        if dpkg -l | grep -q "^ii  $pkg "; then
            echo -e "${GREEN}$pkg is already installed.${NC}"
        else
            # Try to install with apt-get
            if ! sudo apt-get install -y --no-install-recommends -o Acquire::AllowInsecureRepositories=true "$pkg"; then
                echo -e "${YELLOW}Failed to install $pkg with apt-get. Trying with aptitude...${NC}"
                
                # Try with aptitude if available
                if command -v aptitude >/dev/null 2>&1; then
                    sudo aptitude -y --allow-untrusted install "$pkg" || echo -e "${RED}Could not install $pkg. Continuing anyway.${NC}"
                else
                    echo -e "${RED}Could not install $pkg. Continuing anyway.${NC}"
                fi
            fi
        fi
    done
    
    # Try to install security tools via apt with fallback to Go
    for tool in nuclei naabu httpx; do
        echo -e "\nChecking for $tool..."
        if command -v $tool >/dev/null 2>&1; then
            echo -e "${GREEN}$tool is already installed.${NC}"
        else
            echo -e "Installing $tool via apt..."
            sudo apt-get install -y --no-install-recommends -o Acquire::AllowInsecureRepositories=true "$tool" || \
                echo -e "${YELLOW}$tool not available via apt. Will install via Go.${NC}"
        fi
    done
}

# Function to check if offline installation is possible
check_offline_installation() {
    echo -e "\n${BLUE}Checking for offline installation capabilities...${NC}"
    
    # Check if we have already-downloaded tools in expected locations
    TOOL_PATHS=("/usr/bin/naabu" "/usr/bin/httpx" "/usr/bin/nuclei")
    MISSING_TOOLS=()
    
    for tool_path in "${TOOL_PATHS[@]}"; do
        tool_name=$(basename "$tool_path")
        if [ -f "$tool_path" ] && [ -x "$tool_path" ]; then
            echo -e "${GREEN}Found $tool_name at $tool_path${NC}"
        else
            MISSING_TOOLS+=("$tool_name")
        fi
    done
    
    if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
        echo -e "${GREEN}All required tools are already installed!${NC}"
    else
        echo -e "${YELLOW}Missing tools: ${MISSING_TOOLS[*]}${NC}"
        echo "Will attempt to install missing tools with Go."
    fi
}

# Function to install Go
install_go() {
    if command -v go >/dev/null 2>&1; then
        echo -e "${GREEN}Go is already installed.${NC}"
        return
    fi

    echo -e "\n${BLUE}[3/7] Installing Go...${NC}"
    GO_VERSION="1.21.0"
    ARCH=$(uname -m)

    if [ "$ARCH" == "x86_64" ]; then
        GOARCH="amd64"
    elif [ "$ARCH" == "aarch64" ] || [ "$ARCH" == "arm64" ]; then
        GOARCH="arm64"
    else
        GOARCH="amd64"
    fi

    # Try with wget first
    if command -v wget >/dev/null 2>&1; then
        wget -q --show-progress https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz -O /tmp/go.tar.gz || {
            echo -e "${YELLOW}Failed to download Go with wget. Trying with curl...${NC}"
            if command -v curl >/dev/null 2>&1; then
                curl -L https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz -o /tmp/go.tar.gz || {
                    echo -e "${RED}Failed to download Go. Please check your network connection.${NC}"
                    return 1
                }
            else
                echo -e "${RED}Neither wget nor curl is available. Cannot download Go.${NC}"
                return 1
            }
        }
    elif command -v curl >/dev/null 2>&1; then
        curl -L https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz -o /tmp/go.tar.gz || {
            echo -e "${RED}Failed to download Go. Please check your network connection.${NC}"
            return 1
        }
    else
        echo -e "${RED}Neither wget nor curl is available. Cannot download Go.${NC}"
        return 1
    fi
    
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz || { echo "Failed to extract Go."; return 1; }
    rm /tmp/go.tar.gz

    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    
    # Update shell configuration files
    for config_file in ~/.bashrc ~/.zshrc ~/.profile; do
        if [ -f "$config_file" ]; then
            grep -q "export PATH=.*\/usr\/local\/go\/bin" "$config_file" || {
                echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$config_file"
                echo "Updated $config_file with Go path."
            }
        fi
    done
    
    echo -e "${GREEN}Go installed successfully. You may need to restart your terminal or run 'source ~/.bashrc'${NC}"
}

# Function to handle script execution gracefully
function run_script() {
    local script_path="$1"
    if [ -f "$script_path" ]; then
        chmod +x "$script_path"
        bash "$script_path"
    else
        echo "Error: Script $script_path not found."
        exit 1
    fi
}

# Create alternative naabu implementations when needed
create_naabu_alternative() {
    echo -e "\n${BLUE}Creating alternative naabu implementation...${NC}"
    
    NAABU_ALT_PATH="$HOME/go/bin/naabu"
    mkdir -p "$(dirname "$NAABU_ALT_PATH")" 2>/dev/null
    
    # First check if we already have the tool 
    if command -v naabu >/dev/null 2>&1 || [ -f "$NAABU_ALT_PATH" ]; then
        echo -e "${GREEN}naabu already available. Skipping alternative implementation.${NC}"
        return 0
    fi
    
    cat > "$NAABU_ALT_PATH" << 'EOF'
#!/bin/bash
# naabu alternative implementation
# This script provides a basic port scanning capability without external dependencies

VERSION="1.0.0"
TARGET=""
TARGET_FILE=""
PORTS="1-1000"
OUTPUT=""
VERBOSE=false
SILENT=false
JSON=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -host)
            TARGET="$2"
            shift 2
            ;;
        -l)
            TARGET_FILE="$2"
            shift 2
            ;;
        -p|-ports)
            PORTS="$2"
            shift 2
            ;;
        -o|-output)
            OUTPUT="$2"
            shift 2
            ;;
        -v|-verbose)
            VERBOSE=true
            shift
            ;;
        -json)
            JSON=true
            shift
            ;;
        -silent)
            SILENT=true
            shift
            ;;
        -version)
            echo "naabu-alternative v$VERSION"
            exit 0
            ;;
        -h|-help)
            echo "Usage: naabu -host <target> [-p <ports>] [-o <output>]"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Validate input
if [[ -z "$TARGET" && -z "$TARGET_FILE" ]]; then
    echo "Error: No target specified. Use -host or -l."
    exit 1
fi

# Create the output directory if needed
if [[ -n "$OUTPUT" ]]; then
    mkdir -p "$(dirname "$OUTPUT")" 2>/dev/null
    > "$OUTPUT"  # Initialize/clear output file
fi

# Function to check if a port is open using built-in /dev/tcp feature
check_port() {
    local host=$1
    local port=$2
    local timeout=1
    
    # Use bash's built-in /dev/tcp virtual file
    (echo > /dev/tcp/$host/$port) >/dev/null 2>&1
    return $?
}

# Scan a target's ports
scan_target() {
    local target=$1
    local ports=$2
    local results=""
    
    [[ "$SILENT" = false ]] && echo "Scanning $target..."
    
    # Parse port ranges
    if [[ $ports =~ ^([0-9]+)-([0-9]+)$ ]]; then
        start_port=${BASH_REMATCH[1]}
        end_port=${BASH_REMATCH[2]}
        
        for port in $(seq $start_port $end_port); do
            if check_port "$target" "$port"; then
                [[ "$VERBOSE" = true && "$SILENT" = false ]] && echo "Port $port is open on $target"
                results="${results}${target}:${port}\n"
            fi
        done
    else
        # Handle comma-separated list
        IFS=',' read -ra PORT_LIST <<< "$ports"
        for port in "${PORT_LIST[@]}"; do
            if check_port "$target" "$port"; then
                [[ "$VERBOSE" = true && "$SILENT" = false ]] && echo "Port $port is open on $target"
                results="${results}${target}:${port}\n"
            fi
        done
    fi
    
    echo -en "$results"
}

# Main scanning logic
results=""

if [[ -n "$TARGET" ]]; then
    # Single target
    scan_result=$(scan_target "$TARGET" "$PORTS")
    results="$results$scan_result"
elif [[ -n "$TARGET_FILE" && -f "$TARGET_FILE" ]]; then
    # Multiple targets from file
    while IFS= read -r target || [[ -n "$target" ]]; do
        # Skip empty lines and comments
        [[ -z "$target" || "$target" =~ ^[[:space:]]*# ]] && continue
        
        scan_result=$(scan_target "$target" "$PORTS")
        results="$results$scan_result"
    done < "$TARGET_FILE"
fi

# Output handling
if [[ "$JSON" = true ]]; then
    # Format as JSON
    json_output="["
    first=true
    
    while IFS=: read -r host port || [[ -n "$host" ]]; do
        # Skip empty lines
        [[ -z "$host" || -z "$port" ]] && continue
        
        # Add comma separator if not the first entry
        if [[ "$first" = true ]]; then
            first=false
        else
            json_output="$json_output,"
        fi
        
        json_output="$json_output\n  {\"host\":\"$host\",\"port\":$port,\"protocol\":\"tcp\"}"
    done <<< "$results"
    
    json_output="$json_output\n]"
    
    if [[ -n "$OUTPUT" ]]; then
        echo -e "$json_output" > "$OUTPUT"
    else
        echo -e "$json_output"
    fi
else
    # Simple text output
    if [[ -n "$OUTPUT" ]]; then
        echo -e "$results" > "$OUTPUT"
    else
        echo -e "$results"
    fi
fi

exit 0
EOF
    
    # Make it executable
    chmod +x "$NAABU_ALT_PATH"
    echo -e "${GREEN}Alternative naabu implementation created at $NAABU_ALT_PATH${NC}"
    return 0
}

# Function to install security tools with better error handling
install_security_tools() {
    echo -e "\n${BLUE}[4/7] Installing security tools...${NC}"
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    export GOBIN=$HOME/go/bin
    mkdir -p $GOBIN

    # Check if tools are already installed via apt
    naabu_installed=false
    nuclei_installed=false
    httpx_installed=false
    
    if command -v naabu >/dev/null 2>&1; then
        echo -e "${GREEN}naabu is already installed via system package${NC}"
        naabu_installed=true
    fi
    
    if command -v nuclei >/dev/null 2>&1; then
        echo -e "${GREEN}nuclei is already installed via system package${NC}"
        nuclei_installed=true
    fi
    
    if command -v httpx >/dev/null 2>&1; then
        echo -e "${GREEN}httpx is already installed via system package${NC}"
        httpx_installed=true
    fi
    
    # Install httpx via Go if not already installed
    if [ "$httpx_installed" = false ]; then
        echo -e "\n${BLUE}[+] Installing httpx via Go...${NC}"
        # First check if Go is installed
        if ! command -v go >/dev/null 2>&1; then
            echo "Go is required to install httpx. Installing Go first..."
            install_go
        fi

        # Try installing httpx using Go
        if go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest; then
            echo -e "${GREEN}[+] httpx installed successfully.${NC}"
            httpx_installed=true
        else
            echo -e "${RED}Failed to install httpx via Go. Please check your Go installation or network connection.${NC}"
        fi
    fi
}

# Main script execution

# Check for sudo access
check_sudo

# Step 1: Fix any package manager issues first
fix_dpkg

# Step 2: Install required system packages
install_apt_packages

# Step 3: Install Go if needed
install_go

# Step 4: Install security tools
install_security_tools

# Step 5: Create alternative implementations if needed
if ! command -v naabu >/dev/null 2>&1 && ! [ -f "$HOME/go/bin/naabu" ]; then
    create_naabu_alternative
fi

echo -e "\n${GREEN}=====================================${NC}"
echo -e "${GREEN}✓ Vulnerability toolkit setup complete${NC}"
echo -e "${GREEN}=====================================${NC}"

echo -e "\nYou can now use the toolkit by running:"
echo -e "  python3 workflow.py example.com"
echo -e "  python3 code_scanner.py /path/to/project"

exit 0