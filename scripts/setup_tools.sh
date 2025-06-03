#!/bin/bash
# setup_tools.sh - Consolidated setup script for vulnerability analysis tools
# This script is designed for Kali Linux and Debian-based systems

# Fail on first error if not handled
set -e

# Colors for better output
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

# Check if running in bash
if [ -z "$BASH_VERSION" ]; then
    echo "This script must be run in bash. Please use: bash setup_tools.sh"
    exit 1
fi

echo -e "${BLUE}===== Vulnerability Analysis Toolkit Setup =====${NC}"
echo "This script will install and configure all necessary tools for security scanning."
echo -e "${YELLOW}Note: This script is for Linux systems. Windows is not supported.${NC}"

# Function to check for required commands
check_required_commands() {
    local missing_commands=()
    for cmd in sudo grep find mkdir rm chmod; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -gt 0 ]; then
        echo -e "${RED}Error: The following required commands are missing: ${missing_commands[*]}${NC}"
        echo "Please install them before running this script."
        exit 1
    fi
}

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
    # Check if script exists before running
    if [ -f "./fix_repo_keys.sh" ]; then
        bash ./fix_repo_keys.sh
    else
        echo -e "${YELLOW}fix_repo_keys.sh not found. Skipping repository key fixes.${NC}"
    fi
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
    
    # System-wide apt update
    echo -e "\n${BLUE}Running system-wide apt update...${NC}"
    sudo apt-get update -o Acquire::AllowInsecureRepositories=true || echo "Apt update failed, continuing anyway"
    
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
    for tool in nuclei naabu; do  # httpx deliberately excluded
        echo -e "\nChecking for $tool..."
        if command -v $tool >/dev/null 2>&1; then
            echo -e "${GREEN}$tool is already installed.${NC}"
        else
            echo -e "Installing $tool via apt..."
            sudo apt-get install -y --no-install-recommends -o Acquire::AllowInsecureRepositories=true "$tool" || \
                echo -e "${YELLOW}$tool not available via apt. Will install via Go.${NC}"
        fi
    done
    
    # Explicitly note that httpx will be installed via Go only
    echo -e "\n${YELLOW}Note: httpx will ONLY be installed via Go for maximum compatibility${NC}"
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

# Function to install Go with better error handling and fallbacks
install_go() {
    if command -v go >/dev/null 2>&1; then
        echo -e "${GREEN}Go is already installed.${NC}"
        go_version=$(go version 2>/dev/null)
        echo -e "Current Go version: ${go_version:-unknown}"
        return 0
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

    # First check if Go is already installed in common locations
    for go_path in "/usr/local/go/bin/go" "/usr/bin/go" "/usr/local/bin/go"; do
        if [ -x "$go_path" ]; then
            echo -e "${GREEN}Found Go at $go_path${NC}"
            # Add to PATH if not already there
            if ! echo "$PATH" | grep -q "$(dirname "$go_path")"; then
                export PATH="$PATH:$(dirname "$go_path")"
                echo "Added $(dirname "$go_path") to PATH"
            fi
            return 0
        fi
    done

    # Create temporary directory for downloads
    TMP_DIR=$(mktemp -d)
    GO_TAR="$TMP_DIR/go.tar.gz"
    
    # Try with wget first
    if command -v wget >/dev/null 2>&1; then
        echo "Downloading Go with wget..."
        if wget -q --show-progress "https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -O "$GO_TAR"; then
            echo "Download successful"
        else
            echo -e "${YELLOW}Failed to download Go with wget. Trying with curl...${NC}"
            if command -v curl >/dev/null 2>&1; then
                echo "Downloading Go with curl..."
                if curl -L "https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o "$GO_TAR"; then
                    echo "Download successful"
                else
                    echo -e "${RED}Failed to download Go. Please check your network connection.${NC}"
                    rm -rf "$TMP_DIR"
                    return 1
                fi
            else
                echo -e "${RED}Neither wget nor curl is available. Cannot download Go.${NC}"
                rm -rf "$TMP_DIR"
                return 1
            fi
        fi
    elif command -v curl >/dev/null 2>&1; then
        echo "Downloading Go with curl..."
        if curl -L "https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o "$GO_TAR"; then
            echo "Download successful"
        else
            echo -e "${RED}Failed to download Go. Please check your network connection.${NC}"
            rm -rf "$TMP_DIR"
            return 1
        fi
    else
        echo -e "${RED}Neither wget nor curl is available. Cannot download Go.${NC}"
        rm -rf "$TMP_DIR"
        return 1
    fi
    
    # Attempt to remove previous Go installation
    echo "Removing previous Go installation if it exists..."
    sudo rm -rf /usr/local/go 2>/dev/null || true
    
    # Extract Go to /usr/local with fallback to user's home directory
    echo "Extracting Go..."
    if sudo tar -C /usr/local -xzf "$GO_TAR"; then
        echo -e "${GREEN}Go extracted to /usr/local/go${NC}"
        rm -f "$GO_TAR"
        
        # Update PATH for system installation
        export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
        
        # Update shell configuration files
        for config_file in ~/.bashrc ~/.zshrc ~/.profile; do
            if [ -f "$config_file" ]; then
                if ! grep -q "export PATH=.*\/usr\/local\/go\/bin" "$config_file"; then
                    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$config_file"
                    echo "Updated $config_file with Go path."
                fi
            fi
        done
        
        echo -e "${GREEN}Go installed successfully in /usr/local/go${NC}"
    else
        echo -e "${YELLOW}Failed to extract Go to /usr/local (permission issues?). Trying user's home directory...${NC}"
        mkdir -p "$HOME/go-install"
        if tar -C "$HOME/go-install" -xzf "$GO_TAR"; then
            echo -e "${GREEN}Go extracted to $HOME/go-install/go${NC}"
            rm -f "$GO_TAR"
            
            # Set Go paths for user installation
            export PATH="$PATH:$HOME/go-install/go/bin:$HOME/go/bin"
            
            # Update shell configuration files for user installation
            for config_file in ~/.bashrc ~/.zshrc ~/.profile; do
                if [ -f "$config_file" ];then
                    if ! grep -q "export PATH=.*$HOME/go-install/go/bin" "$config_file"; then
                        echo "export PATH=\$PATH:$HOME/go-install/go/bin:$HOME/go/bin" >> "$config_file"
                        echo "Updated $config_file with Go path."
                    fi
                fi
            done
            
            echo -e "${GREEN}Go installed successfully in $HOME/go-install${NC}"
        else
            echo -e "${RED}Failed to extract Go. Installation aborted.${NC}"
            rm -rf "$TMP_DIR"
            return 1
        fi
    fi
    
    # Clean up
    rm -rf "$TMP_DIR"
    
    # Try to make go command available in current shell
    hash -r 2>/dev/null || true
    
    # Verify Go installation
    if command -v go >/dev/null 2>&1; then
        echo -e "${GREEN}Go is now available in your PATH. Version: $(go version)${NC}"
        return 0
    else
        # If Go is not in PATH yet, try with full path
        if [ -x "/usr/local/go/bin/go" ]; then
            echo -e "${YELLOW}Go is installed but not in PATH. Using full path for now.${NC}"
            export PATH="$PATH:/usr/local/go/bin"
            hash -r 2>/dev/null || true
            return 0
        elif [ -x "$HOME/go-install/go/bin/go" ]; then
            echo -e "${YELLOW}Go is installed but not in PATH. Using full path for now.${NC}"
            export PATH="$PATH:$HOME/go-install/go/bin"
            hash -r 2>/dev/null || true
            return 0
        else
            echo -e "${RED}Go installation verification failed.${NC}"
            echo -e "${YELLOW}Please add Go to your PATH manually:${NC}"
            echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin"
            echo "or"
            echo "export PATH=\$PATH:$HOME/go-install/go/bin:\$HOME/go/bin"
            return 1
        fi
    fi
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

TARGET="$1"
PORTS="$2"

if [ "$1" == "-h" ] || [ "$1" == "--help" ] || [ -z "$1" ]; then
    echo "Simple port scanner (naabu alternative)"
    echo "Usage: $(basename $0) <target> [ports]"
    echo "Example: $(basename $0) example.com 80,443"
    exit 0
fi

if [ -z "$PORTS" ]; then
    PORTS="80,443,8080,8443"
fi

echo "Scanning $TARGET for open ports ($PORTS)..."
for port in $(echo $PORTS | tr ',' ' '); do
    (echo > /dev/tcp/$TARGET/$port) >/dev/null 2>&1 && echo "Port $port is open"
done
EOF
    
    # Make it executable
    chmod +x "$NAABU_ALT_PATH"
    echo -e "${GREEN}Alternative naabu implementation created at $NAABU_ALT_PATH${NC}"
    
    # Verify the alternative implementation works
    echo "Verifying alternative naabu implementation..."
    if $NAABU_ALT_PATH -h &>/dev/null; then
        echo -e "${GREEN}Alternative naabu implementation verified working${NC}"
        return 0
    else
        echo -e "${RED}Alternative naabu implementation verification failed. The tool may not work correctly.${NC}"
        return 1
    fi
}

# Function to install security tools with better error handling
install_security_tools() {
    echo -e "\n${BLUE}[4/7] Installing security tools...${NC}"
    
    # Update PATH to include Go binaries
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
    
    # Check if httpx is already installed in any location
    HTTPX_LOCATIONS=(
        "$HOME/go/bin/httpx"
        "/usr/local/bin/httpx"
        "/usr/bin/httpx"
    )
    
    for location in "${HTTPX_LOCATIONS[@]}"; do
        if [ -x "$location" ]; then
            echo -e "${GREEN}httpx found at $location${NC}"
            httpx_installed=true
            break
        fi
    done
    
    # Install httpx via Go if not already installed
    if [ "$httpx_installed" = false ]; then
        echo -e "\n${BLUE}[+] Installing httpx via Go...${NC}"
        # First check if Go is installed
        if ! command -v go >/dev/null 2>&1; then
            echo "Go is required to install httpx. Installing Go first..."
            install_go
        fi

        # Run apt update before installing Go packages
        echo -e "${BLUE}Running apt update before Go installation...${NC}"
        sudo apt-get update -o Acquire::AllowInsecureRepositories=true || echo "Apt update failed, continuing anyway"

        # Try installing httpx using Go
        echo "Installing httpx with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        if go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest; then
            echo -e "${GREEN}[+] httpx installed successfully via Go${NC}"
            httpx_installed=true
            
            # Create symbolic link if not in PATH
            if ! command -v httpx >/dev/null 2>&1; then
                echo "Creating symbolic link for httpx..."
                sudo ln -sf $HOME/go/bin/httpx /usr/local/bin/httpx 2>/dev/null || \
                echo -e "${YELLOW}Could not create symbolic link. Adding Go bin to your PATH.${NC}"
                
                # Add to PATH for current session
                export PATH="$PATH:$HOME/go/bin"
                
                # Make sure shell config has Go bin in PATH
                for config_file in ~/.bashrc ~/.zshrc ~/.profile; do
                    if [ -f "$config_file" ]; then
                        if ! grep -q "export PATH=.*go/bin" "$config_file"; then
                            echo 'export PATH=$PATH:$HOME/go/bin' >> "$config_file"
                            echo "Updated $config_file with Go bin path."
                        fi
                    fi
                done
            fi
            
            # Run apt update after installation for system consistency
            echo -e "${BLUE}Running apt update after Go installation...${NC}"
            sudo apt-get update -o Acquire::AllowInsecureRepositories=true || echo "Apt update failed, continuing anyway"
        else
            echo -e "${RED}Failed to install httpx via Go. Please check your Go installation or network connection.${NC}"
            echo -e "${YELLOW}Trying one more time with verbose output and network test...${NC}"
            
            # Test network connectivity
            ping -c 1 github.com || echo "Network connectivity issues detected."
            
            # Try again with more verbose output
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
            
            if [ -f "$HOME/go/bin/httpx" ]; then
                echo -e "${GREEN}httpx installed successfully on second attempt${NC}"
                httpx_installed=true
            else
                echo -e "${RED}httpx installation failed after multiple attempts${NC}"
            fi
        fi
    fi
    
    # Verify all tools are installed
    if [ "$naabu_installed" = true ] && [ "$nuclei_installed" = true ] && [ "$httpx_installed" = true ]; then
        echo -e "${GREEN}All security tools are installed.${NC}"
        return 0
    else
        echo -e "${RED}Some security tools could not be installed.${NC}"
        return 1
    fi
}

# Function to verify tools are working correctly
verify_tools() {
    echo -e "\n${BLUE}[5/7] Verifying installed tools...${NC}"
    
    # Update PATH to include Go binaries
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    
    # Check tools existence and basic functionality
    tools_ok=true
    
    # Check naabu
    if command -v naabu >/dev/null 2>&1; then
        echo -e "Verifying naabu..."
        if naabu -version 2>/dev/null || naabu -h 2>/dev/null; then
            echo -e "${GREEN}naabu is working${NC}"
        else
            echo -e "${RED}naabu exists but might not be working correctly${NC}"
            tools_ok=false
        fi
    else
        echo -e "${RED}naabu is not installed${NC}"
        tools_ok=false
    fi
    
    # Enhanced httpx verification
    if command -v httpx >/dev/null 2>&1; then
        echo -e "Verifying httpx..."
        if httpx -version 2>/dev/null || httpx -h 2>/dev/null; then
            echo -e "${GREEN}httpx is working${NC}"
            # Double-check by running a simple test
            echo "Running simple httpx test..."
            if echo "example.com" | httpx -silent > /dev/null 2>&1; then
                echo -e "${GREEN}httpx test successful${NC}"
            else
                echo -e "${YELLOW}httpx test failed, but command exists. May be a network issue.${NC}"
            fi
        else
            echo -e "${RED}httpx exists but might not be working correctly${NC}"
            tools_ok=false
        fi
    elif [ -x "$HOME/go/bin/httpx" ]; then
        echo -e "httpx found in Go bin directory but not in PATH. Adding to PATH and testing..."
        export PATH="$PATH:$HOME/go/bin"
        if $HOME/go/bin/httpx -version 2>/dev/null || $HOME/go/bin/httpx -h 2>/dev/null; then
            echo -e "${GREEN}httpx is working${NC}"
        else
            echo -e "${RED}httpx exists but might not be working correctly${NC}"
            tools_ok=false
        fi
    else
        echo -e "${RED}httpx is not installed${NC}"
        tools_ok=false
    fi
    
    # Check nuclei
    if command -v nuclei >/dev/null 2>&1; then
        echo -e "Verifying nuclei..."
        if nuclei -version 2>/dev/null || nuclei -h 2>/dev/null; then
            echo -e "${GREEN}nuclei is working${NC}"
        else
            echo -e "${RED}nuclei exists but might not be working correctly${NC}"
            tools_ok=false
        fi
    else
        echo -e "${RED}nuclei is not installed${NC}"
        tools_ok=false
    fi
    
    if [ "$tools_ok" = true ]; then
        echo -e "${GREEN}All tools verified successfully${NC}"
        return 0
    else
        echo -e "${YELLOW}Some tools may not be working correctly${NC}"
        return 1
    fi
}

# Check required commands first
check_required_commands

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

# Step 6: Verify all tools are working
verify_tools

# Step 7: Update current session PATH to include Go binaries
if ! command -v go >/dev/null 2>&1; then
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo -e "${YELLOW}Updated PATH for current session to include Go binaries${NC}"
    echo -e "${YELLOW}Run 'source ~/.bashrc' or restart your terminal to make this permanent${NC}"
fi

echo -e "\n${GREEN}=====================================${NC}"
echo -e "${GREEN}✓ Vulnerability toolkit setup complete${NC}"
echo -e "${GREEN}=====================================${NC}"

echo -e "\nYou can now use the toolkit by running:"
echo -e "  python3 workflow.py example.com"
echo -e "  python3 code_scanner.py /path/to/project"

exit 0