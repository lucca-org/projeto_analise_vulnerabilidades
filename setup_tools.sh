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

# Function to fix any dpkg issues
fix_dpkg() {
    echo -e "\n${BLUE}[+] Checking for and fixing any package manager issues...${NC}"
    sudo dpkg --configure -a || echo "Failed to configure dpkg. Continuing anyway."
    sudo apt-get update --fix-missing -y || echo "Failed to update package lists. Continuing anyway."
    sudo apt-get install -f -y || echo "Failed to fix broken packages. Continuing anyway."
    sudo apt-get clean || echo "Failed to clean package cache. Continuing anyway."
}

# Function to install apt packages
install_apt_packages() {
    echo -e "\n${BLUE}[+] Installing required system packages...${NC}"
    sudo apt-get update || { echo "Failed to update apt repositories. Continuing anyway."; }
    
    # Essential packages
    sudo apt-get install -y \
        curl wget git python3 python3-pip libpcap-dev \
        build-essential || \
        echo "Warning: Some packages failed to install. Continuing anyway."
    
    # Try to install security tools via apt
    sudo apt-get install -y nuclei naabu httpx || \
        echo "Some security tools not available via apt. Will install via Go."
}

# Function to install Go
install_go() {
    if command -v go >/dev/null 2>&1; then
        echo -e "${GREEN}Go is already installed.${NC}"
        return
    }

    echo -e "\n${BLUE}[+] Installing Go...${NC}"
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
            fi
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

# Function to install security tools
install_security_tools() {
    echo -e "\n${BLUE}[+] Installing security tools...${NC}"
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    export GOBIN=$HOME/go/bin
    mkdir -p $GOBIN

    # Check if tools are already installed via apt
    naabu_installed=false
    nuclei_installed=false
    
    if command -v naabu >/dev/null 2>&1; then
        echo -e "${GREEN}naabu is already installed via system package${NC}"
        naabu_installed=true
    fi
    
    if command -v nuclei >/dev/null 2>&1; then
        echo -e "${GREEN}nuclei is already installed via system package${NC}"
        nuclei_installed=true
    fi
    
    # Try to install via apt if not installed
    if [ "$naabu_installed" = false ]; then
        echo -e "\n${BLUE}Trying to install naabu via apt...${NC}"
        if sudo apt-get install -y naabu; then
            echo -e "${GREEN}Successfully installed naabu via apt${NC}"
            naabu_installed=true
        else
            echo -e "${YELLOW}Could not install naabu via apt, will try Go installation${NC}"
        fi
    fi
    
    if [ "$nuclei_installed" = false ]; then
        echo -e "\n${BLUE}Trying to install nuclei via apt...${NC}"
        if sudo apt-get install -y nuclei; then
            echo -e "${GREEN}Successfully installed nuclei via apt${NC}"
            nuclei_installed=true
        else
            echo -e "${YELLOW}Could not install nuclei via apt, will try Go installation${NC}"
        fi
    fi

    # Install httpx via Go (not typically available via apt)
    if ! command -v httpx >/dev/null 2>&1; then
        echo -e "\n${BLUE}[+] Installing httpx via Go...${NC}"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || {
            echo -e "${RED}[-] Failed to install httpx.${NC}"
            return 1
        }
        echo -e "${GREEN}[+] httpx installed successfully.${NC}"
    else
        echo -e "${GREEN}[+] httpx is already installed${NC}"
    fi
    
    # Install nuclei via Go if not installed via apt
    if [ "$nuclei_installed" = false ]; then
        echo -e "\n${BLUE}[+] Installing nuclei via Go...${NC}"
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || {
            echo -e "${RED}[-] Failed to install nuclei via Go.${NC}"
            return 1
        }
        echo -e "${GREEN}[+] nuclei installed successfully via Go.${NC}"
    fi
    
    # Install naabu via Go if not installed via apt
    if [ "$naabu_installed" = false ]; then
        echo -e "\n${BLUE}[+] Installing naabu via Go...${NC}"
        # Set CGO_ENABLED=0 to avoid libpcap dependency
        export CGO_ENABLED=0
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || {
            echo -e "${RED}[-] Failed to install naabu via Go.${NC}"
            return 1
        }
        echo -e "${GREEN}[+] naabu installed successfully via Go.${NC}"
    fi
    
    # Validate installations
    echo -e "\n${BLUE}[+] Validating installations...${NC}"
    
    for tool in httpx nuclei naabu; do
        if command -v $tool >/dev/null 2>&1; then
            version=$($tool -version 2>/dev/null || echo "Unknown")
            echo -e "${GREEN}[+] $tool is installed: $version${NC}"
        else
            # Check in ~/go/bin
            if [ -f "$HOME/go/bin/$tool" ]; then
                version=$($HOME/go/bin/$tool -version 2>/dev/null || echo "Unknown")
                echo -e "${GREEN}[+] $tool is installed in ~/go/bin: $version${NC}"
            else
                echo -e "${RED}[-] $tool installation validation failed${NC}"
                return 1
            fi
        fi
    done
    
    echo -e "\n${GREEN}[+] Security tools installation completed${NC}"
    return 0
}

# Install Python dependencies
install_python_dependencies() {
    echo -e "\n${BLUE}[+] Installing Python dependencies...${NC}"
    
    if [ ! -f "requirements.txt" ]; then
        echo "Creating requirements.txt..."
        cat > requirements.txt << EOF
requests>=2.28.0
colorama>=0.4.6
jinja2>=3.1.2
markdown>=3.4.1
rich>=13.3.2
tqdm>=4.65.0
EOF
    fi
    
    # Try with pip3 first
    if command -v pip3 >/dev/null 2>&1; then
        pip3 install -r requirements.txt || {
            echo "Warning: Failed to install some Python dependencies. Continuing anyway."
        }
    # Fall back to pip
    elif command -v pip >/dev/null 2>&1; then
        pip install -r requirements.txt || {
            echo "Warning: Failed to install some Python dependencies. Continuing anyway."
        }
    else
        echo "Warning: pip not found. Cannot install Python dependencies."
    fi
    
    echo "Python dependencies installed."
}

# Update nuclei templates
update_nuclei_templates() {
    echo -e "\n${BLUE}[+] Updating nuclei templates...${NC}"
    
    if command -v nuclei >/dev/null 2>&1; then
        nuclei -update-templates || {
            echo "Warning: Failed to update nuclei templates. Continuing anyway."
        }
    else
        echo "Warning: nuclei not found. Cannot update templates."
    fi
}

# Main function
main() {
    echo -e "${BLUE}[+] Starting security tools installation...${NC}"
    
    check_sudo
    fix_dpkg
    install_apt_packages
    install_go
    install_security_tools
    install_python_dependencies
    update_nuclei_templates
    
    echo -e "\n${GREEN}[+] Installation completed successfully!${NC}"
    echo -e "${BLUE}[+] Please run 'source ~/.bashrc' or start a new terminal to update your PATH.${NC}"
    echo -e "${BLUE}[+] You can now run 'python workflow.py example.com' to start scanning.${NC}"
}

# Run the main function
main