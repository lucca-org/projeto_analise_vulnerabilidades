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
echo -e "${YELLOW}Note: This script is for Linux systems. Windows users should use index.py${NC}"

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
    echo -e "\n${BLUE}[1/7] Checking for and fixing any package manager issues...${NC}"
    sudo dpkg --configure -a || echo "Failed to configure dpkg. Continuing anyway."
    sudo apt-get update --fix-missing -y || echo "Failed to update package lists. Continuing anyway."
    sudo apt-get install -f -y || echo "Failed to fix broken packages. Continuing anyway."
    sudo apt-get clean || echo "Failed to clean package cache. Continuing anyway."
}

# Function to install apt packages
install_apt_packages() {
    echo -e "\n${BLUE}[2/7] Installing required system packages...${NC}"
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
    json_output="[
    "
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

# Function to install security tools
install_security_tools() {
    echo -e "\n${BLUE}[4/7] Installing security tools...${NC}"
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
    
    # If naabu couldn't be installed, create the alternative implementation
    if [ "$naabu_installed" = false ]; then
        create_naabu_alternative
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
    echo -e "\n${BLUE}[5/7] Installing Python dependencies...${NC}"
    
    if [ ! -f "requirements.txt" ]; then
        echo "Creating requirements.txt..."
        cat > requirements.txt << EOF
requests>=2.28.0
colorama>=0.4.6
markdown>=3.4.3
jinja2>=3.1.2
rich>=13.3.2
tqdm>=4.65.0
pathlib>=1.0.1
jsonschema>=4.19.0
pyyaml>=6.0.1
EOF
    fi
    
    # Try with pip3 first
    if command -v pip3 >/dev/null 2>&1; then
        pip3 install -r requirements.txt || {
            echo "Warning: Failed to install some Python dependencies. Continuing anyway."
        }
        
        # Ensure markdown is installed for reporting
        pip3 install markdown || {
            echo "Warning: Failed to install markdown. Advanced reports may not work properly."
        }
    # Fall back to pip
    elif command -v pip >/dev/null 2>&1; then
        pip install -r requirements.txt || {
            echo "Warning: Failed to install some Python dependencies. Continuing anyway."
        }
        
        # Ensure markdown is installed for reporting
        pip install markdown || {
            echo "Warning: Failed to install markdown. Advanced reports may not work properly."
        }
    else
        echo "Warning: pip not found. Cannot install Python dependencies."
    fi
    
    echo "Python dependencies installed."
}

# Update nuclei templates
update_nuclei_templates() {
    echo -e "\n${BLUE}[6/7] Updating nuclei templates...${NC}"
    
    if command -v nuclei >/dev/null 2>&1; then
        nuclei -update-templates || {
            echo "Warning: Failed to update nuclei templates. Continuing anyway."
        }
    else
        # Check in ~/go/bin
        if [ -f "$HOME/go/bin/nuclei" ]; then
            $HOME/go/bin/nuclei -update-templates || {
                echo "Warning: Failed to update nuclei templates. Continuing anyway."
            }
        else
            echo "Warning: nuclei not found. Cannot update templates."
        fi
    fi
}

# Create Python command modules
create_command_modules() {
    echo -e "\n${BLUE}[7/7] Creating Python command modules...${NC}"
    
    # Create commands directory
    mkdir -p commands
    
    # Create __init__.py
    cat > commands/__init__.py << EOF
# This file makes the commands directory a proper Python package
__all__ = ["naabu", "httpx", "nuclei"]
EOF
    
    # Create module template
    MODULE_TEMPLATE=$(cat << 'EOF'
#!/usr/bin/env python3
import os
import subprocess
import json
from pathlib import Path
import shutil

def run_{tool}(*args, **kwargs):
    """Run {tool} with provided arguments."""
    # Find the tool path
    tool_path = shutil.which("{tool}")
    if not tool_path:
        # Check in ~/go/bin
        go_bin_path = os.path.expanduser("~/go/bin/{tool}")
        if os.path.exists(go_bin_path):
            tool_path = go_bin_path
        else:
            print(f"{tool} not found in PATH or ~/go/bin")
            return False
    
    cmd = [tool_path]
    
    for arg in args:
        cmd.append(str(arg))
    
    for key, value in kwargs.items():
        key = key.replace("_", "-")
        if value is True:
            cmd.append(f"-{key}")
        elif value is not False and value is not None:
            cmd.append(f"-{key}")
            cmd.append(str(value))
    
    try:
        print(f"Running: " + " ".join(cmd))
        process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, text=True)
        if process.stdout:
            print(process.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running {tool}: {e}")
        if e.stderr:
            print(e.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error running {tool}: {e}")
        return False

def check_{tool}():
    """Check if {tool} is installed."""
    try:
        # First check in PATH
        tool_path = shutil.which("{tool}")
        if not tool_path:
            # Check in ~/go/bin
            go_bin_path = os.path.expanduser("~/go/bin/{tool}")
            if os.path.exists(go_bin_path):
                tool_path = go_bin_path
            else:
                print(f"{tool} not found")
                return False
        
        process = subprocess.run([tool_path, "-version"], 
                               capture_output=True, text=True)
        print(f"{tool} version: {process.stdout.strip()}")
        return True
    except Exception as e:
        print(f"Error checking {tool}: {e}")
        return False
EOF
)

    # Create module files
    for tool in naabu httpx nuclei; do
        if [ ! -f "commands/${tool}.py" ]; then
            echo "Creating commands/${tool}.py..."
            echo "${MODULE_TEMPLATE}" | sed "s/{tool}/${tool}/g" > "commands/${tool}.py"
            chmod +x "commands/${tool}.py"
        fi
    done
    
    echo "Command modules created successfully."
}

# Main function
main() {
    echo -e "${BLUE}=== Starting security tools installation ===${NC}"
    
    check_sudo
    fix_dpkg
    install_apt_packages
    install_go
    install_security_tools
    install_python_dependencies
    update_nuclei_templates
    create_command_modules
    
    echo -e "\n${GREEN}=== Installation completed successfully! ===${NC}"
    echo -e "${BLUE}[+] Please run 'source ~/.bashrc' or start a new terminal to update your PATH.${NC}"
    echo -e "${BLUE}[+] You can now run 'python workflow.py example.com' to start scanning.${NC}"
}

# Run the main function
main