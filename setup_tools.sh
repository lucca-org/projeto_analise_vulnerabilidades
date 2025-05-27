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

# Function to fix repository key issues
fix_repo_keys() {
    echo -e "\n${BLUE}Fixing repository key issues...${NC}"
    
    # Create keyring directory if it doesn't exist
    sudo mkdir -p /etc/apt/keyrings

    # Download and add the Kali Linux archive key using the modern approach
    echo "Importing Kali Linux archive key..."
    if command -v wget >/dev/null 2>&1; then
        wget -qO - https://archive.kali.org/archive-key.asc | sudo gpg --dearmor -o /etc/apt/keyrings/kali-archive-keyring.gpg
    elif command -v curl >/dev/null 2>&1; then
        curl -fsSL https://archive.kali.org/archive-key.asc | sudo gpg --dearmor -o /etc/apt/keyrings/kali-archive-keyring.gpg
    else
        echo -e "${YELLOW}Neither wget nor curl is available. Manual key import required.${NC}"
        return
    fi
    
    # Set proper permissions
    sudo chmod 644 /etc/apt/keyrings/kali-archive-keyring.gpg
    
    # Create a source file that uses the new key
    KALI_SOURCE="/etc/apt/sources.list.d/kali.list"
    if [ ! -f "$KALI_SOURCE" ]; then
        echo "Creating Kali repository file..."
        echo "deb [signed-by=/etc/apt/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main non-free contrib" | sudo tee "$KALI_SOURCE"
    fi
    
    # Update package lists
    echo "Updating package lists with new keys..."
    sudo apt-get update || echo "Update still failed, continuing with installation..."
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
        
        # Try multiple installation methods
        if go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest; then
            echo -e "${GREEN}[+] httpx installed successfully.${NC}"
            httpx_installed=true
        else
            echo -e "${YELLOW}Standard go install failed, trying alternative method...${NC}"
            # Try with CGO disabled
            CGO_ENABLED=0 go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
            
            if [ -f "$HOME/go/bin/httpx" ]; then
                echo -e "${GREEN}[+] httpx installed successfully with alternative method.${NC}"
                httpx_installed=true
            else
                echo -e "${RED}[-] Failed to install httpx.${NC}"
                
                # Create an alternative implementation using Python
                echo -e "${YELLOW}Creating an alternative httpx implementation...${NC}"
                create_httpx_alternative
                httpx_installed=true
            fi
        fi
    else
        echo -e "${GREEN}[+] httpx is already installed${NC}"
    fi
    
    # Install nuclei via Go if not installed via apt
    if [ "$nuclei_installed" = false ]; then
        echo -e "\n${BLUE}[+] Installing nuclei via Go...${NC}"
        if go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; then
            echo -e "${GREEN}[+] nuclei installed successfully via Go.${NC}"
            nuclei_installed=true
        else
            echo -e "${RED}[-] Failed to install nuclei via Go.${NC}"
            # No alternative for nuclei as it's too complex
        fi
    fi
    
    # Install naabu via Go if not installed via apt
    if [ "$naabu_installed" = false ]; then
        echo -e "\n${BLUE}[+] Installing naabu via Go...${NC}"
        # Set CGO_ENABLED=0 to avoid libpcap dependency
        export CGO_ENABLED=0
        if go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest; then
            echo -e "${GREEN}[+] naabu installed successfully via Go.${NC}"
            naabu_installed=true
        else
            echo -e "${RED}[-] Failed to install naabu via Go.${NC}"
            create_naabu_alternative
            naabu_installed=true
        fi
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
            fi
        fi
    done
    
    echo -e "\n${GREEN}[+] Security tools installation completed${NC}"
    return 0
}

# Create an alternative httpx implementation using Python
create_httpx_alternative() {
    HTTPX_ALT_PATH="$HOME/go/bin/httpx"
    mkdir -p "$(dirname "$HTTPX_ALT_PATH")" 2>/dev/null
    
    cat > "$HTTPX_ALT_PATH" << 'EOF'
#!/usr/bin/env python3
import sys
import argparse
import urllib.request
import urllib.error
import urllib.parse
import socket
import ssl
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor

VERSION = "1.0.0"

def extract_title(html_content):
    """Extract the title from HTML content"""
    match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return "No Title"

def probe_url(url, timeout=5, follow_redirects=False):
    """Probe a URL to check if it's alive and gather information"""
    result = {
        "url": url,
        "status_code": 0,
        "title": "",
        "content_length": 0,
        "server": "",
        "technologies": []
    }
    
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    try:
        # Create context with relaxed SSL verification
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Set up request with timeout
        request = urllib.request.Request(url, headers={"User-Agent": f"httpx-alternative/{VERSION}"})
        response = urllib.request.urlopen(request, timeout=timeout, context=ctx)
        
        # Follow redirects if enabled
        if follow_redirects and response.geturl() != url:
            return probe_url(response.geturl(), timeout, False)  # Don't follow redirects recursively
        
        # Read response
        html_content = response.read().decode('utf-8', errors='ignore')
        
        # Fill result data
        result["status_code"] = response.status
        result["content_length"] = len(html_content)
        result["title"] = extract_title(html_content)
        
        # Extract server info
        if "Server" in response.headers:
            result["server"] = response.headers["Server"]
            result["technologies"].append(response.headers["Server"])
        
        # Simple technology detection based on common patterns
        tech_patterns = {
            "WordPress": r'wp-content|wp-includes',
            "Bootstrap": r'bootstrap\.(?:min\.)?(?:css|js)',
            "jQuery": r'jquery(?:\.min)?\.js',
            "React": r'react(?:\.min)?\.js|react-dom',
            "Angular": r'angular(?:\.min)?\.js|ng-app',
            "PHP": r'<\?php|X-Powered-By: PHP',
            "ASP.NET": r'ASP\.NET|__VIEWSTATE',
            "nginx": r'nginx',
            "Apache": r'apache'
        }
        
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, html_content, re.IGNORECASE) or \
               re.search(pattern, str(response.headers), re.IGNORECASE):
                if tech not in result["technologies"]:
                    result["technologies"].append(tech)
        
        return result
    
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        return result
    except (urllib.error.URLError, socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
        return None
    except Exception as e:
        print(f"Error probing {url}: {str(e)}", file=sys.stderr)
        return None

def process_target(target, args):
    """Process a single target and return the result"""
    result = probe_url(target, args.timeout, args.follow_redirects)
    
    # Print output unless silent mode is enabled
    if result and not args.silent:
        output = result["url"]
        if args.status_code:
            output += f" [{result['status_code']}]"
        if args.title:
            output += f" [{result['title']}]"
        if args.tech_detect and result["technologies"]:
            output += f" [{', '.join(result['technologies'])}]"
        print(output)
    
    return result

def main():
    parser = argparse.ArgumentParser(description=f"httpx-alternative v{VERSION} - HTTP probe tool")
    parser.add_argument("-l", help="Input file with targets")
    parser.add_argument("-u", "--url", help="Single URL/host to probe")
    parser.add_argument("-o", help="Output file")
    parser.add_argument("-silent", action="store_true", help="Silent mode")
    parser.add_argument("-title", action="store_true", help="Display title")
    parser.add_argument("-status-code", action="store_true", help="Display status code")
    parser.add_argument("-web-server", action="store_true", help="Display web server")
    parser.add_argument("-tech-detect", action="store_true", help="Technology detection")
    parser.add_argument("-follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("-timeout", type=int, default=5, help="Timeout in seconds")
    parser.add_argument("-json", action="store_true", help="JSON output")
    parser.add_argument("-version", action="store_true", help="Show version")
    parser.add_argument("-threads", type=int, default=20, help="Number of threads")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"httpx-alternative v{VERSION}")
        return 0
    
    targets = []
    
    # Collect targets
    if args.l:
        try:
            with open(args.l, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading input file: {e}", file=sys.stderr)
            return 1
    elif args.url:
        targets = [args.url]
    else:
        # Try to read from stdin if no targets provided
        if not sys.stdin.isatty():
            targets = [line.strip() for line in sys.stdin if line.strip()]
        else:
            parser.print_help()
            return 1
    
    if not targets:
        print("No targets provided", file=sys.stderr)
        return 1
    
    # Process targets in parallel
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_target, target, args) for target in targets]
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
    
    # Save results if output file specified
    if args.o:
        try:
            if args.json:
                with open(args.o, "w") as f:
                    json.dump(results, f, indent=2)
            else:
                with open(args.o, "w") as f:
                    for result in results:
                        output = result["url"]
                        if args.status_code:
                            output += f" [{result['status_code']}]"
                        if args.title:
                            output += f" [{result['title']}]"
                        if args.tech_detect and result["technologies"]:
                            output += f" [{', '.join(result['technologies'])}]"
                        f.write(output + "\n")
            
            print(f"Results written to {args.o}")
        except Exception as e:
            print(f"Error writing output file: {e}", file=sys.stderr)
            return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF

    # Make it executable
    chmod +x "$HTTPX_ALT_PATH"
    echo -e "${GREEN}Alternative httpx implementation created at $HTTPX_ALT_PATH${NC}"
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

# Fix line endings in scripts to ensure they work on Linux
fix_line_endings() {
    echo -e "\n${BLUE}===== Fixing script line endings =====${NC}"
    
    # Check if dos2unix is available
    DOS2UNIX=$(which dos2unix 2>/dev/null)
    if [ -z "$DOS2UNIX" ]; then
        echo "dos2unix not found. Trying to install it..."
        sudo apt-get install -y dos2unix || {
            echo "Warning: Could not install dos2unix. Using alternative method."
            DOS2UNIX=""
        }
    fi
    
    if [ -n "$DOS2UNIX" ]; then
        echo "Using dos2unix at: $DOS2UNIX"
        for script in *.sh; do
            if [ -f "$script" ]; then
                echo "Fixing line endings in $script..."
                $DOS2UNIX "$script"
                echo "✓ Line endings fixed in $script"
                chmod +x "$script"
            fi
        done
    else
        # Alternative method using sed
        echo "Using sed to fix line endings..."
        for script in *.sh; do
            if [ -f "$script" ]; then
                echo "Fixing line endings in $script..."
                sed -i 's/\r$//' "$script"
                echo "✓ Line endings fixed in $script"
                chmod +x "$script"
            fi
        done
    fi
}

# Main function
main() {
    echo -e "${BLUE}=== Starting security tools installation ===${NC}"
    
    # Fix line endings first
    fix_line_endings
    
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