#!/bin/bash
# easy_install.sh - Simple installer for vulnerability analysis tools
#
# This script provides a streamlined installation process for Kali/Debian systems
# that avoids the common issues with dpkg, libpcap, and other dependencies.

set -e
echo "===== Starting Easy Installer for Vulnerability Analysis Tools ====="

# First fix dpkg if needed
echo "Fixing any interrupted dpkg issues..."
sudo dpkg --configure -a
sudo apt-get update --fix-missing
sudo apt-get install -f
sudo apt-get clean
sudo apt-get update

# Install basic dependencies
echo "Installing basic dependencies..."
sudo apt-get install -y build-essential python3 python3-pip python3-venv

# Install port scanning alternatives
echo "Installing port scanners..."
sudo apt-get install -y nmap masscan
if command -v snap &> /dev/null; then
    sudo snap install rustscan
else
    echo "Skipping rustscan installation (snap not available)"
fi

# Install Go (manually to avoid package manager issues)
echo "Installing Go..."
GO_VERSION="1.21.0"
ARCH=$(uname -m)

if [ "$ARCH" == "x86_64" ]; then
    GOARCH="amd64"
elif [ "$ARCH" == "aarch64" ] || [ "$ARCH" == "arm64" ]; then
    GOARCH="arm64"
elif [ "$ARCH" == "armv7l" ]; then
    GOARCH="armv6l"
else
    GOARCH="amd64"  # Default
fi

wget -q https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz -O /tmp/go.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
rm /tmp/go.tar.gz

# Update PATH
GO_PATH=$(echo $HOME/go/bin)
USR_LOCAL_GO_PATH="/usr/local/go/bin"

# Add to current session
export PATH=$PATH:$GO_PATH:$USR_LOCAL_GO_PATH

# Add to shell rc file
SHELL_RC="$HOME/.bashrc"
if [ -n "$SHELL" ]; then
    if [[ "$SHELL" == */zsh ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ "$SHELL" == */bash ]]; then
        SHELL_RC="$HOME/.bashrc"
    fi
fi

if ! grep -q "$GO_PATH" "$SHELL_RC"; then
    echo "export PATH=\$PATH:$GO_PATH:$USR_LOCAL_GO_PATH" >> "$SHELL_RC"
    echo "Updated PATH in $SHELL_RC"
fi

# Install Python packages in a virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv ./.venv
source ./.venv/bin/activate
pip install requests colorama rich tqdm

# Install ProjectDiscovery tools (without CGO for naabu)
echo "Installing security tools..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install naabu alternative
echo "Creating naabu alternative script..."
cat > "$HOME/go/bin/naabu" << 'EOF'
#!/bin/bash
# naabu alternative script that uses other port scanners
# Usage: naabu -host example.com -p 80,443,8080-8090

# Parse arguments
TARGET=""
PORTS="1-1000"
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case $1 in
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
        *)
            shift
            ;;
    esac
done

if [ -z "$TARGET" ] && [ -z "$TARGET_FILE" ]; then
    echo "Error: No target specified. Use -host or -l."
    exit 1
fi

# Determine which scanner to use
if command -v rustscan &> /dev/null; then
    echo "Using rustscan for port scanning..."
    if [ -n "$TARGET" ]; then
        if [ -n "$OUTPUT" ]; then
            rustscan -a "$TARGET" -p "$PORTS" -g | tee "$OUTPUT"
        else
            rustscan -a "$TARGET" -p "$PORTS" -g
        fi
    elif [ -n "$TARGET_FILE" ]; then
        if [ -n "$OUTPUT" ]; then
            cat "$TARGET_FILE" | while read host; do
                rustscan -a "$host" -p "$PORTS" -g >> "$OUTPUT"
            done
        else
            cat "$TARGET_FILE" | while read host; do
                rustscan -a "$host" -p "$PORTS" -g
            done
        fi
    fi
elif command -v masscan &> /dev/null; then
    echo "Using masscan for port scanning..."
    if [ -n "$TARGET" ]; then
        if [ -n "$OUTPUT" ]; then
            sudo masscan "$TARGET" -p "$PORTS" -oL "$OUTPUT"
        else
            sudo masscan "$TARGET" -p "$PORTS"
        fi
    elif [ -n "$TARGET_FILE" ]; then
        if [ -n "$OUTPUT" ]; then
            cat "$TARGET_FILE" | while read host; do
                sudo masscan "$host" -p "$PORTS" -oL "$OUTPUT"
            done
        else
            cat "$TARGET_FILE" | while read host; do
                sudo masscan "$host" -p "$PORTS"
            done
        fi
    fi
else
    echo "Using nmap for port scanning..."
    if [ -n "$TARGET" ]; then
        if [ -n "$OUTPUT" ]; then
            nmap -T4 -p "$PORTS" "$TARGET" -oN "$OUTPUT"
        else
            nmap -T4 -p "$PORTS" "$TARGET"
        fi
    elif [ -n "$TARGET_FILE" ]; then
        if [ -n "$OUTPUT" ]; then
            nmap -T4 -p "$PORTS" -iL "$TARGET_FILE" -oN "$OUTPUT"
        else
            nmap -T4 -p "$PORTS" -iL "$TARGET_FILE"
        fi
    fi
fi
EOF
chmod +x "$HOME/go/bin/naabu"

# Update nuclei templates
echo "Updating nuclei templates..."
nuclei -update-templates

echo "===== Installation Complete! ====="
echo "Available tools:"
echo "- httpx: For probing and analyzing HTTP services"
echo "- nuclei: For vulnerability scanning"
echo "- subfinder: For subdomain discovery"
echo "- naabu: Alternative script using nmap/masscan/rustscan"
echo
echo "Please run: source $SHELL_RC or restart your terminal to update PATH."
echo "To start scanning, try: python3 workflow.py example.com"