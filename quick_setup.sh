#!/bin/bash
# quick_setup.sh - Bypass system package manager entirely and set up tools

set -e
echo "===== Fast Vulnerability Analysis Tools Setup ====="
echo "(This script bypasses the system package manager completely)"

# Create directories
mkdir -p ~/security_tools/bin
mkdir -p ~/.local/bin
mkdir -p ~/go/bin

# Add to PATH
export PATH=$PATH:~/security_tools/bin:~/.local/bin:~/go/bin

# Install Go manually
GO_VERSION=1.21.0
if ! command -v go >/dev/null 2>&1; then
    echo "Installing Go..."
    wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    export PATH=$PATH:/usr/local/go/bin
    
    # Update shell rc files
    for rc_file in ~/.bashrc ~/.zshrc ~/.profile; do
        if [ -f "$rc_file" ]; then
            echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> "$rc_file"
        fi
    done
else
    echo "Go is already installed"
fi

# Install tools directly with Go
echo "Installing required tools..."
GOBIN=~/go/bin go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
GOBIN=~/go/bin go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
GOBIN=~/go/bin go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Create alternatives for tools that might fail to install
cat > ~/go/bin/naabu << 'EOF'
#!/bin/bash
# naabu alternative script using nmap or netcat
set -e

TARGET=""
TARGET_FILE=""
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

if [[ -z "$TARGET" && -z "$TARGET_FILE" ]]; then
    echo "Error: No target specified. Use -host or -l."
    exit 1
fi

if command -v nmap >/dev/null 2>&1; then
    echo "Using nmap for port scanning..."
    if [[ -n "$TARGET" ]]; then
        if [[ -n "$OUTPUT" ]]; then
            nmap -T4 -p "$PORTS" "$TARGET" | grep -E "^[0-9]+/tcp.*open" | sed "s#/tcp.*#:$TARGET#" | awk '{print $2":"$1}' > "$OUTPUT"
            echo "Results saved to $OUTPUT"
        else
            nmap -T4 -p "$PORTS" "$TARGET" | grep -E "^[0-9]+/tcp.*open" | awk '{print "'$TARGET':"$1}' | sed 's#/tcp.*##'
        fi
    elif [[ -n "$TARGET_FILE" ]]; then
        if [[ -n "$OUTPUT" ]]; then
            nmap -T4 -p "$PORTS" -iL "$TARGET_FILE" | grep -E "^[0-9]+/tcp.*open" | awk '{print "'$TARGET':"$1}' | sed 's#/tcp.*##' > "$OUTPUT"
            echo "Results saved to $OUTPUT"
        else
            nmap -T4 -p "$PORTS" -iL "$TARGET_FILE" | grep -E "^[0-9]+/tcp.*open" | awk '{print "'$TARGET':"$1}' | sed 's#/tcp.*##'
        fi
    fi
else
    echo "Warning: nmap not found, port scanning will be limited"
    # Implement basic scanning with nc if available
fi
EOF
chmod +x ~/go/bin/naabu

# Update nuclei templates
echo "Updating nuclei templates..."
nuclei -update-templates 2>/dev/null || echo "Nuclei templates will update on first run"

echo "===== Setup Complete ====="
echo "Available tools:"
echo "- httpx: HTTP/HTTPS service analyzer"
echo "- nuclei: Vulnerability scanner" 
echo "- subfinder: Subdomain discovery tool"
echo "- naabu: Port scanner (alternative version using nmap)"
echo ""
echo "Run 'source ~/.bashrc' (or .zshrc) or open a new terminal to access tools"
echo ""
echo "To scan a target: python3 workflow.py example.com"