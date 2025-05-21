#!/bin/bash
# manual_install.sh - Installs security tools directly without using apt
# This script bypasses dpkg for dependencies that are causing problems

set -e
echo "===== Manual Installation for Security Tools ====="

# Install Go directly if not already installed
install_go() {
  if command -v go >/dev/null 2>&1; then
    echo "Go is already installed"
    return
  fi
  
  echo "Installing Go directly..."
  GO_VERSION="1.21.0"
  ARCH=$(uname -m)
  
  if [ "$ARCH" == "x86_64" ]; then
      GOARCH="amd64"
  elif [ "$ARCH" == "aarch64" ] || [ "$ARCH" == "arm64" ]; then
      GOARCH="arm64"
  else
      GOARCH="amd64"  # Default
  fi
  
  wget -q https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz -O /tmp/go.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz

  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
  echo "export PATH=\$PATH:/usr/local/go/bin:$HOME/go/bin" >> ~/.profile
  echo "export PATH=\$PATH:/usr/local/go/bin:$HOME/go/bin" >> ~/.bashrc
  
  if [ -f ~/.zshrc ]; then
    echo "export PATH=\$PATH:/usr/local/go/bin:$HOME/go/bin" >> ~/.zshrc
  fi
  
  echo "Go installed successfully"
}

# Function to install a ProjectDiscovery tool
install_pd_tool() {
  local tool_name=$1
  local repo_path=$2
  
  echo "Installing $tool_name..."
  
  if command -v $tool_name >/dev/null 2>&1; then
    echo "$tool_name is already installed"
    return 0
  fi
  
  if ! go install -v $repo_path@latest; then
    echo "Failed to install $tool_name with go install"
    return 1
  fi
  
  echo "$tool_name installed successfully"
  return 0
}

# Function to create a script for a tool that couldn't be installed
create_fallback_script() {
  local tool_name=$1
  local script_content=$2
  
  echo "Creating fallback script for $tool_name..."
  mkdir -p $HOME/go/bin
  echo "$script_content" > $HOME/go/bin/$tool_name
  chmod +x $HOME/go/bin/$tool_name
  echo "Fallback script created at $HOME/go/bin/$tool_name"
}

# 1. Install Go
install_go

# 2. Install or download other essential tools
mkdir -p $HOME/.local/bin $HOME/go/bin

# 3. Install ProjectDiscovery tools directly using Go
install_pd_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_pd_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_pd_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"

# 4. Create alternative naabu script since it might fail due to libpcap dependency
create_fallback_script "naabu" "$(cat << 'EOF'
#!/bin/bash
# naabu-wrapper - Alternative to naabu port scanner using nmap
# Usage: naabu -host example.com -p 80,443 -o output.txt

TARGET=""
TARGET_FILE=""
PORTS="1-1000"
OUTPUT=""

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
        -version)
            echo "naabu-wrapper v1.0.0"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -z "$TARGET" && -z "$TARGET_FILE" ]]; then
    echo "No target specified. Use -host or -l."
    exit 1
fi

if command -v nmap >/dev/null 2>&1; then
    echo "Using nmap for port scanning..."
    
    if [[ -n "$TARGET" ]]; then
        if [[ -n "$OUTPUT" ]]; then
            nmap -p "$PORTS" "$TARGET" -oG - | grep -v "^#" | grep open | awk '{print $2":"$5}' | tr '/' ':' | cut -d ':' -f 1,2 > "$OUTPUT"
            echo "Results saved to $OUTPUT"
        else
            nmap -p "$PORTS" "$TARGET" | grep -E '^[0-9]+/tcp' | awk '{print "'$TARGET':" $1}' | tr '/' ':'
        fi
    elif [[ -n "$TARGET_FILE" ]]; then
        if [[ -n "$OUTPUT" ]]; then
            nmap -p "$PORTS" -iL "$TARGET_FILE" -oG - | grep -v "^#" | grep open | awk '{print $2":"$5}' | tr '/' ':' | cut -d ':' -f 1,2 > "$OUTPUT"
            echo "Results saved to $OUTPUT"
        else
            nmap -p "$PORTS" -iL "$TARGET_FILE" | grep -E '^[0-9]+/tcp' | awk '{print $1}' | tr '/' ':'
        fi
    fi
else
    echo "Error: nmap is not installed. Please install nmap first."
    exit 1
fi
EOF
)"

# 5. Update nuclei templates if nuclei is installed
if command -v nuclei >/dev/null 2>&1; then
  echo "Updating nuclei templates..."
  nuclei -update-templates
fi

# 6. Display completion message
echo "===== Installation Complete ====="
echo "Available tools:"
echo "- httpx: For probing HTTP services"
echo "- nuclei: For vulnerability scanning"
echo "- subfinder: For subdomain discovery"
echo "- naabu (alternative): For port scanning (using nmap)"
echo ""
echo "You may need to run 'source ~/.bashrc' or open a new terminal to use these tools."
echo "To check if tools are working, try: nuclei -version"