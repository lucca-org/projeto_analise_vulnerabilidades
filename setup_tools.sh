#!/bin/bash
# setup_tools.sh - Consolidated setup script for vulnerability analysis tools
# This script is designed for Kali Linux and Debian-based systems

set -e

# Function to check for root/sudo access
check_sudo() {
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root or with sudo." >&2
        exit 1
    fi
}

# Function to fix any dpkg issues
fix_dpkg() {
    echo -e "\n[+] Checking for and fixing any package manager issues..."
    sudo dpkg --configure -a || { echo "Failed to configure dpkg."; exit 1; }
    sudo apt-get update --fix-missing -y || { echo "Failed to update package lists."; exit 1; }
    sudo apt-get install -f -y || { echo "Failed to fix broken packages."; exit 1; }
    sudo apt-get clean || { echo "Failed to clean package cache."; exit 1; }
}

# Function to install Go
install_go() {
    if command -v go >/dev/null 2>&1; then
        echo "Go is already installed."
        return
    fi

    echo -e "\n[+] Installing Go..."
    GO_VERSION="1.21.0"
    ARCH=$(uname -m)

    if [ "$ARCH" == "x86_64" ]; then
        GOARCH="amd64"
    elif [ "$ARCH" == "aarch64" ] || [ "$ARCH" == "arm64" ]; then
        GOARCH="arm64"
    else
        GOARCH="amd64"
    fi

    wget -q https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz -O /tmp/go.tar.gz || { echo "Failed to download Go."; exit 1; }
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz || { echo "Failed to extract Go."; exit 1; }
    rm /tmp/go.tar.gz

    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    source ~/.bashrc
    echo "Go installed successfully."
}

# Function to install security tools
install_security_tools() {
    echo -e "\n[+] Installing security tools..."
    export GOBIN=$HOME/go/bin
    mkdir -p $GOBIN

    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || { echo "Failed to install httpx."; exit 1; }
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || { echo "Failed to install nuclei."; exit 1; }

    # Install naabu with CGO disabled
    export CGO_ENABLED=0
    if ! go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest; then
        echo "Failed to install naabu. Creating alternative script..."
        create_naabu_alternative
    fi

    echo "Security tools installed successfully."
}

# Function to create a naabu alternative
create_naabu_alternative() {
    echo "Creating naabu alternative script..."
    cat > $HOME/go/bin/naabu << 'EOF'
#!/bin/bash
# naabu alternative script using netcat
TARGET="$1"
PORTS="1-1000"

if [ -z "$TARGET" ]; then
    echo "Usage: naabu <target>"
    exit 1
fi

for PORT in $(seq 1 1000); do
    if nc -z -w1 $TARGET $PORT 2>/dev/null; then
        echo "Open port: $PORT"
    fi
done
EOF
    chmod +x $HOME/go/bin/naabu
    echo "Naabu alternative script created."
}

# Install Python dependencies
install_python_dependencies() {
    echo -e "\n[+] Installing Python dependencies..."
    sudo apt-get install -y python3-pip || { echo "Failed to install pip."; exit 1; }
    pip3 install -r requirements.txt || { echo "Failed to install Python dependencies."; exit 1; }
    echo "Python dependencies installed successfully."
}

# Main installation flow
main() {
    check_sudo
    fix_dpkg
    install_go
    install_security_tools
    install_python_dependencies
    echo "Setup complete. Please run 'source ~/.bashrc' to update your PATH."
}

main
