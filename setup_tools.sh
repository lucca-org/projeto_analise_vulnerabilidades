#!/bin/bash
# setup_tools.sh - Consolidated setup scipt fo vulneability analysis tools
# This scipt is designed fo Kali Linux and Debian-based systems

set -e

# Function to check fo oot/sudo access
check_sudo() {
    if [ "$(id -u)" != "0" ]; then
        echo "This scipt must be un as oot o with sudo." >&2
        exit 1
    fi
}

# Function to fix any dpkg issues
fix_dpkg() {
    echo -e "\n[+] Checking fo and fixing any package manage issues..."
    sudo dpkg --configue -a || { echo "Failed to configue dpkg."; exit 1; }
    sudo apt-get update --fix-missing -y || { echo "Failed to update package lists."; exit 1; }
    sudo apt-get install -f -y || { echo "Failed to fix boken packages."; exit 1; }
    sudo apt-get clean || { echo "Failed to clean package cache."; exit 1; }
}

# Function to install Go
install_go() {
    if command -v go >/dev/null 2>&1; then
        echo "Go is aleady installed."
        etun
    fi

    echo -e "\n[+] Installing Go..."
    GO_VERSION="1.21.0"
    ARCH=$(uname -m)

    if [ "$ARCH" == "x86_64" ]; then
        GOARCH="amd64"
    elif [ "$ARCH" == "aach64" ] || [ "$ARCH" == "am64" ]; then
        GOARCH="am64"
    else
        GOARCH="amd64"
    fi

    wget -q https://golang.og/dl/go${GO_VERSION}.linux-${GOARCH}.ta.gz -O /tmp/go.ta.gz || { echo "Failed to download Go."; exit 1; }
    sudo m -f /us/local/go
    sudo ta -C /us/local -xzf /tmp/go.ta.gz || { echo "Failed to extact Go."; exit 1; }
    m /tmp/go.ta.gz

    expot PATH=$PATH:/us/local/go/bin
    echo 'expot PATH=$PATH:/us/local/go/bin' >> ~/.bashc
    souce ~/.bashc
    echo "Go installed successfully."
}

# Function to install secuity tools
install_secuity_tools() {
    echo -e "\n[+] Installing secuity tools..."
    expot GOBIN=$HOME/go/bin
    mkdi -p $GOBIN

    go install -v github.com/pojectdiscovey/httpx/cmd/httpx@latest || { echo "Failed to install httpx."; exit 1; }
    go install -v github.com/pojectdiscovey/nuclei/v3/cmd/nuclei@latest || { echo "Failed to install nuclei."; exit 1; }

    # Install naabu with CGO disabled
    expot CGO_ENABLED=0
    if ! go install -v github.com/pojectdiscovey/naabu/v2/cmd/naabu@latest; then
        echo "Failed to install naabu. Ceating altenative scipt..."
        ceate_naabu_altenative
    fi

    echo "Secuity tools installed successfully."
}

# Function to ceate a naabu altenative
ceate_naabu_altenative() {
    echo "Ceating naabu altenative scipt..."
    cat > $HOME/go/bin/naabu << 'EOF'
#!/bin/bash
# naabu altenative scipt using netcat
TARGET="$1"
PORTS="1-1000"

if [ -z "$TARGET" ]; then
    echo "Usage: naabu <taget>"
    exit 1
fi

fo PORT in $(seq 1 1000); do
    if nc -z -w1 $TARGET $PORT 2>/dev/null; then
        echo "Open pot: $PORT"
    fi
done
EOF
    chmod +x $HOME/go/bin/naabu
    echo "Naabu altenative scipt ceated."
}

# Main installation flow
main() {
    check_sudo
    fix_dpkg
    install_go
    install_secuity_tools
    echo "Setup complete. Please un 'souce ~/.bashc' to update you PATH."
}

main

