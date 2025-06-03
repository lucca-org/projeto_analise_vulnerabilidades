#!/bin/bash
# Simple installation script for Linux Vulnerability Analysis Toolkit
# This script detects the Linux distribution and installs the necessary dependencies

set -e  # Exit on any error

# Display banner
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                            ║"
echo "║               🔥 LINUX VULNERABILITY ANALYSIS TOOLKIT 🔥                   ║"
echo "║                         INSTALLATION SCRIPT                               ║"
echo "║                                                                            ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ This script must be run as root (with sudo)"
    echo "Please run: sudo bash install.sh"
    exit 1
fi

# Check if we're on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                          ❌ ERROR ❌                           ║"
    echo "║                                                               ║"
    echo "║     This toolkit is designed EXCLUSIVELY for Linux systems   ║"
    echo "║                                                               ║"
    echo "║     ✅ Supported: Debian, Kali, Ubuntu, Arch Linux          ║"
    echo "║     ❌ NOT Supported: Windows, macOS, WSL                    ║"
    echo "║                                                               ║"
    echo "║     Please run this on a Linux system for optimal security   ║"
    echo "║     tool performance and compatibility.                      ║"
    echo "║                                                               ║"
    echo "║     REASON: The toolkit installs and configures Linux-native ║"
    echo "║     security tools with system-level dependencies that       ║"
    echo "║     cannot function correctly on other operating systems.    ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    exit 1
fi

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "❌ Cannot detect Linux distribution"
    exit 1
fi

echo "✅ Detected Linux distribution: $DISTRO"

# Install system dependencies based on distribution
case $DISTRO in
    debian|ubuntu|kali)
        echo "🔄 Updating package lists..."
        apt-get update
        
        echo "📦 Installing dependencies for $DISTRO..."
        apt-get install -y python3 python3-pip git wget curl build-essential golang-go
        ;;
    arch)
        echo "🔄 Updating package lists..."
        pacman -Sy
        
        echo "📦 Installing dependencies for Arch Linux..."
        pacman -S --noconfirm python python-pip git wget curl base-devel go
        ;;
    fedora|centos|rhel)
        echo "🔄 Updating package lists..."
        dnf check-update || true
        
        echo "📦 Installing dependencies for $DISTRO..."
        dnf install -y python3 python3-pip git wget curl gcc gcc-c++ golang
        ;;
    *)
        echo "⚠️ Unsupported Linux distribution: $DISTRO"
        echo "Attempting to install required packages anyway..."
        # Try common package managers
        if command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y python3 python3-pip git wget curl build-essential golang-go
        elif command -v dnf &> /dev/null; then
            dnf check-update || true
            dnf install -y python3 python3-pip git wget curl gcc gcc-c++ golang
        elif command -v pacman &> /dev/null; then
            pacman -Sy
            pacman -S --noconfirm python python-pip git wget curl base-devel go
        else
            echo "❌ Could not determine package manager. Please install manually:"
            echo "  - Python 3.6+"
            echo "  - Python pip"
            echo "  - Git"
            echo "  - Wget"
            echo "  - Curl"
            echo "  - Build tools (gcc, make, etc.)"
            echo "  - Go (golang)"
            exit 1
        fi
        ;;
esac

# Install Python dependencies
echo "📦 Installing Python dependencies..."
python3 -m pip install -r config/requirements.txt

# Set up Go environment
echo "🔧 Setting up Go environment..."
# Ensure go/bin is in PATH
if ! grep -q "GOPATH" ~/.bashrc; then
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    
    # Also set for current session
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
fi

# Create directories if they don't exist
mkdir -p reports
mkdir -p scripts

# Make script files executable
chmod +x scripts/*.sh

# Run the comprehensive auto-installer
echo "🚀 Running comprehensive auto-installation..."
python3 scripts/autoinstall.py

# Verify installation
echo "🔍 Verifying installation..."
python3 verify_installation.py

echo ""
echo "🎉 Installation completed!"
echo ""
echo "To run the toolkit:"
echo "  python3 run.py --help"
echo "  python3 run.py --target example.com"
echo ""
echo "Or use the shell script:"
echo "  bash scripts/run_toolkit.sh --help"
