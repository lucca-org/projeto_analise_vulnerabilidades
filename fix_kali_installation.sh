#!/bin/bash
# Kali Linux Installation Fix Script
# Fixes common Phase 1 issues that cause hangs

echo "🔧 Kali Linux Installation Fix - Phase 1 Troubleshooting"
echo "========================================================="

# Fix 1: Clean package locks and repair dpkg
echo "🔒 Fixing package locks and dpkg issues..."
sudo rm -f /var/lib/dpkg/lock*
sudo rm -f /var/cache/apt/archives/lock
sudo rm -f /var/lib/apt/lists/lock
sudo dpkg --configure -a
sudo apt --fix-broken install -y

# Fix 2: Update package repositories with timeout and non-interactive mode
echo "📦 Updating repositories (with timeout protection)..."
timeout 300 sudo apt update
if [ $? -eq 124 ]; then
    echo "⚠️ Repository update timed out, trying alternative approach..."
    sudo apt-get clean
    sudo apt-get update --allow-unauthenticated
fi

# Fix 3: Install essential packages one by one to identify hanging package
echo "🛠️ Installing essential packages individually..."
PACKAGES=(
    "curl"
    "wget" 
    "git"
    "build-essential"
    "python3-pip"
    "golang-go"
    "unzip"
    "ca-certificates"
    "libpcap-dev"
    "pkg-config"
    "gcc"
)

for package in "${PACKAGES[@]}"; do
    echo "Installing $package..."
    timeout 180 sudo apt install -y "$package"
    if [ $? -eq 124 ]; then
        echo "⚠️ $package installation timed out, skipping..."
    elif [ $? -eq 0 ]; then
        echo "✅ $package installed successfully"
    else
        echo "❌ $package installation failed"
    fi
done

# Fix 4: Verify Go installation
echo "🔍 Verifying Go installation..."
if command -v go &> /dev/null; then
    echo "✅ Go is installed: $(go version)"
else
    echo "⚠️ Go not found, trying manual installation..."
    # Alternative Go installation for Kali
    wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
fi

echo "🎯 Phase 1 manual fix completed!"
echo "Now try running: sudo python3 install/setup.py"
