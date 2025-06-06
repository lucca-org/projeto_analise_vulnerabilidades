# Installation Guide - Linux Vulnerability Analysis Toolkit

This guide provides detailed installation instructions for the Linux-exclusive vulnerability analysis toolkit.

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux (Debian, Ubuntu, Kali Linux, Arch Linux)
- **Privileges**: Root/sudo access
- **Python**: Version 3.6 or higher
- **Internet**: Active connection required
- **Disk Space**: Minimum 2GB free space
- **Memory**: 2GB RAM recommended

### Supported Distributions
- ✅ **Kali Linux** (Recommended for security testing)
- ✅ **Ubuntu** 18.04, 20.04, 22.04, 24.04
- ✅ **Debian** 10, 11, 12
- ✅ **Arch Linux** (Latest)

### Unsupported Platforms
- ❌ Windows (including WSL)
- ❌ macOS
- ❌ FreeBSD/OpenBSD

## 🚀 Quick Installation

### Automated Installation (Recommended)
```bash
# 1. Clone the repository
git clone <repository-url>
cd projeto_analise_vulnerabilidades

# 2. Run the master installer
sudo python3 install/setup.py
```

The automated installer will:
- Detect your Linux distribution
- Install system dependencies
- Set up Go environment
- Install security tools (naabu, httpx, nuclei)
- Configure optimal settings
- Verify installation

## 📝 Detailed Installation Steps

### Step 1: System Preparation
```bash
# Update package lists
sudo apt update  # Debian/Ubuntu/Kali
# OR
sudo pacman -Sy  # Arch Linux

# Install basic requirements
sudo apt install curl wget git python3 python3-pip  # Debian/Ubuntu/Kali
# OR
sudo pacman -S curl wget git python python-pip      # Arch Linux
```

### Step 2: Download Toolkit
```bash
# Clone from repository
git clone <repository-url>
cd projeto_analise_vulnerabilidades

# Verify download
ls -la
```

### Step 3: Run Master Installer
```bash
# Execute with root privileges
sudo python3 install/setup.py
```

### Step 4: Post-Installation Setup
```bash
# Add Go tools to PATH (if not automatically done)
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
which naabu httpx nuclei
```

## 🔧 Manual Installation (Advanced Users)

If you prefer manual installation or the automated installer fails:

### Install Go Environment
```bash
# Download and install Go
GO_VERSION="1.21.5"
wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

# Set up Go environment
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export GOBIN=$GOPATH/bin
export PATH=$PATH:$GOBIN

# Make permanent
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export GOBIN=$GOPATH/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$GOBIN' >> ~/.bashrc
source ~/.bashrc
```

### Install System Dependencies
```bash
# Debian/Ubuntu/Kali
sudo apt install -y build-essential libpcap-dev pkg-config

# Arch Linux
sudo pacman -S base-devel libpcap pkgconfig
```

### Install Security Tools
```bash
# Create Go directories
mkdir -p $HOME/go/bin

# Install naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Install httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update nuclei templates
nuclei -update-templates
```

## 🛠️ Distribution-Specific Notes

### Kali Linux
```bash
# Kali often has httpx pre-installed via package manager
apt list --installed | grep httpx

# If you prefer the Go version for consistency:
sudo apt remove httpx  # Remove system package
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Ubuntu/Debian
```bash
# Ensure universe repository is enabled (Ubuntu)
sudo add-apt-repository universe
sudo apt update

# Install dependencies
sudo apt install -y golang-go build-essential libpcap-dev
```

### Arch Linux
```bash
# Update system first
sudo pacman -Syu

# Install Go and dependencies
sudo pacman -S go base-devel libpcap
```

## ✅ Verification

### Tool Availability Check
```bash
# Check if tools are installed and accessible
which naabu httpx nuclei go

# Test tool versions
naabu -version
httpx -version
nuclei -version
go version
```

### Functionality Test
```bash
# Quick functionality test
sudo python3 src/workflow.py -naabu -host 127.0.0.1 -p "80,443" -v
```

### Path Configuration
```bash
# Verify Go tools are in PATH
echo $PATH | grep go/bin

# If not, add to current session
export PATH=$PATH:~/go/bin

# Make permanent
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## 🚨 Troubleshooting

### Common Installation Issues

#### 1. Permission Denied
**Problem**: Script fails with permission errors
```bash
# Solution: Ensure running with sudo
sudo python3 install/setup.py

# Check installer permissions
chmod +x install/setup.py
```

#### 2. Go Tools Not Found
**Problem**: Tools installed but not in PATH
```bash
# Solution: Add Go bin to PATH
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
ls -la ~/go/bin/
```

#### 3. Network Connectivity Issues
**Problem**: Downloads fail during installation
```bash
# Solution: Check connectivity
ping google.com

# Configure proxy if needed
export GOPROXY=https://proxy.golang.org,direct

# Use direct mode if proxy fails
export GOPROXY=direct
```

#### 4. Disk Space Issues
**Problem**: Installation fails due to insufficient space
```bash
# Solution: Free up space
sudo apt clean
sudo apt autoremove
df -h  # Check available space

# Minimum 2GB required
```

#### 5. libpcap Development Headers Missing
**Problem**: naabu compilation fails
```bash
# Solution: Install libpcap development package
sudo apt install libpcap-dev  # Debian/Ubuntu/Kali
sudo pacman -S libpcap        # Arch Linux

# Verify headers exist
ls /usr/include/pcap.h
```

### Dependency Issues

#### Missing Build Tools
```bash
# Debian/Ubuntu/Kali
sudo apt install build-essential

# Arch Linux
sudo pacman -S base-devel
```

#### Go Environment Issues
```bash
# Check Go installation
go version
go env GOPATH
go env GOBIN

# Recreate Go directories
mkdir -p $HOME/go/bin
mkdir -p $HOME/go/src
mkdir -p $HOME/go/pkg
```

#### Python Environment Issues
```bash
# Check Python version
python3 --version

# Install pip if missing
sudo apt install python3-pip

# Install Python dependencies
pip3 install --user requests colorama
```

### Tool-Specific Issues

#### naabu Compilation Errors
```bash
# Install missing dependencies
sudo apt install pkg-config libpcap-dev

# Clean and reinstall
go clean -modcache
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

#### httpx Installation on Kali
```bash
# Check if system package exists
dpkg -l | grep httpx

# If conflicts arise, use Go version
sudo apt remove httpx
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

#### nuclei Template Updates
```bash
# Manual template update
nuclei -update-templates

# If update fails, clean template cache
rm -rf ~/.config/nuclei/
nuclei -update-templates
```

## 🔄 Updating

### Update Toolkit
```bash
# Pull latest changes
cd projeto_analise_vulnerabilidades
git pull origin main

# Re-run installer if needed
sudo python3 install/setup.py
```

### Update Security Tools
```bash
# Update all Go tools
go install -a github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -a github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -a github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update nuclei templates
nuclei -update-templates
```

## 🧹 Uninstallation

### Remove Toolkit
```bash
# Remove cloned repository
rm -rf projeto_analise_vulnerabilidades

# Remove Go tools (optional)
rm -f ~/go/bin/naabu ~/go/bin/httpx ~/go/bin/nuclei

# Remove Go environment (optional)
rm -rf ~/go

# Remove PATH modifications from shell profile
# Edit ~/.bashrc and remove Go-related exports
```

### Clean System Packages
```bash
# Remove installed dependencies (be careful!)
sudo apt autoremove
sudo apt autoclean
```

## 📞 Getting Help

### Log Files
Installation logs are available at:
- Console output during installation
- System package manager logs (`/var/log/apt/` for Debian-based)

### Community Support
- Check GitHub issues
- Review documentation in `docs/` directory
- Verify against known working configurations

### Reporting Issues
When reporting installation issues, include:
- Linux distribution and version
- Python version
- Go version (if installed)
- Complete error messages
- Output of `sudo python3 install/setup.py -v`

---

**Success Indicator**: After successful installation, you should be able to run:
```bash
sudo python3 src/workflow.py -naabu -host 127.0.0.1 -v
```

This command should execute without errors and display tool detection messages.
