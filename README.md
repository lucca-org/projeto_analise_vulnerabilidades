# Linux Vulnerability Analysis Toolkit

🛡️ A comprehensive security toolkit for automated vulnerability scanning and analysis, designed **exclusively for Linux systems**.

## Overview

This toolkit integrates powerful security tools (naabu, httpx, nuclei) into a streamlined workflow for vulnerability scanning. It automates the entire process from port scanning to vulnerability detection and report generation.

**⚠️ IMPORTANT: This toolkit only works on Linux systems due to the security tools' dependencies on Linux kernel features and libraries.**

## Features

- 🔍 **Comprehensive Scanning**: Automated port scanning, HTTP service detection, and vulnerability discovery
- 🚀 **Zero-Configuration**: Just provide a target and the toolkit does the rest
- 🛠️ **Auto-Installation**: Automatically installs and configures all necessary tools
- 📊 **Report Generation**: Creates detailed vulnerability reports in multiple formats
- 🐧 **Linux-Optimized**: Built specifically for Linux security environments
- 🔄 **Multi-Distro Support**: Works on Debian, Ubuntu, Kali Linux, Arch Linux, and more

## Supported Linux Distributions

- ✅ Kali Linux (Recommended for security testing)
- ✅ Debian
- ✅ Ubuntu
- ✅ Arch Linux
- ✅ Fedora/CentOS/RHEL (Basic support)

## Installation

### Master Installation Orchestrator (Recommended)

The toolkit now features a comprehensive **single-point master installer** that handles everything automatically:

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
cd linux-vulnerability-toolkit

# Run the master installation orchestrator (requires root privileges)
sudo python3 install/setup.py
```

The master installer performs:
- ✅ Linux platform verification and distribution detection
- ✅ Root/sudo permission enforcement 
- ✅ System package installation (curl, wget, git, build-essential, etc.)
- ✅ Go programming environment setup with PATH management
- ✅ Security tools installation (naabu, httpx, nuclei)
- ✅ Python dependencies and virtual environment setup
- ✅ Configuration optimization and bash aliases creation
- ✅ Complete system verification with functionality testing

### Alternative Installation Methods

#### Option 1: Python Environment Setup Only
```bash
# For Python environment setup and validation only
python3 scripts/autoinstall.py
```

#### Option 2: Shell-Based Installation (Legacy)
```bash
# Run individual shell scripts for specific components
bash scripts/setup_tools.sh        # Security tools only
bash scripts/fix_go_path.sh        # Fix Go environment
bash scripts/update_repos.sh       # Update repositories
```

### Post-Installation Verification

After installation, verify everything is working:

```bash
# Check tool availability and functionality
python3 scripts/autoinstall.py

# Verify specific tools
naabu -version
httpx -version  
nuclei -version

# Check configuration
cat config/toolkit_config.json
```

## Architecture

### New Master Installer Architecture

The toolkit has been completely redesigned with a **single-point master installer** architecture:

```
Linux Vulnerability Analysis Toolkit/
├── install/
│   ├── setup.py           # 🎯 MASTER INSTALLER (Main Entry Point)
│   └── setup_old.py       # Legacy backup
├── scripts/
│   ├── autoinstall.py     # 🐍 Python environment setup & validation
│   ├── setup_tools.sh     # 🔧 Security tools installation (shell)
│   ├── run_toolkit.sh     # 🚀 Main toolkit launcher
│   └── fix_*.sh           # 🔨 System repair utilities
├── src/
│   ├── workflow.py        # 🔄 Main scanning workflow
│   ├── utils.py           # 🛠️ Core utilities
│   └── reporter.py        # 📊 Report generation
├── config/
│   ├── requirements.txt   # 📦 Python dependencies
│   └── toolkit_config.json # ⚙️ Generated configuration
├── output/                # 📁 Scan results output
└── reports/               # 📁 Generated reports
```

### Installation Flow

1. **install/setup.py** (Master Orchestrator)
   - Platform verification & distribution detection
   - Root permission enforcement  
   - System package management
   - Go environment setup
   - Security tools installation
   - Configuration generation

2. **scripts/autoinstall.py** (Python Environment Manager)
   - Python dependencies validation
   - Virtual environment setup
   - Tool availability checking
   - Configuration file creation

3. **Shell Scripts** (System Integration)
   - setup_tools.sh: Security tools installation
   - fix_*.sh: System repair utilities
   - run_toolkit.sh: Main launcher

## Usage

### Quick Start

```bash
# 1. Install the toolkit (one command does everything)
sudo python3 install/setup.py

# 2. Run a scan
python3 run.py <target>
# OR
bash scripts/run_toolkit.sh <target>
```

### Advanced Usage

```bash
# Run a basic scan on a target
python3 run.py --target example.com

# Or use the shell script
bash scripts/run_toolkit.sh --target example.com
```

### Advanced Usage

```bash
# Specify custom ports
python3 run.py --target example.com --ports 80,443,8080-8090

# Specify custom nuclei templates
python3 run.py --target example.com --templates cves,exposures

# Run a more comprehensive scan
python3 run.py --target example.com --ports top-1000 --tags cve,exposure --severity critical,high
```

### Additional Options

- `--verbose`: Display more detailed output
- `--timeout`: Set maximum scan timeout in seconds
- `--scan-code`: Enable code scanning for web applications
- `--auto-config`: Automatically configure tools based on system capabilities

## Output

Results are saved in a timestamped directory (e.g., `results_example.com_20250603_120101/`) including:

- `ports.txt`: Discovered open ports
- `http_services.txt`: Discovered HTTP services
- `vulnerabilities.txt`: Discovered vulnerabilities
- `report.html`: Comprehensive HTML report
- `report.json`: JSON data for further processing

## Validation & Troubleshooting

### Installation Validation

Always validate your installation after setup:

```bash
# Comprehensive installation validation
python3 validate_installation.py

# Python environment validation
python3 scripts/autoinstall.py

# Legacy tool validation
python3 verify_installation.py
```

### Common Issues & Solutions

#### 1. **Master Installer Issues**
```bash
# Problem: Permission denied during installation
sudo python3 install/setup.py

# Problem: Platform not supported
# Solution: Use Linux (Debian/Ubuntu/Kali/Arch only)
```

#### 2. **Security Tools Missing**
```bash
# Check tool availability
which naabu httpx nuclei

# Fix Go PATH issues
bash scripts/fix_go_path.sh

# Reinstall tools manually
bash scripts/setup_tools.sh
```

#### 3. **Python Environment Issues**
```bash
# Validate Python setup
python3 scripts/autoinstall.py

# Check Python version (3.8+ required)
python3 --version

# Install missing Python packages
pip3 install -r config/requirements.txt
```

#### 4. **Configuration Problems**
```bash
# Check configuration file
cat config/toolkit_config.json

# Regenerate configuration
python3 scripts/autoinstall.py

# Fix permissions
chmod +x scripts/*.sh
```

### Linux Distribution-Specific Issues

#### **Debian/Ubuntu/Kali**
```bash
# Fix repository key issues
bash scripts/fix_repo_keys.sh

# Fix package manager locks
bash scripts/fix_dpkg.sh

# Update repositories
bash scripts/update_repos.sh
```

#### **Arch Linux**
```bash
# Update system first
sudo pacman -Syu

# Install base development tools
sudo pacman -S base-devel go git curl wget
```

#### **Fedora/CentOS/RHEL**
```bash
# Install development tools
sudo dnf groupinstall "Development Tools"
sudo dnf install golang git curl wget python3-pip
```

### Advanced Troubleshooting

#### **Complete Reset & Reinstall**
```bash
# 1. Clean previous installation
rm -rf ~/go/bin/{naabu,httpx,nuclei}
rm -f config/toolkit_config.json

# 2. Run master installer
sudo python3 install/setup.py

# 3. Validate installation
python3 validate_installation.py
```

#### **Manual Tool Installation**
```bash
# Install Go manually
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install tools manually
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

#### **Debug Mode**
```bash
# Run with verbose output
python3 run.py --target example.com --verbose

# Check tool versions
naabu -version && httpx -version && nuclei -version

# Test individual tools
echo "example.com" | naabu -top-ports 10
echo "http://example.com" | httpx -title
nuclei -target example.com -t cves/
```

## Security Considerations

- Always obtain proper authorization before scanning any targets
- Use this toolkit responsibly and ethically
- Consider using in an isolated environment for maximum security

## License

This project is licensed under the MIT License - see the LICENSE file for details.
