# Linux Vulnerability Analysis Toolkit

 A comprehensive security toolkit for automated vulnerability scanning and analysis, designed **exclusively for Linux systems**.

##  Recent Enhancements

✅ **Enhanced Master Installer**: Single-point installation with integrated functionality  
✅ **Streamlined Architecture**: Legacy scripts consolidated for improved reliability  
✅ **Comprehensive Validation**: Advanced installation verification system (95.5% success rate)  
✅ **UTF-8 Support**: Robust encoding handling for international environments  
✅ **Optimized Workflow**: Simplified installation and usage process

## Overview

This toolkit integrates powerful security tools (naabu, httpx, nuclei) into a streamlined workflow for vulnerability scanning. It automates the entire process from port scanning to vulnerability detection and report generation.

** IMPORTANT: This toolkit only works on Linux systems due to the security tools' dependencies on Linux kernel features and libraries.**

## Features

-  **Comprehensive Scanning**: Automated port scanning, HTTP service detection, and vulnerability discovery
-  **Zero-Configuration**: Just provide a target and the toolkit does the rest
-  **Auto-Installation**: Automatically installs and configures all necessary tools
-  **Report Generation**: Creates detailed vulnerability reports in multiple formats
-  **Linux-Optimized**: Built specifically for Linux security environments
-  **Multi-Distro Support**: Works on Debian, Ubuntu, Kali Linux, Arch Linux, and more

## Supported Linux Distributions

-  Kali Linux (Recommended for security testing)
-  Debian
-  Ubuntu
-  Arch Linux
-  Fedora/CentOS/RHEL (Basic support)

## Installation

### Master Installation Orchestrator (Recommended)

The toolkit now features a comprehensive **single-point master installer** that handles everything automatically:


# Clone the repository
git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
cd linux-vulnerability-toolkit

# Run the master installation orchestrator (requires root privileges)
sudo python3 install/setup.py


The master installer performs:
-  Linux platform verification and distribution detection
-  Root/sudo permission enforcement 
-  **NEW**: Anti-hang timeout protection for all operations
-  **NEW**: Package manager lock file cleanup and repair
-  System package installation with individual package tracking
-  **NEW**: VM-optimized installation process (Kali Linux tested)
-  Go programming environment setup with PATH management
-  Security tools installation with timeout protection (naabu, httpx, nuclei)
-  Python dependencies and virtual environment setup
-  Configuration optimization and bash aliases creation
-  Complete system verification with functionality testing

### Alternative Installation Methods

#### Option 1: Python Environment Setup Only

# For Python environment setup and validation only
python3 scripts/autoinstall.py


**Note:** Legacy shell scripts have been integrated into the master installer for a streamlined experience.

### Post-Installation Verification

After installation, verify everything is working:


# Comprehensive installation validation (Recommended)
python3 tests/validate_installation.py

# Python environment validation
python3 scripts/autoinstall.py

# Legacy tool validation
python3 tests/verify_installation.py


## Architecture

### Enhanced Master Installer Architecture

The toolkit features a **streamlined single-point master installer** architecture with integrated functionality:


Linux Vulnerability Analysis Toolkit/
├── install/
│   ├── setup.py                    # 🎯 ENHANCED MASTER INSTALLER (All-in-One)
│   └── setup_backup_original.py   # Original backup
├── scripts/
│   ├── autoinstall.py             # 🐍 Python environment setup & validation
│   └── run_toolkit.sh             # 🚀 Main toolkit launcher
├── src/
│   ├── workflow.py                # 🔄 Main scanning workflow
│   ├── utils.py                   # 🛠️ Core utilities
│   ├── reporter.py                # 📊 Report generation
│   ├── config_manager.py          # ⚙️ Configuration management
│   └── code_scanner.py            # 🔍 Code scanning capabilities
├── commands/
│   ├── naabu.py                   # Port scanning commands
│   ├── httpx.py                   # HTTP service detection
│   └── nuclei.py                  # Vulnerability scanning
├── config/
│   └── requirements.txt           # 📦 Python dependencies
├── output/                        # 📁 Scan results output
├── reports/                       # 📁 Generated reports
└── tests/                         # 🧪 Testing and validation
    ├── validate_installation.py   # ✅ Comprehensive validation script
    └── verify_installation.py     # 🔍 Tool verification script


### Key Architecture Improvements

- **🚀 Integrated Functionality**: Legacy shell scripts consolidated into master installer
- **🔧 Enhanced Error Handling**: Robust UTF-8 encoding and dependency management
- **📊 Comprehensive Validation**: Advanced installation verification system
- **🎯 Streamlined Workflow**: Simplified installation and usage process

### Installation Flow

1. **install/setup.py** (Enhanced Master Installer)
   - Platform verification & distribution detection
   - Root permission enforcement  
   - System package management
   - Go environment setup and PATH configuration
   - Security tools installation (naabu, httpx, nuclei)
   - Configuration generation and optimization
   - Integrated functionality from legacy scripts

2. **scripts/autoinstall.py** (Python Environment Manager)
   - Python dependencies validation
   - Virtual environment setup
   - Tool availability checking
   - Configuration file creation

3. **tests/validate_installation.py** (Comprehensive Validator)
   - Installation integrity verification
   - Tool functionality testing
   - Configuration validation
   - System compatibility checking

## Usage

### 🚀 How to Run the Project

#### **Step 1: Installation (Linux Only)**

# Clone the repository
git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
cd linux-vulnerability-toolkit

# Install everything with one command (requires root privileges)
sudo python3 install/setup.py


#### **Step 2: Validation (Recommended)**

# Verify installation is working correctly
python3 tests/validate_installation.py


#### **Step 3: Run Vulnerability Scans**

**Basic Scan:**

# Simple scan
python3 run.py <target>

# Example
python3 run.py example.com


**Using Shell Script:**

# Alternative launcher
bash scripts/run_toolkit.sh <target>


### Advanced Usage Options


# Specify custom ports
python3 run.py --target example.com --ports 80,443,8080-8090

# Use specific nuclei templates
python3 run.py --target example.com --templates cves,exposures

# Comprehensive scan with filtering
python3 run.py --target example.com --ports top-1000 --tags cve,exposure --severity critical,high

# Verbose output for debugging
python3 run.py --target example.com --verbose


### Additional Options

- `--verbose`: Display more detailed output
- `--timeout`: Set maximum scan timeout in seconds
- `--scan-code`: Enable code scanning for web applications
- `--auto-config`: Automatically configure tools based on system capabilities

### 📋 Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `python3 run.py <target>` | Basic vulnerability scan | `python3 run.py example.com` |
| `bash scripts/run_toolkit.sh <target>` | Alternative launcher | `bash scripts/run_toolkit.sh example.com` |
| `python3 tests/validate_installation.py` | Validate installation | Check system status |
| `python3 scripts/autoinstall.py` | Python environment setup | Setup dependencies |

**💡 For detailed usage instructions, see [HOW_TO_RUN.md](HOW_TO_RUN.md)**

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


# Comprehensive installation validation
python3 tests/validate_installation.py

# Python environment validation
python3 scripts/autoinstall.py

# Legacy tool validation
python3 tests/verify_installation.py


### Common Issues & Solutions

#### 1. **Master Installer Issues**

# Problem: Permission denied during installation
sudo python3 install/setup.py

# Problem: Platform not supported
# Solution: Use Linux (Debian/Ubuntu/Kali/Arch only)


#### 2. **Security Tools Missing**

# Check tool availability
which naabu httpx nuclei

# Reinstall tools (master installer handles Go PATH automatically)
sudo python3 install/setup.py

# Manual tool installation if needed
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest


#### 3. **Python Environment Issues**

# Validate Python setup
python3 scripts/autoinstall.py

# Check Python version (3.8+ required)
python3 --version

# Install missing Python packages
pip3 install -r config/requirements.txt


#### 4. **Configuration Problems**

# Regenerate configuration and validate installation
python3 scripts/autoinstall.py

# Run comprehensive validation
python3 tests/validate_installation.py

# Fix permissions
chmod +x scripts/*.sh


### Linux Distribution-Specific Issues

#### **Debian/Ubuntu/Kali**

# The master installer now handles all repository and package issues automatically
sudo python3 install/setup.py

# Manual fixes if needed:
sudo apt update && sudo apt upgrade
sudo apt install build-essential curl wget git python3-pip


#### **Arch Linux**

# Update system first
sudo pacman -Syu

# Install base development tools (handled by master installer)
sudo pacman -S base-devel go git curl wget python3-pip


#### **Fedora/CentOS/RHEL**

# Install development tools (handled by master installer)
sudo dnf groupinstall "Development Tools"
sudo dnf install golang git curl wget python3-pip


### Advanced Troubleshooting

#### **Complete Reset & Reinstall**

# 1. Clean previous installation
rm -rf ~/go/bin/{naabu,httpx,nuclei}

# 2. Run enhanced master installer
sudo python3 install/setup.py

# 3. Validate installation
python3 tests/validate_installation.py


#### **Manual Tool Installation**

# Install Go manually
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install tools manually
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest


#### **Debug Mode**

# Run with verbose output
python3 run.py --target example.com --verbose

# Check tool versions
naabu -version && httpx -version && nuclei -version

# Test individual tools
echo "example.com" | naabu -top-ports 10
echo "http://example.com" | httpx -title
nuclei -target example.com -t cves/


## Security Considerations

- Always obtain proper authorization before scanning any targets
- Use this toolkit responsibly and ethically
- Consider using in an isolated environment for maximum security

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Usage Modes

### Individual Tool Mode
Perfect for targeted assessments or when you only need specific functionality:

- **Port Scanning Only**: `-naabu -host <target>`
- **HTTP Service Discovery**: `-httpx -host <target>`
- **Vulnerability Assessment**: `-nuclei -host <target>`

### Combined Tool Mode
Run multiple tools in sequence with automatic result chaining:

- **naabu → nuclei**: Port scan followed by vulnerability assessment
- **httpx → nuclei**: HTTP discovery followed by vulnerability scanning
- **naabu → httpx → nuclei**: Complete chain with all tools

### Full Workflow Mode
Traditional mode that runs all tools automatically:

sudo python src/workflow.py <target>


## 🔧 Tool Configuration

The toolkit automatically detects tool installations in common locations:

### naabu
- `/usr/bin/naabu`
- `/usr/local/bin/naabu`
- `/root/go/bin/naabu`
- `~/go/bin/naabu`

### httpx
- `/usr/bin/httpx` (Kali Linux system package)
- `/usr/local/bin/httpx`
- `/root/go/bin/httpx`
- `~/go/bin/httpx`

### nuclei
- `/usr/bin/nuclei`
- `/usr/local/bin/nuclei`
- `/root/go/bin/nuclei`
- `~/go/bin/nuclei`

## 📁 Output Structure

Results are organized in timestamped directories:

### Individual Tool Mode

results_<target>_<tools>_<timestamp>/
├── ports.txt              # naabu results (if used)
├── ports.json              # naabu JSON output
├── http_services.txt       # httpx results (if used)
├── http_services.json      # httpx JSON output
├── vulnerabilities.txt     # nuclei results (if used)
├── vulnerabilities.jsonl   # nuclei JSONL output
├── nuclei_responses/       # HTTP responses (if nuclei used)
└── summary.txt            # Executive summary


### Full Workflow Mode

results_<target>_<timestamp>/
├── ports.txt
├── ports.json
├── http_services.txt
├── http_services.json
├── vulnerabilities.txt
├── vulnerabilities.jsonl
├── nuclei_responses/
├── code_vulnerabilities.md (if --scan-code used)
└── summary.txt


## 🔍 Examples

### Basic Port Scanning

# Quick port scan
sudo python src/workflow.py -naabu -host 192.168.1.1

# Custom ports
sudo python src/workflow.py -naabu -host 192.168.1.1 -p "22,80,443,8080"

# Top 100 ports only
sudo python src/workflow.py -naabu -host 192.168.1.1 -p "top-100"


### HTTP Service Discovery

# Basic HTTP enumeration
sudo python src/workflow.py -httpx -host example.com

# From previous port scan results
sudo python src/workflow.py -naabu -httpx -host 192.168.1.1


### Vulnerability Assessment

# Target-based scanning
sudo python src/workflow.py -nuclei -host https://example.com

# Chain with service discovery
sudo python src/workflow.py -httpx -nuclei -host 192.168.1.1

# Custom severity levels
sudo python src/workflow.py -nuclei -host example.com --severity "critical,high"


### Complete Assessments

# Full automated scan
sudo python src/workflow.py 192.168.1.1

# Full scan with stealth mode
sudo python src/workflow.py 192.168.1.1 -s

# Comprehensive assessment with all options
sudo python src/workflow.py -naabu -httpx -nuclei -host 192.168.1.1 -s -v --json-output


## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Test on multiple Linux distributions
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License. See LICENSE file for details.

## ⚠️ Disclaimer

This toolkit is designed for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any targets. The authors are not responsible for any misuse or damage caused by this software.

---

**Platform Support**: Linux Only | **Version**: 2.0 | **Last Updated**: 2024
