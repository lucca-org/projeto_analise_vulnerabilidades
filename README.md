# MTScan - Linux Vulnerability Analysis Toolkit

**[English](#english) | [Português Brasileiro](#português-brasileiro)**

---

## English

A comprehensive security toolkit for automated vulnerability scanning and analysis, designed **exclusively for Linux systems**.

### Recent Enhancements

**LATEST UPDATE: Interactive Menu and Flag Selection System**
- **Enhanced Interactive Menu**: Completely redesigned user interface with intuitive navigation
- **Advanced Flag Selection System**: Comprehensive flag configuration for each scanning tool
- **Tool Path Resolution**: Improved detection of security tools across different Linux installations
- **Network Connectivity Validation**: Multi-method connectivity testing with detailed feedback
- **Clean Output Formatting**: Professional text-only output across all interfaces

**Previous Updates:**
- **Internet Connectivity Check**: Fixed and re-enabled in setup.py for Linux systems
- **Network Connectivity Enforcement**: Automatic scan termination on network failure
- **Port Information Display**: Real-time port range information during scans
- **Enhanced Installation**: Master installer with comprehensive validation
- **Multi-Mode Support**: Interactive menu and direct command-line workflows

### Overview

MTScan integrates powerful security tools (naabu, httpx, nuclei) into a streamlined workflow for vulnerability scanning. It provides an interactive menu system that guides users through the entire process from target selection to vulnerability detection and report generation.

**IMPORTANT: This toolkit only works on Linux systems due to the security tools' dependencies on Linux kernel features and libraries.**

### Key Components

#### Interactive Menu (mtscan.py)
The main interface provides access to all toolkit features:
- **Scan Operations**: Port discovery, HTTP service analysis, and vulnerability assessment
- **Management Operations**: View results, update templates, configure tools, and install updates
- **Tool Status Check**: Automatic verification of required security tools
- **Target Validation**: Comprehensive input validation with helpful suggestions

#### Scanning Workflow
Each scan type follows a structured workflow:
1. **Target Selection**: IP address, domain name, or URL input with validation
2. **Flag Configuration**: Interactive selection of tool-specific parameters
3. **Scan Execution**: Real-time progress monitoring and output display
4. **Results Storage**: Automatic saving of scan results for later analysis

### Features

- **Comprehensive Scanning Suite**: Three integrated scanning tools:
  - **Naabu**: Fast port discovery and service detection
  - **HTTPX**: Web service identification and technology fingerprinting
  - **Nuclei**: Vulnerability detection with 5000+ pre-built templates

- **Advanced Flag Selection System**:
  - **Naabu Flags**: Port ranges, scan types, rate limiting, threading, and more
  - **HTTPX Flags**: Technology detection, status codes, redirects, custom headers
  - **Nuclei Flags**: Template selection, severity filtering, concurrency control

- **User Experience Enhancements**:
  - **Clear Visual Formatting**: Consistent border styles and section headers
  - **Real-time Progress Updates**: Live feedback during scan operations
  - **Comprehensive Help System**: Contextual guidance for all scan operations
  - **Input Validation**: Robust error prevention with helpful feedback

- **Technical Features**:
  - **Tool Path Resolution**: Intelligent detection across different Linux installations
  - **Network Validation**: Multi-method connectivity testing (DNS, Socket, Ping, HTTP)
  - **Error Handling**: Graceful recovery from common failure scenarios
  - **Report Generation**: Structured output in multiple formats (text, JSON, CSV)

### Supported Linux Distributions

- **Kali Linux** (Recommended for security testing)
- **Debian**
- **Ubuntu**
- **Arch Linux**
- **Fedora/CentOS/RHEL** (Basic support)

### System Requirements

- **Operating System**: Linux (64-bit) only - Windows, macOS, and WSL are NOT supported
- **Python**: 3.6 or higher (3.8+ recommended)
- **Memory**: Minimum 2GB RAM (4GB+ recommended for nuclei scanning)
- **Storage**: 1GB free space for tools and results
- **Network**: Internet connection required for installation, updates, and scanning
- **Privileges**: Root/sudo access required for installation and some scanning features
- **Go Language**: Optional - automatically installed by the setup script if needed

### Quick Start

1. **Clone Repository**:
   ```bash
   # Replace 'yourusername' with the actual repository owner
   git clone https://github.com/yourusername/MTScan.git
   cd MTScan
   ```

2. **Run Installation Script**:
   ```bash
   sudo python3 install/setup.py
   ```

3. **Launch Interactive Menu**:
   ```bash
   python3 mtscan.py
   ```

4. **Run a Direct Scan** (Alternative to menu):
   ```bash
   python3 src/workflow.py -naabu -host example.com
   ```

## Installation

### Comprehensive Installation

The toolkit features a **single-point master installer** that handles everything automatically:

```bash
# Run the master installation script (requires root privileges)
sudo python3 install/setup.py
```

The installation process includes:
- Linux platform verification and distribution detection
- System package installation (curl, wget, git, build-essential, python3-pip)
- Go programming environment setup (if needed)
- Security tools installation (naabu, httpx, nuclei)
- Python dependencies configuration
- Path configuration and environment setup

### Manual Installation

For systems where the automatic installer encounters issues:

1. **Install System Prerequisites**:
   ```bash
   # Debian/Ubuntu/Kali
   sudo apt update
   sudo apt install -y curl wget git build-essential python3-pip golang-go libpcap-dev

   # Arch Linux
   sudo pacman -Sy curl wget git base-devel python-pip go libpcap
   ```

2. **Install Security Tools**:
   ```bash
   # Install naabu
   go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
   
   # Install httpx
   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
   
   # Install nuclei
   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   ```

3. **Configure PATH**:
   ```bash
   echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
   source ~/.bashrc
   ```

4. **Install Python Dependencies**:
   ```bash
   pip3 install -r config/requirements.txt
   ```


## Architecture and Code Structure

MTScan is organized into a modular architecture with clear separation of concerns:

```
MTScan/
├── mtscan.py                # Main interactive menu interface
├── commands/               # Tool-specific command wrappers
│   ├── __init__.py
│   ├── httpx.py            # HTTPX command implementation
│   ├── naabu.py            # Naabu command implementation
│   └── nuclei.py           # Nuclei command implementation
├── src/                    # Core functionality
│   ├── workflow.py         # Main scanning workflow
│   ├── utils.py            # Common utility functions
│   ├── reporter.py         # Report generation
│   ├── config_manager.py   # Configuration management
│   └── network_test.py     # Network connectivity testing
├── install/                # Installation scripts
│   └── setup.py            # Main installer script
├── config/                 # Configuration files
│   └── requirements.txt    # Python dependencies
└── docs/                   # Documentation
    └── documentacao/       # Detailed documentation files
```

### Key Components

1. **mtscan.py**: The main entry point with the interactive menu system
   - Provides a user-friendly interface for all toolkit features
   - Handles tool status checking, target validation, and flag selection
   - Orchestrates the execution of scan workflows

2. **commands/**: Tool-specific wrapper modules
   - Each module (naabu.py, httpx.py, nuclei.py) wraps a specific security tool
   - Handles parameter sanitization, command construction, and error handling
   - Provides flexible flag and configuration management

3. **src/workflow.py**: Core scanning engine
   - Manages the execution of individual tools in sequence
   - Handles output collection, formatting, and storage
   - Implements error recovery and progress tracking

4. **src/utils.py**: Common utilities
   - Path resolution for security tools
   - Command execution helpers
   - Network connectivity validation

### Workflow Architecture

MTScan implements a structured workflow for security scanning:

1. **Tool Detection Phase**
   - Identifies installed security tools using multiple detection methods
   - Verifies tool functionality with version/help checks
   - Provides actionable feedback for missing tools

2. **Target Validation Phase**
   - Validates target input (IP, domain, URL)
   - Normalizes and prepares target for scanning
   - Provides helpful guidance for invalid inputs

3. **Flag Selection Phase**
   - Interactive selection of tool-specific parameters
   - Validation of parameter combinations
   - Configuration summary before execution

4. **Execution Phase**
   - Construction of command-line arguments
   - Real-time output streaming and monitoring
   - Error handling and recovery

5. **Results Management Phase**
   - Structured storage of scan results
   - Comprehensive reporting with key findings
   - Results browsing and analysis

## Usage

### How to Run the Project

#### **Step 1: Installation (Linux Only)**

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
cd linux-vulnerability-toolkit

# Install everything with one command (requires root privileges)
sudo python3 install/setup.py
```

#### **Step 2: Validation (Recommended)**

```bash
# Verify installation is working correctly
python3 tests/validate_installation.py
```

#### **Step 3: Run Vulnerability Scans**

**Basic Scan:**

```bash
# Simple scan
python3 run.py <target>

# Example
python3 run.py example.com
```

**Using Shell Script:**

```bash
# Alternative launcher
bash scripts/run_toolkit.sh <target>
```

### Advanced Usage Options

```bash
# Specify custom ports
python3 run.py --target example.com --ports 80,443,8080-8090

# Use specific nuclei templates
python3 run.py --target example.com --templates cves,exposures

# Comprehensive scan with filtering
python3 run.py --target example.com --ports top-1000 --tags cve,exposure --severity critical,high

# Verbose output for debugging
python3 run.py --target example.com --verbose
```

### Port Format Handling

When scanning with naabu, MTScan supports several port specification formats:

1. **Top Ports Format**: Scans the most common N ports
   - Syntax: `top-N` (e.g., `top-100`, `top-1000`, `top-5000`)
   - Example: When selecting "Top 100 ports" in the interactive menu

2. **Range Format**: Scans a range of consecutive ports
   - Syntax: `start-end` (e.g., `1-1000`, `8000-9000`) 
   - Example: When selecting "Port range" in the interactive menu

3. **Specific Ports Format**: Scans only listed ports
   - Syntax: `port1,port2,port3` (e.g., `80,443,8080`)
   - Example: When selecting "Specific ports" in the interactive menu

4. **All Ports**: Scans every possible port
   - Syntax: `1-65535`
   - Example: When selecting "All ports" in the interactive menu

These port formats are automatically converted to the correct naabu command-line arguments when executing scans.

## Usage Guide

### Interactive Menu Interface

MTScan's primary interface is the interactive menu system, launched by running:

```bash
python3 mtscan.py
```

The interactive menu provides:
1. **Tool Status Check**: Verifies that all required security tools are installed
2. **Main Menu Options**: Scan operations and management functions
3. **Guided Workflow**: Step-by-step process for each scan type

#### Main Menu Options

```
SCAN OPERATIONS:
============================================================
  [1] Port Discovery Scan      (naabu)
      Fast port enumeration and service detection

  [2] HTTP Service Analysis    (httpx)
      Web service discovery and technology detection

  [3] Vulnerability Assessment (nuclei)
      Security vulnerability scanning with 5000+ templates

MANAGEMENT OPERATIONS:
============================================================
  [4] View Previous Results
      Browse and analyze past scan results

  [5] Update Nuclei Templates
      Download latest vulnerability templates

  [6] Tool Configuration
      Configure scanning parameters and settings

  [7] Install/Update Tools
      Install or update security scanning tools

  [8] Help & Documentation
      View usage guides and tool documentation

  [0] Exit Program
============================================================
```

### Scan Workflow

Each scan option follows a consistent workflow:

#### 1. Target Selection

Enter an IP address, domain name, or URL:
```
TARGET SPECIFICATION:
Enter your scan target. Examples:
  - IP Address: 192.168.1.100
  - Domain: example.com
  - URL: https://example.com (domain will be extracted)
  - Localhost: 127.0.0.1 or localhost

TIP: Use 'help' for target format examples
```

#### 2. Flag Configuration

Each tool has specific flags that can be configured:

**Naabu Port Scanner Flags**:
- `-p` - Ports to scan (e.g., '80,443,8000-9000')
- `-s` - Stealth mode (reduces rate and uses SYN scan)
- `-t` - Threads/Concurrency
- `-r` - Rate limit (packets per second)
- `-e` - Exclude specific ports
- `-T` - Timeout per port (milliseconds)
- `-v` - Verbose output
- Top ports selection (e.g., top 100, top 1000) is available through the interactive menu

**HTTPX Service Detection Flags**:
- `-t` - Title extraction
- `-s` - Status code display
- `-T` - Technology detection
- `-w` - Web server information
- `-f` - Follow HTTP redirects
- `-r` - Rate limit (requests per second)

**Nuclei Vulnerability Scanner Flags**:
- `-t` - Custom templates/template directory
- `-T` - Template tags (e.g., cve, rce, sqli)
- `-s` - Severity filter (critical, high, medium, low)
- `-e` - Exclude tags
- `-c` - Concurrency/parallel templates

#### 3. Scan Execution

After confirming the configuration, the scan will execute with real-time output:
```
SCAN CONFIGURATION SUMMARY
============================================================
[TOOL]           NAABU
[TARGET]         example.com
[SAVE OUTPUT]    ENABLED (always)
[OUTPUT FORMAT]  TEXT (default)
[REAL-TIME]      ENABLED
[FLAGS COUNT]    3

[ACTIVE FLAGS]
  + ports: top-1000
  + threads: 50
  + naabu_verbose: True
============================================================

[READY TO START] All parameters configured
```

### Practical Examples

Here are some practical examples of how to use MTScan for different scanning scenarios:

#### Basic Vulnerability Assessment Workflow:

1. **Step 1: Port Discovery**
   ```bash
   # Find open ports on a target
   python3 src/workflow.py -naabu -host example.com --top-ports 1000
   ```

2. **Step 2: HTTP Service Detection**
   ```bash
   # Analyze HTTP services on discovered ports
   python3 src/workflow.py -httpx -host example.com --title --tech-detect --web-server
   ```

3. **Step 3: Vulnerability Scanning**
   ```bash
   # Scan for vulnerabilities with nuclei
   python3 src/workflow.py -nuclei -host example.com --severity critical,high
   ```

#### Targeted Scanning Examples:

**Web Application Scanning:**
```bash
# Focus on web application vulnerabilities
python3 src/workflow.py -nuclei -host example.com --tags cve,oast,sqli,xss,rce
```

**Infrastructure Scanning:**
```bash
# Focus on infrastructure vulnerabilities
python3 src/workflow.py -nuclei -host example.com --tags default-login,exposed-panel,misconfig
```

**Stealth Mode Scanning:**
```bash
# Lower intensity scanning for IDS/IPS evasion
python3 src/workflow.py -naabu -host example.com -s --rate 10
```

#### Interactive Menu Workflow:

For a guided experience, use the interactive menu:
```bash
# Launch the interactive menu
python3 mtscan.py
```

Then follow the on-screen prompts to:
1. Select a scan type (Naabu, HTTPX, Nuclei)
2. Enter target information
3. Configure scan parameters
4. Review and confirm the scan settings
```

### Command Line Usage

For automated scanning or integration with scripts, you can bypass the interactive menu:

```bash
# Run port discovery scan
python3 src/workflow.py -naabu -host example.com -p 80,443,8080-8090

# Run port discovery with top ports
python3 src/workflow.py -naabu -host example.com --top-ports 1000

# Run HTTP service detection
python3 src/workflow.py -httpx -host example.com --title --tech-detect

# Run vulnerability scan
python3 src/workflow.py -nuclei -host example.com --severity critical,high
```

Available command line arguments:

**General Options**:
- `-host TARGET`: Target host (domain, URL, or IP address)
- `-s`: Enable stealth mode scanning
- `--save-output`: Save results to file (enabled by default)
- `--json-output`: Output in JSON format

**Naabu Port Scanner Options**:
- `-p PORTS`: Ports to scan (e.g. 80,443,1000-2000)
- `--top-ports N`: Scan top N most common ports
  - **Note**: Use either `-p` OR `--top-ports`, not both at once, to avoid conflicts
- `--threads N`: Number of threads to use
- `--rate N`: Packets per second rate limit
- `--scan-type TYPE`: Scan type (syn/connect)
- `--exclude-ports PORTS`: Exclude specific ports from scan

**HTTPX Options**:
- `--title`: Extract page titles
- `--status-code`: Show status codes
- `--tech-detect`: Enable technology detection
- `--follow-redirects`: Follow HTTP redirects
- `--content-length`: Show response content length
- `--response-time`: Show response time
- `--web-server`: Show web server information

**Nuclei Options**:
- `-t TEMPLATES`: Templates to use
- `--tags TAGS`: Template tags to use
- `--severity LEVEL`: Filter by severity (critical,high,medium,low)
- `--exclude-tags TAGS`: Tags to exclude
- `--concurrency N`: Number of concurrent tasks

## Development and Customization

### Adding New Features

MTScan is designed to be modular and extensible. To add new features:

1. **New Tool Integration**:
   - Create a new wrapper module in the `commands/` directory
   - Implement the required flag handling and command construction
   - Update the menu interface in `mtscan.py` to include the new option

2. **Enhanced Reporting**:
   - Modify the report generation in `src/reporter.py`
   - Add new output formats or visualization options
   - Extend the results analysis functionality

### Customizing Flag Options

To modify the available flags for each tool:

1. Locate the respective flag function in `mtscan.py`:
   - `get_naabu_flags()` for port scanning
   - `get_httpx_flags()` for HTTP service detection
   - `get_nuclei_flags()` for vulnerability scanning

2. Add or modify flag options in the respective function
   - Use the existing pattern for flag selection and validation
   - Update the flag mapping in the `run_scan()` function

## Troubleshooting

### Common Issues

#### Tool Detection Problems

If MTScan cannot find installed security tools:

```
[MISSING] NAABU   Not found in system PATH
[MISSING] HTTPX   Not found in system PATH
[MISSING] NUCLEI  Not found in system PATH
```

**Solutions**:
1. Ensure tools are installed: `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`
2. Add Go bin directory to PATH: `export PATH=$PATH:~/go/bin`
3. Use option [7] in the main menu to install/update tools

#### Network Connectivity Issues

If scans fail due to network problems:

**Solutions**:
1. Verify internet connectivity: `ping 8.8.8.8`
2. Check DNS resolution: `nslookup example.com`
3. Ensure no firewall rules are blocking the tools

#### Permission Errors

If you encounter permission issues:

**Solutions**:
1. For SYN scans: Run with sudo or select Connect scan type
2. For file access errors: Check directory permissions
3. For libpcap errors: Install libpcap-dev package

#### Troubleshooting Port Format Issues

If you encounter errors related to port formats, such as:
```
[FTL] Could not create runner: could not parse ports: could not read ports: invalid port number: 'top'
```
or
```
[FTL] Could not create runner: could not parse ports: invalid top ports option
```

Make sure you're using the correct port specification format:

- With interactive menu: Select option 3 for "Top ports" and enter a number (e.g., 100, 1000)
- With command line: Use `--top-ports 1000` instead of `-p top-1000`
- Important: Never use both `-p` and `--top-ports` flags together - this causes the "invalid top ports option" error

Naabu requires the top ports flag (`-top-ports N`) for scanning top N ports, which is automatically handled when using the interactive menu or workflow.py correctly.

#### HTTPX Command Format Issues

If you encounter an error like:
```
Error: No such option: -u
```

This happens because HTTPX expects the target to be provided directly without a flag:

**Correct format**:
```
httpx example.com
```

**Incorrect format**:
```
httpx -u example.com
```

The toolkit has been updated to use the correct format. If you encounter this error:
1. Make sure you're using the latest version of this toolkit
2. If modifying the code, remember that targets should be passed to HTTPX without a flag
3. For multiple targets, use the `-l` flag with a file containing one target per line

#### Invalid Value Errors

If you encounter errors like:
```
invalid value "None" for flag -c: parse error
```

This indicates that invalid parameter values are being passed to the scanning tools. This has been fixed in recent versions, but if you encounter it:

**Solutions**:
1. Update to the latest version of MTScan
2. Restart the scan - the issue should be resolved
3. If using command line, ensure all parameter values are valid (not None or empty)
4. Use the interactive menu which has better parameter validation

#### Recent Fixes (v1.2)

**Port Flag Handling**: Fixed duplicate `-top-ports` flags that caused "invalid top ports option" errors. The system now ensures only one port specification method is used at a time.

**Timeout Optimization**: Limited maximum timeout values to 60 seconds (60,000ms) to prevent extremely long scan times and improved overall performance.

**Verbose Output**: Fixed duplicate `-v` flags in naabu commands for cleaner output and better compatibility.

**Command Construction**: Improved argument parsing and flag management to prevent conflicts between different flag sources.

**Argument Validation**: Enhanced validation to prevent None values from being passed to command-line tools, fixing "invalid value 'None'" errors.

**Duplicate Flag Prevention**: Improved logic to prevent duplicate flags (like multiple `-c` or `-rate` flags) from being passed to naabu.

## Portuguese Translations

### Português Brasileiro

MTScan é uma ferramenta de análise de vulnerabilidades Linux que integra ferramentas poderosas de segurança (naabu, httpx, nuclei) em um fluxo de trabalho simplificado. O toolkit fornece uma interface de menu interativa que guia os usuários por todo o processo, desde a seleção do alvo até a detecção de vulnerabilidades.

#### Instalação Rápida

```bash
# Clone o repositório
git clone https://github.com/yourusername/mtscan.git
cd mtscan

# Execute o script de instalação
sudo python3 install/setup.py

# Inicie a interface interativa
python3 mtscan.py
```

#### Funcionalidades Principais

- **Menu Interativo**: Interface amigável para todas as funcionalidades
- **Escaneamento Abrangente**: Detecção de portas, serviços HTTP e vulnerabilidades
- **Sistema de Seleção de Flags**: Configuração detalhada para cada ferramenta
- **Validação de Entrada**: Prevenção robusta de erros com feedback útil
- **Geração de Relatórios**: Saída estruturada em múltiplos formatos

Para documentação completa, consulte as seções em inglês acima.
