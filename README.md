# Vulnerability Analysis Toolkit

A comprehensive toolkit for automated vulnerability scanning and security analysis designed for Kali Linux and Debian-based systems. This toolkit integrates powerful open-source security tools from ProjectDiscovery.

## Features

- **Port Scanning**: Fast port discovery using naabu
- **HTTP Service Discovery**: Detect and fingerprint web services with httpx
- **Vulnerability Scanning**: Find security vulnerabilities using nuclei templates
- **Comprehensive Reporting**: Generate detailed reports in multiple formats
- **Cross-platform Compatible**: Designed for Kali Linux and Debian-based systems

## Prerequisites

- Debian-based Linux (Kali Linux recommended)
- Python 3.8+
- Bash shell
- Internet connection for tool installation
- Root/sudo access for dependencies

## Installation

### Option 1: Recommended Single-Script Setup (Kali/Debian)

This is the recommended installation method that installs and configures all necessary tools:

```bash
git clone https://github.com/your-username/vulnerability-analysis-toolkit.git
cd vulnerability-analysis-toolkit
chmod +x setup_tools.sh
./setup_tools.sh
```

The script will:
- Install required system dependencies
- Install Go programming language (if not already installed)
- Install ProjectDiscovery tools (naabu, httpx, nuclei)
- Update nuclei templates for vulnerability scanning
- Configure your PATH environment variable
- Install Python dependencies
- Verify all tools are working properly

### Option 2: Quick Setup (Network Restrictions/Limited Permissions)

If you have network restrictions or limited permissions on your system:

```bash
chmod +x quick_setup.sh
./quick_setup.sh
```

### Option 3: Fix Installation Issues

If you encounter problems with the installation:

```bash
# Fix dependency issues
chmod +x fix_installation.sh
./fix_installation.sh

# Or for specific package manager issues
chmod +x fix_dpkg.sh
./fix_dpkg.sh
```

## Usage

### Basic Scan

```bash
# Simple scan of a domain
python3 workflow.py example.com

# Scan an IP address
python3 workflow.py 192.168.1.1

# Scan with verbose output
python3 workflow.py example.com -v
```

### Advanced Options

```bash
# Scan specific ports
python3 workflow.py example.com -p 80,443,8000-8100

# Focus on specific vulnerability types
python3 workflow.py example.com --tags cve,rce,injection

# Only report critical and high severity vulnerabilities
python3 workflow.py example.com --severity critical,high

# Complete example with multiple options
python3 workflow.py example.com -p 80,443,8000-8100 --tags cve,rce --severity critical,high -v --timeout 7200
```

### Only Generate Reports

If you've already run a scan and just want to regenerate the reports:

```bash
python3 workflow.py example.com --report-only results_example.com_20250520_123456
```

### Command-line Arguments

| Argument | Description |
|----------|-------------|
| `target` | Target to scan (IP address or domain) |
| `-p, --ports` | Specify ports to scan (e.g., `80,443,8000-9000`) |
| `-t, --templates` | Custom nuclei templates (e.g., `/path/to/templates` or built-in template categories) |
| `--tags` | Nuclei template tags (default: `cve`) - e.g., `cve,rce,wordpress` |
| `--severity` | Vulnerability severity filter (default: `critical,high`) |
| `-v, --verbose` | Enable verbose output |
| `-o, --output-dir` | Custom output directory |
| `--update-templates` | Update nuclei templates before scanning |
| `--timeout` | Maximum scan time in seconds (default: 3600) |
| `--report-only` | Generate report for existing results directory |

## Reports and Output

The tool automatically generates detailed reports in multiple formats:

### Report Formats

- **HTML Report** (`report.html`) - Interactive report viewable in any web browser
- **Markdown Report** (`report.md`) - Portable format for documentation
- **JSON Data** (`results.json`) - Machine-readable format for integration with other tools
- **Text Summary** (`summary.txt`) - Quick overview of findings

### Output Directory Structure

Each scan creates a timestamped results directory with the following structure:

```
results_example.com_20250520_123456/
├── ports.txt             # List of open ports
├── ports.json            # Detailed port scan results (JSON)
├── http_services.txt     # List of HTTP services
├── http_services.json    # Detailed HTTP service information (JSON)
├── vulnerabilities.txt   # Human-readable vulnerability findings
├── vulnerabilities.jsonl # Detailed vulnerability data (JSONL)
├── summary.txt           # Summary report
├── report.html           # HTML report (if supported)
├── report.md             # Markdown report (if supported)
└── nuclei_responses/     # HTTP requests/responses for vulnerabilities
```

> **Note:** Advanced report formats (HTML, Markdown) require optional Python libraries. Install them with `pip install jinja2 markdown rich`

## Troubleshooting

### Common Issues and Solutions

#### Tools Not Found

If you receive errors about missing tools:

```
[-] One or more required tools are not installed.
```

Try running the setup script again:
```bash
./setup_tools.sh
```

Or check if the tools are in your PATH:
```bash
echo $PATH | grep -q "$HOME/go/bin" || echo "go/bin is not in PATH"
```

#### Permission Denied Errors

If you see permission errors when running the tools:

```
chmod +x ~/go/bin/*
```

#### Reports Not Generating Correctly

If you're missing the HTML or Markdown reports:

```bash
pip install jinja2 markdown rich
```

#### Scan Takes Too Long

Use more specific options to limit the scope:

```bash
python3 workflow.py example.com --ports 80,443 --severity critical --timeout 1800
```

#### Dependency Issues with naabu

If naabu fails to install or run, try fixing dependencies:

```bash
sudo apt-get install -y libpcap-dev
```

Or use the fix_installation.sh script:

```bash
./fix_installation.sh
```

## Project Structure

- `commands/`: Python modules for each security tool
- `workflow.py`: Main scanning orchestration script
- `reporter.py`: Report generation module
- `utils.py`: Utility functions
- `*.sh`: Installation and setup scripts

## Dependencies

This toolkit utilizes the following open-source tools:
- [naabu](https://github.com/projectdiscovery/naabu): Port scanning
- [httpx](https://github.com/projectdiscovery/httpx): HTTP service probing
- [nuclei](https://github.com/projectdiscovery/nuclei): Vulnerability scanning

## Troubleshooting

If you encounter installation issues:
1. Try running `./fix_dpkg.sh` to repair any package manager problems
2. Make sure you have internet connectivity
3. Check if Go is installed with `go version`
4. Verify tool installation with `~/go/bin/nuclei -version`

Custom scan with specific options:

```bash
python workflow.py example.com --ports 80,443,8000-8100 --templates cves/ --severity critical,high --verbose
```

## Directory Structure

- `commands/` - Python modules for each security tool
- `documentacao/` - Documentation and usage guides
- `results_*/` - Scan results (created during scans)

## Reporting

For each scan, a summary report is generated with findings organized by severity.

## License

MIT