# Linux Vulnerability Analysis Toolkit Documentation

> **⚠️ NOTICE: This documentation has been superseded**
> 
> This file contains legacy installation instructions that have been **completely automated** by the new master installer architecture. Please use the current installation method documented in the main [README.md](../README.md).

## Quick Installation (Current Method)

The toolkit now features a **single-point master installer** that handles everything automatically:

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-vulnerability-toolkit.git
cd linux-vulnerability-toolkit

# Run the master installation orchestrator (requires root privileges)
sudo python3 install/setup.py
```

The master installer automatically handles:
- ✅ Linux platform verification and distribution detection
- ✅ Root/sudo permission enforcement 
- ✅ System package installation (curl, wget, git, build-essential, etc.)
- ✅ Go programming environment setup with PATH management
- ✅ Security tools installation (naabu, httpx, nuclei)
- ✅ Python dependencies and virtual environment setup
- ✅ Configuration optimization and bash aliases creation
- ✅ Complete system verification with functionality testing

## Validation

After installation, verify everything is working:

```bash
# Run installation validator
python3 validate_installation.py

# Run functionality verification
python3 verify_installation.py

# Check tool availability
naabu -version
httpx -version  
nuclei -version
```

## Documentation Structure

For current documentation, please refer to:
- **[Main README.md](../README.md)** - Current installation and usage instructions
- **[TRANSFORMATION_SUMMARY.md](../TRANSFORMATION_SUMMARY.md)** - Architecture overview
- **[DEPLOYMENT_VALIDATION_REPORT.md](../DEPLOYMENT_VALIDATION_REPORT.md)** - Pre-deployment validation results

---

## Legacy Content (Archived)

*The content below represents the previous manual installation process and is preserved for historical reference only. **DO NOT** use these instructions as they have been superseded by the automated master installer.*

## Usage

### Basic Scan

```bash
# Simple scan of a domain
python workflow.py example.com

# Scan an IP address
python workflow.py 192.168.1.1

# Scan with verbose output
python workflow.py example.com -v
```

### Advanced Options

```bash
# Scan specific ports
python workflow.py example.com --ports 80,443,8000-8100

# Focus on specific vulnerability types
python workflow.py example.com --tags cve,rce,injection

# Only report critical and high severity vulnerabilities
python workflow.py example.com --severity critical,high

# Complete example with multiple options
python workflow.py example.com --ports 80,443,8000-8100 --tags cve,rce --severity critical,high -v --timeout 7200
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
| `--auto-config` | Use automatic configuration based on system capabilities |
| `--scan-code` | Scan web application code for vulnerabilities |
| `--config-file` | Use custom configuration file |

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