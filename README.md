# Vulnerability Analysis Toolkit

A comprehensive toolkit for automated vulnerability scanning and security analysis, integrating powerful open-source security tools.

## Features

- Automated installation of security tools (naabu, httpx, nuclei)
- Port scanning and service discovery
- HTTP service fingerprinting
- Vulnerability scanning with customizable templates
- Comprehensive reporting

## Prerequisites

- Python 3.8+
- Go 1.18+ (automated installation available)
- Linux, macOS, or Windows with WSL (Windows Subsystem for Linux)

## Quick Start

### Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/projeto_analise_vulnerabilidades.git
   cd projeto_analise_vulnerabilidades
   ```

2. Run the setup script:
   ```bash
   python index.py
   ```
   
   For Linux users with dependency issues, you can also run:
   ```bash
   chmod +x fix_deps.sh
   ./fix_deps.sh
   ```

3. Verify installation:
   ```bash
   python -c "from commands import naabu, httpx, nuclei; print('Tools ready!')"
   ```

## Usage

Run a complete vulnerability scan:

```bash
python workflow.py example.com
```

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