# How to Run the Linux Vulnerability Analysis Toolkit

## Quick Start

1. **Navigate to the project directory:**
   ```bash
   cd projeto_analise_vulnerabilidades
   ```

2. **Add Go tools to PATH (Required):**
   ```bash
   export PATH=$PATH:~/go/bin
   ```

3. **Launch the interactive menu:**
   ```bash
   python mtscan.py
   ```

## Alternative Methods

### Direct Script Execution
```bash
# Quick launcher
python scripts/run.py

# Direct workflow execution
python src/workflow.py <target>
```

### Command Examples
```bash
# Single target scan
python src/workflow.py example.com

# Network scan
python src/workflow.py 192.168.1.0/24

# Specific tool scan
python src/workflow.py -naabu example.com
python src/workflow.py -httpx example.com
python src/workflow.py -nuclei example.com
```

## Prerequisites

- Linux operating system
- Python 3.6+
- Go tools installed (naabu, httpx, nuclei)
- Proper PATH configuration

## Troubleshooting

If tools show as "Not installed":
1. Check if tools exist: `ls ~/go/bin/`
2. Add to PATH: `export PATH=$PATH:~/go/bin`
3. Make permanent: `echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc`

For installation issues, run:
```bash
sudo python install/setup.py
```
