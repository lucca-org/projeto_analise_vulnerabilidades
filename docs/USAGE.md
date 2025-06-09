# Usage Guide - Linux Vulnerability Analysis Toolkit

This guide covers all usage modes and options available in the vulnerability analysis toolkit.

## 🎯 Usage Modes

### 1. Individual Tool Mode (Recommended)

Run specific tools independently for targeted assessments:

#### Port Scanning with naabu
```bash
# Basic port scan
sudo python src/workflow.py -naabu -host 192.168.0.5

# Custom ports
sudo python src/workflow.py -naabu -host 192.168.0.5 -p "80,443,8080,8443"

# Port ranges
sudo python src/workflow.py -naabu -host 192.168.0.5 -p "1-1000"

# Top ports only
sudo python src/workflow.py -naabu -host 192.168.0.5 -p "top-100"

# Stealth mode
sudo python src/workflow.py -naabu -host 192.168.0.5 -s

# JSON output
sudo python src/workflow.py -naabu -host 192.168.0.5 --json-output
```

#### HTTP Service Discovery with httpx
```bash
# Basic HTTP enumeration
sudo python src/workflow.py -httpx -host example.com

# Target from file
echo "192.168.1.1:80" > targets.txt
sudo python src/workflow.py -httpx -host targets.txt

# With verbose output
sudo python src/workflow.py -httpx -host example.com -v

# Stealth mode (slower, less detectable)
sudo python src/workflow.py -httpx -host example.com -s
```

#### Vulnerability Scanning with nuclei
```bash
# Basic vulnerability scan
sudo python src/workflow.py -nuclei -host https://example.com

# Custom severity filter
sudo python src/workflow.py -nuclei -host example.com --severity "critical,high"

# Specific template tags
sudo python src/workflow.py -nuclei -host example.com --tags "cve,rce"

# Custom templates
sudo python src/workflow.py -nuclei -host example.com -t "/path/to/templates/"

# Stealth mode
sudo python src/workflow.py -nuclei -host example.com -s
```

### 2. Combined Tool Mode

Chain multiple tools together for comprehensive assessments:

#### naabu + nuclei (Port Scan → Vulnerability Assessment)
```bash
# Basic combination
sudo python src/workflow.py -naabu -nuclei -host 192.168.0.5

# With custom ports and severity
sudo python src/workflow.py -naabu -nuclei -host 192.168.0.5 -p "80,443,8080" --severity "critical,high"

# Stealth mode
sudo python src/workflow.py -naabu -nuclei -host 192.168.0.5 -s
```

#### httpx + nuclei (Service Discovery → Vulnerability Assessment)
```bash
# Basic combination
sudo python src/workflow.py -httpx -nuclei -host example.com

# With verbose output
sudo python src/workflow.py -httpx -nuclei -host example.com -v

# JSON output for all tools
sudo python src/workflow.py -httpx -nuclei -host example.com --json-output
```

#### All Three Tools (Complete Chain)
```bash
# Full tool chain: naabu → httpx → nuclei
sudo python src/workflow.py -naabu -httpx -nuclei -host 192.168.0.5

# With all options
sudo python src/workflow.py -naabu -httpx -nuclei -host 192.168.0.5 -p "1-10000" --severity "critical,high,medium" -s -v --json-output

# Custom output directory
sudo python src/workflow.py -naabu -httpx -nuclei -host 192.168.0.5 -o my_assessment_results
```

### 3. Full Workflow Mode (Legacy)

Traditional mode that automatically runs all tools:

```bash
# Basic full scan
sudo python src/workflow.py 192.168.0.5

# Domain scanning
sudo python src/workflow.py example.com

# Network range
sudo python src/workflow.py 192.168.1.0/24

# With additional options
sudo python src/workflow.py 192.168.0.5 -p "1-65535" --severity "critical,high,medium" -v
```

## 🔧 Command Line Options

### Target Specification
```bash
-host <target>              # Specify target (required for individual tool mode)
<target>                    # Positional target (for full workflow mode)
```

### Tool Selection
```bash
-naabu                      # Run naabu port scanner
-httpx                      # Run httpx service discovery
-nuclei                     # Run nuclei vulnerability scanner
```

### Tool-Specific Options
```bash
-p, --ports <ports>         # Ports for naabu (e.g., "80,443,8000-9000")
-t, --templates <path>      # Custom nuclei templates
--tags <tags>               # Nuclei template tags (default: cve)
--severity <levels>         # Nuclei severity filter (default: critical,high)
```

### Output Options
```bash
-o, --output-dir <dir>      # Custom output directory
--json-output               # Enable JSON output for all tools
-v, --verbose               # Enable verbose output
```

### Scanning Options
```bash
-s, --stealth               # Enable stealth mode (slower, less detectable)
--timeout <seconds>         # Maximum scan time (default: 3600)
```

### Advanced Options
```bash
--update-templates          # Update nuclei templates before scanning
--config-file <file>        # Use custom configuration file
--force-tools               # Continue even if tool checks fail
--report-only <dir>         # Generate report for existing results
```

## 📊 Output Examples

### Individual Tool Mode Output
```
results_192.168.0.5_naabu_20241206_143022/
├── ports.txt               # Human-readable port scan results
├── ports.json              # Machine-readable JSON output
└── summary.txt             # Executive summary
```

### Combined Tool Mode Output
```
results_192.168.0.5_naabu_httpx_nuclei_20241206_143022/
├── ports.txt               # naabu results
├── ports.json
├── http_services.txt       # httpx results
├── http_services.json
├── vulnerabilities.txt     # nuclei results
├── vulnerabilities.jsonl
├── nuclei_responses/       # HTTP request/response data
└── summary.txt
```

## 🎨 Real-World Scenarios

### Scenario 1: Quick Port Assessment
```bash
# Quickly check what ports are open on a target
sudo python src/workflow.py -naabu -host 192.168.1.100 -p "top-1000" -v
```

### Scenario 2: Web Application Assessment
```bash
# Full web application security assessment
sudo python src/workflow.py -httpx -nuclei -host example.com --severity "critical,high,medium" -v
```

### Scenario 3: Network Range Reconnaissance
```bash
# First, discover live hosts and open ports
sudo python src/workflow.py -naabu -host 192.168.1.0/24 -p "22,80,443,8080,8443"

# Then, assess web services found
sudo python src/workflow.py -httpx -nuclei -host results_*/ports.txt
```

### Scenario 4: Stealth Assessment
```bash
# Low-profile scanning to avoid detection
sudo python src/workflow.py -naabu -httpx -nuclei -host target.example.com -s -p "top-100"
```

### Scenario 5: Comprehensive Enterprise Assessment
```bash
# Full assessment with maximum coverage
sudo python src/workflow.py -naabu -httpx -nuclei -host enterprise.example.com \
  -p "1-65535" \
  --severity "critical,high,medium,low" \
  --tags "cve,rce,sqli,xss,lfi,rfi" \
  -v \
  --json-output \
  -o enterprise_assessment_$(date +%Y%m%d)
```

## ⚡ Performance Tips

### Speed Optimization
```bash
# Fast scanning with top ports only
sudo python src/workflow.py -naabu -host <target> -p "top-100"

# Parallel assessment
sudo python src/workflow.py -naabu -host <target> &
sudo python src/workflow.py -httpx -host <target> &
wait
```

### Resource Management
```bash
# Limit concurrent operations for resource-constrained systems
sudo python src/workflow.py -naabu -nuclei -host <target> -s
```

### Large-Scale Scanning
```bash
# For multiple targets, use file input
echo "target1.com" > targets.txt
echo "target2.com" >> targets.txt
echo "192.168.1.100" >> targets.txt

# Process each target
while read target; do
  sudo python src/workflow.py -naabu -httpx -nuclei -host "$target" -o "results_$target"
done < targets.txt
```

## 🔍 Troubleshooting

### Tool Path Issues
```bash
# Check tool availability
which naabu httpx nuclei

# Add Go tools to PATH
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Force continue with missing tools (not recommended)
sudo python src/workflow.py -naabu -host <target> --force-tools
```

### Permission Issues
```bash
# Ensure running with appropriate privileges
sudo python src/workflow.py -naabu -host <target>

# Check file permissions
ls -la ~/go/bin/
```

### Network Issues
```bash
# Test connectivity
ping 8.8.8.8

# Use stealth mode for restrictive networks
sudo python src/workflow.py -nuclei -host <target> -s
```

### Output Issues
```bash
# Specify custom output directory with write permissions
sudo python src/workflow.py -naabu -host <target> -o /tmp/scan_results

# Check disk space
df -h
```

## 📈 Best Practices

### 1. Progressive Scanning
Start with basic reconnaissance and progressively increase depth:
```bash
# Step 1: Port discovery
sudo python src/workflow.py -naabu -host <target> -p "top-1000"

# Step 2: Service enumeration
sudo python src/workflow.py -httpx -host <target>

# Step 3: Vulnerability assessment
sudo python src/workflow.py -nuclei -host <target>
```

### 2. Stealth Operations
```bash
# Use stealth mode for sensitive environments
sudo python src/workflow.py -naabu -nuclei -host <target> -s

# Spread scans over time
sudo python src/workflow.py -naabu -host <target> -s
sleep 300  # Wait 5 minutes
sudo python src/workflow.py -nuclei -host <target> -s
```

### 3. Documentation
```bash
# Always use descriptive output directories
sudo python src/workflow.py -naabu -httpx -nuclei -host <target> \
  -o "assessment_$(basename $target)_$(date +%Y%m%d_%H%M%S)"

# Include scan context in filenames
sudo python src/workflow.py -nuclei -host <target> \
  -o "vuln_scan_quarterly_assessment_Q4_2024"
```

### 4. Result Management
```bash
# Compress results for archival
tar -czf assessment_results_$(date +%Y%m%d).tar.gz results_*

# Generate summary reports
sudo python src/workflow.py --report-only results_target_20241206_143022/
```

---

For more detailed information, see the README.md and individual tool documentation.
