# 🚀 How to Run the Linux Vulnerability Analysis Toolkit

## ⚡ Quick Start Guide

### **Prerequisites**
- ✅ **Linux System Required** (Debian, Ubuntu, Kali, Arch, Fedora)
- ✅ **Python 3.8+** installed
- ✅ **Root/sudo privileges** for installation

### **Step 1: Installation**
```bash
# Navigate to the project directory
cd linux-vulnerability-toolkit

# Run the enhanced master installer (one command does everything!)
sudo python3 install/setup.py
```

### **Step 2: Validation (Recommended)**
```bash
# Verify everything is working correctly
python3 validate_installation.py
```
**Expected Result:** 95.5% success rate (only fails on Windows - expected)

### **Step 3: Run Your First Scan**
```bash
# Basic vulnerability scan
python3 run.py example.com

# Alternative using shell script
bash scripts/run_toolkit.sh example.com
```

---

## 🎯 Usage Examples

### **Basic Scans**
```bash
# Simple domain scan
python3 run.py google.com

# IP address scan
python3 run.py 192.168.1.1

# Subdomain scan
python3 run.py subdomain.example.com
```

### **Advanced Scans**
```bash
# Custom port range
python3 run.py example.com --ports 80,443,8080-9000

# Specific vulnerability templates
python3 run.py example.com --templates cves,exposures

# High severity vulnerabilities only
python3 run.py example.com --severity critical,high

# Verbose output for debugging
python3 run.py example.com --verbose
```

### **Batch Scanning**
```bash
# Scan multiple targets from file
python3 run.py --targets-file targets.txt

# Scan with custom configuration
python3 run.py example.com --config custom_config.json
```

---

## 📊 Output and Results

### **Output Location**
Results are automatically saved in timestamped directories:
```
output/results_example.com_20250604_143022/
├── ports.txt              # Discovered open ports
├── http_services.txt      # HTTP services found
├── vulnerabilities.txt    # Security vulnerabilities
├── report.html           # Comprehensive HTML report
└── report.json           # JSON data for analysis
```

### **Report Contents**
- **Port Scan Results**: Open ports and services
- **HTTP Service Discovery**: Web servers and applications
- **Vulnerability Assessment**: Security issues and CVEs
- **Risk Analysis**: Severity ratings and recommendations
- **Remediation Guidance**: How to fix discovered issues

---

## 🔧 Troubleshooting

### **Common Issues**

#### **1. Installation Problems**
```bash
# Problem: Permission denied
# Solution: Use sudo
sudo python3 install/setup.py

# Problem: Platform not supported
# Solution: Must use Linux (not Windows/macOS)
```

#### **2. Tools Not Found**
```bash
# Check if tools are installed
which naabu httpx nuclei

# Reinstall if missing
sudo python3 install/setup.py
```

#### **3. Python Issues**
```bash
# Check Python version (3.8+ required)
python3 --version

# Validate Python environment
python3 scripts/autoinstall.py
```

#### **4. Validation Failures**
```bash
# Run comprehensive validation
python3 validate_installation.py

# Expected: 95.5% success rate on Linux
# Only expected failure: Platform check on Windows
```

### **Complete Reset**
```bash
# Clean installation and start fresh
rm -rf ~/go/bin/{naabu,httpx,nuclei}
sudo python3 install/setup.py
python3 validate_installation.py
```

---

## 🎉 Success Indicators

### **Installation Success**
- ✅ Validation score: 95.5% (21/22 checks pass)
- ✅ Tools available: `naabu`, `httpx`, `nuclei`
- ✅ Python environment working
- ✅ No syntax errors in master installer

### **Scan Success**
- ✅ Target resolution successful
- ✅ Ports discovered and enumerated
- ✅ HTTP services identified
- ✅ Vulnerability templates executed
- ✅ Reports generated in `output/` directory

---

## 💡 Pro Tips

1. **Always validate** after installation: `python3 validate_installation.py`
2. **Use verbose mode** for debugging: `--verbose`
3. **Check output directory** for results after each scan
4. **Run on dedicated security systems** (Kali Linux recommended)
5. **Obtain proper authorization** before scanning any targets

---

## 🚀 You're Ready!

The toolkit is now ready for vulnerability scanning. Start with basic scans and gradually explore advanced features as you become familiar with the system.

**Happy Scanning! 🛡️**
