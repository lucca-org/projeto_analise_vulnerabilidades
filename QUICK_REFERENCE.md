# ⚡ Quick Reference - Linux Vulnerability Toolkit

## 🚀 Essential Commands

```bash
# 1. INSTALL (Linux only, requires sudo)
sudo python3 install/setup.py

# 2. VALIDATE (should show 95.5% success rate)
python3 validate_installation.py

# 3. SCAN A TARGET
python3 run.py <target>
```

## 📋 Common Usage Patterns

```bash
# Basic scans
python3 run.py example.com
python3 run.py 192.168.1.1

# Advanced scans  
python3 run.py example.com --ports 80,443,8080-9000
python3 run.py example.com --severity critical,high
python3 run.py example.com --verbose

# Alternative launcher
bash scripts/run_toolkit.sh example.com
```

## 📁 Project Structure (Post-Cleanup)

```
install/setup.py              # 🎯 Enhanced master installer
scripts/autoinstall.py       # 🐍 Python environment manager
scripts/run_toolkit.sh       # 🚀 Toolkit launcher
validate_installation.py     # ✅ Comprehensive validator
run.py                       # 🔍 Main scanning script
```

## ⚠️ Requirements

- **OS:** Linux only (Debian, Ubuntu, Kali, Arch, Fedora)
- **Python:** 3.8+ required
- **Privileges:** sudo required for installation
- **Network:** Internet connection for tool downloads

## 🎯 Success Indicators

- ✅ Installation validation: 95.5% pass rate
- ✅ Tools available: `naabu`, `httpx`, `nuclei`
- ✅ Scan results in `output/` directory
- ✅ HTML/JSON reports generated

**For complete instructions, see [HOW_TO_RUN.md](HOW_TO_RUN.md)**
