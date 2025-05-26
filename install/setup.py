#!/usr/bin/env python3
"""
setup.py - Main installation script for vulnerability analysis toolkit
Handles installation of all required tools and dependencies
"""

import os
import sys
import platform
import subprocess
import shutil
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional

# Add parent directory to path for local imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# Try to import utils module
try:
    from utils import run_cmd, get_executable_path
except ImportError:
    # Define minimal versions of required functions if utils is not available
    def run_cmd(cmd, shell=False, check=False, use_sudo=False, timeout=300, retry=1, silent=False):
        try:
            if not silent:
                print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
            
            # Check for sudo in a platform-independent way
            if use_sudo and platform.system().lower() != "windows":
                try:
                    # os.geteuid() is only available on Unix-like systems
                    if hasattr(os, "geteuid") and os.geteuid() != 0: # type: ignore
                        cmd = ["sudo"] + cmd if isinstance(cmd, list) else ["sudo"] + [cmd]
                except AttributeError:
                    # We're not on a Unix system, so we can't check for root
                    pass
            
            process = subprocess.run(
                cmd, 
                shell=shell, 
                check=check, 
                timeout=timeout,
                stdout=subprocess.PIPE if silent else None,
                stderr=subprocess.PIPE if silent else None,
                text=True
            )
            return process.returncode == 0
        except Exception as e:
            if not silent:
                print(f"Error running command: {e}")
            return False
            
    def get_executable_path(cmd):
        return shutil.which(cmd)

# Constants
GO_VERSION = "1.21.0"
TOOLS_INFO = {
    "httpx": {
        "name": "httpx",
        "repository": "github.com/projectdiscovery/httpx/cmd/httpx",
        "description": "HTTP probing tool"
    },
    "nuclei": {
        "name": "nuclei",
        "repository": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
        "description": "Vulnerability scanner"
    },
    "naabu": {
        "name": "naabu",
        "repository": "github.com/projectdiscovery/naabu/v2/cmd/naabu",
        "description": "Port scanner"
    }
}

def print_banner():
    """Print a welcome banner"""
    print("\n" + "=" * 80)
    print("Vulnerability Analysis Toolkit - Installation")
    print("=" * 80)
    print("This script will install and configure all necessary tools for security scanning.")
    print("The following tools will be installed:")
    for tool_name, info in TOOLS_INFO.items():
        print(f"  - {tool_name}: {info['description']}")
    print("\nThis may take a few minutes depending on your internet connection and system speed.")
    print("=" * 80 + "\n")

def check_requirements():
    """Check if all system requirements are met"""
    print("\n[+] Checking system requirements...")
    
    # Check Python version
    python_version = platform.python_version_tuple()
    print(f"Python version: {platform.python_version()}")
    if int(python_version[0]) < 3 or (int(python_version[0]) == 3 and int(python_version[1]) < 8):
        print("[-] Warning: Python 3.8 or higher is recommended")
    
    # Check operating system
    system = platform.system().lower()
    print(f"Operating system: {platform.system()} {platform.release()}")
    
    # Check for required command-line tools
    required_tools = ["git", "curl", "wget"]
    missing_tools = []
    
    for tool in required_tools:
        if shutil.which(tool):
            print(f"✓ {tool} is installed")
        else:
            missing_tools.append(tool)
            print(f"✗ {tool} is not installed")
    
    if missing_tools:
        print(f"\n[-] Missing required tools: {', '.join(missing_tools)}")
        
        # Try to install missing tools
        if system == "linux":
            print("[+] Attempting to install missing tools...")
            if run_cmd(["sudo", "apt-get", "update"]):
                for tool in missing_tools:
                    run_cmd(["sudo", "apt-get", "install", "-y", tool])
        elif system == "darwin":  # macOS
            if shutil.which("brew"):
                print("[+] Attempting to install missing tools with Homebrew...")
                for tool in missing_tools:
                    run_cmd(["brew", "install", tool])
            else:
                print("[-] Homebrew not found. Please install Homebrew or manually install: " + 
                      ", ".join(missing_tools))
                print("    You can install Homebrew with:")
                print('    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
        else:
            print("[-] Please install the required tools manually: " + ", ".join(missing_tools))
    
    # Check for internet connectivity
    print("\n[+] Checking internet connectivity...")
    if run_cmd(["curl", "-s", "-m", "5", "https://www.google.com"], silent=True):
        print("✓ Internet connectivity is available")
    else:
        print("✗ No internet connectivity detected. This script requires internet access.")
        return False
    
    return True

def install_go():
    """Install Go programming language if not already installed"""
    print("\n[+] Checking Go installation...")
    
    # Check if Go is already installed
    if shutil.which("go"):
        try:
            go_version = subprocess.check_output(["go", "version"], text=True).strip()
            print(f"✓ Go is already installed: {go_version}")
            return True
        except Exception:
            print("[-] Go is installed but not working correctly.")
    
    print("[+] Installing Go...")
    
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Determine architecture
    if machine in ["x86_64", "amd64"]:
        arch = "amd64"
    elif machine in ["aarch64", "arm64"]:
        arch = "arm64"
    elif "arm" in machine:
        arch = "armv6l"
    else:
        arch = "amd64"  # Default to amd64
    
    # Determine OS type
    if system == "linux":
        os_type = "linux"
    elif system == "darwin":
        os_type = "darwin"
    elif system == "windows":
        os_type = "windows"
    else:
        print(f"[-] Unsupported operating system: {system}")
        return False
    
    # Download and install Go
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    
    if system == "windows":
        # For Windows, download the MSI installer
        go_file = os.path.join(temp_dir, "go_installer.msi")
        download_url = f"https://golang.org/dl/go{GO_VERSION}.windows-{arch}.msi"
        
        print(f"[+] Downloading Go from {download_url}...")
        if not run_cmd(["curl", "-L", download_url, "-o", go_file]):
            print(f"[-] Failed to download Go from {download_url}")
            return False
        
        print("[+] Running Go installer...")
        if not run_cmd(["msiexec", "/i", go_file, "/quiet"]):
            print("[-] Failed to install Go")
            return False
        
        # Add Go to PATH for this session
        go_path = r"C:\Program Files\Go\bin"
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + go_path
        
    else:
        # For Linux/macOS, download the tarball
        go_file = os.path.join(temp_dir, "go.tar.gz")
        download_url = f"https://golang.org/dl/go{GO_VERSION}.{os_type}-{arch}.tar.gz"
        
        print(f"[+] Downloading Go from {download_url}...")
        if not run_cmd(["curl", "-L", download_url, "-o", go_file]):
            print(f"[-] Failed to download Go from {download_url}")
            return False
        
        print("[+] Extracting Go...")
        go_install_dir = "/usr/local" if system != "darwin" else "/usr/local"
        if system == "darwin" and not os.access(go_install_dir, os.W_OK):
            # Use sudo for macOS if needed
            if not run_cmd(["sudo", "tar", "-C", go_install_dir, "-xzf", go_file]):
                print(f"[-] Failed to extract Go to {go_install_dir}")
                return False
        else:
            if not run_cmd(["sudo", "tar", "-C", go_install_dir, "-xzf", go_file]):
                print(f"[-] Failed to extract Go to {go_install_dir}")
                return False
        
        # Add Go to PATH for this session
        go_path = os.path.join(go_install_dir, "go", "bin")
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + go_path
        
        # Update shell configuration files
        home_dir = os.path.expanduser("~")
        for rc_file in [".bashrc", ".zshrc", ".profile"]:
            rc_path = os.path.join(home_dir, rc_file)
            if os.path.exists(rc_path):
                try:
                    with open(rc_path, 'r') as f:
                        content = f.read()
                    
                    if go_path not in content:
                        with open(rc_path, 'a') as f:
                            f.write(f'\n# Add Go to PATH\nexport PATH=$PATH:{go_path}\n')
                        print(f"✓ Updated {rc_file} with Go path")
                except Exception as e:
                    print(f"[-] Failed to update {rc_file}: {e}")
    
    # Verify Go installation
    if shutil.which("go") or os.path.exists(os.path.join(go_path, "go")):
        print("✓ Go installed successfully")
        return True
    else:
        print("[-] Go installation verification failed")
        return False

def install_security_tools():
    """Install security tools using Go"""
    print("\n[+] Installing security tools...")
    
    # Make sure Go bin directory is in PATH
    go_bin_dir = os.path.expanduser("~/go/bin")
    os.makedirs(go_bin_dir, exist_ok=True)
    if go_bin_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + go_bin_dir
    
    # Ensure GO111MODULE is set for module support
    os.environ["GO111MODULE"] = "on"
    
    # Install each tool
    for tool_name, info in TOOLS_INFO.items():
        print(f"\n[+] Installing {tool_name}...")
        
        # Check if tool is already installed
        tool_path = get_executable_path(tool_name)
        if tool_path:
            print(f"✓ {tool_name} is already installed at {tool_path}")
            continue
        
        # Try to install using Go
        if not run_cmd(["go", "install", "-v", f"{info['repository']}@latest"]):
            print(f"[-] Failed to install {tool_name}")
            return False
        
        # Verify installation
        tool_path = get_executable_path(tool_name) or os.path.join(go_bin_dir, tool_name)
        if os.path.exists(tool_path):
            print(f"✓ {tool_name} installed successfully at {tool_path}")
        else:
            print(f"[-] {tool_name} installation verification failed")
            return False
    
    return True

def setup_python_environment():
    """Set up Python virtual environment and install requirements"""
    print("\n[+] Setting up Python environment...")
    
    # Get project root directory
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    requirements_file = os.path.join(project_dir, "requirements.txt")
    
    # Check if requirements.txt exists
    if not os.path.exists(requirements_file):
        print("[-] requirements.txt not found, creating a default one...")
        with open(requirements_file, 'w') as f:
            f.write("""# Core dependencies
requests==2.31.0
colorama==0.4.6

# Reporting dependencies
jinja2==3.1.2
markdown==3.4.3
rich==13.3.5

# Progress and formatting
tqdm==4.65.0

# Utility
pathlib==1.0.1

# JSON processing
jsonschema==4.19.0

# YAML processing
pyyaml==6.0.1
""")
    
    # Create virtual environment
    venv_dir = os.path.join(project_dir, ".venv")
    if not os.path.exists(venv_dir):
        print("[+] Creating Python virtual environment...")
        if not run_cmd([sys.executable, "-m", "venv", venv_dir]):
            print("[-] Failed to create virtual environment, continuing with system Python...")
            venv_dir = None
    else:
        print("✓ Virtual environment already exists")
    
    # Install requirements
    print("[+] Installing Python dependencies...")
    
    if venv_dir:
        # Determine pip command based on OS
        if platform.system().lower() == "windows":
            pip_cmd = os.path.join(venv_dir, "Scripts", "pip")
        else:
            pip_cmd = os.path.join(venv_dir, "bin", "pip")
    else:
        # Use system pip
        pip_cmd = "pip3" if shutil.which("pip3") else "pip"
    
    # Install dependencies
    if not run_cmd([pip_cmd, "install", "-r", requirements_file]):
        print("[-] Failed to install some Python dependencies")
        return False
    
    print("✓ Python dependencies installed successfully")
    return True

def update_nuclei_templates():
    """Update nuclei templates"""
    print("\n[+] Updating nuclei templates...")
    
    nuclei_path = get_executable_path("nuclei")
    if not nuclei_path:
        nuclei_path = os.path.join(os.path.expanduser("~/go/bin"), "nuclei")
        if not os.path.exists(nuclei_path):
            print("[-] nuclei not found, cannot update templates")
            return False
    
    if not run_cmd([nuclei_path, "-update-templates"]):
        print("[-] Failed to update nuclei templates")
        return False
    
    print("✓ nuclei templates updated successfully")
    return True

# Add these missing functions
def get_config() -> Dict[str, Any]:
    """
    Get default configuration dictionary
    
    Returns:
        Dict containing default configuration settings
    """
    return {
        "general": {
            "output_dir": "results",
            "timeout": 3600,
            "verbose": False,
            "max_threads": os.cpu_count() or 4
        },
        "naabu": {
            "ports": "top-1000",
            "scan_type": "CONNECT",
            "threads": 25
        },
        "httpx": {
            "threads": 50,
            "timeout": 5
        },
        "nuclei": {
            "templates": None,
            "tags": "cve",
            "severity": "critical,high"
        }
    }

def get_system_memory_gb() -> float:
    """
    Get system memory in GB in a platform-independent way
    
    Returns:
        Memory in GB (float)
    """
    try:
        if platform.system() == "Linux":
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        # Extract value and convert from KB to GB
                        mem_kb = int(line.split()[1])
                        return mem_kb / (1024 * 1024)
        elif platform.system() == "Windows":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            c_ulong = ctypes.c_ulong
            class MEMORYSTATUS(ctypes.Structure):
                _fields_ = [
                    ('dwLength', c_ulong),
                    ('dwMemoryLoad', c_ulong),
                    ('dwTotalPhys', c_ulong),
                    ('dwAvailPhys', c_ulong),
                    ('dwTotalPageFile', c_ulong),
                    ('dwAvailPageFile', c_ulong),
                    ('dwTotalVirtual', c_ulong),
                    ('dwAvailVirtual', c_ulong)
                ]
            memory_status = MEMORYSTATUS()
            memory_status.dwLength = ctypes.sizeof(MEMORYSTATUS)
            kernel32.GlobalMemoryStatus(ctypes.byref(memory_status))
            return memory_status.dwTotalPhys / (1024 * 1024 * 1024)
        elif platform.system() == "Darwin":  # macOS
            result = subprocess.run(['sysctl', '-n', 'hw.memsize'], 
                                  capture_output=True, text=True)
            mem_bytes = int(result.stdout.strip())
            return mem_bytes / (1024 * 1024 * 1024)
    except Exception as e:
        print(f"Error detecting system memory: {e}")
    
    # Default to a conservative 4GB if detection fails
    return 4.0

def auto_configure():
    """
    Automatically configure settings based on system capabilities
    
    Returns:
        Updated configuration dictionary
    """
    config = get_config()
    
    # Detect system capabilities
    cpu_count = os.cpu_count() or 4
    total_memory_gb = get_system_memory_gb()
    
    # Check for root/admin access in a platform-independent way
    is_root = False
    if platform.system() != "Windows":
        try:
            # os.geteuid() is only available on Unix-like systems
            is_root = os.geteuid() == 0 # type: ignore
        except AttributeError:
            # We're not on a Unix system, so we can't check for root
            is_root = False
    
    # Set thread count based on CPU count
    thread_count = min(25, cpu_count * 2) if cpu_count is not None else 10
    httpx_thread_count = min(50, cpu_count * 4) if cpu_count is not None else 20
    
    # Update configuration with detected values
    config["general"]["max_threads"] = cpu_count or 4
    config["naabu"]["scan_type"] = "SYN" if is_root else "CONNECT"
    config["naabu"]["threads"] = thread_count
    config["httpx"]["threads"] = httpx_thread_count
    
    # Print detected configuration
    print("\n[+] Detected system configuration:")
    print(f"  - CPU Count: {cpu_count}")
    print(f"  - Total Memory: {total_memory_gb} GB")
    print(f"  - Root Access: {'Yes' if is_root else 'No'}")
    print(f"  - Naabu Threads: {thread_count}")
    print(f"  - HTTPX Threads: {httpx_thread_count}")
    
    return config

def create_config_file():
    """Create configuration file with default settings"""
    print("\n[+] Creating configuration file...")
    
    # Get project root directory
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_dir = os.path.join(project_dir, "config")
    
    # Create config directory if it doesn't exist
    os.makedirs(config_dir, exist_ok=True)
    
    # Check for root/admin access in a platform-independent way
    is_root = False
    if platform.system() != "Windows":
        try:
            # os.geteuid() is only available on Unix-like systems
            is_root = os.geteuid() == 0 # type: ignore
        except AttributeError:
            # We're not on a Unix system, so we can't check for root
            is_root = False
    
    # Set thread count based on CPU count
    cpu_count = os.cpu_count() or 4
    thread_count = min(25, cpu_count * 2) if cpu_count is not None else 10
    httpx_thread_count = min(50, cpu_count * 4) if cpu_count is not None else 20
    
    # Create default configuration
    default_config = {
        "general": {
            "output_dir": "results",
            "timeout": 3600,
            "verbose": False,
            "max_threads": cpu_count or 4
        },
        "naabu": {
            "ports": "top-1000",
            "exclude_ports": None,
            "scan_type": "SYN" if is_root else "CONNECT",
            "threads": thread_count,
            "timeout": 5,
            "retries": 3
        },
        "httpx": {
            "threads": httpx_thread_count,
            "timeout": 5,
            "follow_redirects": True,
            "status_code": True,
            "title": True,
            "tech_detect": True,
            "web_server": True
        },
        "nuclei": {
            "templates": None,
            "tags": "cve",
            "severity": "critical,high",
            "rate_limit": 150,
            "timeout": 5,
            "retries": 2,
            "bulk_size": 25,
            "exclude_tags": "fuzz,dos"
        },
        "reporting": {
            "formats": ["json", "md", "txt"],
            "include_evidence": True,
            "max_findings": 1000
        }
    }
    
    # Save configuration to file
    config_file = os.path.join(config_dir, "config.json")
    try:
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        print(f"✓ Configuration file created at {config_file}")
        return True
    except Exception as e:
        print(f"[-] Failed to create configuration file: {e}")
        return False

def run_tests():
    """Run tests to verify installation"""
    print("\n[+] Running tests to verify installation...")
    
    # Get project root directory
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test_script = os.path.join(project_dir, "test_environment.py")
    
    # Create a simple test script if it doesn't exist
    if not os.path.exists(test_script):
        print("[+] Creating test script...")
        
        test_content = """#!/usr/bin/env python3
import os
import platform
import subprocess
import shutil

def check_tool(tool_name):
    \"\"\"Check if a tool is installed and working\"\"\"
    # Check in PATH
    tool_path = shutil.which(tool_name)
    if not tool_path:
        # Check in ~/go/bin
        go_bin_path = os.path.expanduser(f"~/go/bin/{tool_name}")
        if os.path.exists(go_bin_path):
            tool_path = go_bin_path
    
    if tool_path:
        try:
            result = subprocess.run([tool_path, "-version"], 
                                   capture_output=True, text=True)
            print(f"✓ {tool_name} is installed: {result.stdout.strip()}")
            return True
        except Exception as e:
            print(f"✗ {tool_name} is installed but not working: {e}")
            return False
    else:
        print(f"✗ {tool_name} is not installed")
        return False

def main():
    print("==== Environment Test ====")
    print(f"Python version: {platform.python_version()}")
    print(f"Operating system: {platform.system()} {platform.release()}")
    
    # Check security tools
    tools = ["naabu", "httpx", "nuclei"]
    all_installed = True
    
    print("\\nChecking security tools:")
    for tool in tools:
        if not check_tool(tool):
            all_installed = False
    
    if all_installed:
        print("\\n✅ All tools are installed and working!")
        return 0
    else:
        print("\\n❌ Some tools are missing or not working correctly.")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
"""
        
        with open(test_script, 'w') as f:
            f.write(test_content)
        
        # Make the script executable
        os.chmod(test_script, 0o755)
    
    # Run the test script
    if not run_cmd([sys.executable, test_script]):
        print("[-] Tests failed. Some components may not be working correctly.")
        return False
    
    print("✓ All tests passed!")
    return True

def main():
    """Main installation function"""
    print_banner()
    
    # Check if the user wants to proceed
    response = input("Do you want to proceed with the installation? (y/n): ")
    if response.lower() != 'y':
        print("Installation aborted.")
        return 1
    
    # Check requirements
    if not check_requirements():
        print("[-] System requirements not met. Please install the required dependencies and try again.")
        return 1
    
    # Install Go
    if not install_go():
        print("[-] Failed to install Go. Please install Go manually and try again.")
        return 1
    
    # Install security tools
    if not install_security_tools():
        print("[-] Failed to install security tools. Please check the error messages and try again.")
        return 1
    
    # Set up Python environment
    if not setup_python_environment():
        print("[-] Failed to set up Python environment. Some features may not work correctly.")
    
    # Update nuclei templates
    if not update_nuclei_templates():
        print("[-] Failed to update nuclei templates. You can update them later with 'nuclei -update-templates'.")
    
    # Create configuration file
    if not create_config_file():
        print("[-] Failed to create configuration file. You can create it manually later.")
    
    # Run tests
    if not run_tests():
        print("[-] Some installation tests failed. Please check the error messages and try again.")
    
    print("\n" + "=" * 80)
    print("Installation completed!")
    print("=" * 80)
    print("\nYou can now use the vulnerability analysis toolkit:")
    print("  1. Run the test environment: python test_environment.py")
    print("  2. Run a vulnerability scan: python workflow.py example.com")
    print("  3. Configure settings in the config/config.json file")
    print("\nThank you for installing the Vulnerability Analysis Toolkit!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
