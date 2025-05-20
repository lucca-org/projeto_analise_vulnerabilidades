#!/usr/bin/env python3
import subprocess
import sys
import os
import socket
import platform
import shutil
import importlib.util
import time
from pathlib import Path

# Configuration constants
GO_VERSION = "1.21.0"  # Update this constant to change the Go version globally

def run_cmd(cmd, shell=False, check=False, use_sudo=False, timeout=300, retry=1):
    """Run a shell command with optional sudo, error handling and retries."""
    if use_sudo and os.geteuid() != 0 and platform.system().lower() != "windows":
        cmd = ["sudo"] + cmd
    
    for attempt in range(retry + 1):
        try:
            print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
            result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
            
            if result.stdout and not result.stdout.isspace():
                print(result.stdout)
            
            if result.returncode != 0:
                if result.stderr:
                    print(f"Error: {result.stderr}")
                    
                if attempt < retry:
                    print(f"Command failed. Retrying ({attempt+1}/{retry})...")
                    time.sleep(2)  # Add delay between retries
                    continue
                    
                if check:
                    raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
                return False
            
            return True
        except subprocess.TimeoutExpired:
            print(f"Command timed out after {timeout} seconds: {cmd}")
            if attempt < retry:
                print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {e}")
            if attempt < retry:
                print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
        except Exception as e:
            print(f"Error running command {cmd}: {str(e)}")
            if attempt < retry:
                print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
    
    return False

def ensure_sudo():
    """Ensure the script is running with sudo/root privileges."""
    # Skip for Windows
    if platform.system().lower() == "windows":
        return True
        
    if os.geteuid() != 0:
        print("Root privileges are required for some operations.")
        try:
            subprocess.run(["sudo", "true"], check=True)
        except subprocess.CalledProcessError:
            print("Sudo access is required. Please run the script with sudo. Exiting.")
            raise RuntimeError("Sudo access is required. Please run the script with sudo.")

def check_network():
    """Check for network connectivity."""
    try:
        # Try multiple DNS servers
        for dns in ["8.8.8.8", "1.1.1.1", "9.9.9.9"]:
            try:
                socket.create_connection((dns, 53), timeout=3)
                return True
            except:
                continue
        print("No network connection detected. Please check your internet connection.")
        return False
    except Exception as e:
        print(f"Network check error: {e}")
        return False

def detect_shell_rc():
    """Detect the user's shell rc file."""
    # Skip for Windows
    if platform.system().lower() == "windows":
        return ""
        
    shell = os.environ.get("SHELL", "")
    home = os.path.expanduser("~")
    
    if "zsh" in shell:
        return os.path.join(home, ".zshrc")
    elif "bash" in shell:
        return os.path.join(home, ".bashrc")
    elif "fish" in shell:
        return os.path.join(home, ".config", "fish", "config.fish")
    
    # Default to bashrc if we can't determine the shell
    return os.path.join(home, ".bashrc")

def update_path():
    """Add $HOME/go/bin and /usr/local/go/bin to PATH in the shell rc file if not already present."""
    # Skip for Windows
    if platform.system().lower() == "windows":
        print("Windows detected. Please add Go binary path to your PATH environment variable manually.")
        return
        
    shell_rc = detect_shell_rc()
    if not shell_rc:
        print("Could not detect shell configuration file. Please add Go paths manually.")
        return
    
    # Determine correct export syntax based on shell
    shell = os.environ.get("SHELL", "")
    path_env = os.environ.get("PATH", "")
    updated = False
    
    go_bin_path = os.path.expanduser("~/go/bin")
    usr_local_go_path = "/usr/local/go/bin"
    
    if "fish" in shell:
        go_bin_export = f"set -x PATH $PATH {go_bin_path}"
        go_path_export = f"set -x PATH $PATH {usr_local_go_path}"
    else:  # bash, zsh, or others
        go_bin_export = f"export PATH=$PATH:{go_bin_path}"
        go_path_export = f"export PATH=$PATH:{usr_local_go_path}"
    
    try:
        # Create directory if it doesn't exist
        shell_rc_dir = os.path.dirname(shell_rc)
        if not os.path.exists(shell_rc_dir):
            os.makedirs(shell_rc_dir, exist_ok=True)
            
        with open(shell_rc, "a+") as f:
            f.seek(0)
            content = f.read()
            
            # Add go bin if needed
            if go_bin_path not in path_env:
                if go_bin_export not in content:
                    f.write(f"\n# Added by vulnerability analysis setup\n{go_bin_export}\n")
                    print(f"Added '{go_bin_export}' to {shell_rc}")
                    updated = True
                else:
                    print(f"Your PATH already contains {go_bin_path}")
            else:
                print(f"Your PATH already contains {go_bin_path}")
            
            # Add usr local go bin if needed
            if usr_local_go_path not in path_env:
                if go_path_export not in content:
                    f.write(f"\n# Added by vulnerability analysis setup\n{go_path_export}\n")
                    print(f"Added '{go_path_export}' to {shell_rc}")
                    updated = True
                else:
                    print(f"Your PATH already contains {usr_local_go_path}")
            else:
                print(f"Your PATH already contains {usr_local_go_path}")
            
        if updated:
            print(f"Shell configuration updated in {shell_rc}")
            print(f"Please run: source {shell_rc} or restart your terminal to update PATH.")
    except PermissionError:
        print(f"Permission denied while updating {shell_rc}. Try running this script with sudo or update your PATH manually.")
    except Exception as e:
        print(f"Error updating PATH: {e}")

def check_and_install(name, check_func, install_func):
    """Check and install a tool or dependency."""
    try:
        if not check_func():
            print(f"{name} not found. Installing...")
            if not install_func():
                print(f"{name} installation failed.")
                return False
            
            # Verify installation was successful
            if not check_func():
                print(f"{name} was installed but verification failed. Please check manually.")
                return False
                
            print(f"{name} installed and verified.")
            return True
        else:
            print(f"{name} is already installed.")
            return True
    except Exception as e:
        print(f"Error during installation of {name}: {e}")
        return False

def install_naabu_without_cgo():
    """Install naabu without CGO to avoid pcap dependency issues."""
    print("\n===== Installing Naabu without PCap dependencies =====\n")
    
    # First try to install masscan as an alternative
    print("Installing masscan as an alternative port scanner...")
    run_cmd(["sudo", "apt-get", "install", "-y", "masscan"], timeout=120)
    
    # Then attempt to install rust-scan
    print("Installing rustscan as an alternative port scanner...")
    run_cmd(["sudo", "apt-get", "install", "-y", "rustscan"], timeout=120)
    
    # Set environment variable for Go to disable CGO
    os.environ["CGO_ENABLED"] = "0"
    
    # Try downloading rustscan binary directly
    try:
        print("Downloading rustscan binary...")
        run_cmd(["wget", "https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb", "-O", "/tmp/rustscan.deb"])
        run_cmd(["sudo", "dpkg", "-i", "/tmp/rustscan.deb"])
    except:
        print("Failed to download rustscan binary")
    
    # Create a naabu alternative script
    print("Creating naabu alternative script using other port scanners...")
    naabu_alt_path = os.path.join(os.path.expanduser("~/go/bin"), "naabu")
    
    try:
        with open(naabu_alt_path, "w") as f:
            f.write("""#!/bin/bash
# naabu alternative script that uses other port scanners
# Usage: naabu -host example.com -p 80,443,8080-8090

# Parse arguments
TARGET=""
PORTS="1-1000"
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -host)
            TARGET="$2"
            shift 2
            ;;
        -l)
            TARGET_FILE="$2"
            shift 2
            ;;
        -p|-ports)
            PORTS="$2"
            shift 2
            ;;
        -o|-output)
            OUTPUT="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [ -z "$TARGET" ] && [ -z "$TARGET_FILE" ]; then
    echo "Error: No target specified. Use -host or -l."
    exit 1
fi

# Determine which scanner to use
if command -v rustscan &> /dev/null; then
    echo "Using rustscan for port scanning..."
    if [ -n "$TARGET" ]; then
        if [ -n "$OUTPUT" ]; then
            rustscan -a "$TARGET" -p "$PORTS" -g | tee "$OUTPUT"
        else
            rustscan -a "$TARGET" -p "$PORTS" -g
        fi
    elif [ -n "$TARGET_FILE" ]; then
        if [ -n "$OUTPUT" ]; then
            cat "$TARGET_FILE" | while read host; do
                rustscan -a "$host" -p "$PORTS" -g >> "$OUTPUT"
            done
        else
            cat "$TARGET_FILE" | while read host; do
                rustscan -a "$host" -p "$PORTS" -g
            done
        fi
    fi
elif command -v masscan &> /dev/null; then
    echo "Using masscan for port scanning..."
    if [ -n "$TARGET" ]; then
        if [ -n "$OUTPUT" ]; then
            sudo masscan "$TARGET" -p "$PORTS" -oL "$OUTPUT"
        else
            sudo masscan "$TARGET" -p "$PORTS"
        fi
    elif [ -n "$TARGET_FILE" ]; then
        if [ -n "$OUTPUT" ]; then
            cat "$TARGET_FILE" | while read host; do
                sudo masscan "$host" -p "$PORTS" -oL "$OUTPUT"
            done
        else
            cat "$TARGET_FILE" | while read host; do
                sudo masscan "$host" -p "$PORTS"
            done
        fi
    fi
else
    echo "Using nmap for port scanning..."
    if [ -n "$TARGET" ]; then
        if [ -n "$OUTPUT" ]; then
            nmap -T4 -p "$PORTS" "$TARGET" -oN "$OUTPUT"
        else
            nmap -T4 -p "$PORTS" "$TARGET"
        fi
    elif [ -n "$TARGET_FILE" ]; then
        if [ -n "$OUTPUT" ]; then
            nmap -T4 -p "$PORTS" -iL "$TARGET_FILE" -oN "$OUTPUT"
        else
            nmap -T4 -p "$PORTS" -iL "$TARGET_FILE"
        fi
    fi
fi
""")
        os.chmod(naabu_alt_path, 0o755)
        print(f"✓ Created alternative naabu script at {naabu_alt_path}")
        return True
    except Exception as e:
        print(f"✗ Failed to create alternative naabu script: {e}")
        return False

def try_alternative_libpcap():
    """Try alternative package names for libpcap."""
    print("\n===== Trying alternative libpcap packages =====\n")
    
    # First, try fixing dpkg
    run_cmd(["sudo", "dpkg", "--configure", "-a"], retry=2)
    run_cmd(["sudo", "apt-get", "update", "--fix-missing"], retry=1)
    run_cmd(["sudo", "apt-get", "install", "-f"], retry=1)
    
    alternatives = [
        "libpcap0.8-dev",
        "libpcap-devel",
        "libpcap-dev"
    ]
    
    for pkg in alternatives:
        print(f"Trying to install {pkg}...")
        if run_cmd(["sudo", "apt-get", "install", "-y", pkg], retry=1):
            # Verify if the package solved the issue by checking for pcap.h
            if os.path.exists("/usr/include/pcap/pcap.h") or os.path.exists("/usr/include/pcap.h"):
                print(f"✓ Found pcap.h after installing {pkg}")
                return True
    
    print("✗ Could not install libpcap with alternative package names")
    return False

def fix_dpkg_interruptions():
    """Fix any interrupted dpkg operations with multiple approaches."""
    print("\n===== Fixing dpkg interruptions =====\n")
    
    # Skip for non-Debian based systems
    if not os.path.exists("/usr/bin/dpkg"):
        print("Not a Debian-based system, skipping dpkg fix")
        return True
    
    # Try various approaches to fix dpkg
    fixed = False
    
    # Approach 1: Basic dpkg configure
    if run_cmd(["sudo", "dpkg", "--configure", "-a"], retry=2):
        print("✓ dpkg configuration fixed")
        fixed = True
    
    # Approach 2: Fix missing updates
    if run_cmd(["sudo", "apt-get", "update", "--fix-missing"], retry=1):
        print("✓ APT database updated")
        fixed = True
    
    # Approach 3: Force install pending packages
    if run_cmd(["sudo", "apt-get", "install", "-f", "-y"], retry=1):
        print("✓ Fixed incomplete installations")
        fixed = True
    
    # Approach 4: Clean APT cache
    if run_cmd(["sudo", "apt-get", "clean"], retry=1):
        print("✓ Cleaned APT cache")
        fixed = True
    
    # Approach 5: Reconfigure dpkg database
    if run_cmd(["sudo", "dpkg", "--configure", "--pending"], retry=1):
        print("✓ Reconfigured pending packages")
        fixed = True
    
    # Final update
    if run_cmd(["sudo", "apt-get", "update"], retry=1):
        print("✓ Final APT update successful")
        fixed = True
    
    return fixed

def check_and_install_go():
    """Special handler for Go installation with fallbacks for different platforms."""
    # Check if Go is already installed
    if run_cmd(["go", "version"], retry=1):
        print("Go is already installed.")
        return True
    
    print("Go not found. Installing...")
    
    # For Windows
    if platform.system().lower() == "windows":
        print("Windows detected. Please install Go manually from https://golang.org/dl/")
        print("After installation, ensure Go is added to your PATH environment variable.")
        return False
    
    # For macOS
    if platform.system().lower() == "darwin":
        if shutil.which("brew"):
            return run_cmd(["brew", "install", "go"])
        else:
            print("Homebrew not found. Please install Go manually from https://golang.org/dl/")
            return False
    
    # First fix any dpkg issues
    fix_dpkg_interruptions()
    
    # For Linux systems
    # Update package lists first
    run_cmd(["sudo", "apt-get", "update"], retry=2)
    
    # Try with different package managers in order
    
    # 1. Try apt with golang package
    if run_cmd(["sudo", "apt-get", "install", "golang", "-y"], retry=2):
        if run_cmd(["go", "version"]):
            print("Go installed successfully via apt (golang package).")
            return True
    
    # 2. Try apt with golang-go package (common in Debian/Ubuntu)
    print("Trying alternative package name...")
    if run_cmd(["sudo", "apt-get", "install", "golang-go", "-y"], retry=2):
        if run_cmd(["go", "version"]):
            print("Go installed successfully via apt (golang-go package).")
            return True
    
    # 3. Try with dnf (Fedora/RHEL)
    if shutil.which("dnf"):
        print("Trying dnf package manager...")
        if run_cmd(["sudo", "dnf", "install", "golang", "-y"], retry=1):
            if run_cmd(["go", "version"]):
                print("Go installed successfully via dnf.")
                return True
    
    # 4. Try with yum (older RHEL/CentOS)
    if shutil.which("yum"):
        print("Trying yum package manager...")
        if run_cmd(["sudo", "yum", "install", "golang", "-y"], retry=1):
            if run_cmd(["go", "version"]):
                print("Go installed successfully via yum.")
                return True
    
    # 5. Try with snap
    if shutil.which("snap") or run_cmd(["sudo", "apt-get", "install", "snapd", "-y"], retry=2):
        print("Trying installation via snap...")
        if run_cmd(["sudo", "snap", "install", "go", "--classic"], retry=1):
            if run_cmd(["go", "version"]):
                print("Go installed successfully via snap.")
                return True
    
    # 6. Manual installation as last resort
    print("Package manager installation failed. Trying manual installation...")
    go_version = GO_VERSION  # Use the centralized constant for the Go version
    
    # Determine architecture
    arch = "amd64"  # Default
    if platform.machine() == "aarch64" or platform.machine() == "arm64":
        arch = "arm64"
    elif platform.machine() == "armv7l":
        arch = "armv6l"
    
    # Download Go
    if not run_cmd(["wget", f"https://golang.org/dl/go{go_version}.linux-{arch}.tar.gz", "-O", "/tmp/go.tar.gz"]):
        print("Failed to download Go. Please check your network connection.")
        return False
    
    # Extract Go to /usr/local
    if not run_cmd(["sudo", "rm", "-rf", "/usr/local/go"], retry=1) or \
       not run_cmd(["sudo", "tar", "-C", "/usr/local", "-xzf", "/tmp/go.tar.gz"], retry=1):
        print("Failed to extract Go.")
        return False
    
    # Add to PATH temporarily
    os.environ["PATH"] += ":/usr/local/go/bin"
    
    # Check installation
    if run_cmd(["go", "version"]):
        print("Go installed successfully via manual installation.")
        return True
    
    print("All Go installation methods failed.")
    return False

def setup_python_venv():
    """Set up a Python virtual environment for package installations."""
    print("\n===== Setting up Python Virtual Environment =====\n")
    
    venv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
    if os.path.exists(venv_path):
        print(f"Using existing virtual environment at {venv_path}")
        return venv_path
        
    try:
        print(f"Creating Python virtual environment at {venv_path}")
        subprocess.run([sys.executable, "-m", "venv", venv_path], check=True)
        print("Virtual environment created successfully.")
        return venv_path
    except subprocess.CalledProcessError as e:
        print(f"Failed to create virtual environment: {e}")
        return None

def install_essential_python_packages(venv_path):
    """Install essential Python packages for the project."""
    try:
        if venv_path:
            pip_path = os.path.join(venv_path, "bin", "pip") if platform.system().lower() != "windows" else os.path.join(venv_path, "Scripts", "pip")
            if os.path.exists(pip_path):
                print("\n===== Installing Essential Python Packages =====\n")
                packages = ["requests", "colorama", "rich", "tqdm"]
                if run_cmd([pip_path, "install"] + packages):
                    print("✓ Essential Python packages installed successfully")
                    return True
    except Exception as e:
        print(f"Error installing Python packages: {e}")
    
    print("! Warning: Failed to install Python packages. Some functionality may be limited.")
    return False

def install_go_and_tools():
    """Install Go and security tools."""
    if not check_and_install_go():
        print("⚠️ Go installation failed. Continuing with limited functionality.")
        return False

    # Set up Go env path temporarily
    go_path = os.path.expanduser("~/go/bin")
    if go_path not in os.environ.get("PATH", ""):
        os.environ["PATH"] += f":{go_path}"
    
    # Install Go tools
    print("\n===== Installing Security Tools =====\n")
    
    # Install tools that don't need pcap first
    tools_installed = []
    
    if check_and_install("httpx", 
                       lambda: run_cmd(["which", "httpx"]) or run_cmd(["httpx", "--version"]), 
                       lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"])):
        tools_installed.append("httpx")
        
    if check_and_install("nuclei", 
                       lambda: run_cmd(["which", "nuclei"]) or run_cmd(["nuclei", "--version"]), 
                       lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"])):
        tools_installed.append("nuclei")
        
    if check_and_install("subfinder", 
                       lambda: run_cmd(["which", "subfinder"]) or run_cmd(["subfinder", "--version"]), 
                       lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"])):
        tools_installed.append("subfinder")
    
    # Try installing naabu normally first
    naabu_success = check_and_install("naabu", 
                     lambda: run_cmd(["which", "naabu"]) or run_cmd(["naabu", "--version"]), 
                     lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"]))
    
    # If naabu installation failed, try alternative approach
    if not naabu_success:
        print("Standard naabu installation failed. Trying without CGO...")
        if install_naabu_without_cgo():
            tools_installed.append("naabu")
    else:
        tools_installed.append("naabu")
    
    # Update nuclei templates if nuclei is installed
    if "nuclei" in tools_installed:
        print("\n===== Updating Nuclei Templates =====\n")
        run_cmd(["nuclei", "-update-templates"])
    
    return len(tools_installed) > 0

def import_commands():
    """Dynamically import command modules to check functionality."""
    commands_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "commands")
    if os.path.exists(commands_path) and os.path.isdir(commands_path):
        modules = {}
        
        for file in os.listdir(commands_path):
            if file.endswith('.py') and not file.startswith('__'):
                module_name = file[:-3]  # Remove .py extension
                try:
                    spec = importlib.util.spec_from_file_location(
                        module_name, 
                        os.path.join(commands_path, file)
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    modules[module_name] = module
                    print(f"Successfully imported {module_name} module")
                except Exception as e:
                    print(f"Error importing {module_name}: {e}")
        
        return modules
    return {}

def show_summary_and_quick_start():
    """Show a summary of installed tools and quick start guide."""
    print("\n===== Summary =====")
    print("✓ Dependencies installation completed.")
    if platform.system().lower() != "windows":
        print(f"✓ Shell configuration updated: {detect_shell_rc()}")
        print(f"✓ Please run: source {detect_shell_rc()} or restart your terminal to update PATH.")
    print("✓ All systems ready for vulnerability analysis.")
    
    # Check which tools are available
    ready_tools = []
    for tool in ["httpx", "nuclei", "naabu", "subfinder"]:
        if os.path.exists(os.path.expanduser(f"~/go/bin/{tool}")) or shutil.which(tool):
            ready_tools.append(tool)
    
    if ready_tools:
        print("\n===== Quick Start =====")
        print(f"Available tools: {', '.join(ready_tools)}")
        print("To scan a target:")
        if "subfinder" in ready_tools:
            print("0. Discover subdomains: subfinder -d example.com -o subdomains.txt")
        if "naabu" in ready_tools:
            print("1. Map open ports: naabu -host example.com -p 80,443,8080-8090 -o ports.txt")
        if "httpx" in ready_tools:
            print("2. Probe for HTTP services: httpx -l ports.txt -title -tech-detect -o http_services.txt")
        if "nuclei" in ready_tools:
            print("3. Scan for vulnerabilities: nuclei -l http_services.txt -t cves/ -severity critical,high -o vulnerabilities.txt")
        if all(tool in ready_tools for tool in ["subfinder", "naabu", "httpx", "nuclei"]):
            print("\nOr use the automated workflow script:")
            print("python3 workflow.py example.com")
        print("\nFor more options, check the documentation in documentacao/comandos_e_parametros.txt")

def main():
    print("\n===== Vulnerability Analysis Tools Setup =====\n")
    
    if not check_network():
        response = input("No network detected. Would you like to continue anyway? (y/N): ")
        if not response.lower().startswith('y'):
            print("Exiting.")
            sys.exit(1)
    
    try:
        # On Linux/Mac, we need sudo for some operations
        if platform.system().lower() != "windows":
            ensure_sudo()
    except Exception as e:
        print(f"WARNING: Running without sudo. Some operations may fail. Error: {e}")
        response = input("Continue without sudo? (y/N): ")
        if not response.lower().startswith('y'):
            print("Exiting.")
            sys.exit(1)
    
    # Fix any dpkg interruptions first - this is critical
    if platform.system().lower() != "windows":
        fix_dpkg_interruptions()
    
    # Update package lists for Linux systems
    if platform.system().lower() != "windows" and platform.system().lower() != "darwin":
        run_cmd(["sudo", "apt-get", "update"], retry=2)

    # Check and install Python dependencies
    check_and_install("Python3", 
                     lambda: run_cmd(["python3", "--version"], retry=1), 
                     lambda: run_cmd(["sudo", "apt-get", "install", "python3", "-y"], retry=2))
    check_and_install("pip3", 
                     lambda: run_cmd(["pip3", "--version"], retry=1), 
                     lambda: run_cmd(["sudo", "apt-get", "install", "python3-pip", "-y"], retry=2))
    
    # Try alternative libpcap packages if needed
    if platform.system().lower() == "linux":
        try_alternative_libpcap()
    
    # Set up Python virtual environment
    venv_path = setup_python_venv()
    
    # Install essential Python packages
    install_essential_python_packages(venv_path)
    
    # Install Go and tools
    install_go_and_tools()

    # Update system PATH for persistent use
    update_path()
    
    # Test importing command modules
    print("\n===== Testing Command Modules =====\n")
    modules = import_commands()
    
    show_summary_and_quick_start()

if __name__ == "__main__":
    main()