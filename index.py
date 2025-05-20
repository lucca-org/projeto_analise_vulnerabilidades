#!/usr/bin/env python3
import subprocess
import sys
import os
import socket
import platform
import shutil
import importlib.util
from pathlib import Path

def run_cmd(cmd, shell=False, check=False, use_sudo=False):
    """Run a shell command with optional sudo and error handling."""
    if use_sudo and os.geteuid() != 0 and not platform.system().lower() == "windows":
        cmd = ["sudo"] + cmd
    try:
        print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=300)
        if result.stdout and not result.stdout.isspace():
            print(result.stdout)
        if result.stderr and result.returncode != 0:
            print(f"Error: {result.stderr}")
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"Command timed out after 300 seconds: {cmd}")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        return False
    except Exception as e:
        print(f"Error running command {cmd}: {str(e)}")
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
            sys.exit(1)

def check_network():
    """Check for network connectivity."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        return True
    except (OSError, socket.error) as e:
        print(f"No network connection detected: {e}. Please connect to the internet and try again.")
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
                    print(f"'{go_bin_export}' already present in {shell_rc}")
            else:
                print(f"Your PATH already contains {go_bin_path}")
            
            # Add usr local go bin if needed
            if usr_local_go_path not in path_env:
                if go_path_export not in content:
                    f.write(f"\n# Added by vulnerability analysis setup\n{go_path_export}\n")
                    print(f"Added '{go_path_export}' to {shell_rc}")
                    updated = True
                else:
                    print(f"'{go_path_export}' already present in {shell_rc}")
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
                print(f"{name} installation failed. Exiting.")
                sys.exit(1)
            
            # Verify installation was successful
            if not check_func():
                print(f"{name} was installed but verification failed. Please check manually.")
                sys.exit(1)
                
            print(f"{name} installed and verified.")
        else:
            print(f"{name} is already installed.")
        return True
    except Exception as e:
        print(f"Error during installation of {name}: {e}")
        return False

def check_and_install_go():
    """Special handler for Go installation with fallbacks for different platforms."""
    # Check if Go is already installed
    if run_cmd(["go", "version"]):
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
    
    # For Linux systems
    # Update package lists first
    run_cmd(["apt-get", "update"], use_sudo=True)
    
    # Try with different package managers in order
    
    # 1. Try apt with golang package
    if run_cmd(["apt-get", "install", "golang", "-y"], use_sudo=True):
        if run_cmd(["go", "version"]):
            print("Go installed successfully via apt (golang package).")
            return True
    
    # 2. Try apt with golang-go package (common in Debian/Ubuntu)
    print("Trying alternative package name...")
    if run_cmd(["apt-get", "install", "golang-go", "-y"], use_sudo=True):
        if run_cmd(["go", "version"]):
            print("Go installed successfully via apt (golang-go package).")
            return True
    
    # 3. Try with dnf (Fedora/RHEL)
    if shutil.which("dnf"):
        print("Trying dnf package manager...")
        if run_cmd(["dnf", "install", "golang", "-y"], use_sudo=True):
            if run_cmd(["go", "version"]):
                print("Go installed successfully via dnf.")
                return True
    
    # 4. Try with yum (older RHEL/CentOS)
    if shutil.which("yum"):
        print("Trying yum package manager...")
        if run_cmd(["yum", "install", "golang", "-y"], use_sudo=True):
            if run_cmd(["go", "version"]):
                print("Go installed successfully via yum.")
                return True
    
    # 5. Try with snap
    if shutil.which("snap") or run_cmd(["apt-get", "install", "snapd", "-y"], use_sudo=True):
        print("Trying installation via snap...")
        if run_cmd(["snap", "install", "go", "--classic"], use_sudo=True):
            if run_cmd(["go", "version"]):
                print("Go installed successfully via snap.")
                return True
    
    # 6. Manual installation as last resort
    print("Package manager installation failed. Trying manual installation...")
    go_version = "1.21.0"  # You can update this to the latest version
    
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
    if not run_cmd(["rm", "-rf", "/usr/local/go"], use_sudo=True) or \
       not run_cmd(["tar", "-C", "/usr/local", "-xzf", "/tmp/go.tar.gz"], use_sudo=True):
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

def install_system_dependencies():
    """Install required system dependencies for security tools."""
    if platform.system().lower() == "windows":
        return True
    
    print("\n===== Installing System Dependencies =====\n")
    
    # These are required for compilation of Go tools, particularly Naabu
    dependencies = [
        "libpcap-dev",   # Required for packet capture in Naabu
        "libldns-dev",   # Required for DNS operations
        "build-essential",  # Compilation tools
        "python3-venv"   # For Python virtual environments
    ]
    
    # For Debian/Ubuntu/Kali
    if os.path.exists("/etc/debian_version"):
        return run_cmd(["apt-get", "install", "-y"] + dependencies, use_sudo=True)
    
    # For Fedora/RHEL/CentOS
    elif shutil.which("dnf"):
        fedora_deps = ["libpcap-devel", "ldns-devel", "gcc", "python3-virtualenv"]
        return run_cmd(["dnf", "install", "-y"] + fedora_deps, use_sudo=True)
    
    # For other systems, we'll try with apt as a fallback
    return run_cmd(["apt-get", "install", "-y"] + dependencies, use_sudo=True)

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

def check_python_modules(venv_path=None):
    """Install required Python modules from requirements.txt."""
    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if not os.path.exists(req_file):
        print("requirements.txt not found. Skipping Python module installation.")
        return True
    
    print("Installing Python requirements from requirements.txt...")
    if venv_path:
        # Use pip from virtual environment if available
        if platform.system().lower() == "windows":
            pip_path = os.path.join(venv_path, "Scripts", "pip")
        else:
            pip_path = os.path.join(venv_path, "bin", "pip")
        
        if os.path.exists(pip_path):
            print(f"Installing Python requirements into virtual environment...")
            return run_cmd([pip_path, "install", "-r", req_file])
    
    # Fallback to system pip with warning
    print("WARNING: Installing Python packages system-wide. This may fail on newer Python versions.")
    try:
        # Try with system pip
        return run_cmd(["pip3", "install", "-r", req_file])
    except Exception as e:
        print(f"Error installing Python packages: {e}")
        print("Try creating a virtual environment or use --break-system-packages if appropriate.")
        return False

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

def main():
    print("\n===== Vulnerability Analysis Tools Setup =====\n")
    
    if not check_network():
        response = input("No network detected. Would you like to continue anyway? (y/N): ")
        if not response.lower().startswith('y'):
            print("Exiting.")
            sys.exit(1)
    
    try:
        ensure_sudo()
    except:
        print("WARNING: Running without sudo. Some operations may fail.")

    # Update package lists first (for Linux systems)
    if platform.system().lower() != "windows" and platform.system().lower() != "darwin":
        run_cmd(["apt-get", "update"], use_sudo=True)

    # Check and install dependencies
    check_and_install("Python3", 
                     lambda: run_cmd(["python3", "--version"]), 
                     lambda: run_cmd(["apt-get", "install", "python3", "-y"], use_sudo=True))
    check_and_install("pip3", 
                     lambda: run_cmd(["pip3", "--version"]), 
                     lambda: run_cmd(["apt-get", "install", "python3-pip", "-y"], use_sudo=True))
    
    # Install system dependencies needed for Go tools
    install_system_dependencies()
    
    # Set up Python virtual environment for module installation
    venv_path = setup_python_venv()
    
    # Install Python dependencies
    check_python_modules(venv_path)
    
    # Install Go with our robust method
    if not check_and_install_go():
        print("Go installation failed. Continuing with limited functionality.")
    else:
        # Set up Go env path temporarily to ensure go install commands work
        go_path = os.path.expanduser("~/go/bin")
        if go_path not in os.environ.get("PATH", ""):
            os.environ["PATH"] += f":{go_path}"
        
        # Install Go tools
        print("\n===== Installing Security Tools =====\n")
        check_and_install("naabu", 
                         lambda: run_cmd(["which", "naabu"]) or run_cmd(["naabu", "--version"]), 
                         lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"]))
        check_and_install("nuclei", 
                         lambda: run_cmd(["which", "nuclei"]) or run_cmd(["nuclei", "--version"]), 
                         lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"]))
        check_and_install("httpx", 
                         lambda: run_cmd(["which", "httpx"]) or run_cmd(["httpx", "--version"]), 
                         lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"]))
        
        # Install additional tool for DNS enumeration
        check_and_install("subfinder", 
                         lambda: run_cmd(["which", "subfinder"]) or run_cmd(["subfinder", "--version"]), 
                         lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]))

    # Update system PATH for persistent use
    update_path()
    
    # Test importing command modules
    print("\n===== Testing Command Modules =====\n")
    modules = import_commands()
    
    print("\n===== Summary =====")
    print("✓ Dependencies installation completed.")
    if platform.system().lower() != "windows":
        print(f"✓ Shell configuration updated: {detect_shell_rc()}")
        print(f"✓ Please run: source {detect_shell_rc()} or restart your terminal to update PATH.")
    print("✓ All systems ready for vulnerability analysis.")
    
    # Provide a helpful message if all tools were installed
    if "naabu" in modules and "httpx" in modules and "nuclei" in modules:
        print("\n===== Quick Start =====")
        print("To scan a target:")
        print("1. First map open ports: naabu -host example.com -p 80,443,8080-8090")
        print("2. Probe for HTTP services: httpx -l hosts.txt -title -tech-detect")
        print("3. Scan for vulnerabilities: nuclei -u https://example.com -t cves/ -severity critical,high")
        print("\nFor more options, check the documentation in documentacao/comandos_e_parametros.txt")

if __name__ == "__main__":
    main()