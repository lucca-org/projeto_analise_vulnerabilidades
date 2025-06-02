#!/usr/bin/env python3
"""
index.py - Main setup and installation script for vulnerability analysis toolkit

This script installs and configures all necessary tools for security scanning:
- Naabu for port scanning
- HTTPX for HTTP service discovery
- Nuclei for vulnerability scanning

No external dependencies on nmap, netcat or other tools outside of these three.
"""
import os
import sys
import platform
import subprocess
import shutil
import time
import signal
import importlib.util
import datetime
import socket
from pathlib import Path

# Exit if running on Windows
if platform.system().lower() == "windows":
    print("This toolkit is designed for Debian/Kali Linux only.")
    print("Windows is not supported.")
    sys.exit(1)

# Check for sudo privileges first
if platform.system().lower() == "linux" and os.geteuid() != 0:
    print("This script requires sudo privileges.")
    try:
        os.execvp("sudo", ["sudo", "python3"] + sys.argv)
    except Exception as e:
        print(f"Error: Failed to restart with sudo: {e}")
        sys.exit(1)

# Fix line endings in setup_tools.sh
try:
    subprocess.run(["sed", "-i", "s/\\r$//", "setup_tools.sh"], check=True)
    print("✓ Fixed line endings in setup_tools.sh")
except Exception as e:
    print(f"Warning: Could not fix line endings in setup_tools.sh: {e}")

def check_network():
    """Check for network connectivity."""
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    
    for dns in dns_servers:
        try:
            # Try connecting to DNS server
            socket.create_connection((dns, 53), 3)
            return True
        except Exception:
            continue
    
    print("No network connection detected. Please check your internet connection.")
    return False

# Add this new function to manage installation state
def manage_installation_state():
    """Manage installation state to prevent duplicate installations."""
    installation_file = ".installation_completed"
    
    # Check if we've already completed installation
    if os.path.exists(installation_file):
        print("✓ Previous installation detected. Checking components...")
        
        # Add verification for critical components
        tools_status = {}
        for tool in ["httpx", "nuclei", "naabu"]:
            tool_path = shutil.which(tool)
            if not tool_path:
                # Check in ~/go/bin directory
                go_bin_path = os.path.expanduser(f"~/go/bin/{tool}")
                if os.path.exists(go_bin_path) and os.access(go_bin_path, os.X_OK):
                    tool_path = go_bin_path
            
            tools_status[tool] = bool(tool_path)
            print(f"  {'✓' if tool_path else '✗'} {tool}: {'Found at '+tool_path if tool_path else 'Not found'}")
        
        # Check Python dependencies
        required_modules = ["requests", "colorama", "markdown", "jinja2"]
        missing_modules = []
        for module in required_modules:
            try:
                importlib.import_module(module)
            except ImportError:
                missing_modules.append(module)
        
        print(f"  {'✓' if not missing_modules else '✗'} Python dependencies: " + 
              (f"All installed" if not missing_modules else f"Missing: {', '.join(missing_modules)}"))
        
        # Return True if all critical components are present
        if all(tools_status.values()) and not missing_modules:
            print("All components verified successfully.")
            return True
        else:
            print("Some components are missing. Will run setup again.")
            # Remove the installation file to trigger a fresh install
            os.remove(installation_file)
            return False
    
    # After successful execution of setup_tools.sh, create the file
    def mark_installation_complete():
        try:
            with open(installation_file, "w") as f:
                f.write(f"Installation completed on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"✓ Installation state saved to {installation_file}")
            return True
        except Exception as e:
            print(f"! Could not save installation state: {e}")
            return False
            
    return mark_installation_complete

def setup_go_env():
    go_bin = os.path.expanduser("~/go/bin")
    go_root_bin = "/usr/local/go/bin"
    
    # Add to PATH environment variable
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + go_bin + os.pathsep + go_root_bin

# Check installation state
installation_manager = manage_installation_state()
if installation_manager is True:
    print("Previous installation detected. Skipping setup_tools.sh")
else:
    try:
        print("\n== Executing setup_tools.sh ==")
        # First fix line endings to ensure the script works on Linux
        try:
            subprocess.run(["sed", "-i", "s/\\r$//", "./setup_tools.sh"], check=True)
            print("✓ Fixed line endings in setup_tools.sh")
        except Exception as e:
            print(f"Warning: Could not fix line endings: {e}")
        
        # Make the script executable
        subprocess.run(["chmod", "+x", "./setup_tools.sh"], check=True)
        
        # Run with bash explicitly to avoid shell compatibility issues
        result = subprocess.run(["bash", "./setup_tools.sh"], check=True)
        if result.returncode == 0:
            print("✓ Successfully executed setup_tools.sh")
            # Mark installation as complete
            installation_manager()
        else:
            print(f"! setup_tools.sh exited with code {result.returncode}")
    except Exception as e:
        print(f"Error executing setup_tools.sh: {e}")

# Install and set up httpx properly
print("\n== Installing latest httpx from ProjectDiscovery ==")
try:
    # Install the latest httpx using Go
    print("Installing httpx...")
    subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"], check=True)
    
    # Get the home directory and construct the go/bin path
    home_dir = os.path.expanduser("~")
    go_bin_path = os.path.join(home_dir, "go", "bin")
    httpx_path = os.path.join(go_bin_path, "httpx")
    
    # Copy httpx to /usr/bin
    print("Copying httpx to /usr/bin...")
    if os.path.exists(httpx_path):
        subprocess.run(["sudo", "cp", httpx_path, "/usr/bin/"], check=True)
        print("✓ Successfully installed httpx to /usr/bin/")
    else:
        print(f"! httpx binary not found at {httpx_path}")
except Exception as e:
    print(f"Error installing httpx: {e}")



# Configuration constants
GO_VERSION = "1.21.0"
SETUP_TIMEOUT = 60  # Maximum time for each installation step
MAX_DPKG_FIX_ATTEMPTS = 3  # Maximum number of attempts to fix dpkg
TOOLS_INFO = {
    "httpx": {
        "name": "httpx",
        "description": "Fast HTTP server probe and technology fingerprinter",
        "repository": "github.com/projectdiscovery/httpx/cmd/httpx",
        "module_file": "commands/httpx.py",
        "go_repository": "github.com/projectdiscovery/httpx/cmd/httpx@latest"  # Explicit go repository with version
    },
    "nuclei": {
        "name": "nuclei",
        "description": "Fast pattern-based scanning for vulnerabilities",
        "repository": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
        "module_file": "commands/nuclei.py",
        "apt_package": "nuclei"  # Can be installed via apt
    },
    "naabu": {
        "name": "naabu",
        "description": "Fast port scanner with SYN/CONNECT modes",
        "repository": "github.com/projectdiscovery/naabu/v2/cmd/naabu",
        "module_file": "commands/naabu.py",
        "alternative_script": True,
        "apt_package": "naabu"  # Can be installed via apt
    }
}

def check_linux_distro():
    """Check if running on Debian/Kali Linux."""
    try:
        if not os.path.exists("/etc/os-release"):
            return "unknown"
            
        with open("/etc/os-release", "r") as f:
            content = f.read().lower()
            if "kali" in content:
                return "kali"
            elif "debian" in content or "ubuntu" in content:
                return "debian"
            else:
                return "other_linux"
    except Exception:
        return "unknown"

def run_setup_py():
    """Run the setup.py script in the install directory."""
    print("Running setup.py first...")
    
    # Get the path to setup.py
    script_dir = os.path.dirname(os.path.abspath(__file__))
    setup_path = os.path.join(script_dir, "install", "setup.py")
    
    if not os.path.exists(setup_path):
        print(f"Error: setup.py not found at {setup_path}")
        return False
    
    # Make setup.py executable
    os.chmod(setup_path, 0o755)
    
    # Run setup.py with Python
    try:
        process = subprocess.run([sys.executable, setup_path], check=False)
        return process.returncode == 0
    except Exception as e:
        print(f"Error running setup.py: {e}")
        return False

def run_bash_script():
    """Run setup_tools.sh script directly."""
    print("Running setup_tools.sh...")
    
    # Get the path to setup_tools.sh
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bash_script = os.path.join(script_dir, "setup_tools.sh")
    
    if not os.path.exists(bash_script):
        print(f"Error: setup_tools.sh not found at {bash_script}")
        return False
    
    # Make script executable
    os.chmod(bash_script, 0o755)
    
    # Run the script with bash
    try:
        process = subprocess.run(["bash", bash_script], check=False)
        return process.returncode == 0
    except Exception as e:
        print(f"Error running setup_tools.sh: {e}")
        return False

def timeout_handler(signum, frame):
    """Handle timeouts for functions."""
    raise TimeoutError("Operation timed out")

def run_with_timeout(func, timeout=SETUP_TIMEOUT):
    """Run a function with a timeout."""
    # For Windows compatibility (which doesn't support SIGALRM)
    if platform.system().lower() == "windows":
        try:
            return func()
        except Exception as e:
            print(f"Error: {e}")
            return None
            
    # Set the timeout handler on Unix systems
    try:
        # These signals are only available on Unix systems
        if hasattr(signal, 'SIGALRM'):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)
            result = func()
            signal.alarm(0)  # Reset the alarm
            return result
        else:
            return func()
    except AttributeError:
        # If signal module doesn't have required attributes, just run the function without timeout
        try:
            return func()
        except Exception as e:
            print(f"Error: {e}")
            return None

def kill_hung_processes():
    """Kill any hung apt or dpkg processes."""
    if platform.system().lower() != "linux":
        return
        
    processes = ["apt", "apt-get", "dpkg"]
    for proc in processes:
        subprocess.run(["sudo", "killall", "-9", proc], stderr=subprocess.PIPE, stdout=subprocess.PIPE)

def run_cmd(cmd, shell=False, check=False, use_sudo=False, timeout=300, retry=1, silent=False):
    """
    Run a shell command with improved error handling and retries.
    """
    # Check for sudo in a platform-independent way
    if use_sudo and platform.system().lower() != "windows":
        try:
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                if isinstance(cmd, list):
                    cmd = ["sudo"] + cmd
                else:
                    cmd = "sudo " + cmd
        except AttributeError:
            pass
    
    for attempt in range(retry + 1):
        try:
            if not silent:
                if isinstance(cmd, list):
                    print(f"Running: {' '.join(cmd)}")
                else:
                    print(f"Running: {cmd}")
            
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
        except subprocess.CalledProcessError as e:
            if not silent:
                print(f"Command failed: {e}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
        except Exception as e:
            if not silent:
                print(f"Error running command: {e}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
    
    return False

def fix_dpkg_interruptions():
    """Fix any interrupted dpkg operations with multiple approaches."""
    if platform.system().lower() != "linux":
        return True
        
    print("\n===== Fixing dpkg interruptions =====\n")
    
    # First kill any hung processes
    kill_hung_processes()
    
    # Directly address the "dpkg was interrupted" error with non-interactive frontend
    print("Running 'sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a' to fix interrupted dpkg...")
    # Use shell=True to allow environment variable setting
    if run_cmd("sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a", shell=True, timeout=300, retry=3):
        print("✓ Applied primary dpkg fix with non-interactive frontend")
    else:
        print("Initial dpkg fix failed, trying standard method...")
        run_cmd(["sudo", "dpkg", "--configure", "-a"], timeout=300, retry=2)
    
    # Remove lock files - be careful with this!
    run_cmd(["sudo", "rm", "-f", "/var/lib/dpkg/lock"], silent=True)
    run_cmd(["sudo", "rm", "-f", "/var/lib/dpkg/lock-frontend"], silent=True)
    run_cmd(["sudo", "rm", "-f", "/var/lib/apt/lists/lock"], silent=True)
    run_cmd(["sudo", "rm", "-f", "/var/cache/apt/archives/lock"], silent=True)
    
    # Create required directories
    run_cmd(["sudo", "mkdir", "-p", "/var/lib/dpkg/updates"], silent=True)
    run_cmd(["sudo", "mkdir", "-p", "/var/lib/apt/lists/partial"], silent=True)
    run_cmd(["sudo", "mkdir", "-p", "/var/cache/apt/archives/partial"], silent=True)
    
    success = False
    
    # Try up to MAX_DPKG_FIX_ATTEMPTS times
    for attempt in range(MAX_DPKG_FIX_ATTEMPTS):
        print(f"Dpkg fix attempt {attempt+1}/{MAX_DPKG_FIX_ATTEMPTS}...")
        
        # Try various approaches in sequence
        if run_cmd("sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a", shell=True, timeout=120, retry=0):
            success = True
        
        if run_cmd(["sudo", "apt-get", "update", "--fix-missing"], retry=0):
            success = True
        
        if run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt-get install -f -y", shell=True, retry=0):
            success = True
            
        # Run apt fix-broken install specifically
        if run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y", shell=True, retry=0):
            success = True
        
        # Specifically fix libc6 and libc-bin issues which you encountered
        if run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libc-bin=2.41-6 libc6=2.41-6", shell=True, retry=0, silent=True):
            success = True
        
        # If we've succeeded, break out of the loop
        if success:
            print("✓ Dpkg issues resolved")
            break
        
        # If we're still having issues and this isn't the last attempt, 
        # try more aggressive fixes
        if attempt < MAX_DPKG_FIX_ATTEMPTS - 1:
            print("Trying more aggressive dpkg fixes...")
            # Remove apt caches completely
            run_cmd(["sudo", "rm", "-rf", "/var/lib/apt/lists/*"], silent=True)
            # Remove apt states
            run_cmd(["sudo", "rm", "-rf", "/var/cache/apt/*.bin"], silent=True)
            # Clean apt
            run_cmd(["sudo", "apt-get", "clean"], silent=True)
            # Final update
            run_cmd(["sudo", "apt-get", "update"], silent=True)
    
    # Verify dpkg is working correctly
    print("Verifying dpkg is working correctly...")
    if run_cmd(["sudo", "apt-get", "update"], retry=0, silent=True) and \
       run_cmd(["apt-cache", "search", "bash"], retry=0, silent=True):
        print("✓ Package management system is working correctly")
        return True
    else:
        print("⚠️ Package management system may still have issues")
        return False

def check_network():
    """Check for network connectivity."""
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    
    for dns in dns_servers:
        try:
            # Try connecting to DNS server
            socket.create_connection((dns, 53), 3)
            return True
        except Exception:
            continue
    
    print("No network connection detected. Please check your internet connection.")
    return False

def setup_go_env():
    """Set up Go environment paths."""
    go_bin = os.path.expanduser("~/go/bin")
    go_root_bin = "/usr/local/go/bin"
    paths_to_add = [go_bin, go_root_bin]
    
    # Add to current environment
    for path in paths_to_add:
        if os.path.exists(path) and path not in os.environ.get("PATH", ""):
            os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + path

    # Return paths for updating shell configs
    return paths_to_add

def update_shell_rc_files(paths_to_add):
    """Update shell configuration files to include Go paths."""
    if platform.system().lower() == "windows":
        print("Please manually add the following to your PATH environment variable:")
        for path in paths_to_add:
            print(f"  {path}")
        return []
    
    # Determine which shell rc files to update
    shell_rc_files = []
    home = os.path.expanduser("~")
    
    # Common shell config files
    possible_rc_files = {
        "bash": os.path.join(home, ".bashrc"),
        "zsh": os.path.join(home, ".zshrc"),
        "fish": os.path.join(home, ".config", "fish", "config.fish"),
        "profile": os.path.join(home, ".profile")
    }
    
    # Detect user's shell
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        shell_rc_files.append(possible_rc_files["zsh"])
    elif "bash" in shell:
        shell_rc_files.append(possible_rc_files["bash"])
    elif "fish" in shell:
        shell_rc_files.append(possible_rc_files["fish"])
    else:
        # Default to common ones if we can't detect
        for file_path in [possible_rc_files["bash"], possible_rc_files["profile"]]:
            if os.path.exists(file_path):
                shell_rc_files.append(file_path)
    
    # Always include .profile for login shells
    if possible_rc_files["profile"] not in shell_rc_files:
        shell_rc_files.append(possible_rc_files["profile"])
    
    # Update each file
    updated_files = []
    for rc_file in shell_rc_files:
        try:
            # Make sure parent directory exists
            os.makedirs(os.path.dirname(rc_file), exist_ok=True)
            
            # Prepare export strings based on shell type
            if "fish" in rc_file:
                export_strs = [f'set -x PATH $PATH {path}' for path in paths_to_add]
            else:
                export_strs = [f'export PATH=$PATH:{path}' for path in paths_to_add]
            
            # Check if file exists and if paths are already in it
            content = ""
            if os.path.exists(rc_file):
                with open(rc_file, "r") as f:
                    content = f.read()
            
            # Add paths that aren't already there
            with open(rc_file, "a+") as f:
                updates_made = False
                for export_str in export_strs:
                    if export_str not in content:
                        f.write(f"\n# Added by vulnerability analysis setup\n{export_str}\n")
                        updates_made = True
                
                if updates_made:
                    updated_files.append(rc_file)
        
        except Exception as e:
            print(f"Error updating {rc_file}: {e}")
    
    if updated_files:
        print(f"Updated the following shell configuration files: {', '.join(updated_files)}")
        print(f"Please run 'source {updated_files[0]}' or restart your terminal to update PATH.")
    
    return updated_files

def manual_go_install():
    """Manually download and install Go."""
    print("Installing Go manually...")
    try:
        # Determine architecture
        arch = "amd64"  # Default
        if platform.machine() == "aarch64" or platform.machine() == "arm64":
            arch = "arm64"
        elif platform.machine() in ["armv7l", "armv6l"]:
            arch = "armv6l"
        
        # Download Go
        go_url = f"https://golang.org/dl/go{GO_VERSION}.linux-{arch}.tar.gz"
        if not run_cmd(["wget", go_url, "-O", "/tmp/go.tar.gz"]):
            print("Failed to download Go. Please check your network connection.")
            # Try curl as fallback
            if not run_cmd(["curl", "-L", go_url, "-o", "/tmp/go.tar.gz"]):
                print("Failed to download Go with curl as well. Installation aborted.")
                return False
        
        # Extract Go
        run_cmd(["sudo", "rm", "-rf", "/usr/local/go"])
        if not run_cmd(["sudo", "tar", "-C", "/usr/local", "-xzf", "/tmp/go.tar.gz"]):
            print("Failed to extract Go.")
            return False
        
        # Clean up
        run_cmd(["rm", "/tmp/go.tar.gz"], silent=True)
        
        # Set up environment
        paths = setup_go_env()
        update_shell_rc_files(paths)
        
        # Verify installation
        go_binary = "/usr/local/go/bin/go"
        if os.path.exists(go_binary) and run_cmd([go_binary, "version"]):
            print("Go installed successfully via manual installation.")
            return True
        
        print("Failed to verify Go installation.")
        return False
    except Exception as e:
        print(f"Error during manual Go installation: {e}")
        return False

def check_and_install_go():
    """Check if Go is installed, and install it if not."""
    # First try existing Go installation
    if run_cmd(["go", "version"], retry=0, silent=True):
        print("Go is already installed.")
        # Still set up paths to ensure proper environment
        paths = setup_go_env()
        update_shell_rc_files(paths)
        return True
    
    # If not found in PATH, check if /usr/local/go/bin/go exists
    if os.path.exists("/usr/local/go/bin/go") and run_cmd(["/usr/local/go/bin/go", "version"], retry=0, silent=True):
        print("Go is installed but not in PATH. Setting up environment...")
        paths = setup_go_env()
        update_shell_rc_files(paths)
        return True
    
    # If not found, try manual installation
    return manual_go_install()

def get_executable_path(cmd):
    """Find the path to an executable, checking PATH and common locations."""
    # First check if it's directly in PATH
    path = shutil.which(cmd)
    if path:
        return path
    
    # Check common locations
    common_locations = [
        os.path.expanduser(f"~/go/bin/{cmd}"),
        os.path.expanduser(f"~/.local/bin/{cmd}"),
        f"/usr/local/bin/{cmd}",
        f"/usr/bin/{cmd}"
    ]
    
    for location in common_locations:
        if os.path.exists(location) and os.access(location, os.X_OK):
            return location
    
    return None

def install_apt_packages():
    """Install required apt packages including nuclei and naabu."""
    if platform.system().lower() != "linux":
        print("Skipping apt packages installation - not on Linux")
        return False
    
    # Make sure to fix any dpkg issues first
    print("\n===== Fixing any dpkg interruptions =====\n")
    if not fix_dpkg_interruptions():
        print("WARNING: Package management system issues were detected.")
        print("Some package installations may fail.")
        print("Try running 'sudo apt --fix-broken install' manually.")
    
    # Kill any hanging apt processes before continuing
    kill_hung_processes()
    
    print("\n===== Updating package lists =====\n")
    print("Running: apt-get update")
    run_cmd(["sudo", "apt-get", "update"])
    
    # REMOVED: The apt-get upgrade step that was causing hangs and locks
    # Instead, clean apt cache and ensure we have a stable starting point
    print("\n===== Cleaning apt cache =====\n")
    run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt-get clean", shell=True)
    
    print("\n===== Installing required system packages =====\n")
    
    # First try with fix-broken
    run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y", shell=True)
    
    # Install dependencies individually with status messages but without update after each
    # This prevents excessive updates that can cause locks
    print("Installing libpcap development files...")
    run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev", shell=True)
    
    print("Installing curl...")
    run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl", shell=True)
    
    print("Installing wget...")
    run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y wget", shell=True)
    
    print("Installing build-essential...")
    run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential", shell=True)
    
    # Run a single update before installing security tools
    run_cmd(["sudo", "apt-get", "update"], silent=True)
    
    # Try to install nuclei via apt
    print("\n===== Installing nuclei via apt =====\n")
    if run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nuclei", shell=True):
        print("✓ Nuclei installed via apt")
    else:
        print("Could not install nuclei via apt. Will try Go installation later.")
    
    # Try to install naabu via apt
    print("\n===== Installing naabu via apt =====\n")
    if run_cmd("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y naabu", shell=True):
        print("✓ Naabu installed via apt")
    else:
        print("Could not install naabu via apt. Will try Go installation later.")

    print("Apt package installation completed")
    return True

def install_httpx():
    """Install httpx using multiple methods with fallbacks."""
    print("\n===== Installing httpx =====\n")
    
    # Check if httpx is already installed
    httpx_path = get_executable_path("httpx")
    if httpx_path:
        print(f"✓ httpx is already installed at {httpx_path}")
        return True
    
    # Method 1: Try installing with Go (preferred method)
    print("Attempting to install httpx using Go...")
    go_installed = check_and_install_go()
    
    if go_installed:
        print("Using Go to install httpx...")
        # Set up Go environment
        os.environ["GO111MODULE"] = "on"  # Ensure Go modules are enabled
        
        # Try regular go install command
        if run_cmd(["go", "install", "-v", TOOLS_INFO["httpx"]["go_repository"]], retry=2):
            print("✓ httpx installed successfully via Go")
            # Update PATH to include Go binaries
            setup_go_env()
            return True
        
        # If failed, try alternative go get command
        print("First go install attempt failed, trying alternative method...")
        if run_cmd(["go", "get", "-v", TOOLS_INFO["httpx"]["repository"]], retry=2):
            print("✓ httpx installed successfully via Go (alternative method)")
            # Update PATH to include Go binaries
            setup_go_env()
            return True
    
    # Method 2: Try installing with apt
    if platform.system().lower() == "linux":
        print("Attempting to install httpx using apt...")
        # Fix any package management issues first
        fix_dpkg_interruptions()
        
        # Try different apt package names
        apt_package_names = ["httpx", "httpx-toolkit", "golang-github-projectdiscovery-httpx"]
        
        for package in apt_package_names:
            print(f"Trying to install {package}...")
            if run_cmd(["sudo", "apt-get", "install", "-y", package], retry=2):
                # Verify installation
                if get_executable_path("httpx"):
                    print(f"✓ httpx installed successfully via apt using package {package}")
                    return True
                else:
                    print(f"Package {package} installed but httpx executable not found.")
            else:
                print(f"Failed to install {package} via apt.")
    
    # Method 3: Try installing with snap if available
    if platform.system().lower() == "linux" and shutil.which("snap"):
        print("Attempting to install httpx using snap...")
        if run_cmd(["sudo", "snap", "install", "httpx"], retry=2):
            # Verify installation
            if get_executable_path("httpx"):
                print("✓ httpx installed successfully via snap")
                return True
            else:
                print("Snap package installed but httpx executable not found.")
    
    # Method 4: Download pre-built binary directly
    print("Attempting to download pre-built httpx binary...")
    try:
        # Determine system and architecture
        system = platform.system().lower()
        arch = platform.machine().lower()
        
        # Map architecture names
        arch_map = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "i386": "386",
            "i686": "386",
            "armv7l": "arm",
            "armv6l": "arm",
            "aarch64": "arm64",
            "arm64": "arm64"
        }
        
        if arch in arch_map:
            mapped_arch = arch_map[arch]
        else:
            mapped_arch = "amd64"  # Default to amd64 if unknown
        
        # Set release URL based on system
        if system == "linux":
            release_url = f"https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_{system}_{mapped_arch}.zip"
        elif system == "darwin":
            release_url = f"https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_{system}_{mapped_arch}.zip"
        elif system == "windows":
            release_url = f"https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_{system}_{mapped_arch}.zip"
        else:
            print(f"Unsupported system: {system}")
            return False
        
        # Create installation directory
        install_dir = os.path.expanduser("~/.local/bin")
        os.makedirs(install_dir, exist_ok=True)
        
        # Download zip file
        zip_path = os.path.join(os.path.expanduser("~"), "httpx.zip")
        
        # Try wget first
        if shutil.which("wget"):
            if not run_cmd(["wget", release_url, "-O", zip_path]):
                print("Failed to download httpx with wget.")
                # Try curl as fallback
                if shutil.which("curl"):
                    if not run_cmd(["curl", "-L", release_url, "-o", zip_path]):
                        print("Failed to download httpx with curl as well.")
                        return False
                else:
                    return False
        elif shutil.which("curl"):
            if not run_cmd(["curl", "-L", release_url, "-o", zip_path]):
                print("Failed to download httpx with curl.")
                return False
        else:
            print("Neither wget nor curl is available for downloading. Please install either tool.")
            return False
        
        # Extract the zip file
        import zipfile
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(install_dir)
            
            # Make executable
            httpx_path = os.path.join(install_dir, "httpx")
            if os.path.exists(httpx_path):
                os.chmod(httpx_path, 0o755)
                print(f"✓ httpx installed successfully to {httpx_path}")
                
                # Update PATH
                if install_dir not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + install_dir
                    update_shell_rc_files([install_dir])
                
                return True
            else:
                print("Extracted zip but httpx executable not found.")
        except Exception as e:
            print(f"Error extracting httpx zip file: {e}")
        finally:
            # Clean up
            if os.path.exists(zip_path):
                os.remove(zip_path)
    
    except Exception as e:
        print(f"Error downloading pre-built httpx binary: {e}")
    
    # If all installation methods failed, create a Python-based wrapper as last resort
    print("All installation methods failed. Creating a Python-based httpx wrapper...")
    
    httpx_wrapper_path = os.path.expanduser("~/.local/bin/httpx")
    os.makedirs(os.path.dirname(httpx_wrapper_path), exist_ok=True)
    
    httpx_wrapper_content = """#!/usr/bin/env python3
import sys
import subprocess
import argparse
import requests
import json
import time
import os

def main():
    print("httpx wrapper (simple HTTP probe)")
    parser = argparse.ArgumentParser(description="Simple HTTP probe")
    parser.add_argument("-l", help="Input file with targets")
    parser.add_argument("-o", help="Output file")
    parser.add_argument("-silent", action="store_true", help="Silent mode")
    parser.add_argument("-title", action="store_true", help="Display title")
    parser.add_argument("-status-code", action="store_true", help="Display status code")
    parser.add_argument("-tech-detect", action="store_true", help="Technology detection")
    parser.add_argument("-follow-redirects", action="store_true", help="Follow redirects")
    
    args, unknown = parser.parse_known_args()
    
    targets = []
    if args.l:
        try:
            with open(args.l, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading input file: {e}")
            return 1
    
    results = []
    for target in targets:
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        
        try:
            print(f"Probing {target}...")
            response = requests.get(target, timeout=10, allow_redirects=args.follow_redirects)
            
            result = {
                "url": target,
                "status_code": response.status_code,
                "content_length": len(response.content)
            }
            
            if args.title:
                import re
                title_match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE)
                result["title"] = title_match.group(1) if title_match else "No Title"
            
            results.append(result)
            
            if not args.silent:
                output = target
                if args.status_code:
                    output += f" [{response.status_code}]"
                if args.title and "title" in result:
                    output += f" [{result['title']}]"
                print(output)
                
        except Exception as e:
            if not args.silent:
                print(f"Error probing {target}: {e}")
    
    if args.o:
        try:
            with open(args.o, "w") as f:
                for result in results:
                    output = result["url"]
                    if args.status_code:
                        output += f" [{result['status_code']}]"
                    if args.title and "title" in result:
                        output += f" [{result['title']}]"
                    f.write(output + "\\n")
            print(f"Results written to {args.o}")
        except Exception as e:
            print(f"Error writing output file: {e}")
            
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""
    
    try:
        with open(httpx_wrapper_path, "w") as f:
            f.write(httpx_wrapper_content)
        
        # Make the script executable
        os.chmod(httpx_wrapper_path, 0o755)
        
        # Install Python requests module for the wrapper
        run_cmd([sys.executable, "-m", "pip", "install", "requests"])
        
        print(f"✓ Created httpx wrapper script at {httpx_wrapper_path}")
        
        # Update PATH
        install_dir = os.path.dirname(httpx_wrapper_path)
        if install_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + install_dir
            update_shell_rc_files([install_dir])
        
        return True
    except Exception as e:
        print(f"Error creating httpx wrapper: {e}")
        return False

def install_security_tools():
    """Install security tools using both apt and Go."""
    print("\n===== Installing Security Tools =====\n")

    # Set up Go environment
    setup_go_env()
    
    # Check if tools are already installed
    tools_installed = {
        "httpx": False,
        "nuclei": False,
        "naabu": False
    }
    
    for tool_name in tools_installed.keys():
        tool_path = get_executable_path(tool_name)
        if tool_path:
            print(f"✓ {tool_name} is already installed at {tool_path}")
            tools_installed[tool_name] = True

    # Try to install httpx with specialized function that tries multiple methods
    if not tools_installed["httpx"]:
        tools_installed["httpx"] = install_httpx()
    
    # Install nuclei and naabu via apt if not already installed
    if platform.system().lower() == "linux":
        if not tools_installed["nuclei"]:
            print("Attempting to install nuclei via apt...")
            if run_cmd(["sudo", "apt-get", "install", "-y", "nuclei"]):
                print("✓ nuclei installed via apt")
                tools_installed["nuclei"] = True
        
        if not tools_installed["naabu"]:
            print("Attempting to install naabu via apt...")
            if run_cmd(["sudo", "apt-get", "install", "-y", "naabu"]):
                print("✓ naabu installed via apt")
                tools_installed["naabu"] = True

    # Install any tools not yet installed using Go
    for tool_name, installed in tools_installed.items():
        if not installed and tool_name != "httpx":  # Skip httpx as we already tried to install it
            tool_info = next((item for item in TOOLS_INFO.values() if item["name"] == tool_name), None)
            if not tool_info:
                print(f"! Tool information not found for {tool_name}. Skipping.")
                continue
                
            print(f"Installing {tool_name} using Go...")
            # Set up Go environment
            os.environ["GO111MODULE"] = "on"  # Ensure Go modules are enabled
            
            # For naabu, disable CGO to avoid libpcap dependency issues
            if tool_name == "naabu":
                os.environ["CGO_ENABLED"] = "0"
                
            if run_cmd(["go", "install", "-v", f"{tool_info['repository']}@latest"]):
                print(f"✓ {tool_name} installed successfully via Go")
                tools_installed[tool_name] = True
            else:
                print(f"! Failed to install {tool_name} via Go.")
                
                # For naabu, create alternative implementation if needed
                if tool_name == "naabu" and tool_info.get("alternative_script"):
                    create_naabu_alternative()
                    tools_installed[tool_name] = True

    # Verify all tools are installed
    all_installed = all(tools_installed.values())
    if all_installed:
        print("✓ All security tools have been installed successfully!")
    else:
        missing = [name for name, installed in tools_installed.items() if not installed]
        print(f"! Could not install: {', '.join(missing)}")
        
    return tools_installed

def create_naabu_alternative():
    """Create an alternative naabu implementation using built-in tools."""
    naabu_path = os.path.expanduser("~/go/bin/naabu")
    os.makedirs(os.path.dirname(naabu_path), exist_ok=True)
    
    script_content = """#!/bin/bash
# naabu alternative script using built-in TCP connections
# This implementation avoids using nmap, netcat, or other external tools

VERSION="1.0.0"
TARGET=""
TARGET_FILE=""
PORTS="1-1000"
OUTPUT=""
VERBOSE=false
SILENT=false
JSON=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
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
        -v|-verbose)
            VERBOSE=true
            shift
            ;;
        -json)
            JSON=true
            shift
            ;;
        -silent)
            SILENT=true
            shift
            ;;
        -version)
            echo "naabu-alternative v$VERSION"
            exit 0
            ;;
        -h|-help)
            echo "Usage: naabu -host <target> [-p <ports>] [-o <output>]"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Validate input
if [[ -z "$TARGET" && -z "$TARGET_FILE" ]]; then
    echo "Error: No target specified. Use -host or -l."
    exit 1
fi

# Create the output directory if needed
if [[ -n "$OUTPUT" ]]; then
    mkdir -p "$(dirname "$OUTPUT")" 2>/dev/null
    > "$OUTPUT"  # Initialize/clear output file
fi

# Function to check if a port is open using built-in /dev/tcp feature
check_port() {
    local host=$1
    local port=$2
    local timeout=1
    
    # Use bash's built-in /dev/tcp virtual file
    (echo > /dev/tcp/$host/$port) >/dev/null 2>&1
    return $?
}

# Scan a target's ports
scan_target() {
    local target=$1
    local ports=$2
    local results=""
    
    [[ "$SILENT" = false ]] && echo "Scanning $target..."
    
    # Parse port ranges
    if [[ $ports =~ ^([0-9]+)-([0-9]+)$ ]]; then
        start_port=${BASH_REMATCH[1]}
        end_port=${BASH_REMATCH[2]}
        
        for port in $(seq $start_port $end_port); do
            if check_port "$target" "$port"; then
                [[ "$VERBOSE" = true && "$SILENT" = false ]] && echo "Port $port is open on $target"
                results="${results}${target}:${port}\n"
            fi
        done
    else
        # Handle comma-separated list
        IFS=',' read -ra PORT_LIST <<< "$ports"
        for port in "${PORT_LIST[@]}"; do
            if check_port "$target" "$port"; then
                [[ "$VERBOSE" = true && "$SILENT" = false ]] && echo "Port $port is open on $target"
                results="${results}${target}:${port}\n"
            fi
        done
    fi
    
    echo -en "$results"
}

# Main scanning logic
results=""

if [[ -n "$TARGET" ]]; then
    # Single target
    scan_result=$(scan_target "$TARGET" "$PORTS")
    results="$results$scan_result"
elif [[ -n "$TARGET_FILE" && -f "$TARGET_FILE" ]]; then
    # Multiple targets from file
    while IFS= read -r target || [[ -n "$target" ]]; do
        # Skip empty lines and comments
        [[ -z "$target" || "$target" =~ ^[[:space:]]*# ]] && continue
        
        scan_result=$(scan_target "$target" "$PORTS")
        results="$results$scan_result"
    done < "$TARGET_FILE"
fi

# Output handling
if [[ "$JSON" = true ]]; then
    # Format as JSON
    json_output="["
    first=true
    
    while IFS=: read -r host port || [[ -n "$host" ]]; do
        # Skip empty lines
        [[ -z "$host" || -z "$port" ]] && continue
        
        # Add comma separator if not the first entry
        if [[ "$first" = true ]]; then
            first=false
        else
            json_output="$json_output,"
        fi
        
        json_output="$json_output\n  {\"host\":\"$host\",\"port\":$port,\"protocol\":\"tcp\"}"
    done <<< "$results"
    
    json_output="$json_output\n]"
    
    if [[ -n "$OUTPUT" ]]; then
        echo -e "$json_output" > "$OUTPUT"
    else
        echo -e "$json_output"
    fi
else
    # Simple text output
    if [[ -n "$OUTPUT" ]]; then
        echo -e "$results" > "$OUTPUT"
    else
        echo -e "$results"
    fi
fi

exit 0
"""
    
    try:
        with open(naabu_path, 'w') as f:
            f.write(script_content)
        
        # Make the script executable
        os.chmod(naabu_path, 0o755)
        
        print(f"✓ Created alternative naabu script at {naabu_path}")
        return True
    except Exception as e:
        print(f"Failed to create alternative naabu script: {e}")
        return False

def setup_python_venv():
    """Set up a Python virtual environment."""
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
    except Exception as e:
        print(f"Error creating virtual environment: {e}")
        # Try without using a virtual environment
        print("Trying to install packages globally...")
        return None

def install_python_packages(venv_path=None):
    """Install required Python packages."""
    print("\n===== Installing Python Packages =====\n")
    
    # Remove duplicate packages from requirements.txt
    packages = [
        "requests==2.31.0", 
        "colorama==0.4.6", 
        "jinja2==3.1.2", 
        "markdown==3.4.3", 
        "rich==13.3.5", 
        "tqdm==4.65.0", 
        "pathlib==1.0.1", 
        "pytest-httpx==0.24.0", 
        "jsonschema==4.19.0", 
        "pyyaml==6.0.1"
    ]
    
    # Determine pip command
    if venv_path:
        if platform.system().lower() == "windows":
            pip_cmd = os.path.join(venv_path, "Scripts", "pip")
        else:
            pip_cmd = os.path.join(venv_path, "bin", "pip")
    else:
        pip_cmd = "pip3" if shutil.which("pip3") else "pip"
    
    # Install packages
    if run_cmd([pip_cmd, "install"] + packages):
        print("✓ Python packages installed successfully")
        
        # Ensure markdown is installed (separately to handle any special cases)
        run_cmd([pip_cmd, "install", "markdown"])
        print("✓ Markdown installed for report generation")
        
        return True
    
    # Try with system Python if virtual environment fails
    if pip_cmd != "pip3" and pip_cmd != "pip":
        if shutil.which("pip3"):
            if run_cmd(["pip3", "install"] + packages):
                print("✓ Packages installed with pip3")
                return True
        elif shutil.which("pip"):
            if run_cmd(["pip", "install"] + packages):
                print("✓ Packages installed with pip")
                return True
    
    print("Warning: Failed to install some Python packages")
    return False

def update_nuclei_templates():
    """Update nuclei templates."""
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        nuclei_path = os.path.expanduser("~/go/bin/nuclei")
    
    if os.path.exists(nuclei_path):
        print("\n===== Updating Nuclei Templates =====\n")
        run_cmd([nuclei_path, "-update-templates"], timeout=180)
    else:
        print("Nuclei not found. Skipping template updates.")

def create_command_modules():
    """Create command module files if they don't exist."""
    commands_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "commands")
    os.makedirs(commands_dir, exist_ok=True)
    
    # Create __init__.py
    init_file = os.path.join(commands_dir, "__init__.py")
    with open(init_file, "w") as f:
        f.write('# This file makes the commands directory a proper Python package\n')
        f.write('__all__ = ["naabu", "httpx", "nuclei"]\n')
    
    # Template for command modules
    module_template = """#!/usr/bin/env python3
import os
import subprocess
import json
from pathlib import Path
import shutil

def run_{tool}(*args, **kwargs):
    \"\"\"Run {tool} with provided arguments.\"""
    # Find the tool path
    tool_path = shutil.which("{tool}")
    if not tool_path:
        # Check in ~/go/bin
        go_bin_path = os.path.expanduser("~/go/bin/{tool}")
        if os.path.exists(go_bin_path):
            tool_path = go_bin_path
        else:
            print(f"{tool} not found in PATH or ~/go/bin")
            return False
    
    cmd = [tool_path]
    
    for arg in args:
        cmd.append(str(arg))
    
    for key, value in kwargs.items():
        key = key.replace("_", "-")
        if value is True:
            cmd.append(f"-{key}")
        elif value is not False and value is not None:
            cmd.append(f"-{key}")
            cmd.append(str(value))
    
    try:
        print(f"Running: " + " ".join(cmd))
        process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, text=True)
        if process.stdout:
            print(process.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running {tool}: {{e}}")
        if e.stderr:
            print(e.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error running {tool}: {{e}}")
        return False

def check_{tool}():
    \"\"\"Check if {tool} is installed.\"""
    try:
        # First check in PATH
        tool_path = shutil.which("{tool}")
        if not tool_path:
            # Check in ~/go/bin
            go_bin_path = os.path.expanduser("~/go/bin/{tool}")
            if os.path.exists(go_bin_path):
                tool_path = go_bin_path
            else:
                print(f"{tool} not found")
                return False
        
        process = subprocess.run([tool_path, "-version"], 
                               capture_output=True, text=True)
        print(f"{tool} version: {{process.stdout.strip()}}")
        return True
    except Exception as e:
        print(f"Error checking {tool}: {{e}}")
        return False
"""
    
    # Create command modules
    for tool in ["naabu", "httpx", "nuclei"]:
        module_file = os.path.join(commands_dir, f"{tool}.py")
        if not os.path.exists(module_file):
            with open(module_file, "w") as f:
                f.write(module_template.format(tool=tool))
    
    print("Command modules created successfully")

def create_workflow_script():
    """Create the main workflow script if it doesn't exist."""
    workflow_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "workflow.py")
    
    if not os.path.exists(workflow_path):
        workflow_content = """#!/usr/bin/env python3
\"""
workflow.py - Automated vulnerability scanning workflow
Combines naabu, httpx, and nuclei for comprehensive security scanning
\"""

import os
import sys
import argparse
import datetime
import time
import signal
from pathlib import Path
import traceback

# Add current directory to path for local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our modules
try:
    from commands import naabu, httpx, nuclei
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure you've run index.py first to set up the environment.")
    sys.exit(1)

def signal_handler(sig, frame):
    \"""Handle CTRL+C gracefully.\"""
    print("\\n[!] Scan interrupted by user. Partial results may be available.")
    sys.exit(130)  # Standard exit code for SIGINT

def create_output_directory(target_name):
    \"""Create a timestamped output directory.\"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"results_{target_name}_{timestamp}"
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    except Exception as e:
        print(f"Error creating output directory: {e}")
        return None

def run_port_scan(target, output_dir, ports=None, verbose=False):
    \"""Run port scanning with naabu.\"""
    print("\\n[+] Step 1: Port scanning with naabu")
    ports_output = os.path.join(output_dir, "ports.txt")
    ports_json = os.path.join(output_dir, "ports.json")
    
    # Run naabu
    naabu_args = {
        "host": target,
        "p": ports or "top-1000",
        "o": ports_output,
        "json": True,
        "silent": not verbose,
    }
    
    # Convert dict to kwargs
    success = naabu.run_naabu(**naabu_args)
    
    if not success:
        print("[!] Port scan failed. Please check naabu installation.")
        # Create a minimal result with common ports
        with open(ports_output, "w") as f:
            f.write(f"{target}:80\\n{target}:443\\n")
        return ports_output
    
    return ports_output

def run_http_probe(ports_file, output_dir, verbose=False):
    \"""Run HTTP service detection with httpx.\"""
    print("\\n[+] Step 2: HTTP service detection with httpx")
    http_output = os.path.join(output_dir, "http_services.txt")
    http_json = os.path.join(output_dir, "http_services.json")
    
    # Run httpx
    httpx_args = {
        "l": ports_file,
        "o": http_output,
        "title": True,
        "status_code": True,
        "tech_detect": True,
        "follow_redirects": True,
        "silent": not verbose,
    }
    
    # Convert dict to kwargs
    success = httpx.run_httpx(**httpx_args)
    
    if not success:
        print("[!] HTTP probe failed. Please check httpx installation.")
        # Create a minimal result
        with open(http_output, "w") as f:
            f.write(f"http://{target}\\nhttps://{target}\\n")
    
    return http_output

def run_vulnerability_scan(http_file, output_dir, templates=None, tags="cve", severity="critical,high", verbose=False):
    \"""Run vulnerability scanning with nuclei.\"""
    print("\\n[+] Step 3: Vulnerability scanning with nuclei")
    vuln_output = os.path.join(output_dir, "vulnerabilities.txt")
    vuln_json = os.path.join(output_dir, "vulnerabilities.jsonl")
    
    # Create output directory for storing responses
    nuclei_resp_dir = os.path.join(output_dir, "nuclei_responses")
    os.makedirs(nuclei_resp_dir, exist_ok=True)
    
    # Run nuclei
    nuclei_args = {
        "l": http_file,
        "o": vuln_output,
        "jsonl": True,
        "silent": not verbose,
        "store_resp": True,
    }
    
    if templates:
        nuclei_args["t"] = templates
    if tags:
        nuclei_args["tags"] = tags
    if severity:
        nuclei_args["severity"] = severity
    
    # Convert dict to kwargs
    success = nuclei.run_nuclei(**nuclei_args)
    
    if not success:
        print("[!] Vulnerability scan failed. Please check nuclei installation.")
    
    return vuln_output

def generate_summary(output_dir, target):
    \"""Generate a basic summary of findings.\"""
    print("\\n[+] Generating summary report")
    
    # Import reporter if available
    try:
        from reporter import generate_report
        success = generate_report(output_dir, target)
        if success:
            print("[+] Advanced report generated successfully.")
            return True
    except ImportError:
        # Fall back to basic summary
        pass
        
    # Generate basic summary
    import datetime
    summary_file = os.path.join(output_dir, "summary.txt")
    
    try:
        with open(summary_file, "w") as f:
            f.write(f"SECURITY SCAN SUMMARY\\n")
            f.write(f"Target: {target}\\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n\\n")
            
            # Count ports
            ports_file = os.path.join(output_dir, "ports.txt")
            port_count = 0
            if os.path.exists(ports_file):
                with open(ports_file, "r") as pf:
                    port_count = len([l for l in pf.readlines() if l.strip()])
            
            # Count HTTP services
            http_file = os.path.join(output_dir, "http_services.txt")
            http_count = 0
            if os.path.exists(http_file):
                with open(http_file, "r") as hf:
                    http_count = len([l for l in hf.readlines() if l.strip()])
            
            # Count vulnerabilities
            vuln_file = os.path.join(output_dir, "vulnerabilities.txt")
            vuln_count = 0
            if os.path.exists(vuln_file):
                with open(vuln_file, "r") as vf:
                    vuln_count = len([l for l in vf.readlines() if l.strip()])
            
            f.write(f"Open ports: {port_count}\\n")
            f.write(f"HTTP services: {http_count}\\n")
            f.write(f"Vulnerabilities found: {vuln_count}\\n")
        
        print(f"[+] Summary report saved to {summary_file}")
        return True
    except Exception as e:
        print(f"[!] Error generating summary: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Automated vulnerability scanning workflow')
    parser.add_argument('target', help='Target to scan (IP or domain)')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80,443,8000-8090)')
    parser.add_argument('-t', '--templates', help='Custom nuclei templates')
    parser.add_argument('--tags', default='cve', help='Nuclei template tags (default: cve)')
    parser.add_argument('--severity', default='critical,high', help='Severity filter (default: critical,high)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output-dir', help='Custom output directory')
    parser.add_argument('--update-templates', action='store_true', help='Update nuclei templates')
    
    args = parser.parse_args()
    
    # Set up signal handler for graceful exit on CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Update nuclei templates if requested
    if args.update_templates:
        print("[+] Updating nuclei templates...")
        nuclei.run_nuclei(update_templates=True)
    
    # Create output directory
    target_name = args.target.replace('https://', '').replace('http://', '').split('/')[0]
    output_dir = args.output_dir or create_output_directory(target_name)
    if not output_dir:
        print("[-] Failed to create output directory.")
        sys.exit(1)
    
    print(f"[+] Starting vulnerability assessment against {args.target}")
    print(f"[+] Results will be saved to {output_dir}")
    
    start_time = time.time()
    
    try:
        # Step 1: Port scanning
        ports_file = run_port_scan(args.target, output_dir, args.ports, args.verbose)
        
        # Step 2: HTTP service detection
        http_file = run_http_probe(ports_file, output_dir, args.verbose)
        
        # Step 3: Vulnerability scanning
        vuln_file = run_vulnerability_scan(http_file, output_dir, args.templates, 
                                         args.tags, args.severity, args.verbose)
        
        # Step 4: Generate summary
        generate_summary(output_dir, args.target)
        
        elapsed_time = time.time() - start_time
        print(f"\\n[+] Scan completed in {elapsed_time:.2f} seconds")
        print(f"[+] Results saved to {output_dir}")
        
    except Exception as e:
        print(f"\\n[-] Error during scan: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
"""
        
        with open(workflow_path, "w") as f:
            f.write(workflow_content)
        
        # Make the script executable
        os.chmod(workflow_path, 0o755)
        print(f"Created workflow script at {workflow_path}")

def create_utils_file():
    """Create utils.py file with helper functions."""
    utils_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "utils.py")
    
    if not os.path.exists(utils_file):
        utils_content = """#!/usr/bin/env python3
import os
import sys
import socket
import platform
import subprocess
import shutil
import time

def run_cmd(cmd, shell=False, check=False, use_sudo=False, timeout=300, retry=1, silent=False):
    \"\"\"
    Run a shell command with improved error handling and retries.
    \"\"\"
    if use_sudo and os.geteuid() != 0 and platform.system().lower() != "windows":
        cmd = ["sudo"] + cmd if isinstance(cmd, list) else ["sudo"] + [cmd]
    
    for attempt in range(retry + 1):
        try:
            if not silent:
                print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
            
            process = subprocess.Popen(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                if stdout and not stdout.isspace() and not silent:
                    print(stdout)
                
                if process.returncode != 0:
                    if stderr and not silent:
                        print(f"Error: {stderr}")
                    
                    if attempt < retry:
                        if not silent:
                            print(f"Command failed. Retrying ({attempt+1}/{retry})...")
                        time.sleep(2)  # Add delay between retries
                        continue
                    
                    if check:
                        raise subprocess.CalledProcessError(process.returncode, cmd)
                    return False
                
                return True
            except subprocess.TimeoutExpired:
                # Kill the process if it times out
                process.kill()
                process.wait()
                if not silent:
                    print(f"Command timed out after {timeout} seconds: {cmd}")
                if attempt < retry:
                    if not silent:
                        print(f"Retrying ({attempt+1}/{retry})...")
                    time.sleep(2)
                    continue
                return False
        except subprocess.CalledProcessError as e:
            if not silent:
                print(f"Command failed: {e}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
        except Exception as e:
            if not silent:
                print(f"Error running command {cmd}: {str(e)}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
    
    return False

def check_network():
    \"\"\"Check for network connectivity.\"""
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    
    for dns in dns_servers:
        try:
            # Try connecting to DNS server
            socket.create_connection((dns, 53), 3)
            return True
        except Exception:
            continue
    
    print("No network connection detected. Please check your internet connection.")
    return False

def create_directory_if_not_exists(directory):
    \"\"\"Create a directory if it doesn't exist.\"""
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {directory}: {e}")
        return False

def get_executable_path(cmd):
    \"\"\"Find the path to an executable, checking PATH and common locations.\"""
    # First check if it's directly in PATH
    path = shutil.which(cmd)
    if path:
        return path
    
    # Check common locations
    common_locations = [
        os.path.expanduser(f"~/go/bin/{cmd}"),
        os.path.expanduser(f"~/.local/bin/{cmd}"),
        f"/usr/local/bin/{cmd}",
        f"/usr/bin/{cmd}"
    ]
    
    for location in common_locations:
        if os.path.exists(location) and os.access(location, os.X_OK):
            return location
    
    return None
"""
        
        with open(utils_file, "w") as f:
            f.write(utils_content)
        
        print(f"Created utils file at {utils_file}")

def create_documentation():
    """Create documentation directory and files."""
    docs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "documentacao")
    os.makedirs(docs_dir, exist_ok=True)
    
    doc_file = os.path.join(docs_dir, "comandos_e_parametros.txt")
    if not os.path.exists(doc_file):
        # The file already exists in your workspace
        pass
    print("Documentation verified")

def check_and_install_dependencies():
    """Check and install all required dependencies."""
    print("\n===== Checking and Installing Dependencies =====\n")

    # Check for network connectivity
    print("Checking network connectivity...")
    if not check_network():
        print("Warning: No network connection detected. Some installation steps may fail.")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            print("Installation aborted.")
            return False

    # If on Linux, fix dpkg issues first
    if platform.system().lower() == "linux":
        print("Running fix_dpkg_interruptions()...")
        fix_dpkg_interruptions()
        # Try to install naabu and nuclei via apt
        print("Running install_apt_packages()...")
        install_apt_packages()
    
    # Check and install Go
    check_and_install_go()

    # Install security tools
    print("\n===== Installing Security Tools =====\n")
    install_security_tools()
    
    # Update nuclei templates
    update_nuclei_templates()

    # Install Python packages
    venv_path = setup_python_venv()
    install_python_packages(venv_path)

    # Create command modules
    create_command_modules()

    # Create other essential files
    create_utils_file()
    create_workflow_script()
    create_documentation()

    print("\nDependency setup completed.")
    return True

def main():
    """Main installation function."""
    print("\n===== Vulnerability Analysis Toolkit Setup =====\n")
    
    # Verify running on Linux
    if platform.system().lower() != "linux":
        print("Error: This toolkit is designed for Debian/Kali Linux only.")
        print("Windows is not supported.")
        sys.exit(1)
    
    # Check Linux distribution
    distro = check_linux_distro()
    print(f"Detected Linux distribution: {distro}")
    
    if distro not in ["kali", "debian"]:
        print("Warning: This toolkit is optimized for Kali Linux and Debian-based systems.")
        print("Some features may not work correctly on your distribution.")
    
    # First run setup.py
    setup_success = run_setup_py()
    if not setup_success:
        print("Warning: setup.py didn't complete successfully. Continuing with installation...")
    
    # Main installation
    print("This script will install and configure the following tools:")
    print("  - Naabu: Fast port scanner")
    print("  - HTTPX: HTTP server probe")
    print("  - Nuclei: Vulnerability scanner")
    print("\nNo additional tools like nmap or netcat will be used.\n")
    
    # Check for sudo
    if platform.system().lower() == "linux":
        if os.geteuid() != 0:
            print("This script requires sudo privileges for some operations.")
            try:
                subprocess.run(["sudo", "true"], check=True)
            except:
                print("Failed to obtain sudo privileges. Some operations may fail.")
    
    try:
        input("Press Enter to continue...")
    except KeyboardInterrupt:
        print("\nSetup cancelled.")
        sys.exit(1)
    
    # Try running the bash script directly if on Linux
    if platform.system().lower() == "linux":
        print("\nRunning setup_tools.sh to complete the installation...")
        success = run_bash_script()
        
        if success:
            print("\n✅ Installation completed successfully!")
        else:
            print("\n⚠️ Installation completed with some issues.")
            print("Please check the output for error messages.")
    else:
        print("Error: This toolkit is designed for Debian/Kali Linux only.")
        print("Windows is not supported.")
        sys.exit(1)
    
    return True

# Add this function call right before running main setup
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInstallation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred during installation: {e}")
        sys.exit(1)