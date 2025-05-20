import subprocess
import os
import sys
import socket
import platform
import shutil

def run_cmd(cmd, shell=False, check=False, use_sudo=False):
    """Run a shell command with optional sudo and error handling."""
    if use_sudo and os.geteuid() != 0 and platform.system().lower() != "windows":
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
        except Exception:
            print("Sudo access is required. Please run the script with sudo. Exiting.")
            sys.exit(1)

def check_network():
    """Check for network connectivity."""
    try:
        # Try to connect to Google's DNS server
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        return True
    except (socket.error, OSError) as e:
        print(f"Network connectivity check failed: {e}")
        # Fallback to ping if socket connection fails
        try:
            if platform.system().lower() == "windows":
                ping_cmd = ["ping", "-n", "1", "8.8.8.8"]
            else:
                ping_cmd = ["ping", "-c", "1", "8.8.8.8"]
                
            result = subprocess.run(ping_cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Ping failed: {e}")
            return False

def get_temp_dir():
    """Return the appropriate temp directory based on platform."""
    if platform.system().lower() == "windows":
        return os.environ.get("TEMP", "C:\\Windows\\Temp")
    else:
        return "/tmp"

def check_tool_in_path(tool_name):
    """Check if a tool is available in the PATH."""
    return shutil.which(tool_name) is not None

def detect_os():
    """Detect the operating system details."""
    system = platform.system().lower()
    if system == "linux":
        try:
            with open("/etc/os-release") as f:
                os_info = f.read()
                if "ID=debian" in os_info:
                    return "debian"
                elif "ID=ubuntu" in os_info:
                    return "ubuntu"
                elif "ID=kali" in os_info:
                    return "kali"
                elif "ID=fedora" in os_info:
                    return "fedora"
                elif "ID=centos" in os_info or "ID=rhel" in os_info:
                    return "rhel"
        except:
            pass
    return system  # windows, darwin, or linux if not identified