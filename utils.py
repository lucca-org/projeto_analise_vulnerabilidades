import os
import sys
import socket
import platform
import subprocess
import shutil
import time

def run_cmd(cmd, shell=False, check=False, use_sudo=False, timeout=300, retry=1):
    """Run a shell command with optional sudo, error handling, and retries."""
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
                    time.sleep(2)  # Add a short delay between retries
                    continue
                    
                if check:
                    raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
            
            # Command succeeded
            return result.returncode == 0
            
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
    
    return False  # All attempts failed

def check_network():
    """Check for network connectivity."""
    try:
        # Try multiple DNS servers to ensure we're actually connected
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

def format_duration(seconds):
    """Format seconds into human-readable time."""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"

def is_valid_ip(ip):
    """Check if a string is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def detect_os():
    """Detect the operating system with more detail."""
    system = platform.system().lower()
    
    if system == "linux":
        # Detect Linux distribution
        try:
            with open("/etc/os-release") as f:
                content = f.read()
                if "kali" in content.lower():
                    return "kali"
                elif "ubuntu" in content.lower():
                    return "ubuntu"
                elif "debian" in content.lower():
                    return "debian"
                elif "centos" in content.lower() or "rhel" in content.lower():
                    return "rhel"
        except:
            pass
    return system  # windows, darwin, or linux if not identified

def create_directory_if_not_exists(directory_path):
    """Create a directory if it doesn't exist."""
    if not os.path.exists(directory_path):
        try:
            os.makedirs(directory_path, exist_ok=True)
            return True
        except Exception as e:
            print(f"Error creating directory {directory_path}: {e}")
            return False
    return True

def is_tool_installed(tool_name):
    """Check if a specific tool is installed and available in PATH."""
    return shutil.which(tool_name) is not None

def get_go_version():
    """Get the installed Go version."""
    try:
        result = subprocess.run(["go", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except:
        return None

def write_to_file(filename, content, append=False):
    """Write content to a file, creating directories as needed."""
    try:
        # Create directory if it doesn't exist
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        
        # Write content to file
        mode = "a" if append else "w"
        with open(filename, mode) as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"Error writing to file {filename}: {e}")
        return False

def read_file(filename):
    """Read content from a file safely."""
    try:
        if not os.path.exists(filename):
            print(f"File not found: {filename}")
            return None
        
        with open(filename, "r") as f:
            return f.read()
    except Exception as e:
        print(f"Error reading file {filename}: {e}")
        return None

def human_readable_size(size_bytes):
    """Convert bytes to a human-readable format."""
    if size_bytes == 0:
        return "0B"
    
    size_names = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def print_banner(text):
    """Print a stylized banner."""
    border = "=" * (len(text) + 4)
    print(f"\n{border}")
    print(f"| {text} |")
    print(f"{border}\n")