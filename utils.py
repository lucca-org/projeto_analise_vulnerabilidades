import os
import sys
import socket
import platform
import subprocess
import shutil
import time
import json
from pathlib import Path
from typing import List, Dict, Any, Union, Optional, Tuple

# Constants for reuse across modules
DEFAULT_TIMEOUT = 300
DEFAULT_RETRY = 1
SECURITY_TOOLS = ["naabu", "httpx", "nuclei"]

def run_cmd(cmd: Union[str, List[str]], shell: bool = False, check: bool = False, use_sudo: bool = False, timeout: int = DEFAULT_TIMEOUT, retry: int = DEFAULT_RETRY, silent: bool = False) -> bool:
    """Enhanced command runner with better retry logic and error detection."""
    if isinstance(cmd, list):
        cmd_str = ' '.join(cmd)
    else:
        cmd_str = cmd
        
    for attempt in range(retry + 1):
        try:
            if not silent:
                print(f"Running: {cmd_str}")
            
            # Handle sudo and Windows special case in a platform-independent way
            if use_sudo and platform.system().lower() != "windows":
                try:
                    # os.geteuid() is only available on Unix-like systems
                    if hasattr(os, 'geteuid') and os.geteuid() != 0: # type: ignore
                        if isinstance(cmd, list):
                            cmd = ["sudo"] + cmd
                        else:
                            cmd = f"sudo {cmd}"
                except AttributeError:
                    # We're not on a Unix system, so we can't use sudo
                    pass
            
            # Start process
            process = subprocess.Popen(
                cmd, 
                shell=shell, 
                stdout=subprocess.PIPE if not silent else subprocess.DEVNULL, 
                stderr=subprocess.PIPE if not silent else subprocess.DEVNULL, 
                text=True
            )
            
            # Wait with timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                
                # Process output if collected
                if not silent and stdout and stdout.strip():
                    # Only show first 10 lines if output is very long
                    if stdout.count('\n') > 20:
                        short_stdout = '\n'.join(stdout.split('\n')[:10])
                        print(f"{short_stdout}\n[...output truncated...]")
                    else:
                        print(stdout)
                
                # Check return code
                if process.returncode != 0:
                    if not silent and stderr and stderr.strip():
                        print(f"Error: {stderr}")
                    
                    # Retry logic
                    if attempt < retry:
                        if not silent:
                            print(f"Command failed. Retrying ({attempt+1}/{retry})...")
                        time.sleep(2 * (attempt + 1))  # Exponential backoff
                        continue
                    
                    if check:
                        raise subprocess.CalledProcessError(process.returncode, cmd)
                    return False
                
                return True
                
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                if not silent:
                    print(f"Command timed out after {timeout} seconds: {cmd_str}")
                if attempt < retry:
                    if not silent:
                        print(f"Retrying ({attempt+1}/{retry})...")
                    time.sleep(2 * (attempt + 1))
                    continue
                return False
                
        except subprocess.CalledProcessError as e:
            if not silent:
                print(f"Command failed: {e}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2 * (attempt + 1))
                continue
            return False
        except Exception as e:
            if not silent:
                print(f"Error running command {cmd_str}: {str(e)}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2 * (attempt + 1))
                continue
            return False
    
    return False

def check_required_commands(commands: List[str]) -> List[str]:
    """Check if required commands are available and return missing ones."""
    missing = []
    for cmd in commands:
        if not shutil.which(cmd) and not os.path.exists(os.path.expanduser(f"~/go/bin/{cmd}")):
            missing.append(cmd)
    return missing

def safe_read_json(json_file: str, default: Any = None) -> Any:
    """Safely read a JSON file with error handling."""
    if not os.path.exists(json_file):
        return default
    
    try:
        with open(json_file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        # Try to read line by line for JSONL format
        try:
            results = []
            with open(json_file, 'r') as f:
                for line in f:
                    if line.strip():
                        results.append(json.loads(line))
            if results:
                return results
        except:
            pass
            
        print(f"Warning: Could not parse JSON from {json_file}")
        return default
    except Exception as e:
        print(f"Error reading {json_file}: {e}")
        return default

def safe_write_json(data: Any, json_file: str) -> bool:
    """Safely write data to a JSON file with error handling."""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(json_file)), exist_ok=True)
        
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error writing to {json_file}: {e}")
        return False

def check_tools_installation() -> Dict[str, Dict[str, Any]]:
    """Verify if all required security tools are installed and working."""
    tools = {
        "naabu": {"installed": False, "version": None, "command": "naabu -version"},
        "httpx": {"installed": False, "version": None, "command": "httpx -version"},
        "nuclei": {"installed": False, "version": None, "command": "nuclei -version"}
    }
    
    for tool, data in tools.items():
        # Check if tool exists in PATH or ~/go/bin
        tool_path = shutil.which(tool)
        if not tool_path and os.path.exists(os.path.expanduser(f"~/go/bin/{tool}")):
            tool_path = os.path.expanduser(f"~/go/bin/{tool}")
        
        if tool_path:
            try:
                result = subprocess.run(data["command"].split(), 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=5)
                
                data["installed"] = True
                data["version"] = result.stdout.strip() if result.stdout else "Unknown"
                data["path"] = tool_path
            except Exception as e:
                data["error"] = str(e)
    
    return tools

def check_network() -> bool:
    """Check for network connectivity."""
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    
    for dns in dns_servers:
        try:
            # Try connecting to DNS server with timeout
            socket.create_connection((dns, 53), 3)
            return True
        except (socket.timeout, socket.error, OSError):
            continue
    
    print("No network connection detected. Please check your internet connection.")
    return False

def create_directory_if_not_exists(directory: str) -> bool:
    """Create a directory if it doesn't exist."""
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {directory}: {e}")
        return False

def get_executable_path(cmd: str) -> Optional[str]:
    """Find the path to an executable, checking PATH and common locations."""
    # Check in PATH
    cmd_path = shutil.which(cmd)
    if cmd_path:
        return cmd_path
        
    # Check in ~/go/bin
    go_bin_path = os.path.expanduser(f"~/go/bin/{cmd}")
    if os.path.exists(go_bin_path) and os.access(go_bin_path, os.X_OK):
        return go_bin_path
    
    # Check Windows common locations if on Windows
    if platform.system() == "Windows":
        for path in [f"C:\\Program Files\\{cmd}\\{cmd}.exe", 
                    f"C:\\Program Files (x86)\\{cmd}\\{cmd}.exe"]:
            if os.path.exists(path):
                return path
    
    return None

def get_system_memory_gb() -> float:
    """
    Get the total system memory in GB.
    """
    try:
        if platform.system() == "Linux":
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
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
    return 4.0  # Default to 4GB if detection fails

def normalize_path(path: str) -> str:
    """
    Normalize file paths for the current operating system.
    """
    if os.name == 'nt':  # Windows
        return path.replace('/', '\\')
    else:
        return path.replace('\\', '/')

# Add utility for ensuring proper file permissions 
def ensure_executable(file_path: str) -> bool:
    """Make sure a file is executable (Unix only)."""
    if platform.system().lower() != "windows":
        try:
            os.chmod(file_path, 0o755)
            return True
        except Exception as e:
            print(f"Error making {file_path} executable: {e}")
            return False
    return True