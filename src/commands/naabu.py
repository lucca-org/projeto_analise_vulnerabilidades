#!/usr/bin/env python3
"""
naabu.py - Naabu port scanner interface
Handles naabu execution with proper path resolution and configuration.
"""

import os
import sys
import subprocess
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from utils import run_cmd, get_executable_path

# Global variable to store the naabu path
NAABU_PATH = None

def set_naabu_path(path: str) -> None:
    """Set the naabu executable path."""
    global NAABU_PATH
    NAABU_PATH = path

def get_naabu_executable() -> str:
    """Get the naabu executable path, trying multiple methods."""
    global NAABU_PATH
    
    # First, try the configured path
    if NAABU_PATH and os.path.exists(NAABU_PATH):
        return NAABU_PATH
    
    # Try environment variable
    env_path = os.environ.get('NAABU_PATH')
    if env_path and os.path.exists(env_path):
        NAABU_PATH = env_path
        return env_path
    
    # Try standard PATH
    path_result = get_executable_path('naabu')
    if path_result:
        NAABU_PATH = path_result
        return path_result
    
    # Try common installation locations
    common_paths = [
        '/root/go/bin/naabu',
        os.path.expanduser('~/go/bin/naabu'),
        '/usr/local/bin/naabu',
        '/usr/bin/naabu'
    ]
    
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            NAABU_PATH = path
            return path
    
    # Fallback to 'naabu' and hope it's in PATH
    return 'naabu'

def check_naabu_availability() -> bool:
    """Check if naabu is available and working."""
    naabu_path = get_naabu_executable()
    print(f"Naabu is available: ")
    
    try:
        # Test if naabu is executable
        result = subprocess.run([naabu_path, '-version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True
        else:
            print(f"naabu version check failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error checking naabu: {e}")
        return False

def run_naabu(target: str, ports: str = "top-1000", output_file: str = "ports.txt",
              json_output: bool = False, silent: bool = False, 
              additional_args: Optional[List[str]] = None) -> bool:
    """
    Run naabu port scanner with the configured executable path.
    
    Args:
        target: Target to scan (IP, domain, or CIDR)
        ports: Port specification (default: top-1000)
        output_file: Output file path
        json_output: Enable JSON output format
        silent: Run in silent mode
        additional_args: Additional command line arguments
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        naabu_path = get_naabu_executable()
        
        # Build command
        cmd = [naabu_path, '-host', target, '-p', ports]
        
        # Add output file
        if json_output:
            cmd.extend(['-json', '-o', output_file])
        else:
            cmd.extend(['-o', output_file])
        
        # Add silent mode
        if silent:
            cmd.append('-silent')
        
        # Add additional arguments
        if additional_args:
            cmd.extend(additional_args)
        
        # Execute command
        print(f"Running: {' '.join(cmd)}")
        success = run_cmd(cmd)
        
        if success:
            print(f"[+] Naabu scan completed successfully")
            return True
        else:
            print(f"[-] Naabu scan failed")
            return False
            
    except Exception as e:
        print(f"Error running naabu: {e}")
        return False

def update_naabu() -> bool:
    """Update naabu to the latest version."""
    try:
        print("[+] Updating naabu...")
        cmd = ['go', 'install', '-v', 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest']
        success = run_cmd(cmd)
        
        if success:
            print("[+] Naabu updated successfully")
            return True
        else:
            print("[-] Failed to update naabu")
            return False
            
    except Exception as e:
        print(f"Error updating naabu: {e}")
        return False

def run_naabu_scan(target: str, ports: Optional[str] = None, output_file: Optional[str] = None, 
             json_output: bool = False, silent: bool = False, 
             additional_args: Optional[List[str]] = None) -> bool:
    """
    Run naabu port scanner with given parameters.
    
    Args:
        target: Target to scan (IP, domain, or CIDR)
        ports: Ports to scan (e.g., 80,443,8000-9000)
        output_file: Output file to save results
        json_output: Whether to output in JSON format
        silent: Whether to suppress output
        additional_args: Additional arguments to pass to naabu
        
    Returns:
        True if successful, False otherwise
    """
    # Get the naabu executable path
    naabu_path = get_naabu_executable()
    
    # Build command with proper string handling
    command = [naabu_path]
    
    # Add required arguments
    command.extend(["-host", target])
    
    # Add optional arguments with None checks
    if ports is not None:
        command.extend(["-p", ports])
    
    if output_file is not None:
        command.extend(["-o", output_file])
    
    if json_output:
        command.append("-json")
    
    if silent:
        command.append("-silent")
    
    # Add any additional arguments
    if additional_args is not None:
        command.extend(additional_args)
    
    try:
        print(f"Naabu is available: ")
        print(f"Running: {' '.join(command)}")
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        print(f"Error running command {' '.join(command)}: [Errno 2] No such file or directory: '{naabu_path}'")
        
        # Try one retry
        print("Retrying (1/1)...")
        try:
            print(f"Running: {' '.join(command)}")
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            print(f"Error running command {' '.join(command)}: [Errno 2] No such file or directory: '{naabu_path}'")
            
            # Try to auto-install naabu if not found
            print("Naabu not found in PATH or in ~/go/bin.")
            print("🔧 Naabu not found. Attempting automatic installation...")
            if auto_install_naabu():
                # Update the command with new path
                updated_naabu_path = get_naabu_executable()
                command[0] = updated_naabu_path
                # Retry after installation
                try:
                    result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    return True
                except Exception as e:
                    print(f"Failed to execute Naabu after installation: {e}")
                    return False
            else:
                print("Failed to install Naabu automatically.")
                return False
    except subprocess.CalledProcessError as e:
        print(f"Error running Naabu: {e}")
        if e.stderr:
            print(f"STDERR: {e.stderr.decode('utf-8', errors='ignore')}")
        print("Failed to execute Naabu. Please check the parameters and try again.")
        return False
    except Exception as e:
        print(f"Unexpected error running Naabu: {e}")
        return False

def auto_install_naabu() -> bool:
    """
    Attempt to automatically install naabu if it's not found.
    
    Returns:
        bool: True if successful, False otherwise
    """
    print("🔧 Starting automatic installation of Naabu...")
    
    # Check if naabu is already in PATH or in common Go bin directories
    if os.path.exists(os.path.expanduser("~/go/bin/naabu")):
        global NAABU_PATH
        NAABU_PATH = os.path.expanduser("~/go/bin/naabu")
        print(f"Naabu found at {NAABU_PATH}")
        return True
    
    # Try installing with Go
    print("📦 Installing Naabu using Go...")
    try:
        subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"], 
                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Update NAABU_PATH to the installed location
        NAABU_PATH = os.path.expanduser("~/go/bin/naabu")
        if os.path.exists(NAABU_PATH):
            print(f"✅ Naabu installed successfully to {NAABU_PATH}")
            return True
        else:
            print("⚠️ Naabu installation succeeded but the binary cannot be found.")
            return False
    except Exception as e:
        print(f"❌ Failed to install Naabu: {e}")
        return False

def update_nuclei_templates() -> bool:
    """
    Update nuclei templates.
    
    Returns:
        bool: True if successful, False otherwise
    """
    # This function belongs in nuclei.py, not naabu.py - should be removed
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python naabu.py <target> [ports]")
        sys.exit(1)
    
    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else "top-1000"
    
    success = run_naabu(target, ports=ports)
    if not success:
        print("Naabu scan failed.")
        sys.exit(1)