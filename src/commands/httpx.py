#!/usr/bin/env python3
"""
httpx.py - HTTPX HTTP toolkit interface
Handles httpx execution with proper path resolution for both system and Go installations.
"""

import os
import sys
import subprocess
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from utils import run_cmd, get_executable_path

# Global variable to store the httpx path
HTTPX_PATH = None

def set_httpx_path(path: str) -> None:
    """Set the httpx executable path."""
    global HTTPX_PATH
    HTTPX_PATH = path

def get_httpx_executable() -> str:
    """Get the httpx executable path, checking both system and Go installations."""
    global HTTPX_PATH
    
    # First, try the configured path
    if HTTPX_PATH and os.path.exists(HTTPX_PATH):
        return HTTPX_PATH
    
    # Try environment variable
    env_path = os.environ.get('HTTPX_PATH')
    if env_path and os.path.exists(env_path):
        HTTPX_PATH = env_path
        return env_path
    
    # Try standard PATH first
    path_result = get_executable_path('httpx')
    if path_result:
        HTTPX_PATH = path_result
        return path_result
    
    # Try common installation locations in priority order
    # System installations (Kali, Ubuntu packages) first, then Go installations
    common_paths = [
        '/usr/bin/httpx',                               # Kali Linux system package
        '/usr/local/bin/httpx',                         # System-wide installation
        '/usr/bin/httpx-toolkit',                       # Alternative Kali package name
        '/usr/local/bin/httpx-toolkit',                 # Alternative system installation
        '/root/go/bin/httpx',                          # Go installation (root)
        os.path.expanduser('~/go/bin/httpx'),          # Go installation (user)
        '/snap/bin/httpx',                             # Snap package
        '/opt/httpx/httpx',                            # Custom installation
        f"{os.path.expanduser('~')}/.local/bin/httpx"  # User local installation
    ]
    
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            HTTPX_PATH = path
            return path
    
    # Fallback to 'httpx' and hope it's in PATH
    return 'httpx'

def check_httpx_availability() -> bool:
    """Check if httpx is available and working."""
    httpx_path = get_httpx_executable()
    
    try:
        # Test if httpx is executable with version check
        for version_flag in ['-version', '--version', '-V']:
            try:
                result = subprocess.run([httpx_path, version_flag], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return True
            except:
                continue
        
        # If version check fails, try help flag as fallback
        try:
            result = subprocess.run([httpx_path, '-h'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return True
        except:
            pass
            
        return False
            
    except Exception as e:
        print(f"Error checking httpx: {e}")
        return False

def run_httpx(target_list: str, output_file: str = "http_services.txt",
              title: bool = True, status_code: bool = True, 
              tech_detect: bool = True, web_server: bool = True,
              follow_redirects: bool = True, silent: bool = False,
              timeout: Optional[int] = None, threads: Optional[int] = None,
              additional_args: Optional[List[str]] = None) -> bool:
    """
    Run httpx HTTP toolkit with the configured executable path.
    
    Args:
        target_list: File containing targets or single target
        output_file: Output file path
        title: Extract page titles
        status_code: Show status codes
        tech_detect: Enable technology detection
        web_server: Show web server information
        follow_redirects: Follow HTTP redirects
        silent: Run in silent mode
        timeout: Request timeout in seconds
        threads: Number of threads
        additional_args: Additional command line arguments
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        httpx_path = get_httpx_executable()
        
        # Build command
        if os.path.isfile(target_list):
            cmd = [httpx_path, '-list', target_list]
        else:
            cmd = [httpx_path, '-u', target_list]
        
        # Add output file
        cmd.extend(['-o', output_file])
        
        # Add optional flags
        if title:
            cmd.append('-title')
        if status_code:
            cmd.append('-status-code')
        if tech_detect:
            cmd.append('-tech-detect')
        if web_server:
            cmd.append('-web-server')
        if follow_redirects:
            cmd.append('-follow-redirects')
        if silent:
            cmd.append('-silent')
        
        # Add timeout and threads if specified
        if timeout:
            cmd.extend(['-timeout', str(timeout)])
        if threads:
            cmd.extend(['-threads', str(threads)])
        
        # Add additional arguments
        if additional_args:
            cmd.extend(additional_args)
        
        # Execute command
        print(f"Running: {' '.join(cmd)}")
        success = run_cmd(cmd)
        
        if success:
            print(f"[+] HTTPX scan completed successfully")
            return True
        else:
            print(f"[-] HTTPX scan failed")
            return False
            
    except Exception as e:
        print(f"Error running httpx: {e}")
        return False

def update_httpx() -> bool:
    """Update httpx to the latest version (Go installation only)."""
    try:
        print("[+] Updating httpx...")
        cmd = ['go', 'install', '-v', 'github.com/projectdiscovery/httpx/cmd/httpx@latest']
        success = run_cmd(cmd)
        
        if success:
            print("[+] HTTPX updated successfully")
            return True
        else:
            print("[-] Failed to update httpx")
            return False
            
    except Exception as e:
        print(f"Error updating httpx: {e}")
        return False

def install_httpx_automatically() -> bool:
    """Attempt to automatically install httpx if not found."""
    try:
        print("🔧 HTTPX not found. Attempting automatic installation...")
        
        # Try Go installation first
        print("🔧 Starting automatic installation of HTTPX...")
        if check_httpx_availability():
            print(f"httpx is installed at {get_httpx_executable()} but not working correctly.")
        
        print("📦 Installing HTTPX using Go...")
        cmd = ['go', 'install', '-v', 'github.com/projectdiscovery/httpx/cmd/httpx@latest']
        success = run_cmd(cmd)
        
        if success:
            print("✅ HTTPX installed successfully via Go")
            # Update the global path
            global HTTPX_PATH
            HTTPX_PATH = None  # Reset to trigger re-detection
            httpx_path = get_httpx_executable()
            if check_httpx_availability():
                print(f"✅ HTTPX verified at: {httpx_path}")
                return True
        
        print("❌ Automatic HTTPX installation failed")
        return False
        
    except Exception as e:
        print(f"Error during automatic httpx installation: {e}")
        return False