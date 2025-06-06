#!/usr/bin/env python3
"""
nuclei.py - Nuclei vulnerability scanner interface
Handles nuclei execution with proper path resolution and configuration.
"""

import os
import sys
import subprocess
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from utils import run_cmd, get_executable_path

# Global variable to store the nuclei path
NUCLEI_PATH = None

def set_nuclei_path(path: str) -> None:
    """Set the nuclei executable path."""
    global NUCLEI_PATH
    NUCLEI_PATH = path

def get_nuclei_executable() -> str:
    """Get the nuclei executable path, trying multiple methods."""
    global NUCLEI_PATH
    
    # First, try the configured path
    if NUCLEI_PATH and os.path.exists(NUCLEI_PATH):
        return NUCLEI_PATH
    
    # Try environment variable
    env_path = os.environ.get('NUCLEI_PATH')
    if env_path and os.path.exists(env_path):
        NUCLEI_PATH = env_path
        return env_path
    
    # Try standard PATH
    path_result = get_executable_path('nuclei')
    if path_result:
        NUCLEI_PATH = path_result
        return path_result
    
    # Try common installation locations
    common_paths = [
        '/root/go/bin/nuclei',
        os.path.expanduser('~/go/bin/nuclei'),
        '/usr/local/bin/nuclei',
        '/usr/bin/nuclei'
    ]
    
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            NUCLEI_PATH = path
            return path
    
    # Fallback to 'nuclei' and hope it's in PATH
    return 'nuclei'

def check_nuclei_availability() -> bool:
    """Check if nuclei is available and working."""
    nuclei_path = get_nuclei_executable()
    
    try:
        # Test if nuclei is executable
        result = subprocess.run([nuclei_path, '-version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True
        else:
            print(f"nuclei version check failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error checking nuclei: {e}")
        return False

def run_nuclei(target_list: str, templates: Optional[str] = None, 
               tags: str = "cve", severity: str = "critical,high",
               output_file: str = "vulnerabilities.txt", jsonl: bool = False,
               store_resp: bool = False, silent: bool = False,
               additional_args: Optional[List[str]] = None) -> bool:
    """
    Run nuclei vulnerability scanner with the configured executable path.
    
    Args:
        target_list: File containing targets or single target
        templates: Path to custom templates
        tags: Template tags to run
        severity: Severity filter
        output_file: Output file path
        jsonl: Enable JSONL output format
        store_resp: Store HTTP responses
        silent: Run in silent mode
        additional_args: Additional command line arguments
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        nuclei_path = get_nuclei_executable()
        
        # Build command
        if os.path.isfile(target_list):
            cmd = [nuclei_path, '-list', target_list]
        else:
            cmd = [nuclei_path, '-target', target_list]
        
        # Add templates or tags
        if templates:
            cmd.extend(['-templates', templates])
        else:
            cmd.extend(['-tags', tags])
        
        # Add severity filter
        if severity:
            cmd.extend(['-severity', severity])
        
        # Add output file
        if jsonl:
            cmd.extend(['-jsonl', '-o', output_file])
        else:
            cmd.extend(['-o', output_file])
        
        # Add optional flags
        if store_resp:
            cmd.append('-store-resp')
        if silent:
            cmd.append('-silent')
        
        # Add additional arguments
        if additional_args:
            cmd.extend(additional_args)
        
        # Execute command
        print(f"Running: {' '.join(cmd)}")
        success = run_cmd(cmd)
        
        if success:
            print(f"[+] Nuclei scan completed successfully")
            return True
        else:
            print(f"[-] Nuclei scan failed")
            return False
            
    except Exception as e:
        print(f"Error running nuclei: {e}")
        return False

def update_nuclei_templates() -> bool:
    """Update nuclei templates to the latest version."""
    try:
        nuclei_path = get_nuclei_executable()
        print("[+] Updating nuclei templates...")
        cmd = [nuclei_path, '-update-templates']
        success = run_cmd(cmd)
        
        if success:
            print("[+] Nuclei templates updated successfully")
            return True
        else:
            print("[-] Failed to update nuclei templates")
            return False
            
    except Exception as e:
        print(f"Error updating nuclei templates: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nuclei.py <targets_file> [output_file]")
        sys.exit(1)
    
    targets_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "vulnerabilities.txt"
    
    success = run_nuclei(targets_file, output_file=output_file)
    if not success:
        print("Nuclei scan failed.")
        sys.exit(1)