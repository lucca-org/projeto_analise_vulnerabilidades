#!/usr/bin/env python3
"""
Setup script that orchestrates the installation process.
On Linux systems, it runs the Bash setup script for better compatibility.
On other platforms, it uses Python-based installation.
"""

import os
import sys
import platform
import subprocess

def main():
    """Run the installation process based on the platform."""
    print("Starting Vulnerability Analysis Toolkit installation...")
    
    # Check platform - only allow Linux
    if platform.system().lower() != "linux":
        print("ERROR: This toolkit is designed for Debian/Kali Linux only.")
        print("Windows is NOT supported for this security toolkit.")
        print("Please use a Linux environment (VM, WSL, or native Linux).")
        return False
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    
    # Use the bash script for Linux systems
    setup_script = os.path.join(parent_dir, "setup_tools.sh")
    
    # Make sure the script is executable
    try:
        os.chmod(setup_script, 0o755)
    except Exception:
        pass
        
    print(f"Running setup script: {setup_script}")
    
    # Run the script with bash
    if os.path.exists(setup_script):
        # First try running with bash directly
        process = subprocess.run(["bash", setup_script], check=False)
        success = process.returncode == 0
        
        # If bash fails, try sh as fallback
        if not success:
            print("Trying with sh instead of bash...")
            process = subprocess.run(["sh", setup_script], check=False)
            success = process.returncode == 0
    else:
        print(f"Error: Setup script not found at {setup_script}")
        success = False
    
    if success:
        print("\nInstallation completed successfully!")
    else:
        print("\nInstallation completed with some issues. Please check the output for details.")
    
    return success

if __name__ == "__main__":
    # Verify running on Linux
    if platform.system().lower() != "linux":
        print("ERROR: This toolkit is designed for Debian/Kali Linux only.")
        print("Windows is NOT supported for this security toolkit.")
        print("Please use a Linux environment (VM, WSL, or native Linux).")
        sys.exit(1)
        
    sys.exit(0 if main() else 1)
