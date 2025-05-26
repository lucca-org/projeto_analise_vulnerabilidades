#!/usr/bin/env python3
"""
index.py - Main installer entry point for vulnerability analysis toolkit
"""

import os
import sys
import platform
import subprocess
from pathlib import Path

# Add parent directory to path for local imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

def run_installation():
    """Run the full installation process"""
    print("Starting vulnerability analysis toolkit installation...")
    
    # Import setup module 
    try:
        from install.setup import main as setup_main
        setup_main()
    except ImportError:
        print("Error: Could not import setup module. Running as standalone script.")
        # Run setup.py as a standalone script
        setup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup.py")
        if os.path.exists(setup_path):
            if platform.system() == "Windows":
                subprocess.run([sys.executable, setup_path], check=False)
            else:
                subprocess.run(["python3", setup_path], check=False)
        else:
            print(f"Error: Setup script not found at {setup_path}")
            return False
    
    print("Installation completed!")
    return True

if __name__ == "__main__":
    run_installation()
