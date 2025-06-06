#!/usr/bin/env python3
"""
Quick launcher script for the vulnerability analysis toolkit
"""

import os
import sys
import subprocess

def main():
    # Get the parent directory (project root)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    
    # Change to project root
    os.chdir(project_root)
    
    # Launch mtscan.py
    mtscan_path = os.path.join(project_root, "mtscan.py")
    
    if os.path.exists(mtscan_path):
        subprocess.run(["python", "mtscan.py"])
    else:
        print("❌ Could not find mtscan.py")
        print("Please ensure you're running from the project directory")

if __name__ == "__main__":
    main()
