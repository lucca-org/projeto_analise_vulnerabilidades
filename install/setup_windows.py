#!/usr/bin/env python3
"""
Windows Setup Script for Vulnerability Analysis Toolkit
Installs security tools: naabu, httpx, nuclei via Go
"""

import os
import sys
import platform
import subprocess
import shutil
import requests
import json
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

def check_admin():
    """Check if running as administrator (optional but recommended)."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_go_installation():
    """Check if Go is installed and properly configured."""
    print("🔍 Checking Go installation...")
    
    # Check if go command exists
    try:
        result = subprocess.run(['go', 'version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Go is installed: {result.stdout.strip()}")
            
            # Check GOPATH and GOBIN
            gopath_result = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True)
            if gopath_result.returncode == 0:
                gopath = gopath_result.stdout.strip()
                gobin = os.path.join(gopath, 'bin')
                print(f"✅ GOPATH: {gopath}")
                print(f"✅ GOBIN: {gobin}")
                
                # Check if GOBIN is in PATH
                current_path = os.environ.get('PATH', '')
                if gobin.lower() not in current_path.lower():
                    print(f"⚠️  GOBIN ({gobin}) is not in PATH")
                    print("   You may need to add it manually or restart your terminal")
                
                return True, gobin
            else:
                print("❌ Could not get GOPATH")
                return False, None
        else:
            print("❌ Go is not installed or not in PATH")
            return False, None
    except FileNotFoundError:
        print("❌ Go is not installed")
        return False, None

def install_go():
    """Download and install Go for Windows."""
    print("\n🔧 Installing Go for Windows...")
    
    # Get the latest Go version
    try:
        response = requests.get("https://go.dev/dl/?mode=json")
        releases = response.json()
        latest_release = releases[0]
        version = latest_release['version']
        
        # Find Windows AMD64 download
        windows_download = None
        for file_info in latest_release['files']:
            if file_info['os'] == 'windows' and file_info['arch'] == 'amd64' and file_info['kind'] == 'archive':
                windows_download = file_info
                break
        
        if not windows_download:
            print("❌ Could not find Windows Go download")
            return False
        
        download_url = f"https://go.dev/dl/{windows_download['filename']}"
        print(f"📥 Downloading {windows_download['filename']}...")
        
        # Download Go
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, windows_download['filename'])
            
            response = requests.get(download_url, stream=True)
            total_size = int(response.headers.get('content-length', 0))
            
            with open(zip_path, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            print(f"\rProgress: {percent:.1f}%", end='', flush=True)
            
            print(f"\n✅ Downloaded {windows_download['filename']}")
            
            # Extract Go
            extract_path = "C:\\Go"
            print(f"📂 Extracting to {extract_path}...")
            
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall("C:\\")
                print(f"✅ Go extracted to {extract_path}")
                
                # Add Go to PATH (user environment variable)
                print("🔧 Adding Go to PATH...")
                go_bin = "C:\\Go\\bin"
                
                # Get current user PATH
                import winreg
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_ALL_ACCESS) as key:
                        try:
                            current_path, _ = winreg.QueryValueEx(key, "PATH")
                        except FileNotFoundError:
                            current_path = ""
                        
                        if go_bin not in current_path:
                            new_path = f"{current_path};{go_bin}" if current_path else go_bin
                            winreg.SetValueEx(key, "PATH", 0, winreg.REG_EXPAND_SZ, new_path)
                            print("✅ Added Go to user PATH")
                            print("⚠️  Please restart your terminal for PATH changes to take effect")
                        else:
                            print("✅ Go is already in PATH")
                            
                except Exception as e:
                    print(f"⚠️  Could not update PATH automatically: {e}")
                    print(f"   Please manually add {go_bin} to your PATH")
                
                return True
                
            except Exception as e:
                print(f"❌ Failed to extract Go: {e}")
                return False
                
    except Exception as e:
        print(f"❌ Failed to download Go: {e}")
        return False

def install_security_tools(gobin_path):
    """Install security tools using Go."""
    tools = {
        'naabu': 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
        'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
        'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
    }
    
    print("\n🔧 Installing security tools...")
    
    # Set environment variables for Go
    env = os.environ.copy()
    if gobin_path:
        env['GOBIN'] = gobin_path
    
    for tool_name, tool_package in tools.items():
        print(f"\n📦 Installing {tool_name}...")
        try:
            cmd = ['go', 'install', tool_package]
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            
            if result.returncode == 0:
                print(f"✅ {tool_name} installed successfully")
                
                # Verify installation
                tool_path = os.path.join(gobin_path, f"{tool_name}.exe") if gobin_path else f"{tool_name}.exe"
                if os.path.exists(tool_path):
                    print(f"✅ {tool_name} binary found at: {tool_path}")
                else:
                    print(f"⚠️  {tool_name} binary not found in expected location")
            else:
                print(f"❌ Failed to install {tool_name}")
                print(f"Error: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Error installing {tool_name}: {e}")

def update_nuclei_templates():
    """Update nuclei templates."""
    print("\n🔄 Updating nuclei templates...")
    try:
        result = subprocess.run(['nuclei', '-update-templates'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Nuclei templates updated")
        else:
            print("⚠️  Template update may have failed, but this is often normal")
    except Exception as e:
        print(f"⚠️  Could not update templates: {e}")

def install_python_dependencies():
    """Install Python dependencies."""
    print("\n🐍 Installing Python dependencies...")
    
    requirements_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'requirements.txt')
    
    if os.path.exists(requirements_file):
        try:
            result = subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', requirements_file], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Python dependencies installed")
            else:
                print(f"⚠️  Some Python dependencies may have failed: {result.stderr}")
        except Exception as e:
            print(f"❌ Error installing Python dependencies: {e}")
    else:
        # Fallback to individual packages
        packages = ['requests', 'colorama', 'jinja2', 'markdown', 'rich', 'tqdm']
        for package in packages:
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                             capture_output=True, text=True)
                print(f"✅ Installed {package}")
            except Exception as e:
                print(f"⚠️  Failed to install {package}: {e}")

def verify_installation():
    """Verify that all tools are working."""
    print("\n🔍 Verifying installation...")
    
    tools = ['naabu', 'httpx', 'nuclei']
    all_good = True
    
    for tool in tools:
        try:
            result = subprocess.run([tool, '-version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_output = result.stdout.strip() or result.stderr.strip()
                print(f"✅ {tool}: {version_output}")
            else:
                print(f"❌ {tool}: Version check failed")
                all_good = False
        except subprocess.TimeoutExpired:
            print(f"⚠️  {tool}: Version check timed out")
        except FileNotFoundError:
            print(f"❌ {tool}: Not found in PATH")
            all_good = False
        except Exception as e:
            print(f"⚠️  {tool}: {e}")
    
    return all_good

def main():
    print("🚀 Windows Setup for Vulnerability Analysis Toolkit")
    print("=" * 60)
    
    # Check if we're on Windows
    if platform.system() != "Windows":
        print("❌ This script is for Windows only")
        sys.exit(1)
    
    # Check if running as admin (optional)
    if not check_admin():
        print("⚠️  Not running as administrator. Some operations may fail.")
        print("   Consider running as administrator for best results.")
    
    print(f"📋 System: {platform.system()} {platform.release()}")
    print(f"🐍 Python: {platform.python_version()}")
    
    # Step 1: Check/Install Go
    go_installed, gobin_path = check_go_installation()
    
    if not go_installed:
        print("\n📥 Go is required but not installed.")
        install_choice = input("Would you like to install Go automatically? (y/n): ").lower().strip()
        
        if install_choice == 'y':
            if install_go():
                print("✅ Go installation completed")
                print("⚠️  Please restart your terminal and run this script again to continue with tool installation")
                sys.exit(0)
            else:
                print("❌ Go installation failed")
                print("Please install Go manually from https://golang.org/dl/")
                sys.exit(1)
        else:
            print("❌ Go is required for tool installation")
            print("Please install Go from https://golang.org/dl/ and run this script again")
            sys.exit(1)
    
    # Step 2: Install security tools
    install_security_tools(gobin_path)
    
    # Step 3: Update nuclei templates
    update_nuclei_templates()
    
    # Step 4: Install Python dependencies
    install_python_dependencies()
    
    # Step 5: Verify installation
    if verify_installation():
        print("\n🎉 Installation completed successfully!")
        print("\nYou can now use the toolkit:")
        print("  python src\\workflow.py example.com")
        print("  python tests\\test_environment.py")
    else:
        print("\n⚠️  Installation completed with some issues")
        print("Some tools may not be working correctly")
        print("Please check the output above for details")

if __name__ == "__main__":
    main()
