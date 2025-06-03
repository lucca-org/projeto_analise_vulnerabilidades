#!/usr/bin/env python3
"""
Test script to verify installation functionality
"""

import os
import sys
import platform
import subprocess
import shutil

# Add current directory to path to import local modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import run_cmd, get_executable_path
from index import check_and_install_go, install_httpx, setup_go_env

def test_go_installation():
    """Test Go installation and detection"""
    print("=== Testing Go Installation ===")
    
    # Test Go detection
    go_path = get_executable_path("go")
    if go_path:
        print(f"✓ Go found at: {go_path}")
        
        # Test Go version
        try:
            result = subprocess.run([go_path, "version"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✓ Go version: {result.stdout.strip()}")
            else:
                print(f"✗ Go version check failed: {result.stderr}")
        except Exception as e:
            print(f"✗ Error checking Go version: {e}")
    else:
        print("✗ Go not found in PATH")
        
        # Try to install Go
        print("Attempting to install Go...")
        if check_and_install_go():
            print("✓ Go installation successful")
        else:
            print("✗ Go installation failed")
    
    # Test environment setup
    print("\nTesting Go environment setup...")
    paths = setup_go_env()
    print(f"Go paths configured: {paths}")
    
    return go_path is not None

def test_httpx_installation():
    """Test httpx installation and detection"""
    print("\n=== Testing httpx Installation ===")
    
    # Test httpx detection
    httpx_path = get_executable_path("httpx")
    if httpx_path:
        print(f"✓ httpx found at: {httpx_path}")
        
        # Test httpx version
        try:
            result = subprocess.run([httpx_path, "-version"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✓ httpx version: {result.stdout.strip()}")
            else:
                print(f"✗ httpx version check failed: {result.stderr}")
        except Exception as e:
            print(f"✗ Error checking httpx version: {e}")
            
        # Test basic httpx functionality
        try:
            result = subprocess.run([httpx_path, "-h"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✓ httpx help command works")
            else:
                print("✗ httpx help command failed")
        except Exception as e:
            print(f"✗ Error testing httpx functionality: {e}")
            
    else:
        print("✗ httpx not found in PATH")
        
        # Try to install httpx
        print("Attempting to install httpx...")
        if install_httpx():
            print("✓ httpx installation successful")
            # Test again after installation
            httpx_path = get_executable_path("httpx")
            if httpx_path:
                print(f"✓ httpx now found at: {httpx_path}")
            else:
                print("✗ httpx still not found after installation")
        else:
            print("✗ httpx installation failed")
    
    return httpx_path is not None

def test_paths_and_environment():
    """Test PATH and environment variables"""
    print("\n=== Testing Environment Variables ===")
    
    # Check PATH
    path_env = os.environ.get("PATH", "")
    go_paths = [p for p in path_env.split(os.pathsep) if "go" in p.lower()]
    
    if go_paths:
        print(f"✓ Go paths in PATH: {go_paths}")
    else:
        print("✗ No Go paths found in PATH")
    
    # Check Go environment variables
    gopath = os.environ.get("GOPATH")
    goroot = os.environ.get("GOROOT")
    
    if gopath:
        print(f"✓ GOPATH set to: {gopath}")
    else:
        print("! GOPATH not set")
    
    if goroot:
        print(f"✓ GOROOT set to: {goroot}")
    else:
        print("! GOROOT not set (may be okay if using system package)")
    
    # Check if Go bin directories exist
    go_bin_dirs = [
        os.path.expanduser("~/go/bin"),
        "/usr/local/go/bin"
    ]
    
    for go_bin in go_bin_dirs:
        if os.path.exists(go_bin):
            print(f"✓ Go bin directory exists: {go_bin}")
            # List contents
            try:
                contents = os.listdir(go_bin)
                if contents:
                    print(f"  Contents: {', '.join(contents[:5])}{'...' if len(contents) > 5 else ''}")
                else:
                    print("  Directory is empty")
            except Exception as e:
                print(f"  Error listing directory: {e}")
        else:
            print(f"✗ Go bin directory missing: {go_bin}")

def main():
    """Run all tests"""
    print("Installation Test Suite")
    print("=" * 50)
    
    if platform.system().lower() == "windows":
        print("WARNING: This toolkit is designed for Linux systems.")
        print("Some functionality may not work on Windows.")
        print()
    
    # Run tests
    go_ok = test_go_installation()
    httpx_ok = test_httpx_installation()
    test_paths_and_environment()
    
    # Summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    print(f"Go installation: {'✓ PASS' if go_ok else '✗ FAIL'}")
    print(f"httpx installation: {'✓ PASS' if httpx_ok else '✗ FAIL'}")
    
    if go_ok and httpx_ok:
        print("\n🎉 All core tools are working!")
    else:
        print("\n⚠️ Some tools need attention. Check the output above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
