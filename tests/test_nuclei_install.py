#!/usr/bin/env python3
"""
Test script for nuclei installation retry logic
This script bypasses Linux checks to test the nuclei installation function directly.
"""

import os
import sys
import subprocess
import shutil

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

# Color codes for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    WHITE = '\033[97m'
    END = '\033[0m'

def clean_go_mod_cache():
    """Clean Go module cache to resolve download issues."""
    try:
        print(f"{Colors.YELLOW}Cleaning Go module cache...{Colors.END}")
        subprocess.run(['go', 'clean', '-modcache'], check=True)
        print(f"{Colors.GREEN}  ✅ Go module cache cleaned{Colors.END}")
    except Exception as e:
        print(f"{Colors.YELLOW}  ⚠️ Could not clean Go module cache: {e}{Colors.END}")

def install_nuclei_with_retries(repo, max_retries=3):
    """Try to install nuclei with retries, cleaning cache and switching proxy if needed."""
    for attempt in range(1, max_retries+1):
        print(f"{Colors.WHITE}Installing nuclei (attempt {attempt}/{max_retries})...{Colors.END}")
        env = os.environ.copy()
        env['CGO_ENABLED'] = '1'
        env['GO111MODULE'] = 'on'
        # On 2nd+ attempt, switch to direct proxy
        if attempt >= 2:
            env['GOPROXY'] = 'direct'
            print(f"{Colors.YELLOW}  Using GOPROXY=direct for retry{Colors.END}")
        else:
            env['GOPROXY'] = 'https://proxy.golang.org,direct'
        # On 2nd+ attempt, clean cache
        if attempt >= 2:
            clean_go_mod_cache()
        timeout_seconds = 600  # 10 min
        
        try:
            result = subprocess.run(['go', 'install', '-v', repo], capture_output=True, text=True, env=env, timeout=timeout_seconds)
            if result.returncode == 0:
                print(f"{Colors.GREEN}  ✅ nuclei installed successfully{Colors.END}")
                return True
            else:
                print(f"{Colors.RED}  ❌ nuclei install failed (exit {result.returncode}){Colors.END}")
                print(f"{Colors.YELLOW}  --- go install output ---{Colors.END}")
                print(result.stdout[-1000:])
                print(result.stderr[-1000:])
                if attempt == max_retries:
                    print(f"{Colors.RED}  ❌ nuclei installation failed after {max_retries} attempts{Colors.END}")
                    return False
                print(f"{Colors.YELLOW}  Retrying nuclei installation...{Colors.END}")
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}  ❌ nuclei install timed out after {timeout_seconds} seconds{Colors.END}")
            if attempt == max_retries:
                return False
            print(f"{Colors.YELLOW}  Retrying nuclei installation...{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}  ❌ nuclei install error: {e}{Colors.END}")
            if attempt == max_retries:
                return False
            print(f"{Colors.YELLOW}  Retrying nuclei installation...{Colors.END}")
    
    return False

def main():
    print(f"{Colors.BLUE}🔬 Testing Nuclei Installation with Retry Logic{Colors.END}")
    
    # Check if Go is available
    if not shutil.which('go'):
        print(f"{Colors.RED}❌ Go is not installed or not in PATH{Colors.END}")
        return False
    
    # Test the enhanced installation
    repo = 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
    
    print(f"{Colors.WHITE}Testing nuclei installation with enhanced retry logic...{Colors.END}")
    success = install_nuclei_with_retries(repo, max_retries=3)
    
    if success:
        print(f"{Colors.GREEN}✅ Test completed successfully - nuclei installation worked!{Colors.END}")
        
        # Check if nuclei is now available
        nuclei_path = shutil.which('nuclei')
        if nuclei_path:
            print(f"{Colors.GREEN}✅ nuclei found at: {nuclei_path}{Colors.END}")
            try:
                result = subprocess.run([nuclei_path, '-version'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"{Colors.GREEN}✅ nuclei version: {result.stdout.strip()}{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}⚠️ nuclei version check failed{Colors.END}")
            except Exception as e:
                print(f"{Colors.YELLOW}⚠️ nuclei version check error: {e}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}⚠️ nuclei not found in PATH after installation{Colors.END}")
            
        return True
    else:
        print(f"{Colors.RED}❌ Test failed - nuclei installation did not work with retry logic{Colors.END}")
        return False

if __name__ == "__main__":
    main()
