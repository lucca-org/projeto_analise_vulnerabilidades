#!/usr/bin/env python3
"""
Linux Vulnerability Analysis Toolkit - Master Installation Script
================================================================================

This is the MAIN installer, setup, and configuration script for the Linux-only
Vulnerability Analysis Toolkit. It handles everything:

- Linux platform verification and distribution detection  
- Root permission enforcement
- System package management and updates
- Dependency installation and verification
- Go environment setup
- Security tools installation (naabu, httpx, nuclei)
- Python dependencies and virtual environment
- Configuration optimization
- Complete system verification

Usage: sudo python3 install/setup.py

Requirements:
- Linux operating system (Debian/Ubuntu/Kali/Arch)
- Root privileges (sudo)
- Internet connection
- Python 3.6+

================================================================================
"""

import os
import sys
import platform
import subprocess
import shutil
import json
import time
import ctypes
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ANSI Color codes for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Linux distribution configurations
SUPPORTED_DISTROS = {
    'debian': {
        'name': 'Debian',
        'package_manager': 'apt',
        'install_cmd': ['apt', 'install', '-y'],
        'update_cmd': ['apt', 'update'],
        'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'golang-go', 'unzip', 'ca-certificates', 'libpcap-dev', 'pkg-config', 'gcc']
    },
    'kali': {
        'name': 'Kali Linux',
        'package_manager': 'apt',
        'install_cmd': ['apt', 'install', '-y'],
        'update_cmd': ['apt', 'update'],
        'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'golang-go', 'unzip', 'ca-certificates', 'libpcap-dev', 'pkg-config', 'gcc'],
        'special_repos': True
    },
    'ubuntu': {
        'name': 'Ubuntu',
        'package_manager': 'apt',
        'install_cmd': ['apt', 'install', '-y'],
        'update_cmd': ['apt', 'update'],
        'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'golang-go', 'unzip', 'software-properties-common', 'ca-certificates', 'libpcap-dev', 'pkg-config', 'gcc']
    },
    'arch': {
        'name': 'Arch Linux',
        'package_manager': 'pacman',
        'install_cmd': ['pacman', '-S', '--noconfirm'],
        'update_cmd': ['pacman', '-Sy'],
        'packages': ['curl', 'wget', 'git', 'base-devel', 'python-pip', 'go', 'unzip', 'ca-certificates', 'libpcap', 'pkgconfig', 'gcc']
    }
}

def print_header():
    """Print installation header."""
    print(f"{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.WHITE}🔥 Linux Vulnerability Analysis Toolkit - Master Installer 🔥{Colors.END}")
    print(f"{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.YELLOW}Single-point installer for complete toolkit setup{Colors.END}")
    print(f"{Colors.YELLOW}Platform: Linux-Only | Requires: Root/Sudo access{Colors.END}")
    print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")

def detect_linux_distro() -> Optional[str]:
    """Detect the Linux distribution with enhanced detection."""
    try:
        # Try reading /etc/os-release first (most reliable)
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if content:  # Ensure content is not None or empty
                    content = content.lower()
                    if 'kali' in content:
                        return 'kali'
                    elif 'arch' in content:
                        return 'arch'
                    elif 'ubuntu' in content:
                        return 'ubuntu'
                    elif 'debian' in content:
                        return 'debian'
        
        # Check /etc/debian_version for Debian-based systems
        if os.path.exists('/etc/debian_version'):
            if os.path.exists('/etc/lsb-release'):
                with open('/etc/lsb-release', 'r') as f:
                    lsb_content = f.read()
                    if lsb_content and 'ubuntu' in lsb_content.lower():
                        return 'ubuntu'
            return 'debian'
        
        # Fallback to package manager detection
        if shutil.which('pacman'):
            return 'arch'
        elif shutil.which('apt') or shutil.which('apt-get'):
            return 'debian'
            
    except Exception as e:
        print(f"{Colors.YELLOW}Warning: Could not detect distribution: {e}{Colors.END}")
    
    return None

def ensure_linux_only() -> bool:
    """Ensure the system is Linux-only and reject other platforms."""
    if platform.system().lower() != "linux":
        print(f"\n{Colors.RED}╔═══════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.RED}║                          ❌ ERROR ❌                           ║{Colors.END}")
        print(f"{Colors.RED}║                                                               ║{Colors.END}")
        print(f"{Colors.RED}║     This toolkit is designed EXCLUSIVELY for Linux systems   ║{Colors.END}")
        print(f"{Colors.RED}║                                                               ║{Colors.END}")
        print(f"{Colors.RED}║     ✅ Supported: Debian, Kali, Ubuntu, Arch Linux          ║{Colors.END}")
        print(f"{Colors.RED}║     ❌ NOT Supported: Windows, macOS, WSL (limited)          ║{Colors.END}")
        print(f"{Colors.RED}║                                                               ║{Colors.END}")
        print(f"{Colors.RED}║     Please use a native Linux environment for optimal        ║{Colors.END}")
        print(f"{Colors.RED}║     security tool performance and compatibility.             ║{Colors.END}")
        print(f"{Colors.RED}╚═══════════════════════════════════════════════════════════════╝{Colors.END}")
        return False
    return True

def check_root_permissions() -> bool:
    """Check for root/sudo permissions."""
    try:
        # Method 1: Check effective user ID (Linux/Unix only)
        try:
            # On Windows, ctypes.CDLL(None) fails, so we need to check platform first
            if platform.system().lower() == "linux":
                euid = ctypes.CDLL(None).geteuid()
                if euid == 0:
                    print(f"{Colors.GREEN}✅ Running with root privileges{Colors.END}")
                    return True
            else:
                print(f"{Colors.YELLOW}⚠️  Not on Linux - skipping root user ID check{Colors.END}")
        except (OSError, AttributeError) as e:
            # Not on a Unix-like system or geteuid not available
            print(f"{Colors.YELLOW}⚠️  Cannot check effective user ID: {e}{Colors.END}")
        
        # Method 2: Check sudo access
        print(f"{Colors.YELLOW}⚠️  Not running as root. Checking sudo access...{Colors.END}")
        try:
            result = subprocess.run(['sudo', '-n', 'true'], 
                                  capture_output=True, check=False)
            if result.returncode == 0:
                print(f"{Colors.GREEN}✅ Sudo access confirmed{Colors.END}")
                return True
            else:
                print(f"{Colors.RED}❌ This script requires root privileges or sudo access{Colors.END}")
                print(f"{Colors.WHITE}Please run: sudo python3 install/setup.py{Colors.END}")
                return False
        except FileNotFoundError:
            print(f"{Colors.RED}❌ 'sudo' command not found. This script requires sudo access on Linux{Colors.END}")
            print(f"{Colors.WHITE}Please ensure you're running on a Linux system with sudo installed{Colors.END}")
            return False
            
    except Exception as e:
        print(f"{Colors.RED}❌ Error checking permissions: {e}{Colors.END}")
        print(f"{Colors.WHITE}Please ensure you have root/sudo access{Colors.END}")
        return False

def validate_system_requirements() -> Tuple[bool, Optional[str]]:
    """Validate all system requirements."""
    
    # Check Linux platform
    if not ensure_linux_only():
        return False, None
    
    # Detect distribution
    distro = detect_linux_distro()
    if not distro or distro not in SUPPORTED_DISTROS:
        print(f"{Colors.RED}❌ Could not detect supported Linux distribution{Colors.END}")
        print(f"{Colors.WHITE}Supported: Debian, Ubuntu, Kali Linux, Arch Linux{Colors.END}")
        return False, None
    
    print(f"{Colors.GREEN}✅ Detected: {SUPPORTED_DISTROS[distro]['name']}{Colors.END}")
    
    # Check Python version
    if sys.version_info < (3, 6):
        print(f"{Colors.RED}❌ Python 3.6+ required. Current: {sys.version}{Colors.END}")
        return False, None
    
    print(f"{Colors.GREEN}✅ Python version: {sys.version.split()[0]}{Colors.END}")
    
    # Check internet connectivity
    try:
        urllib.request.urlopen('https://google.com', timeout=5)
        print(f"{Colors.GREEN}✅ Internet connectivity verified{Colors.END}")
    except:
        print(f"{Colors.YELLOW}⚠️  Internet connectivity check failed{Colors.END}")
        print(f"{Colors.WHITE}Installation may fail without internet access{Colors.END}")
    
    return True, distro

def install_system_packages(distro_config: Dict) -> bool:
    """Install system packages based on distribution."""
    try:
        print(f"\n{Colors.BLUE}📦 Phase 1: System Package Installation{Colors.END}")
        print(f"{Colors.WHITE}Updating package repository...{Colors.END}")
        
        # Update package repository
        subprocess.run(distro_config['update_cmd'], check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        print(f"{Colors.GREEN}✅ Repository updated{Colors.END}")
        
        # Install base packages
        print(f"{Colors.WHITE}Installing base packages...{Colors.END}")
        cmd = distro_config['install_cmd'] + distro_config['packages']
        subprocess.run(cmd, check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        for package in distro_config['packages']:
            print(f"{Colors.GREEN}  ✅ {package}{Colors.END}")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}❌ Package installation failed: {e}{Colors.END}")
        if e.stderr:
            print(f"{Colors.RED}Error details: {e.stderr.decode()}{Colors.END}")
        return False

def setup_go_environment_complete() -> bool:
    """Complete Go environment setup."""
    try:
        print(f"\n{Colors.BLUE}🔧 Phase 2: Go Environment Setup{Colors.END}")
        
        # Check if Go is already properly installed
        try:
            result = subprocess.run(['go', 'version'], 
                                  capture_output=True, text=True, check=True)
            version = result.stdout.strip()
            print(f"{Colors.GREEN}✅ Go already installed: {version}{Colors.END}")
            
            # Verify GOPATH and GOBIN
            gopath = subprocess.run(['go', 'env', 'GOPATH'], 
                                  capture_output=True, text=True, check=True).stdout.strip()
            gobin = os.path.join(gopath, 'bin')
            
            # Ensure GOBIN is in PATH
            current_path = os.environ.get('PATH', '')
            if gobin not in current_path:
                os.environ['PATH'] = f"{gobin}:{current_path}"
                print(f"{Colors.GREEN}✅ Added {gobin} to PATH{Colors.END}")
            
            return True
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.YELLOW}⚠️  Go not found or improperly configured{Colors.END}")
        
        # Install/configure Go manually if needed
        print(f"{Colors.WHITE}Installing Go manually...{Colors.END}")
        go_version = "1.21.5"
        go_archive = f"go{go_version}.linux-amd64.tar.gz"
        
        # Download Go
        subprocess.run([
            'wget', '-q', 
            f'https://golang.org/dl/{go_archive}',
            '-O', f'/tmp/{go_archive}'
        ], check=True)
        
        # Extract Go
        subprocess.run(['sudo', 'tar', '-C', '/usr/local', '-xzf', f'/tmp/{go_archive}'], check=True)
        
        # Set up environment
        go_bin = '/usr/local/go/bin'
        current_path = os.environ.get('PATH', '')
        if go_bin not in current_path:
            os.environ['PATH'] = f"{go_bin}:{current_path}"
            
        # Add to shell profile
        profile_lines = [
            'export PATH=$PATH:/usr/local/go/bin',
            'export GOPATH=$HOME/go',
            'export PATH=$PATH:$GOPATH/bin'
        ]
        
        for profile in ['.bashrc', '.zshrc']:
            profile_path = os.path.expanduser(f'~/{profile}')
            if os.path.exists(profile_path):
                with open(profile_path, 'a') as f:
                    f.write('\n# Go environment\n')
                    for line in profile_lines:
                        f.write(f'{line}\n')
        
        print(f"{Colors.GREEN}✅ Go environment configured{Colors.END}")
        return True
        
    except Exception as e:
        print(f"{Colors.RED}❌ Go environment setup failed: {e}{Colors.END}")
        return False

def check_system_dependencies(distro: str) -> bool:
    """Check and install required system dependencies before Go tools installation."""
    try:
        print(f"\n{Colors.BLUE}🔍 Pre-installation: Dependency Verification{Colors.END}")
        
        if distro not in SUPPORTED_DISTROS:
            print(f"{Colors.RED}❌ Unsupported distribution for dependency checking{Colors.END}")
            return False
            
        distro_config = SUPPORTED_DISTROS[distro]
        missing_deps = []
        
        # Define dependencies required for Go tools
        dependency_map = {
            'ubuntu': ['libpcap-dev', 'pkg-config', 'gcc'],
            'debian': ['libpcap-dev', 'pkg-config', 'gcc'],
            'kali': ['libpcap-dev', 'pkg-config', 'gcc'],
            'arch': ['libpcap', 'pkgconfig', 'gcc']
        }
        
        required_deps = dependency_map.get(distro, [])
        
        print(f"{Colors.WHITE}Checking dependencies for {distro_config['name']}...{Colors.END}")
        
        # Check each dependency
        for dep in required_deps:
            if distro == 'arch':
                # Use pacman for Arch Linux
                try:
                    result = subprocess.run(['pacman', '-Q', dep], 
                                          capture_output=True, check=True)
                    print(f"{Colors.GREEN}  ✅ {dep} is installed{Colors.END}")
                except subprocess.CalledProcessError:
                    print(f"{Colors.RED}  ❌ {dep} is missing{Colors.END}")
                    missing_deps.append(dep)
            else:
                # Use dpkg for Debian-based systems
                try:
                    result = subprocess.run(['dpkg', '-l', dep], 
                                          capture_output=True, check=True)
                    if result.returncode == 0:
                        print(f"{Colors.GREEN}  ✅ {dep} is installed{Colors.END}")
                    else:
                        missing_deps.append(dep)
                except subprocess.CalledProcessError:
                    print(f"{Colors.RED}  ❌ {dep} is missing{Colors.END}")
                    missing_deps.append(dep)
        
        # Install missing dependencies automatically
        if missing_deps:
            print(f"\n{Colors.YELLOW}Installing missing dependencies: {', '.join(missing_deps)}{Colors.END}")
            
            try:
                if distro == 'arch':
                    cmd = ['pacman', '-S', '--noconfirm'] + missing_deps
                else:
                    cmd = distro_config['install_cmd'] + missing_deps
                
                subprocess.run(cmd, check=True, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                
                for dep in missing_deps:
                    print(f"{Colors.GREEN}  ✅ {dep} installed successfully{Colors.END}")
                    
            except subprocess.CalledProcessError as e:
                print(f"{Colors.RED}❌ Failed to install dependencies: {e}{Colors.END}")
                print(f"{Colors.YELLOW}Please install manually: {' '.join(missing_deps)}{Colors.END}")
                return False
        
        return True
        
    except Exception as e:
        print(f"{Colors.RED}❌ Dependency verification failed: {e}{Colors.END}")
        return False

def verify_go_tools_prerequisites() -> bool:
    """Verify prerequisites for Go tools compilation."""
    try:
        print(f"{Colors.WHITE}Verifying Go tools prerequisites...{Colors.END}")
        
        # Check for pcap.h header file
        pcap_headers = [
            '/usr/include/pcap.h',
            '/usr/local/include/pcap.h',
            '/usr/include/pcap/pcap.h'
        ]
        
        pcap_found = False
        for header in pcap_headers:
            if os.path.exists(header):
                print(f"{Colors.GREEN}  ✅ pcap.h found at {header}{Colors.END}")
                pcap_found = True
                break
        
        if not pcap_found:
            print(f"{Colors.RED}  ❌ pcap.h header not found{Colors.END}")
            print(f"{Colors.YELLOW}  This is required for naabu compilation{Colors.END}")
            return False
        
        # Check pkg-config for libpcap
        try:
            result = subprocess.run(['pkg-config', '--exists', 'libpcap'], 
                                  check=True, capture_output=True)
            print(f"{Colors.GREEN}  ✅ libpcap pkg-config found{Colors.END}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.YELLOW}  ⚠️  libpcap pkg-config not found{Colors.END}")
        
        return True
        
    except Exception as e:
        print(f"{Colors.RED}❌ Prerequisites verification failed: {e}{Colors.END}")
        return False

def attempt_dependency_recovery(distro: str) -> bool:
    """Attempt to recover from dependency installation failures."""
    try:
        print(f"\n{Colors.YELLOW}🔧 Attempting dependency recovery...{Colors.END}")
        
        distro_config = SUPPORTED_DISTROS[distro]
        
        # Clean package cache and update
        if distro == 'arch':
            print(f"{Colors.WHITE}Cleaning pacman cache...{Colors.END}")
            subprocess.run(['pacman', '-Scc', '--noconfirm'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['pacman', '-Sy'], check=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        else:
            print(f"{Colors.WHITE}Cleaning apt cache and updating...{Colors.END}")
            subprocess.run(['apt-get', 'clean'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['apt-get', 'update'], check=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        # Try to fix broken packages
        if distro != 'arch':
            print(f"{Colors.WHITE}Fixing broken packages...{Colors.END}")
            subprocess.run(['apt-get', 'install', '-f', '-y'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Retry dependency installation
        print(f"{Colors.WHITE}Retrying dependency installation...{Colors.END}")
        return check_system_dependencies(distro)
        
    except Exception as e:
        print(f"{Colors.RED}❌ Recovery attempt failed: {e}{Colors.END}")
        return False

def install_security_tools_complete(distro: str) -> bool:
    """Install all security tools with enhanced dependency checking and error handling."""
    try:
        print(f"\n{Colors.BLUE}🛡️  Phase 3: Security Tools Installation{Colors.END}")
        
        # Pre-installation dependency check with recovery
        if not check_system_dependencies(distro):
            print(f"{Colors.YELLOW}⚠️  Initial dependency check failed, attempting recovery...{Colors.END}")
            if not attempt_dependency_recovery(distro):
                print(f"{Colors.RED}❌ System dependencies check failed after recovery attempt{Colors.END}")
                print(f"{Colors.WHITE}Manual intervention may be required{Colors.END}")
                return False
        
        # Verify Go tools prerequisites
        if not verify_go_tools_prerequisites():
            print(f"{Colors.RED}❌ Go tools prerequisites not met{Colors.END}")
            return False
        
        tools = {
            'naabu': 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
            'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest', 
            'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
        }
        
        success_count = 0
        
        for tool, repo in tools.items():
            try:
                print(f"{Colors.WHITE}Installing {tool}...{Colors.END}")
                
                # Check if already installed
                if shutil.which(tool):
                    print(f"{Colors.GREEN}  ✅ {tool} already installed{Colors.END}")
                    success_count += 1
                    continue
                
                # Install using go install with enhanced environment
                env = os.environ.copy()
                env['CGO_ENABLED'] = '1'  # Enable CGO for tools that need it (like naabu)
                env['GO111MODULE'] = 'on'  # Ensure module mode
                
                result = subprocess.run(['go', 'install', repo], 
                                      check=True, env=env,
                                      stdout=subprocess.DEVNULL, 
                                      stderr=subprocess.PIPE,
                                      timeout=300)  # 5 minute timeout
                print(f"{Colors.GREEN}  ✅ {tool} installed successfully{Colors.END}")
                success_count += 1
                
            except subprocess.TimeoutExpired:
                print(f"{Colors.RED}  ❌ {tool} installation timed out{Colors.END}")
                print(f"{Colors.YELLOW}  💡 Try installing manually: go install {repo}{Colors.END}")
                
            except subprocess.CalledProcessError as e:
                print(f"{Colors.RED}  ❌ Failed to install {tool}: {e}{Colors.END}")
                if e.stderr:
                    error_msg = e.stderr.decode()
                    print(f"{Colors.RED}  Error: {error_msg}{Colors.END}")
                    
                    # Provide specific guidance for common errors
                    if 'pcap.h' in error_msg.lower():
                        print(f"{Colors.YELLOW}  💡 Solution: Install libpcap development package{Colors.END}")
                        print(f"{Colors.WHITE}     Ubuntu/Debian: sudo apt install libpcap-dev{Colors.END}")
                        print(f"{Colors.WHITE}     Arch Linux: sudo pacman -S libpcap{Colors.END}")
                    elif 'gcc' in error_msg.lower() or 'compiler' in error_msg.lower():
                        print(f"{Colors.YELLOW}  💡 Solution: Install build tools{Colors.END}")
                        print(f"{Colors.WHITE}     Ubuntu/Debian: sudo apt install build-essential{Colors.END}")
                        print(f"{Colors.WHITE}     Arch Linux: sudo pacman -S base-devel{Colors.END}")
                    elif 'permission denied' in error_msg.lower():
                        print(f"{Colors.YELLOW}  💡 Solution: Check Go installation and GOPATH permissions{Colors.END}")
                    elif 'network' in error_msg.lower() or 'timeout' in error_msg.lower():
                        print(f"{Colors.YELLOW}  💡 Solution: Check internet connection and try again{Colors.END}")
        
        # Update nuclei templates if nuclei was installed
        if shutil.which('nuclei'):
            print(f"{Colors.WHITE}Updating nuclei templates...{Colors.END}")
            try:
                subprocess.run(['nuclei', '-update-templates'], 
                              check=True, stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL, timeout=120)
                print(f"{Colors.GREEN}✅ Nuclei templates updated{Colors.END}")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                print(f"{Colors.YELLOW}⚠️  Template update failed or timed out{Colors.END}")
        
        # Evaluate installation success
        if success_count >= 2:  # At least 2 out of 3 tools must be installed
            print(f"{Colors.GREEN}✅ Security tools installation completed ({success_count}/3 tools){Colors.END}")
            return True
        else:
            print(f"{Colors.RED}❌ Insufficient tools installed ({success_count}/3){Colors.END}")
            print(f"{Colors.WHITE}Minimum 2 tools required for operation{Colors.END}")
            return False
        
    except Exception as e:
        print(f"{Colors.RED}❌ Security tools installation failed: {e}{Colors.END}")
        return False

def install_python_dependencies() -> bool:
    """Install Python dependencies for enhanced functionality."""
    try:
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        requirements_file = os.path.join(script_dir, 'config', 'requirements.txt')
        
        if os.path.exists(requirements_file):
            print(f"{Colors.WHITE}Installing Python dependencies from requirements.txt...{Colors.END}")
            subprocess.run(['pip3', 'install', '-r', requirements_file], check=True, 
                          stdout=subprocess.DEVNULL)
            print(f"{Colors.GREEN}✅ Python dependencies installed{Colors.END}")
        else:
            # Fallback essential packages
            print(f"{Colors.WHITE}Installing essential Python packages...{Colors.END}")
            essential_packages = [
                'requests>=2.32.0',
                'colorama>=0.4.6', 
                'markdown>=3.4.0',
                'jinja2>=3.1.0',
                'rich>=13.0.0'
            ]
            
            for package in essential_packages:
                subprocess.run(['pip3', 'install', package], check=True, 
                              stdout=subprocess.DEVNULL)
                print(f"{Colors.GREEN}  ✅ {package}{Colors.END}")
            
        return True
    except Exception as e:
        print(f"{Colors.RED}❌ Python dependencies installation failed: {e}{Colors.END}")
        return False

def setup_python_environment() -> bool:
    """Setup Python environment and dependencies."""
    try:
        print(f"\n{Colors.BLUE}🐍 Phase 4: Python Environment Setup{Colors.END}")
        
        # Upgrade pip
        print(f"{Colors.WHITE}Upgrading pip...{Colors.END}")
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'], 
                      check=True, stdout=subprocess.DEVNULL)
        print(f"{Colors.GREEN}✅ pip upgraded{Colors.END}")
        
        # Install Python dependencies
        return install_python_dependencies()
        
    except Exception as e:
        print(f"{Colors.RED}❌ Python environment setup failed: {e}{Colors.END}")
        return False

def run_setup_scripts() -> bool:
    """Run additional setup scripts if they exist."""
    try:
        print(f"\n{Colors.BLUE}📜 Phase 5: Additional Setup Scripts{Colors.END}")
        
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        setup_script = os.path.join(script_dir, 'scripts', 'setup_tools.sh')
        
        if os.path.exists(setup_script):
            print(f"{Colors.WHITE}Running setup_tools.sh...{Colors.END}")
            
            # Fix line endings and permissions
            subprocess.run(['sed', '-i', 's/\r$//', setup_script], check=True)
            os.chmod(setup_script, 0o755)
            
            # Run the script
            subprocess.run(['bash', setup_script], check=True, cwd=script_dir,
                          stdout=subprocess.DEVNULL)
            print(f"{Colors.GREEN}✅ Additional setup completed{Colors.END}")
        else:
            print(f"{Colors.YELLOW}⚠️  setup_tools.sh not found, skipping{Colors.END}")
        
        return True
        
    except Exception as e:
        print(f"{Colors.RED}❌ Setup scripts execution failed: {e}{Colors.END}")
        return False

def create_configuration_files() -> bool:
    """Create optimized configuration files."""
    try:
        print(f"\n{Colors.BLUE}⚙️  Phase 6: Configuration Optimization{Colors.END}")
        
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_dir = os.path.join(script_dir, 'config')
        
        # Create config directory if it doesn't exist
        os.makedirs(config_dir, exist_ok=True)
        
        # Create optimized configuration
        config = {
            "general": {
                "max_threads": 50,
                "timeout": 3600,
                "optimize_for_linux": True,
                "platform": "linux",
                "installation_date": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "naabu": {
                "threads": 100,
                "rate": 1000,
                "timeout": 3,
                "top_ports": "1000",
                "exclude_ports": "443,80"
            },
            "httpx": {
                "threads": 100,
                "timeout": 5,
                "max_redirects": 3,
                "follow_redirects": True,
                "status_code": True
            },
            "nuclei": {
                "rate_limit": 200,
                "bulk_size": 50,
                "timeout": 5,
                "update_templates": True,
                "severity": ["critical", "high", "medium"]
            },
            "tools_paths": {
                "naabu": shutil.which('naabu') or 'naabu',
                "httpx": shutil.which('httpx') or 'httpx',
                "nuclei": shutil.which('nuclei') or 'nuclei'
            }
        }
        
        config_file = os.path.join(config_dir, 'optimized_config.json')
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"{Colors.GREEN}✅ Configuration file created: {config_file}{Colors.END}")
        
        # Create bash aliases for easy access
        aliases_content = '''#!/bin/bash
# Vulnerability Analysis Toolkit Aliases
alias vat-scan="python3 $(find . -name 'workflow.py' 2>/dev/null | head -1)"
alias vat-naabu="naabu"
alias vat-httpx="httpx"
alias vat-nuclei="nuclei"
alias vat-update="nuclei -update-templates"
'''
        
        aliases_file = os.path.join(config_dir, 'vat_aliases.sh')
        with open(aliases_file, 'w') as f:
            f.write(aliases_content)
        os.chmod(aliases_file, 0o755)
        
        print(f"{Colors.GREEN}✅ Aliases created: {aliases_file}{Colors.END}")
        print(f"{Colors.YELLOW}💡 To use aliases: source {aliases_file}{Colors.END}")
        
        return True
        
    except Exception as e:
        print(f"{Colors.RED}❌ Configuration creation failed: {e}{Colors.END}")
        return False

def final_verification() -> bool:
    """Comprehensive final verification."""
    try:
        print(f"\n{Colors.BLUE}🔍 Phase 7: Final Verification{Colors.END}")
        
        tools_to_check = ['naabu', 'httpx', 'nuclei', 'go']
        all_good = True
        
        print(f"{Colors.WHITE}Checking tool availability...{Colors.END}")
        for tool in tools_to_check:
            if shutil.which(tool):
                print(f"{Colors.GREEN}  ✅ {tool}: Available{Colors.END}")
            else:
                print(f"{Colors.RED}  ❌ {tool}: Not found{Colors.END}")
                all_good = False
        
        # Test basic functionality
        if all_good:
            print(f"{Colors.WHITE}Testing tool functionality...{Colors.END}")
            
            # Test nuclei
            try:
                result = subprocess.run(['nuclei', '-version'], 
                                      capture_output=True, text=True, 
                                      timeout=10, check=True)
                print(f"{Colors.GREEN}  ✅ nuclei: {result.stdout.strip()}{Colors.END}")
            except:
                print(f"{Colors.YELLOW}  ⚠️  nuclei: Version check failed{Colors.END}")
            
            # Test naabu
            try:
                result = subprocess.run(['naabu', '-version'], 
                                      capture_output=True, text=True, 
                                      timeout=10, check=True)
                print(f"{Colors.GREEN}  ✅ naabu: Working{Colors.END}")
            except:
                print(f"{Colors.YELLOW}  ⚠️  naabu: Version check failed{Colors.END}")
            
            # Test httpx
            try:
                result = subprocess.run(['httpx', '-version'], 
                                      capture_output=True, text=True, 
                                      timeout=10, check=True)
                print(f"{Colors.GREEN}  ✅ httpx: Working{Colors.END}")
            except:
                print(f"{Colors.YELLOW}  ⚠️  httpx: Version check failed{Colors.END}")
        
        return all_good
        
    except Exception as e:
        print(f"{Colors.RED}❌ Verification failed: {e}{Colors.END}")
        return False

def print_success_message():
    """Print successful installation message."""
    print(f"\n{Colors.GREEN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}🎉 INSTALLATION COMPLETED SUCCESSFULLY! 🎉{Colors.END}")
    print(f"{Colors.GREEN}{'='*80}{Colors.END}")
    print(f"{Colors.WHITE}🚀 Your Linux Vulnerability Analysis Toolkit is ready!{Colors.END}")
    print(f"\n{Colors.CYAN}Next Steps:{Colors.END}")
    print(f"{Colors.WHITE}1. Navigate to the project directory{Colors.END}")
    print(f"{Colors.WHITE}2. Run a scan: python3 src/workflow.py <target>{Colors.END}")
    print(f"{Colors.WHITE}3. Check config/optimized_config.json for settings{Colors.END}")
    print(f"{Colors.WHITE}4. Source config/vat_aliases.sh for shortcuts{Colors.END}")
    print(f"\n{Colors.YELLOW}Example usage:{Colors.END}")
    print(f"{Colors.WHITE}  python3 src/workflow.py example.com{Colors.END}")
    print(f"{Colors.WHITE}  python3 src/workflow.py 192.168.1.0/24{Colors.END}")
    print(f"\n{Colors.GREEN}{'='*80}{Colors.END}")

def main():
    """Main installation orchestrator with complete multi-phase setup."""
    try:
        # Print header
        print_header()
        
        # Phase 0: System validation
        print(f"{Colors.BLUE}🔍 Phase 0: System Validation{Colors.END}")
        
        # Check root permissions first
        if not check_root_permissions():
            return False
        
        # Validate system requirements
        valid, distro = validate_system_requirements()
        if not valid or not distro:
            return False
        
        distro_config = SUPPORTED_DISTROS[distro]
        print(f"{Colors.GREEN}✅ System validation passed{Colors.END}")
        
        # Installation phases
        phases = [
            ("System Packages", lambda: install_system_packages(distro_config)),
            ("Go Environment", setup_go_environment_complete),
            ("Security Tools", lambda: install_security_tools_complete(distro)),
            ("Python Environment", setup_python_environment),
            ("Setup Scripts", run_setup_scripts),
            ("Configuration", create_configuration_files),
            ("Final Verification", final_verification)
        ]
        
        for phase_name, phase_func in phases:
            if not phase_func():
                print(f"\n{Colors.RED}❌ Installation failed at: {phase_name}{Colors.END}")
                print(f"{Colors.WHITE}Please check the error messages above and try again{Colors.END}")
                return False
        
        # Success!
        print_success_message()
        return True
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}❌ Installation cancelled by user{Colors.END}")
        return False
    except Exception as e:
        print(f"\n{Colors.RED}❌ Unexpected error during installation: {e}{Colors.END}")
        return False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}❌ Installation cancelled by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Unexpected error: {e}{Colors.END}")
        sys.exit(1)
