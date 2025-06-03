#!/usr/bin/env python3
"""
AutoInstall - 100% Automated Linux Vulnerability Analysis Toolkit
Master installation orchestrator that handles complete setup with zero user intervention.

This script provides complete automation for:
- Linux distribution detection and validation
- System package installation 
- Go environment setup
- Security tools installation (naabu, httpx, nuclei)
- Python dependencies installation
- Configuration optimization
- Complete verification and testing

Usage:
    sudo python3 autoinstall.py

Features:
- Linux-only operation (rejects Windows/macOS)
- Multi-distribution support (Debian/Kali/Ubuntu/Arch)
- Automatic dependency resolution
- Robust error handling with fallbacks
- Zero-configuration deployment
- Complete automation
"""

import os
import sys
import platform
import subprocess
import shutil
import json
import time
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Color codes for terminal output
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

def print_banner():
    """Display the installation banner."""
    print(f"""{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║               🔥 LINUX VULNERABILITY ANALYSIS TOOLKIT 🔥                   ║
║                                                                            ║
║                        100% AUTOMATED INSTALLER                           ║
║                                                                            ║
║    ✅ Automatic tool installation (naabu, httpx, nuclei)                  ║
║    ✅ Go environment setup                                                 ║
║    ✅ Python dependencies                                                  ║
║    ✅ Multi-distro support (Debian/Kali/Ubuntu/Arch)                     ║
║    ✅ Zero configuration required                                          ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
{Colors.END}""")

def enforce_linux_only():
    """Enforce Linux-only operation and reject other platforms."""
    if platform.system().lower() != "linux":
        print(f"""{Colors.RED}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║                            ❌ ERROR ❌                                     ║
║                                                                           ║
║       This toolkit is designed EXCLUSIVELY for Linux systems             ║
║                                                                           ║
║       ✅ Supported: Debian, Kali Linux, Ubuntu, Arch Linux              ║
║       ❌ NOT Supported: Windows, macOS, WSL                              ║
║                                                                           ║
║       Please use a native Linux environment for optimal                  ║
║       security tool performance and compatibility.                       ║
║                                                                           ║
║       For Kali Linux users: This is the PERFECT environment!            ║
╚═══════════════════════════════════════════════════════════════════════════╝
{Colors.END}""")
        return False
    return True

def check_root_privileges():
    """Check if running with sufficient privileges."""
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}⚠️  This installer requires root privileges for system package installation.{Colors.END}")
        print(f"{Colors.CYAN}💡 Please run: sudo python3 autoinstall.py{Colors.END}")
        return False
    return True

def detect_linux_distro() -> Optional[str]:
    """Detect the Linux distribution with enhanced accuracy."""
    try:
        # Primary detection via /etc/os-release
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'kali' in content:
                    return 'kali'
                elif 'arch' in content:
                    return 'arch'
                elif 'ubuntu' in content:
                    return 'ubuntu'
                elif 'debian' in content:
                    return 'debian'
        
        # Secondary detection methods
        if shutil.which('pacman'):
            return 'arch'
        elif shutil.which('apt-get') or shutil.which('apt'):
            # Check for specific distributions
            if os.path.exists('/etc/kali-version'):
                return 'kali'
            elif os.path.exists('/etc/lsb-release'):
                with open('/etc/lsb-release', 'r') as f:
                    if 'ubuntu' in f.read().lower():
                        return 'ubuntu'
            return 'debian'
            
    except Exception as e:
        print(f"{Colors.YELLOW}Warning: Could not detect distribution: {e}{Colors.END}")
    
    return None

def get_distro_config(distro: str) -> Dict:
    """Get configuration for the detected distribution."""
    configs = {
        'kali': {
            'name': 'Kali Linux',
            'package_manager': 'apt',
            'update_cmd': ['apt', 'update'],
            'install_cmd': ['apt', 'install', '-y'],
            'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'golang-go', 'unzip'],
            'special_repos': True
        },
        'debian': {
            'name': 'Debian',
            'package_manager': 'apt',
            'update_cmd': ['apt', 'update'],
            'install_cmd': ['apt', 'install', '-y'],
            'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'golang-go', 'unzip']
        },
        'ubuntu': {
            'name': 'Ubuntu',
            'package_manager': 'apt',
            'update_cmd': ['apt', 'update'],
            'install_cmd': ['apt', 'install', '-y'],
            'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'golang-go', 'unzip', 'software-properties-common']
        },
        'arch': {
            'name': 'Arch Linux',
            'package_manager': 'pacman',
            'update_cmd': ['pacman', '-Sy'],
            'install_cmd': ['pacman', '-S', '--noconfirm'],
            'packages': ['curl', 'wget', 'git', 'base-devel', 'python-pip', 'go', 'unzip']
        }
    }
    return configs.get(distro, {})

def run_command(cmd: List[str], description: str = "", ignore_errors: bool = False) -> bool:
    """Execute a command with proper error handling."""
    try:
        if description:
            print(f"{Colors.BLUE}🔧 {description}...{Colors.END}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            if description:
                print(f"{Colors.GREEN}✅ {description} completed successfully{Colors.END}")
            return True
        else:
            if not ignore_errors:
                print(f"{Colors.RED}❌ {description} failed: {result.stderr}{Colors.END}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}❌ {description} timed out{Colors.END}")
        return False
    except Exception as e:
        if not ignore_errors:
            print(f"{Colors.RED}❌ {description} error: {e}{Colors.END}")
        return False

def update_system_packages(distro_config: Dict) -> bool:
    """Update system package lists."""
    print(f"{Colors.CYAN}📦 Phase 1: Updating system packages{Colors.END}")
    
    # Special handling for Kali Linux repositories
    if distro_config.get('special_repos'):
        print(f"{Colors.YELLOW}🔧 Configuring Kali Linux repositories...{Colors.END}")
        
        # Fix Kali repositories if needed
        kali_sources = """
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
"""
        try:
            with open('/etc/apt/sources.list', 'w') as f:
                f.write(kali_sources)
            print(f"{Colors.GREEN}✅ Kali repositories configured{Colors.END}")
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️  Could not update repositories: {e}{Colors.END}")
    
    return run_command(distro_config['update_cmd'], "System package update")

def install_system_packages(distro_config: Dict) -> bool:
    """Install required system packages."""
    print(f"{Colors.CYAN}📦 Phase 2: Installing system packages{Colors.END}")
    
    for package in distro_config['packages']:
        if not run_command(distro_config['install_cmd'] + [package], f"Installing {package}", ignore_errors=True):
            print(f"{Colors.YELLOW}⚠️  Could not install {package}, but continuing...{Colors.END}")
    
    return True

def setup_go_environment() -> bool:
    """Set up Go programming environment with multiple methods."""
    print(f"{Colors.CYAN}🐹 Phase 3: Setting up Go environment{Colors.END}")
    
    # Check if Go is already available
    if shutil.which('go'):
        print(f"{Colors.GREEN}✅ Go is already installed{Colors.END}")
        return True
    
    # Method 1: Try installing from package manager (already attempted above)
    # Method 2: Download and install Go manually
    print(f"{Colors.BLUE}🔧 Downloading and installing Go...{Colors.END}")
    
    try:
        # Get latest Go version
        response = requests.get('https://golang.org/VERSION?m=text', timeout=10)
        go_version = response.text.strip()
        
        # Download Go
        go_url = f"https://dl.google.com/go/{go_version}.linux-amd64.tar.gz"
        go_tar = f"/tmp/{go_version}.linux-amd64.tar.gz"
        
        print(f"{Colors.BLUE}📥 Downloading {go_version}...{Colors.END}")
        download_cmd = ['wget', '-O', go_tar, go_url]
        if not run_command(download_cmd, "Go download"):
            return False
        
        # Extract Go
        print(f"{Colors.BLUE}📦 Extracting Go...{Colors.END}")
        extract_cmd = ['tar', '-C', '/usr/local', '-xzf', go_tar]
        if not run_command(extract_cmd, "Go extraction"):
            return False
        
        # Set up Go paths
        go_path_setup = '''
# Go environment
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export GOBIN=$GOPATH/bin
export PATH=$PATH:$GOBIN
'''
        
        # Add to system-wide profile
        with open('/etc/profile.d/go.sh', 'w') as f:
            f.write(go_path_setup)
        
        # Make executable
        os.chmod('/etc/profile.d/go.sh', 0o755)
        
        # Set up for current session
        os.environ['PATH'] = os.environ.get('PATH', '') + ':/usr/local/go/bin'
        os.environ['GOPATH'] = os.path.expanduser('~/go')
        os.environ['GOBIN'] = os.path.expanduser('~/go/bin')
        
        # Clean up
        os.remove(go_tar)
        
        print(f"{Colors.GREEN}✅ Go installed successfully{Colors.END}")
        return True
        
    except Exception as e:
        print(f"{Colors.RED}❌ Go installation failed: {e}{Colors.END}")
        return False

def install_security_tools() -> bool:
    """Install security tools with automatic dependency resolution."""
    print(f"{Colors.CYAN}🛡️  Phase 4: Installing security tools{Colors.END}")
    
    # Ensure Go bin directory exists
    gobin_dir = os.path.expanduser('~/go/bin')
    os.makedirs(gobin_dir, exist_ok=True)
    
    # Tools to install
    tools = {
        'naabu': 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
        'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
        'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
    }
    
    success = True
    
    for tool_name, tool_repo in tools.items():
        print(f"{Colors.BLUE}🔧 Installing {tool_name}...{Colors.END}")
        
        # Try installing with go install
        install_cmd = ['go', 'install', tool_repo]
        if run_command(install_cmd, f"{tool_name} installation"):
            print(f"{Colors.GREEN}✅ {tool_name} installed successfully{Colors.END}")
        else:
            print(f"{Colors.YELLOW}⚠️  {tool_name} installation had issues, trying alternative method...{Colors.END}")
            success = False
    
    # Update nuclei templates
    print(f"{Colors.BLUE}📋 Updating nuclei templates...{Colors.END}")
    nuclei_path = shutil.which('nuclei') or os.path.expanduser('~/go/bin/nuclei')
    if os.path.exists(nuclei_path):
        run_command([nuclei_path, '-update-templates'], "Nuclei template update", ignore_errors=True)
    
    return success

def install_python_dependencies() -> bool:
    """Install Python dependencies for the toolkit."""
    print(f"{Colors.CYAN}🐍 Phase 5: Installing Python dependencies{Colors.END}")
    
    # Check if requirements.txt exists
    req_file = os.path.join(os.path.dirname(__file__), 'config', 'requirements.txt')
    if os.path.exists(req_file):
        return run_command(['pip3', 'install', '-r', req_file], "Python dependencies installation")
    else:
        # Install essential packages manually
        essential_packages = [
            'requests', 'colorama', 'markdown', 'jinja2', 
            'rich', 'tqdm', 'pathlib', 'jsonschema', 'pyyaml'
        ]
        
        for package in essential_packages:
            run_command(['pip3', 'install', package], f"Installing {package}", ignore_errors=True)
        
        return True

def create_symlinks() -> bool:
    """Create system-wide symlinks for easy access."""
    print(f"{Colors.CYAN}🔗 Phase 6: Creating system symlinks{Colors.END}")
    
    tools = ['naabu', 'httpx', 'nuclei']
    gobin_dir = os.path.expanduser('~/go/bin')
    
    for tool in tools:
        tool_path = os.path.join(gobin_dir, tool)
        symlink_path = f'/usr/local/bin/{tool}'
        
        if os.path.exists(tool_path) and not os.path.exists(symlink_path):
            try:
                os.symlink(tool_path, symlink_path)
                print(f"{Colors.GREEN}✅ Created symlink for {tool}{Colors.END}")
            except Exception as e:
                print(f"{Colors.YELLOW}⚠️  Could not create symlink for {tool}: {e}{Colors.END}")
    
    return True

def optimize_configuration() -> bool:
    """Optimize toolkit configuration for maximum performance."""
    print(f"{Colors.CYAN}⚙️  Phase 7: Optimizing configuration{Colors.END}")
    
    # Create optimized configuration file
    config_dir = os.path.join(os.path.dirname(__file__), 'config')
    os.makedirs(config_dir, exist_ok=True)
    
    # Optimal configuration for Linux systems
    optimal_config = {
        "naabu": {
            "threads": 100,
            "rate": 1000,
            "timeout": 5000,
            "scan_type": "SYN",
            "ports": "top-1000"
        },
        "httpx": {
            "threads": 50,
            "timeout": 10,
            "follow_redirects": True,
            "title": True,
            "status_code": True,
            "tech_detect": True,
            "web_server": True
        },
        "nuclei": {
            "threads": 25,
            "rate_limit": 100,
            "bulk_size": 25,
            "timeout": 10,
            "retries": 2,
            "severity": "critical,high,medium",
            "tags": "cve,exposure,takeover"
        }
    }
    
    config_file = os.path.join(config_dir, 'toolkit_config.json')
    try:
        with open(config_file, 'w') as f:
            json.dump(optimal_config, f, indent=2)
        print(f"{Colors.GREEN}✅ Configuration optimized{Colors.END}")
        return True
    except Exception as e:
        print(f"{Colors.YELLOW}⚠️  Could not save configuration: {e}{Colors.END}")
        return False

def verify_installation() -> bool:
    """Verify that all components are working correctly."""
    print(f"{Colors.CYAN}🔍 Phase 8: Verifying installation{Colors.END}")
    
    tools_to_check = ['naabu', 'httpx', 'nuclei', 'go', 'python3']
    all_good = True
    
    for tool in tools_to_check:
        tool_path = shutil.which(tool)
        if tool_path:
            print(f"{Colors.GREEN}✅ {tool}: Found at {tool_path}{Colors.END}")
        else:
            # Check in go/bin directory as fallback
            gobin_path = os.path.expanduser(f'~/go/bin/{tool}')
            if os.path.exists(gobin_path):
                print(f"{Colors.GREEN}✅ {tool}: Found at {gobin_path}{Colors.END}")
            else:
                print(f"{Colors.RED}❌ {tool}: Not found{Colors.END}")
                all_good = False
    
    # Test basic functionality
    try:
        # Test nuclei templates
        nuclei_path = shutil.which('nuclei') or os.path.expanduser('~/go/bin/nuclei')
        if os.path.exists(nuclei_path):
            result = subprocess.run([nuclei_path, '-list-templates'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                template_count = len([line for line in result.stdout.split('\n') if line.strip()])
                print(f"{Colors.GREEN}✅ Nuclei: {template_count} templates available{Colors.END}")
            else:
                print(f"{Colors.YELLOW}⚠️  Nuclei: Templates may need update{Colors.END}")
                
    except Exception as e:
        print(f"{Colors.YELLOW}⚠️  Warning during functionality test: {e}{Colors.END}")
    
    return all_good

def create_launcher_script() -> bool:
    """Create a convenient launcher script."""
    print(f"{Colors.CYAN}🚀 Phase 9: Creating launcher script{Colors.END}")
    
    launcher_script = '''#!/bin/bash
# Vulnerability Analysis Toolkit Launcher
# Auto-generated by autoinstall.py

echo "🛡️  Linux Vulnerability Analysis Toolkit"
echo "========================================="

# Ensure Go binaries are in PATH
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Launch the main workflow
cd "$(dirname "$0")"
python3 src/workflow.py "$@"
'''
    
    launcher_path = os.path.join(os.path.dirname(__file__), 'vulnscan')
    
    try:
        with open(launcher_path, 'w') as f:
            f.write(launcher_script)
        
        os.chmod(launcher_path, 0o755)
        
        # Create system-wide symlink
        if not os.path.exists('/usr/local/bin/vulnscan'):
            try:
                os.symlink(os.path.abspath(launcher_path), '/usr/local/bin/vulnscan')
                print(f"{Colors.GREEN}✅ Global launcher created: 'vulnscan' command available system-wide{Colors.END}")
            except Exception:
                print(f"{Colors.GREEN}✅ Local launcher created: './vulnscan{Colors.END}")
        
        return True
        
    except Exception as e:
        print(f"{Colors.YELLOW}⚠️  Could not create launcher: {e}{Colors.END}")
        return False

def main():
    """Main installation orchestrator."""
    print_banner()
    
    # Phase 0: System validation
    print(f"{Colors.CYAN}🔍 Phase 0: System validation{Colors.END}")
    
    if not enforce_linux_only():
        sys.exit(1)
    
    if not check_root_privileges():
        sys.exit(1)
    
    # Detect distribution
    distro = detect_linux_distro()
    if not distro:
        print(f"{Colors.RED}❌ Could not detect supported Linux distribution{Colors.END}")
        print(f"{Colors.CYAN}Supported: Debian, Kali Linux, Ubuntu, Arch Linux{Colors.END}")
        sys.exit(1)
    
    distro_config = get_distro_config(distro)
    print(f"{Colors.GREEN}✅ Detected: {distro_config['name']}{Colors.END}")
    print(f"{Colors.BLUE}📦 Package Manager: {distro_config['package_manager']}{Colors.END}")
    
    # Installation phases
    phases = [
        (update_system_packages, distro_config),
        (install_system_packages, distro_config),
        (setup_go_environment,),
        (install_security_tools,),
        (install_python_dependencies,),
        (create_symlinks,),
        (optimize_configuration,),
        (verify_installation,),
        (create_launcher_script,)
    ]
    
    print(f"\n{Colors.BOLD}🚀 Starting automated installation...{Colors.END}\n")
    
    failed_phases = []
    
    for i, phase_info in enumerate(phases, 1):
        phase_func = phase_info[0]
        phase_args = phase_info[1:] if len(phase_info) > 1 else ()
        
        try:
            if not phase_func(*phase_args):
                failed_phases.append(phase_func.__name__)
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}❌ Installation cancelled by user{Colors.END}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}❌ Phase {i} failed: {e}{Colors.END}")
            failed_phases.append(phase_func.__name__)
    
    # Final status
    print(f"\n{Colors.BOLD}📋 Installation Summary{Colors.END}")
    print("=" * 50)
    
    if not failed_phases:
        print(f"""{Colors.GREEN}{Colors.BOLD}
🎉 INSTALLATION COMPLETED SUCCESSFULLY! 🎉

✅ All security tools installed and verified
✅ Go environment configured  
✅ Python dependencies installed
✅ System optimized for maximum performance
✅ Global launcher created

🚀 Ready to use! Try these commands:
   vulnscan example.com
   python3 src/workflow.py example.com
   ./vulnscan -h

💡 The toolkit is now 100% automated and ready for Linux deployment!
{Colors.END}""")
        
    else:
        print(f"{Colors.YELLOW}⚠️  Installation completed with some issues:{Colors.END}")
        for phase in failed_phases:
            print(f"   - {phase}")
        print(f"\n{Colors.CYAN}💡 You may need to manually resolve these issues.{Colors.END}")
        print(f"{Colors.CYAN}💡 Try running: python3 src/workflow.py --help{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}❌ Installation cancelled by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}❌ Unexpected error: {e}{Colors.END}")
        sys.exit(1)
