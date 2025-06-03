#!/usr/bin/env python3
"""
Specialized Installation Orchestrator for Linux Vulnerability Analysis Toolkit
Multi-Distro Support: Debian/Kali/Ubuntu/Arch Linux
Maximized Tool Utilization: httpx, nuclei, naabu
Linux-Only File Endings and Optimal Performance
"""

import os
import sys
import platform
import subprocess
import shutil
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Multi-distro detection and configuration
SUPPORTED_DISTROS = {
    'debian': {
        'name': 'Debian/Kali',
        'package_manager': 'apt',
        'install_cmd': ['sudo', 'apt', 'install', '-y'],
        'update_cmd': ['sudo', 'apt', 'update'],
        'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip']
    },
    'ubuntu': {
        'name': 'Ubuntu',
        'package_manager': 'apt',
        'install_cmd': ['sudo', 'apt', 'install', '-y'],
        'update_cmd': ['sudo', 'apt', 'update'],
        'packages': ['curl', 'wget', 'git', 'build-essential', 'python3-pip', 'software-properties-common']
    },
    'arch': {
        'name': 'Arch Linux',
        'package_manager': 'pacman',
        'install_cmd': ['sudo', 'pacman', '-S', '--noconfirm'],
        'update_cmd': ['sudo', 'pacman', '-Sy'],
        'packages': ['curl', 'wget', 'git', 'base-devel', 'python-pip', 'go']
    }
}

def detect_linux_distro() -> Optional[str]:
    """Detect the Linux distribution."""
    try:
        # Try reading /etc/os-release
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'arch' in content:
                    return 'arch'
                elif 'ubuntu' in content:
                    return 'ubuntu'
                elif 'debian' in content or 'kali' in content:
                    return 'debian'
        
        # Fallback checks
        if shutil.which('pacman'):
            return 'arch'
        elif shutil.which('apt'):
            if os.path.exists('/etc/lsb-release'):
                with open('/etc/lsb-release', 'r') as f:
                    if 'ubuntu' in f.read().lower():
                        return 'ubuntu'
            return 'debian'
            
    except Exception as e:
        print(f"Warning: Could not detect distribution: {e}")
    
    return None

def ensure_linux_only():
    """Ensure the system is Linux-only and reject other platforms."""
    if platform.system().lower() != "linux":
        print("╔═══════════════════════════════════════════════════════════════╗")
        print("║                          ❌ ERROR ❌                           ║")
        print("║                                                               ║")
        print("║     This toolkit is designed EXCLUSIVELY for Linux systems   ║")
        print("║                                                               ║")
        print("║     ✅ Supported: Debian, Kali, Ubuntu, Arch Linux          ║")
        print("║     ❌ NOT Supported: Windows, macOS, WSL (limited)          ║")
        print("║                                                               ║")
        print("║     Please use a native Linux environment for optimal        ║")
        print("║     security tool performance and compatibility.             ║")
        print("╚═══════════════════════════════════════════════════════════════╝")
        return False
    return True

def main():
    """Specialized installation orchestrator with multi-distro support."""
    print("🔥 Linux Vulnerability Analysis Toolkit - Specialized Installer 🔥")
    print("=" * 65)
    
    # Enforce Linux-only operation
    if not ensure_linux_only():
        return False
        
    # Detect Linux distribution
    distro = detect_linux_distro()
    if not distro:
        print("❌ Could not detect supported Linux distribution")
        print("Supported: Debian, Kali, Ubuntu, Arch Linux")
        return False
        
    distro_config = SUPPORTED_DISTROS[distro]
    print(f"✅ Detected: {distro_config['name']}")
    print(f"📦 Package Manager: {distro_config['package_manager']}")
    print("=" * 65)    
    # Phase 1: System Preparation
    print("🔧 Phase 1: System Preparation")
    if not prepare_system(distro_config):
        print("❌ System preparation failed")
        return False
    
    # Phase 2: Go Environment Setup
    print("\n🔧 Phase 2: Go Environment Setup")
    if not setup_go_environment():
        print("❌ Go environment setup failed")
        return False
    
    # Phase 3: Security Tools Installation
    print("\n🔧 Phase 3: Security Tools Installation")
    if not install_security_tools():
        print("❌ Security tools installation failed")
        return False
        
    # Phase 4: Python Dependencies
    print("\n🔧 Phase 4: Python Dependencies")
    if not install_python_dependencies():
        print("❌ Python dependencies installation failed")
        return False
        
    # Phase 5: Configuration and Optimization
    print("\n🔧 Phase 5: Configuration and Optimization")
    if not optimize_configuration():
        print("❌ Configuration optimization failed")
        return False
        
    # Phase 6: Final Verification
    print("\n🔧 Phase 6: Final Verification")
    if not verify_installation():
        print("❌ Installation verification failed")
        return False
        
    print("\n🎉 Installation completed successfully!")
    print("🚀 Ready to use: python3 src/workflow.py <target>")
    return True

def prepare_system(distro_config: Dict) -> bool:
    """Prepare the system with required packages."""
    try:
        print(f"📦 Updating {distro_config['name']} package repository...")
        subprocess.run(distro_config['update_cmd'], check=True)
        
        print("📦 Installing base packages...")
        cmd = distro_config['install_cmd'] + distro_config['packages']
        subprocess.run(cmd, check=True)
        
        # Fix line endings for all shell scripts
        fix_line_endings()
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Package installation failed: {e}")
        return False

def fix_line_endings():
    """Ensure all files have Linux-only line endings."""
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Fix shell scripts
    for script in ['scripts/setup_tools.sh', 'scripts/fix_dpkg.sh', 
                   'scripts/fix_go_path.sh', 'scripts/fix_repo_keys.sh', 
                   'scripts/update_repos.sh']:
        script_path = os.path.join(script_dir, script)
        if os.path.exists(script_path):
            try:
                subprocess.run(['sed', '-i', 's/\r$//', script_path], check=True)
                os.chmod(script_path, 0o755)
                print(f"✅ Fixed line endings: {script}")
            except Exception as e:
                print(f"⚠️  Warning: Could not fix {script}: {e}")

def setup_go_environment() -> bool:
    """Set up Go programming language environment."""
    try:
        # Check if Go is already installed
        if shutil.which('go'):
            print("✅ Go is already installed")
            return True
            
        print("📥 Installing Go...")
        # Download and install Go
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
        
        print("✅ Go environment configured")
        return True
        
    except Exception as e:
        print(f"❌ Go setup failed: {e}")
        return False

def install_security_tools() -> bool:
    """Install security tools with maximum utilization."""
    tools = {
        'naabu': 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
        'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest', 
        'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
    }
    
    for tool, repo in tools.items():
        try:
            print(f"🔧 Installing {tool}...")
            subprocess.run(['go', 'install', repo], check=True)
            print(f"✅ {tool} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {tool}: {e}")
            return False
    
    # Update nuclei templates for maximum coverage
    try:
        print("📋 Updating nuclei templates...")
        subprocess.run(['nuclei', '-update-templates'], check=True)
        print("✅ Nuclei templates updated")
    except Exception as e:
        print(f"⚠️  Warning: Template update failed: {e}")
    
    return True

def install_python_dependencies() -> bool:
    """Install Python dependencies for enhanced functionality."""
    try:
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        requirements_file = os.path.join(script_dir, 'config', 'requirements.txt')
        
        if os.path.exists(requirements_file):
            print("📦 Installing Python dependencies...")
            subprocess.run(['pip3', 'install', '-r', requirements_file], check=True)
            print("✅ Python dependencies installed")
        else:
            # Fallback essential packages
            essential_packages = [
                'requests>=2.32.0',
                'colorama>=0.4.6', 
                'markdown>=3.4.0',
                'jinja2>=3.1.0',
                'rich>=13.0.0'
            ]
            
            for package in essential_packages:
                subprocess.run(['pip3', 'install', package], check=True)
            print("✅ Essential Python packages installed")
            
        return True
    except Exception as e:
        print(f"❌ Python dependencies installation failed: {e}")
        return False

def optimize_configuration() -> bool:
    """Optimize configuration for maximum tool utilization."""
    try:
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Create optimized configuration
        config = {
            "general": {
                "max_threads": 50,
                "timeout": 3600,
                "optimize_for_linux": True
            },
            "naabu": {
                "threads": 100,
                "rate": 1000,
                "timeout": 3
            },
            "httpx": {
                "threads": 100,
                "timeout": 5,
                "max_redirects": 3
            },
            "nuclei": {
                "rate_limit": 200,
                "bulk_size": 50,
                "timeout": 5
            }
        }
        
        config_file = os.path.join(script_dir, 'config', 'optimized_config.json')
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
        print("✅ Optimized configuration created")
        return True
        
    except Exception as e:
        print(f"❌ Configuration optimization failed: {e}")
        return False

def verify_installation() -> bool:
    """Verify all components are working correctly."""
    tools_to_check = ['naabu', 'httpx', 'nuclei', 'go']
    
    print("🔍 Verifying installation...")
    all_good = True
    
    for tool in tools_to_check:
        if shutil.which(tool):
            print(f"✅ {tool}: Found")
        else:
            print(f"❌ {tool}: Not found")
            all_good = False
    
    # Test tools functionality
    try:
        # Test nuclei templates
        result = subprocess.run(['nuclei', '-templates'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Nuclei templates: Available")
        else:
            print("⚠️  Nuclei templates: May need update")
            
    except Exception as e:
        print(f"⚠️  Warning during verification: {e}")    
    return all_good

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n❌ Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
