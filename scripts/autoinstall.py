#!/usr/bin/env python3
"""
AutoInstall Module for Linux Vulnerability Analysis Toolkit
==========================================================

This module provides Python-based installation assistance that complements
the main setup.py orchestrator. It handles Python-specific tasks, dependency
validation, and provides a bridge between the master installer and shell scripts.

Features:
- Python environment validation and setup
- Virtual environment management
- Dependency installation and verification
- Integration with shell-based installers
- Post-installation configuration and testing
- Tool availability checking and PATH management

Author: Linux Vulnerability Analysis Toolkit
License: MIT
"""

import sys
import os
import subprocess
import json
import shutil
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import importlib.util

# ANSI Color codes for consistent output with setup.py
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    @staticmethod
    def print_colored(text: str, color: str, bold: bool = False) -> None:
        """Print colored text with optional bold formatting."""
        prefix = Colors.BOLD if bold else ""
        print(f"{prefix}{color}{text}{Colors.RESET}")

class PythonEnvironmentManager:
    """Manages Python environment setup and validation for the toolkit."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.venv_path = self.project_root / "venv"
        self.requirements_file = self.project_root / "requirements.txt"
        
    def check_python_version(self) -> bool:
        """Check if Python version is compatible (3.8+)."""
        version = sys.version_info
        if version.major != 3 or version.minor < 8:
            Colors.print_colored(
                f"❌ Python {version.major}.{version.minor} detected. Minimum required: Python 3.8+",
                Colors.RED, bold=True
            )
            return False
        
        Colors.print_colored(
            f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible",
            Colors.GREEN
        )
        return True
    
    def check_pip_availability(self) -> bool:
        """Check if pip is available and working."""
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                Colors.print_colored("✅ pip is available and working", Colors.GREEN)
                return True
            else:
                Colors.print_colored("❌ pip is not working correctly", Colors.RED)
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            Colors.print_colored("❌ pip is not available", Colors.RED)
            return False
    
    def create_virtual_environment(self) -> bool:
        """Create a virtual environment for the toolkit."""
        if self.venv_path.exists():
            Colors.print_colored("📦 Virtual environment already exists", Colors.YELLOW)
            return True
        
        try:
            Colors.print_colored("📦 Creating virtual environment...", Colors.BLUE)
            subprocess.run([sys.executable, "-m", "venv", str(self.venv_path)], 
                          check=True, timeout=60)
            Colors.print_colored("✅ Virtual environment created successfully", Colors.GREEN)
            return True
        except subprocess.CalledProcessError as e:
            Colors.print_colored(f"❌ Failed to create virtual environment: {e}", Colors.RED)
            return False
        except subprocess.TimeoutExpired:
            Colors.print_colored("❌ Virtual environment creation timed out", Colors.RED)
            return False
    
    def install_base_requirements(self) -> bool:
        """Install base Python requirements."""
        base_requirements = [
            "requests>=2.28.0",
            "colorama>=0.4.6", 
            "markdown>=3.5.1",
            "jinja2>=3.1.2",
            "rich>=13.0.0",
            "urllib3>=1.26.0",
            "certifi>=2022.0.0",
            "charset-normalizer>=3.0.0"
        ]
        
        Colors.print_colored("📦 Installing base Python requirements...", Colors.BLUE)
        
        for requirement in base_requirements:
            try:
                Colors.print_colored(f"  Installing {requirement}...", Colors.CYAN)
                subprocess.run([sys.executable, "-m", "pip", "install", requirement], 
                              check=True, capture_output=True, timeout=120)
                Colors.print_colored(f"  ✅ {requirement} installed", Colors.GREEN)
            except subprocess.CalledProcessError as e:
                Colors.print_colored(f"  ❌ Failed to install {requirement}: {e}", Colors.RED)
                return False
            except subprocess.TimeoutExpired:
                Colors.print_colored(f"  ❌ Installation of {requirement} timed out", Colors.RED)
                return False
        
        Colors.print_colored("✅ All base requirements installed successfully", Colors.GREEN)
        return True

class SecurityToolsValidator:
    """Validates security tools installation and functionality."""
    
    def __init__(self):
        self.required_tools = {
            "naabu": {
                "description": "Fast port scanner",
                "test_command": ["-version"],
                "fallback_test": ["-h"]
            },
            "httpx": {
                "description": "Fast HTTP toolkit",
                "test_command": ["-version"],
                "fallback_test": ["-h"]
            },
            "nuclei": {
                "description": "Vulnerability scanner",
                "test_command": ["-version"],
                "fallback_test": ["-h"]
            }
        }
        
        self.go_bin_paths = [
            os.path.expanduser("~/go/bin"),
            "/usr/local/go/bin",
            "/usr/bin",
            "/usr/local/bin"
        ]
    
    def find_tool_path(self, tool_name: str) -> Optional[str]:
        """Find the full path to a security tool."""
        # First check if it's in PATH
        tool_path = shutil.which(tool_name)
        if tool_path:
            return tool_path
        
        # Check common Go and system paths
        for path in self.go_bin_paths:
            potential_path = os.path.join(path, tool_name)
            if os.path.isfile(potential_path) and os.access(potential_path, os.X_OK):
                return potential_path
        
        return None
    
    def test_tool_functionality(self, tool_name: str, tool_path: str) -> bool:
        """Test if a tool is working correctly."""
        tool_config = self.required_tools.get(tool_name, {})
        test_commands = [
            tool_config.get("test_command", ["-h"]),
            tool_config.get("fallback_test", ["-h"])
        ]
        
        for test_cmd in test_commands:
            try:
                result = subprocess.run(
                    [tool_path] + test_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        
        return False
    
    def validate_all_tools(self) -> Dict[str, Dict[str, Any]]:
        """Validate all required security tools."""
        results = {}
        
        Colors.print_colored("🔍 Validating security tools installation...", Colors.BLUE, bold=True)
        
        for tool_name, tool_info in self.required_tools.items():
            Colors.print_colored(f"  Checking {tool_name} ({tool_info['description']})...", Colors.CYAN)
            
            tool_path = self.find_tool_path(tool_name)
            if not tool_path:
                results[tool_name] = {
                    "installed": False,
                    "path": None,
                    "working": False,
                    "error": "Tool not found in PATH or common locations"
                }
                Colors.print_colored(f"    ❌ {tool_name} not found", Colors.RED)
                continue
            
            is_working = self.test_tool_functionality(tool_name, tool_path)
            results[tool_name] = {
                "installed": True,
                "path": tool_path,
                "working": is_working,
                "error": None if is_working else "Tool found but not responding correctly"
            }
            
            if is_working:
                Colors.print_colored(f"    ✅ {tool_name} working at {tool_path}", Colors.GREEN)
            else:
                Colors.print_colored(f"    ⚠️  {tool_name} found at {tool_path} but not working", Colors.YELLOW)
        
        return results

class ConfigurationManager:
    """Manages toolkit configuration and settings."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.config_dir = self.project_root / "config"
        self.config_file = self.config_dir / "toolkit_config.json"
        
    def ensure_config_directory(self) -> bool:
        """Ensure configuration directory exists."""
        try:
            self.config_dir.mkdir(exist_ok=True)
            return True
        except OSError as e:
            Colors.print_colored(f"❌ Failed to create config directory: {e}", Colors.RED)
            return False
    
    def create_default_config(self, tools_status: Dict[str, Dict[str, Any]]) -> bool:
        """Create default configuration file with tool paths."""
        if not self.ensure_config_directory():
            return False
        
        config = {
            "version": "1.0.0",
            "toolkit_name": "Linux Vulnerability Analysis Toolkit",
            "installation_date": subprocess.run(
                ["date", "-Iseconds"], capture_output=True, text=True
            ).stdout.strip(),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "tools": {},
            "settings": {
                "max_concurrent_scans": 10,
                "default_timeout": 30,
                "output_format": "json",
                "log_level": "INFO",
                "auto_update_nuclei_templates": True,
                "rate_limit": 100
            },
            "paths": {
                "project_root": str(self.project_root),
                "config_dir": str(self.config_dir),
                "output_dir": str(self.project_root / "output"),
                "reports_dir": str(self.project_root / "reports")
            }
        }
        
        # Add tool information
        for tool_name, tool_info in tools_status.items():
            config["tools"][tool_name] = {
                "installed": tool_info["installed"],
                "path": tool_info["path"],
                "working": tool_info["working"],
                "last_checked": subprocess.run(
                    ["date", "-Iseconds"], capture_output=True, text=True
                ).stdout.strip()
            }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            Colors.print_colored(f"✅ Configuration file created: {self.config_file}", Colors.GREEN)
            return True
        except OSError as e:
            Colors.print_colored(f"❌ Failed to create configuration file: {e}", Colors.RED)
            return False

class ShellScriptIntegrator:
    """Integrates with existing shell scripts."""
    
    def __init__(self):
        self.scripts_dir = Path(__file__).parent
        self.available_scripts = {
            "setup_tools.sh": "Main security tools setup script",
            "fix_dpkg.sh": "Fix package manager issues",
            "fix_go_path.sh": "Fix Go environment PATH issues", 
            "fix_repo_keys.sh": "Fix repository key issues",
            "update_repos.sh": "Update system repositories",
            "run_toolkit.sh": "Main toolkit launcher"
        }
    
    def check_script_availability(self) -> Dict[str, bool]:
        """Check which shell scripts are available."""
        results = {}
        
        Colors.print_colored("🔍 Checking shell script availability...", Colors.BLUE)
        
        for script_name, description in self.available_scripts.items():
            script_path = self.scripts_dir / script_name
            is_available = script_path.exists() and os.access(script_path, os.X_OK)
            results[script_name] = is_available
            
            if is_available:
                Colors.print_colored(f"  ✅ {script_name} - {description}", Colors.GREEN)
            else:
                Colors.print_colored(f"  ❌ {script_name} - {description}", Colors.RED)
        
        return results
    
    def run_script(self, script_name: str, args: Optional[List[str]] = None) -> Tuple[bool, str]:
        """Run a shell script and return success status and output."""
        script_path = self.scripts_dir / script_name
        
        if not script_path.exists():
            return False, f"Script {script_name} not found"
        
        if not os.access(script_path, os.X_OK):
            # Try to make it executable
            try:
                os.chmod(script_path, 0o755)
            except OSError:
                return False, f"Script {script_name} is not executable and cannot be made executable"
        
        cmd = ["bash", str(script_path)]
        if args:
            cmd.extend(args)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, "Script execution timed out"
        except Exception as e:
            return False, f"Script execution failed: {e}"

class AutoInstaller:
    """Main autoinstaller class that orchestrates the installation process."""
    
    def __init__(self):
        self.env_manager = PythonEnvironmentManager()
        self.tools_validator = SecurityToolsValidator()
        self.config_manager = ConfigurationManager()
        self.shell_integrator = ShellScriptIntegrator()
        
    def print_banner(self):
        """Print the autoinstaller banner."""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║           🐍 PYTHON AUTOINSTALLER FOR VULNERABILITY TOOLKIT 🐍              ║
║                                                                              ║
║  This module provides Python-based installation assistance and validation    ║
║  for the Linux Vulnerability Analysis Toolkit.                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        Colors.print_colored(banner, Colors.CYAN, bold=True)
    
    def validate_environment(self) -> bool:
        """Validate the Python environment and requirements."""
        Colors.print_colored("\n🔍 Phase 1: Python Environment Validation", Colors.BLUE, bold=True)
        
        if not self.env_manager.check_python_version():
            return False
        
        if not self.env_manager.check_pip_availability():
            Colors.print_colored("💡 Install pip with: sudo apt-get install python3-pip", Colors.YELLOW)
            return False
        
        return True
    
    def setup_python_environment(self) -> bool:
        """Set up the Python environment with required packages."""
        Colors.print_colored("\n📦 Phase 2: Python Environment Setup", Colors.BLUE, bold=True)
        
        if not self.env_manager.install_base_requirements():
            return False
        
        return True
    
    def validate_security_tools(self) -> Dict[str, Dict[str, Any]]:
        """Validate security tools installation."""
        Colors.print_colored("\n🔐 Phase 3: Security Tools Validation", Colors.BLUE, bold=True)
        
        return self.tools_validator.validate_all_tools()
    
    def create_configuration(self, tools_status: Dict[str, Dict[str, Any]]) -> bool:
        """Create toolkit configuration."""
        Colors.print_colored("\n⚙️  Phase 4: Configuration Setup", Colors.BLUE, bold=True)
        
        return self.config_manager.create_default_config(tools_status)
    
    def integrate_shell_scripts(self) -> bool:
        """Integrate with existing shell scripts."""
        Colors.print_colored("\n🔗 Phase 5: Shell Script Integration", Colors.BLUE, bold=True)
        
        available_scripts = self.shell_integrator.check_script_availability()
        missing_scripts = [name for name, available in available_scripts.items() if not available]
        
        if missing_scripts:
            Colors.print_colored(f"⚠️  Missing scripts: {', '.join(missing_scripts)}", Colors.YELLOW)
            return False
        
        Colors.print_colored("✅ All shell scripts are available and executable", Colors.GREEN)
        return True
    
    def run_full_installation(self) -> bool:
        """Run the complete autoinstallation process."""
        self.print_banner()
        
        # Phase 1: Environment validation
        if not self.validate_environment():
            Colors.print_colored("\n❌ Environment validation failed", Colors.RED, bold=True)
            return False
        
        # Phase 2: Python environment setup
        if not self.setup_python_environment():
            Colors.print_colored("\n❌ Python environment setup failed", Colors.RED, bold=True)
            return False
        
        # Phase 3: Security tools validation
        tools_status = self.validate_security_tools()
        
        # Check if all tools are working
        all_tools_working = all(
            tool_info["installed"] and tool_info["working"] 
            for tool_info in tools_status.values()
        )
        
        if not all_tools_working:
            Colors.print_colored("\n⚠️  Some security tools are not working correctly", Colors.YELLOW, bold=True)
            Colors.print_colored("💡 Run install/setup.py first to install security tools", Colors.CYAN)
        
        # Phase 4: Configuration
        if not self.create_configuration(tools_status):
            Colors.print_colored("\n❌ Configuration setup failed", Colors.RED, bold=True)
            return False
        
        # Phase 5: Shell script integration
        if not self.integrate_shell_scripts():
            Colors.print_colored("\n⚠️  Shell script integration issues detected", Colors.YELLOW, bold=True)
        
        # Final summary
        Colors.print_colored("\n" + "="*80, Colors.GREEN, bold=True)
        Colors.print_colored("🎉 PYTHON AUTOINSTALLER COMPLETED SUCCESSFULLY", Colors.GREEN, bold=True)
        Colors.print_colored("="*80, Colors.GREEN, bold=True)
        
        Colors.print_colored("\n📋 Summary:", Colors.WHITE, bold=True)
        Colors.print_colored("  ✅ Python environment validated and configured", Colors.GREEN)
        Colors.print_colored("  ✅ Base requirements installed", Colors.GREEN)
        Colors.print_colored("  ✅ Configuration file created", Colors.GREEN)
        
        if all_tools_working:
            Colors.print_colored("  ✅ All security tools validated and working", Colors.GREEN)
        else:
            Colors.print_colored("  ⚠️  Security tools need installation (run install/setup.py)", Colors.YELLOW)
        
        Colors.print_colored("\n🚀 Next Steps:", Colors.CYAN, bold=True)
        Colors.print_colored("  1. Run 'install/setup.py' if security tools are not installed", Colors.CYAN)
        Colors.print_colored("  2. Use 'scripts/run_toolkit.sh <target>' to start scanning", Colors.CYAN)
        Colors.print_colored("  3. Check 'config/toolkit_config.json' for configuration options", Colors.CYAN)
        
        return True

def main():
    """Main entry point for the autoinstaller."""
    installer = AutoInstaller()
    
    # Check if we're on Linux
    if not sys.platform.startswith('linux'):
        Colors.print_colored(
            "❌ This autoinstaller is designed for Linux systems only",
            Colors.RED, bold=True
        )
        Colors.print_colored(
            "💡 Please run this on a Linux system (Debian, Ubuntu, Kali, Arch)",
            Colors.YELLOW
        )
        sys.exit(1)
    
    try:
        success = installer.run_full_installation()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        Colors.print_colored("\n⚠️  Installation interrupted by user", Colors.YELLOW)
        sys.exit(1)
    except Exception as e:
        Colors.print_colored(f"\n❌ Unexpected error: {e}", Colors.RED, bold=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
