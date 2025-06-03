#!/usr/bin/env python3
"""
Complete Installation Validation Script
=======================================

This script validates the entire Linux Vulnerability Analysis Toolkit 
installation, including the new master installer architecture and all 
integrated components.

Features:
- Validates master installer (setup.py) functionality
- Tests Python autoinstaller (autoinstall.py) integration
- Verifies shell script availability and permissions
- Checks security tools installation paths
- Validates configuration files and directory structure
- Tests toolkit integration and workflow functionality
- Provides comprehensive installation health report

Usage: python3 validate_installation.py
"""

import sys
import os
import subprocess
import json
import platform
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

# ANSI Color codes for consistent output
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

class InstallationValidator:
    """Comprehensive installation validator for the toolkit."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.errors = []
        self.warnings = []
        self.success_count = 0
        self.total_checks = 0
        
    def print_colored(self, text: str, color: str, bold: bool = False):
        """Print colored text."""
        prefix = Colors.BOLD if bold else ""
        print(f"{prefix}{color}{text}{Colors.RESET}")
    
    def print_header(self, title: str):
        """Print section header."""
        self.print_colored(f"\n{'='*80}", Colors.CYAN, bold=True)
        self.print_colored(f"🔍 {title}", Colors.CYAN, bold=True)
        self.print_colored(f"{'='*80}", Colors.CYAN, bold=True)
    
    def check_pass(self, message: str):
        """Record a successful check."""
        self.print_colored(f"✅ {message}", Colors.GREEN)
        self.success_count += 1
        self.total_checks += 1
    
    def check_fail(self, message: str, is_critical: bool = True):
        """Record a failed check."""
        self.print_colored(f"❌ {message}", Colors.RED)
        if is_critical:
            self.errors.append(message)
        else:
            self.warnings.append(message)
        self.total_checks += 1
    
    def check_warning(self, message: str):
        """Record a warning."""
        self.print_colored(f"⚠️  {message}", Colors.YELLOW)
        self.warnings.append(message)
        self.total_checks += 1
    
    def validate_platform(self) -> bool:
        """Validate platform requirements."""
        self.print_header("Platform Validation")
        
        # Check OS
        if platform.system().lower() != 'linux':
            self.check_fail("This toolkit requires Linux (detected: {platform.system()})")
            return False
        
        self.check_pass(f"Running on Linux: {platform.platform()}")
        
        # Check Python version
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            self.check_fail(f"Python 3.8+ required (detected: {version.major}.{version.minor})")
            return False
        
        self.check_pass(f"Python version compatible: {version.major}.{version.minor}.{version.micro}")
        return True
    
    def validate_directory_structure(self) -> bool:
        """Validate project directory structure."""
        self.print_header("Directory Structure Validation")
        
        required_dirs = [
            "install",
            "scripts", 
            "src",
            "config",
            "reports",
            "output",
            "commands"
        ]
        
        required_files = [
            "install/setup.py",
            "scripts/autoinstall.py",
            "scripts/setup_tools.sh",
            "scripts/run_toolkit.sh",
            "src/workflow.py",
            "config/requirements.txt",
            "run.py",
            "verify_installation.py",
            "README.md"
        ]
        
        all_good = True
        
        # Check directories
        for dir_name in required_dirs:
            dir_path = self.project_root / dir_name
            if dir_path.exists() and dir_path.is_dir():
                self.check_pass(f"Directory exists: {dir_name}/")
            else:
                self.check_fail(f"Missing directory: {dir_name}/")
                all_good = False
        
        # Check files
        for file_path in required_files:
            full_path = self.project_root / file_path
            if full_path.exists() and full_path.is_file():
                self.check_pass(f"File exists: {file_path}")
            else:
                self.check_fail(f"Missing file: {file_path}")
                all_good = False
        
        return all_good
    
    def validate_master_installer(self) -> bool:
        """Validate the master installer setup.py."""
        self.print_header("Master Installer Validation")
        
        setup_py = self.project_root / "install" / "setup.py"
        
        if not setup_py.exists():
            self.check_fail("Master installer (install/setup.py) not found")
            return False
        
        # Check if it's executable
        if not os.access(setup_py, os.R_OK):
            self.check_fail("Master installer is not readable")
            return False
        
        self.check_pass("Master installer file exists and is readable")
        
        # Try to validate syntax
        try:
            with open(setup_py, 'r') as f:
                content = f.read()
                compile(content, str(setup_py), 'exec')
            self.check_pass("Master installer syntax is valid")
        except SyntaxError as e:
            self.check_fail(f"Master installer syntax error: {e}")
            return False
        
        # Check for key functions/classes
        required_elements = [
            "print_header",
            "detect_linux_distro", 
            "SUPPORTED_DISTROS",
            "Colors"
        ]
        
        with open(setup_py, 'r') as f:
            content = f.read()
            
        for element in required_elements:
            if element in content:
                self.check_pass(f"Master installer contains: {element}")
            else:
                self.check_warning(f"Master installer missing: {element}")
        
        return True
    
    def validate_autoinstaller(self) -> bool:
        """Validate the Python autoinstaller."""
        self.print_header("Python Autoinstaller Validation")
        
        autoinstall_py = self.project_root / "scripts" / "autoinstall.py"
        
        if not autoinstall_py.exists():
            self.check_fail("Python autoinstaller (scripts/autoinstall.py) not found")
            return False
        
        # Check syntax
        try:
            with open(autoinstall_py, 'r') as f:
                content = f.read()
                compile(content, str(autoinstall_py), 'exec')
            self.check_pass("Python autoinstaller syntax is valid")
        except SyntaxError as e:
            self.check_fail(f"Python autoinstaller syntax error: {e}")
            return False
        
        # Check for key classes
        required_classes = [
            "PythonEnvironmentManager",
            "SecurityToolsValidator",
            "ConfigurationManager",
            "AutoInstaller"
        ]
        
        with open(autoinstall_py, 'r') as f:
            content = f.read()
            
        for class_name in required_classes:
            if f"class {class_name}" in content:
                self.check_pass(f"Autoinstaller contains class: {class_name}")
            else:
                self.check_fail(f"Autoinstaller missing class: {class_name}")
        
        return True
    
    def validate_shell_scripts(self) -> bool:
        """Validate shell scripts."""
        self.print_header("Shell Scripts Validation")
        
        scripts_dir = self.project_root / "scripts"
        shell_scripts = [
            "setup_tools.sh",
            "run_toolkit.sh", 
            "fix_go_path.sh",
            "fix_dpkg.sh",
            "fix_repo_keys.sh",
            "update_repos.sh"
        ]
        
        all_good = True
        
        for script in shell_scripts:
            script_path = scripts_dir / script
            if script_path.exists():
                # Check if executable on Linux (skip on Windows)
                if platform.system().lower() == 'linux':
                    if os.access(script_path, os.X_OK):
                        self.check_pass(f"Shell script executable: {script}")
                    else:
                        self.check_warning(f"Shell script not executable: {script}")
                else:
                    self.check_pass(f"Shell script exists: {script}")
            else:
                self.check_fail(f"Missing shell script: {script}")
                all_good = False
        
        return all_good
    
    def validate_python_modules(self) -> bool:
        """Validate Python modules can be imported."""
        self.print_header("Python Modules Validation")
        
        # Add paths to sys.path
        sys.path.insert(0, str(self.project_root))
        sys.path.insert(0, str(self.project_root / "src"))
        sys.path.insert(0, str(self.project_root / "commands"))
        
        modules_to_test = [
            ("src.workflow", "Main workflow module"),
            ("src.utils", "Utilities module"),
            ("src.reporter", "Reporter module"),
            ("commands.naabu", "Naabu command module"),
            ("commands.httpx", "Httpx command module"),
            ("commands.nuclei", "Nuclei command module")
        ]
        
        all_good = True
        
        for module_name, description in modules_to_test:
            try:
                __import__(module_name)
                self.check_pass(f"Module imports successfully: {module_name} ({description})")
            except ImportError as e:
                self.check_fail(f"Module import failed: {module_name} - {e}")
                all_good = False
            except Exception as e:
                self.check_warning(f"Module import warning: {module_name} - {e}")
        
        return all_good
    
    def validate_configuration(self) -> bool:
        """Validate configuration files and structure."""
        self.print_header("Configuration Validation")
        
        # Check requirements.txt
        req_file = self.project_root / "config" / "requirements.txt"
        if req_file.exists():
            self.check_pass("Requirements file exists: config/requirements.txt")
            try:
                with open(req_file, 'r') as f:
                    requirements = f.read().strip()
                    if len(requirements) > 0:
                        self.check_pass("Requirements file has content")
                    else:
                        self.check_warning("Requirements file is empty")
            except Exception as e:
                self.check_warning(f"Could not read requirements file: {e}")
        else:
            self.check_fail("Missing requirements file: config/requirements.txt")
        
        # Check for toolkit config (created by autoinstaller)
        config_file = self.project_root / "config" / "toolkit_config.json"
        if config_file.exists():
            self.check_pass("Toolkit configuration exists: config/toolkit_config.json")
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    if "tools" in config and "settings" in config:
                        self.check_pass("Configuration file has required sections")
                    else:
                        self.check_warning("Configuration file missing required sections")
            except json.JSONDecodeError:
                self.check_warning("Configuration file has invalid JSON")
            except Exception as e:
                self.check_warning(f"Could not read configuration file: {e}")
        else:
            self.check_warning("Toolkit configuration not found (run scripts/autoinstall.py to create)")
        
        return True
    
    def validate_security_tools(self) -> Dict[str, bool]:
        """Validate security tools availability (best effort)."""
        self.print_header("Security Tools Validation")
        
        tools = {
            "naabu": "Port scanner",
            "httpx": "HTTP toolkit", 
            "nuclei": "Vulnerability scanner",
            "go": "Go programming language"
        }
        
        results = {}
        
        for tool, description in tools.items():
            # Try to find tool in PATH
            tool_path = subprocess.run(
                ["which", tool] if platform.system().lower() == 'linux' else ["where", tool],
                capture_output=True, text=True
            )
            
            if tool_path.returncode == 0:
                self.check_pass(f"Tool found in PATH: {tool} ({description})")
                results[tool] = True
            else:
                # Check common Go installation paths
                common_paths = [
                    f"/usr/local/go/bin/{tool}",
                    f"/usr/bin/{tool}",
                    f"/usr/local/bin/{tool}",
                    os.path.expanduser(f"~/go/bin/{tool}")
                ]
                
                found = False
                for path in common_paths:
                    if os.path.exists(path) and os.access(path, os.X_OK):
                        self.check_pass(f"Tool found at: {tool} -> {path}")
                        found = True
                        break
                
                if not found:
                    self.check_warning(f"Tool not found: {tool} ({description}) - run install/setup.py")
                
                results[tool] = found
        
        return results
    
    def generate_report(self) -> None:
        """Generate final validation report."""
        self.print_header("Installation Validation Report")
        
        # Calculate success rate
        success_rate = (self.success_count / self.total_checks * 100) if self.total_checks > 0 else 0
        
        # Print summary
        if success_rate >= 90:
            self.print_colored("🎉 EXCELLENT! Installation is in great shape", Colors.GREEN, bold=True)
            status_color = Colors.GREEN
        elif success_rate >= 75:
            self.print_colored("✅ GOOD! Installation is mostly complete", Colors.YELLOW, bold=True)
            status_color = Colors.YELLOW
        elif success_rate >= 50:
            self.print_colored("⚠️  NEEDS ATTENTION! Several issues detected", Colors.YELLOW, bold=True)
            status_color = Colors.YELLOW
        else:
            self.print_colored("❌ CRITICAL! Major installation issues", Colors.RED, bold=True)
            status_color = Colors.RED
        
        print(f"\n{Colors.WHITE}📊 Validation Statistics:{Colors.RESET}")
        self.print_colored(f"  Total Checks: {self.total_checks}", Colors.WHITE)
        self.print_colored(f"  Successful: {self.success_count}", Colors.GREEN)
        self.print_colored(f"  Errors: {len(self.errors)}", Colors.RED if self.errors else Colors.GREEN)
        self.print_colored(f"  Warnings: {len(self.warnings)}", Colors.YELLOW if self.warnings else Colors.GREEN)
        self.print_colored(f"  Success Rate: {success_rate:.1f}%", status_color)
        
        # Show errors if any
        if self.errors:
            print(f"\n{Colors.RED}🚨 Critical Issues:{Colors.RESET}")
            for i, error in enumerate(self.errors, 1):
                self.print_colored(f"  {i}. {error}", Colors.RED)
        
        # Show warnings if any
        if self.warnings:
            print(f"\n{Colors.YELLOW}⚠️  Warnings:{Colors.RESET}")
            for i, warning in enumerate(self.warnings, 1):
                self.print_colored(f"  {i}. {warning}", Colors.YELLOW)
        
        # Recommendations
        print(f"\n{Colors.CYAN}💡 Recommendations:{Colors.RESET}")
        
        if self.errors:
            self.print_colored(f"  1. Fix critical issues before using the toolkit", Colors.CYAN)
        
        if "Tool not found" in str(self.warnings):
            self.print_colored(f"  2. Run 'sudo python3 install/setup.py' to install security tools", Colors.CYAN)
        
        if "not executable" in str(self.warnings):
            self.print_colored(f"  3. Fix script permissions: chmod +x scripts/*.sh", Colors.CYAN)
        
        if "autoinstall.py" in str(self.warnings):
            self.print_colored(f"  4. Run 'python3 scripts/autoinstall.py' for Python environment setup", Colors.CYAN)
        
        self.print_colored(f"  5. Run 'python3 verify_installation.py' for detailed tool testing", Colors.CYAN)
        
        print(f"\n{Colors.GREEN}{'='*80}{Colors.RESET}")
        self.print_colored("🚀 Validation Complete! Ready to scan vulnerabilities", Colors.GREEN, bold=True)
        self.print_colored("Usage: python3 run.py <target> or bash scripts/run_toolkit.sh <target>", Colors.GREEN)
        print(f"{Colors.GREEN}{'='*80}{Colors.RESET}\n")

def main():
    """Main validation function."""
    validator = InstallationValidator()
    
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                                                                              ║")
    print("║        🔍 LINUX VULNERABILITY TOOLKIT - INSTALLATION VALIDATOR 🔍           ║") 
    print("║                                                                              ║")
    print("║    Comprehensive validation of the new master installer architecture         ║")
    print("║                                                                              ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    # Run all validations
    try:
        validator.validate_platform()
        validator.validate_directory_structure() 
        validator.validate_master_installer()
        validator.validate_autoinstaller()
        validator.validate_shell_scripts()
        validator.validate_python_modules()
        validator.validate_configuration()
        validator.validate_security_tools()
        
        # Generate final report
        validator.generate_report()
        
        # Exit code based on critical errors
        return 0 if not validator.errors else 1
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Validation interrupted by user{Colors.RESET}")
        return 1
    except Exception as e:
        print(f"\n{Colors.RED}❌ Validation failed with error: {e}{Colors.RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
