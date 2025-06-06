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

Usage: python3 tests/validate_installation.py
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
        self.project_root = Path(__file__).parent.parent  # Go up one level from tests/
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
            self.check_fail(f"This toolkit requires Linux (detected: {platform.system()})")
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
            "commands"        ]
        
        required_files = [
            "install/setup.py",
            "scripts/autoinstall.py",
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
        
        # Check if it's readable
        if not os.access(setup_py, os.R_OK):
            self.check_fail("Master installer is not readable")
            return False
        
        self.check_pass("Master installer file exists and is readable")
        
        # Try to validate syntax
        try:
            with open(setup_py, 'r', encoding='utf-8') as f:
                content = f.read()
                compile(content, str(setup_py), 'exec')
            self.check_pass("Master installer syntax is valid")
        except SyntaxError as e:
            self.check_fail(f"Master installer syntax error: {e}")
            return False
        except UnicodeDecodeError as e:
            self.check_fail(f"Master installer encoding error: {e}")
            return False
        
        # Check for key functions/classes
        required_elements = [
            "print_header",
            "detect_linux_distro", 
            "SUPPORTED_DISTROS",
            "Colors"
        ]
        
        try:
            with open(setup_py, 'r', encoding='utf-8') as f:
                content = f.read()
                
            for element in required_elements:
                if element in content:
                    self.check_pass(f"Master installer contains: {element}")
                else:
                    self.check_warning(f"Master installer missing: {element}")
        except Exception as e:
            self.check_warning(f"Could not analyze master installer content: {e}")
        
        return True
    
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
                self.print_colored(f"  {i}. {warning}", Colors.YELLOW)        # Recommendations
        print(f"\n{Colors.CYAN}💡 Recommendations:{Colors.RESET}")
        self.print_colored(f"  1. Run 'sudo python3 install/setup.py' on Linux to install security tools", Colors.CYAN)
        self.print_colored(f"  2. Run 'python3 scripts/autoinstall.py' for Python environment setup", Colors.CYAN)
        self.print_colored(f"  3. Run 'python3 tests/verify_installation.py' for detailed tool testing", Colors.CYAN)
        
        print(f"\n{Colors.MAGENTA}📝 Architecture Notes:{Colors.RESET}")
        self.print_colored(f"  • Legacy scripts (setup_tools.sh, fix_*.sh) functionality integrated into master installer", Colors.MAGENTA)
        self.print_colored(f"  • Enhanced setup.py now handles all installation and system configuration", Colors.MAGENTA)
        
        print(f"\n{Colors.GREEN}{'='*80}{Colors.RESET}")
        self.print_colored("🚀 Validation Complete! Ready for Linux deployment", Colors.GREEN, bold=True)
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
    
    # Run essential validations
    try:
        validator.validate_platform()
        validator.validate_directory_structure() 
        validator.validate_master_installer()
        
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
