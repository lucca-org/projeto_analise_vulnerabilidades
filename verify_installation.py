#!/usr/bin/env python3
"""
Comprehensive installation verification script for the Linux Vulnerability Analysis Toolkit.
Tests all enhanced modules with auto-installation capabilities.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
from src.utils import verify_linux_platform

# Add the project directory to the Python path
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir / "src"))
sys.path.insert(0, str(project_dir / "commands"))

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(title):
    """Print a formatted header."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{title.center(60)}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.END}\n")

def print_success(message):
    """Print a success message."""
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")

def print_error(message):
    """Print an error message."""
    print(f"{Colors.RED}❌ {message}{Colors.END}")

def print_warning(message):
    """Print a warning message."""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")

def print_info(message):
    """Print an info message."""
    print(f"{Colors.BLUE}ℹ️  {message}{Colors.END}")

def check_platform():
    """Verify we're running on Linux."""
    print_header("PLATFORM VERIFICATION")

    if not verify_linux_platform():
        print_error("This toolkit is designed for Linux only.")
        print_info("Please run this on a Linux system (Kali, Ubuntu, Debian, Arch, etc.)")
        return False

    print_success(f"Running on Linux: {platform.platform()}")
    return True

def check_python_dependencies():
    """Check if all Python dependencies are available."""
    print_header("PYTHON DEPENDENCIES CHECK")
    
    dependencies_ok = True
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
        print_error(f"Python 3.6+ required. Current: {python_version.major}.{python_version.minor}")
        dependencies_ok = False
    else:
        print_success(f"Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    # Check if our modules can be imported
    modules_to_check = [
        ("utils", "src/utils.py"),
        ("workflow", "src/workflow.py"),
        ("naabu", "commands/naabu.py"),
        ("httpx", "commands/httpx.py"),
        ("nuclei", "commands/nuclei.py"),
    ]
    
    for module_name, module_path in modules_to_check:
        try:
            if module_name == "utils":
                import utils
                print_success(f"Module '{module_name}' imported successfully")
            elif module_name == "workflow":
                import workflow
                print_success(f"Module '{module_name}' imported successfully")
            elif module_name == "naabu":
                from commands import naabu
                print_success(f"Module '{module_name}' imported successfully")
            elif module_name == "httpx":
                from commands import httpx as httpx_module
                print_success(f"Module '{module_name}' imported successfully")
            elif module_name == "nuclei":
                from commands import nuclei
                print_success(f"Module '{module_name}' imported successfully")
        except ImportError as e:
            print_error(f"Failed to import '{module_name}': {e}")
            print_info(f"Check if {module_path} exists and is valid")
            dependencies_ok = False
        except Exception as e:
            print_warning(f"Issue with '{module_name}': {e}")
    
    return dependencies_ok

def check_go_installation():
    """Check if Go is installed and properly configured."""
    print_header("GO INSTALLATION CHECK")
    
    try:
        result = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            go_version = result.stdout.strip()
            print_success(f"Go is installed: {go_version}")
            
            # Check GOPATH and GOROOT
            try:
                gopath_result = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True, timeout=5)
                if gopath_result.returncode == 0:
                    gopath = gopath_result.stdout.strip()
                    print_success(f"GOPATH: {gopath}")
                    
                    # Check if ~/go/bin is in PATH
                    go_bin = os.path.expanduser("~/go/bin")
                    if go_bin in os.environ.get("PATH", ""):
                        print_success("~/go/bin is in PATH")
                    else:
                        print_warning("~/go/bin is not in PATH - tools may not be accessible")
                        print_info("Consider adding 'export PATH=$PATH:~/go/bin' to your ~/.bashrc")
            except:
                print_warning("Could not check GOPATH")
            
            return True
        else:
            print_error("Go is installed but not working correctly")
            return False
    except FileNotFoundError:
        print_error("Go is not installed")
        print_info("Install Go using: sudo apt install golang-go (Debian/Ubuntu)")
        print_info("Or use the scripts/autoinstall.py script for automatic installation")
        return False
    except Exception as e:
        print_error(f"Error checking Go: {e}")
        return False

def test_tool_modules():
    """Test the enhanced tool modules with auto-installation capabilities."""
    print_header("TOOL MODULES TESTING")
    
    tools_status = {}
    
    # Test naabu module
    try:
        from commands import naabu
        print_info("Testing Naabu module...")
        
        # Test check function
        naabu_available = naabu.check_naabu()
        if naabu_available:
            print_success("Naabu is available and working")
            
            # Test capabilities detection
            capabilities = naabu.get_naabu_capabilities()
            if capabilities.get("version"):
                print_success(f"Naabu version: {capabilities['version']}")
            if capabilities.get("scan_types"):
                print_success(f"Supported scan types: {', '.join(capabilities['scan_types'])}")
        else:
            print_warning("Naabu not currently available")
            print_info("Auto-installation will be attempted when needed")
        
        tools_status["naabu"] = naabu_available
        
    except Exception as e:
        print_error(f"Error testing naabu module: {e}")
        tools_status["naabu"] = False
    
    # Test httpx module
    try:
        from commands import httpx as httpx_module
        print_info("Testing HTTPX module...")
        
        # Test check function
        httpx_available = httpx_module.check_httpx()
        if httpx_available:
            print_success("HTTPX is available and working")
            
            # Test capabilities detection
            capabilities = httpx_module.get_httpx_capabilities()
            if capabilities.get("version"):
                print_success(f"HTTPX version: {capabilities['version']}")
        else:
            print_warning("HTTPX not currently available")
            print_info("Auto-installation will be attempted when needed")
        
        tools_status["httpx"] = httpx_available
        
    except Exception as e:
        print_error(f"Error testing httpx module: {e}")
        tools_status["httpx"] = False
    
    # Test nuclei module
    try:
        from commands import nuclei
        print_info("Testing Nuclei module...")
        
        # Test check function
        nuclei_available = nuclei.check_nuclei()
        if nuclei_available:
            print_success("Nuclei is available and working")
            
            # Test capabilities detection
            capabilities = nuclei.get_nuclei_capabilities()
            if capabilities.get("version"):
                print_success(f"Nuclei version: {capabilities['version']}")
            if capabilities.get("templates_count", 0) > 0:
                print_success(f"Nuclei templates available: {capabilities['templates_count']}")
        else:
            print_warning("Nuclei not currently available")
            print_info("Auto-installation will be attempted when needed")
        
        tools_status["nuclei"] = nuclei_available
        
    except Exception as e:
        print_error(f"Error testing nuclei module: {e}")
        tools_status["nuclei"] = False
    
    return tools_status

def test_auto_installation():
    """Test the auto-installation capabilities (dry run)."""
    print_header("AUTO-INSTALLATION CAPABILITIES TEST")
    
    # Check if Go is available for installations
    go_available = False
    try:
        result = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=5)
        go_available = result.returncode == 0
    except:
        pass
    
    if not go_available:
        print_warning("Go is not available - auto-installation will not work")
        print_info("Install Go first using the scripts/autoinstall.py script")
        return False
    
    print_success("Go is available - auto-installation should work")
    
    # Test if the auto-install functions exist and are callable
    try:
        from commands import naabu
        if hasattr(naabu, 'auto_install_naabu'):
            print_success("Naabu auto-installation function available")
        else:
            print_warning("Naabu auto-installation function not found")
    except:
        print_error("Could not test naabu auto-installation")
    
    try:
        from commands import httpx as httpx_module
        if hasattr(httpx_module, 'auto_install_httpx'):
            print_success("HTTPX auto-installation function available")
        else:
            print_warning("HTTPX auto-installation function not found")
    except:
        print_error("Could not test httpx auto-installation")
    
    try:
        from commands import nuclei
        if hasattr(nuclei, 'auto_install_nuclei'):
            print_success("Nuclei auto-installation function available")
        else:
            print_warning("Nuclei auto-installation function not found")
    except:
        print_error("Could not test nuclei auto-installation")
    
    return True

def generate_report(platform_ok, deps_ok, go_ok, tools_status, auto_install_ok):
    """Generate a final verification report."""
    print_header("VERIFICATION REPORT")
    
    total_checks = 0
    passed_checks = 0
    
    # Platform check
    total_checks += 1
    if platform_ok:
        passed_checks += 1
        print_success("Platform: Linux ✓")
    else:
        print_error("Platform: Not Linux ✗")
    
    # Dependencies check
    total_checks += 1
    if deps_ok:
        passed_checks += 1
        print_success("Python Dependencies: All OK ✓")
    else:
        print_error("Python Dependencies: Issues found ✗")
    
    # Go installation check
    total_checks += 1
    if go_ok:
        passed_checks += 1
        print_success("Go Installation: Working ✓")
    else:
        print_error("Go Installation: Not available ✗")
    
    # Tools status
    for tool, status in tools_status.items():
        total_checks += 1
        if status:
            passed_checks += 1
            print_success(f"{tool.upper()}: Available ✓")
        else:
            print_warning(f"{tool.upper()}: Will be auto-installed when needed")
    
    # Auto-installation capabilities
    total_checks += 1
    if auto_install_ok:
        passed_checks += 1
        print_success("Auto-installation: Ready ✓")
    else:
        print_error("Auto-installation: Not ready ✗")
    
    # Summary
    print(f"\n{Colors.BOLD}SUMMARY:{Colors.END}")
    print(f"Passed: {passed_checks}/{total_checks} checks")
    
    if passed_checks == total_checks:
        print_success("🎉 All systems ready! The toolkit is fully operational.")
    elif passed_checks >= total_checks - len(tools_status):
        print_success("🚀 Core systems ready! Tools will be installed automatically as needed.")
    else:
        print_warning("⚠️  Some issues found. Please address them before using the toolkit.")
    
    print(f"\n{Colors.PURPLE}Next steps:{Colors.END}")
    if not go_ok:
        print_info("1. Run 'python3 scripts/autoinstall.py' to install Go and all tools")
    else:
        print_info("1. Tools will be automatically installed when first used")
    print_info("2. Run 'python3 src/workflow.py --help' to see available options")
    print_info("3. Try a quick scan: python3 src/workflow.py --target example.com")

def main():
    """Main verification function."""
    print(f"{Colors.PURPLE}{Colors.BOLD}")
    print("🛡️  LINUX VULNERABILITY ANALYSIS TOOLKIT")
    print("📋 Installation Verification Script")
    print(f"{'='*60}{Colors.END}")
    
    # Run all verification checks
    platform_ok = check_platform()
    deps_ok = check_python_dependencies()
    go_ok = check_go_installation()
    tools_status = test_tool_modules()
    auto_install_ok = test_auto_installation()
    
    # Generate final report
    generate_report(platform_ok, deps_ok, go_ok, tools_status, auto_install_ok)

if __name__ == "__main__":
    main()
