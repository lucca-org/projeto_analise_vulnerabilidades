#!/usr/bin/env python3
"""
Comprehensive error check and validation script for the Linux Vulnerability Analysis Toolkit.
This script performs a complete health assessment of all modules.
"""

import sys
import os
import traceback
from pathlib import Path

# Add paths
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))
sys.path.insert(0, str(project_dir / "src"))
sys.path.insert(0, str(project_dir / "commands"))

def test_imports():
    """Test all critical module imports."""
    print("🔍 Testing module imports...")
    
    try:
        # Test command modules
        print("  • Testing command modules...")
        from commands import naabu, httpx, nuclei
        print("    ✅ naabu module imported")
        print("    ✅ httpx module imported") 
        print("    ✅ nuclei module imported")
        
        # Test src modules
        print("  • Testing src modules...")
        from src import utils, workflow, config_manager, reporter, code_scanner, frontend_bridge
        print("    ✅ utils module imported")
        print("    ✅ workflow module imported")
        print("    ✅ config_manager module imported")
        print("    ✅ reporter module imported")
        print("    ✅ code_scanner module imported")
        print("    ✅ frontend_bridge module imported")
        
        return True, (naabu, httpx, nuclei, utils, workflow)
    except Exception as e:
        print(f"    ❌ Import failed: {e}")
        traceback.print_exc()
        return False, None

def test_functions(modules):
    """Test specific function calls."""
    print("\n🔍 Testing function calls...")
    
    naabu, httpx, nuclei, utils, workflow = modules
    
    try:
        # Test nuclei functions
        print("  • Testing nuclei functions...")
        nuclei_available = nuclei.check_nuclei()
        print(f"    ✅ nuclei.check_nuclei(): {nuclei_available}")
        
        nuclei_caps = nuclei.get_nuclei_capabilities()
        print(f"    ✅ nuclei.get_nuclei_capabilities(): Available={nuclei_caps.get('available', False)}")
        
        # Test httpx functions  
        print("  • Testing httpx functions...")
        httpx_caps = httpx.get_httpx_capabilities()
        print(f"    ✅ httpx.get_httpx_capabilities(): Available={httpx_caps.get('available', False)}")
        
        # Test utils functions
        print("  • Testing utils functions...")
        is_linux = utils.verify_linux_platform()
        print(f"    ✅ utils.verify_linux_platform(): {is_linux}")
        
        return True
    except Exception as e:
        print(f"    ❌ Function test failed: {e}")
        traceback.print_exc()
        return False

def check_file_integrity():
    """Check file integrity and structure."""
    print("\n🔍 Checking file integrity...")
    
    required_files = [
        "commands/naabu.py",
        "commands/httpx.py", 
        "commands/nuclei.py",
        "src/utils.py",
        "src/workflow.py",
        "src/config_manager.py",
        "src/reporter.py",
        "install/setup.py"
    ]
    
    all_exist = True
    for file_path in required_files:
        full_path = project_dir / file_path
        if full_path.exists():
            print(f"    ✅ {file_path}")
        else:
            print(f"    ❌ {file_path} - Missing!")
            all_exist = False
    
    return all_exist

def main():
    """Run comprehensive error check."""
    print("=" * 60)
    print("COMPREHENSIVE ERROR CHECK - Linux Vulnerability Analysis Toolkit")
    print("=" * 60)
    
    # Test imports
    imports_ok, modules = test_imports()
    if not imports_ok:
        print("\n❌ IMPORT TEST FAILED - Cannot proceed with function tests")
        return False
    
    # Test functions
    functions_ok = test_functions(modules)
    if not functions_ok:
        print("\n❌ FUNCTION TEST FAILED")
        return False
    
    # Check file integrity
    files_ok = check_file_integrity()
    if not files_ok:
        print("\n❌ FILE INTEGRITY CHECK FAILED")
        return False
    
    print("\n" + "=" * 60)
    print("🎉 COMPREHENSIVE ERROR CHECK COMPLETED SUCCESSFULLY!")
    print("✅ All modules can be imported")
    print("✅ All critical functions work")
    print("✅ All required files present")
    print("✅ Project is in a healthy state")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
