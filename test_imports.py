#!/usr/bin/env python3
"""
Test script to validate all critical imports in the Linux Vulnerability Analysis Toolkit.
This script uses dynamic imports to work around static analysis limitations.
"""

import sys
import os
from typing import Any, Optional

# Add paths for module resolution
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))
sys.path.insert(0, os.path.join(project_root, 'commands'))

print("✅ Testing critical imports...")

def safe_import_module(module_name: str, file_path: str) -> Optional[Any]:
    """Safely import a module from a file path."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load spec for {module_name}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print(f"❌ Failed to import {module_name}: {e}")
        return None

def test_imports() -> bool:
    """Test all critical imports and return success status."""
    success = True
    
    try:
        # Import nuclei
        nuclei = safe_import_module("nuclei", os.path.join(project_root, "commands", "nuclei.py"))
        if nuclei and hasattr(nuclei, 'check_nuclei') and hasattr(nuclei, 'get_nuclei_capabilities'):
            print("✅ nuclei functions imported successfully")
        else:
            print("❌ nuclei module or functions not found")
            success = False
        
        # Import httpx module
        httpx_module = safe_import_module("httpx_cmd", os.path.join(project_root, "commands", "httpx.py"))
        if httpx_module and hasattr(httpx_module, 'get_httpx_capabilities'):
            print("✅ httpx functions imported successfully")
        else:
            print("❌ httpx module or functions not found")
            success = False
        
        # Import utils
        utils = safe_import_module("utils", os.path.join(project_root, "src", "utils.py"))
        if utils and hasattr(utils, 'verify_linux_platform'):
            print("✅ utils functions imported successfully")
        else:
            print("❌ utils module or functions not found")
            success = False
        
        # Import workflow
        workflow = safe_import_module("workflow", os.path.join(project_root, "src", "workflow.py"))
        if workflow and hasattr(workflow, 'run_full_scan'):
            print("✅ workflow functions imported successfully")
        else:
            print("❌ workflow module or functions not found")
            success = False
            
        return success
        
    except Exception as e:
        print(f"❌ Error during import testing: {e}")
        return False

if __name__ == "__main__":
    try:
        success = test_imports()
        
        if success:
            print("\n🎉 ALL CRITICAL FUNCTIONS IMPORTED SUCCESSFULLY!")
            print("🎉 COMPREHENSIVE ERROR CHECK COMPLETED!")
            sys.exit(0)
        else:
            print("\n❌ SOME IMPORTS FAILED!")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
