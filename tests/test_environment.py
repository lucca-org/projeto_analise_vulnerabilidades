#!/usr/bin/env python3
"""
test_environment.py - Test the environment setup and tool availability
"""

import os
import sys
import shutil
import platform
import subprocess
from pathlib import Path

def check_python_version():
    print(f"Python version: {platform.python_version()}")
    if sys.version_info < (3, 8):
        print("WARNING: Python version older than 3.8. Some features may not work.")
    return True

def check_required_modules():
    required_modules = ["requests", "colorama", "jinja2", "markdown", "rich", "tqdm", "pathlib"]
    missing_modules = []
    optional_modules = []
    
    print("\nChecking Python modules:")
    for module in required_modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError:
            if module in ["jinja2", "markdown", "rich"]:
                optional_modules.append(module)
            else:
                missing_modules.append(module)
                print(f"✗ {module} (missing)")
    
    if optional_modules:
        print("\nOptional modules missing (reports will have limited features):")
        for module in optional_modules:
            print(f"- {module}")
    
    if missing_modules:
        print("\nRequired modules missing. Install them with:")
        print(f"pip install {' '.join(missing_modules)}")
        return False
    
    return True

def check_tool_in_path(tool):
    """Check if a tool is in the PATH or in ~/go/bin."""
    # Check in PATH
    if shutil.which(tool):
        return shutil.which(tool)
    
    # Check in ~/go/bin
    go_bin_path = os.path.expanduser(f"~/go/bin/{tool}")
    if os.path.exists(go_bin_path) and os.access(go_bin_path, os.X_OK):
        print(f"Note: {tool} found in ~/go/bin but not in PATH")
        print("You may need to add ~/go/bin to your PATH")
        return go_bin_path
    
    return None

def check_security_tools():
    tools = ["naabu", "httpx", "nuclei"]
    missing_tools = []
    
    print("\nChecking security tools:")
    for tool in tools:
        tool_path = check_tool_in_path(tool)
        if tool_path:
            try:
                version_output = subprocess.check_output([tool_path, "-version"], 
                                                       stderr=subprocess.STDOUT,
                                                       universal_newlines=True,
                                                       timeout=5)
                if tool == "httpx":
                    print(f"✓ httpx: {version_output.strip()} (Go installation)")
                    if "go/bin" in tool_path:
                        print(f"  Note: httpx is installed via Go at {tool_path}")
                        print("  Make sure ~/go/bin is in your PATH")
                else:
                    print(f"✓ {tool}: {version_output.strip()}")
            except (subprocess.SubprocessError, FileNotFoundError):
                print(f"✓ {tool} (found but couldn't get version)")
        else:
            missing_tools.append(tool)
            print(f"✗ {tool} (not found)")
            if tool == "httpx":
                print("  httpx must be installed via Go. Run setup_tools.sh")
    
    if missing_tools:
        print("\nMissing tools. Please run setup_tools.sh to install them.")
        return False
    
    return True

def check_python_modules():
    module_paths = {
        "commands.naabu": "commands/naabu.py",
        "commands.httpx": "commands/httpx.py",
        "commands.nuclei": "commands/nuclei.py",
        "utils": "utils.py",
        "workflow": "workflow.py",
        "reporter": "reporter.py"
    }
    
    missing_modules = []
    
    print("\nChecking Python project modules:")
    for module_name, file_path in module_paths.items():
        if os.path.exists(file_path):
            try:
                __import__(module_name.split(".")[0])
                print(f"✓ {module_name}")
            except ImportError as e:
                print(f"✓ {module_name} (file exists but import error: {e})")
        else:
            missing_modules.append(file_path)
            print(f"✗ {module_name} (file missing: {file_path})")
    
    if missing_modules:
        print("\nSome project modules are missing:")
        for module in missing_modules:
            print(f"- {module}")
        return False
    
    return True

def main():
    print("===== Environment Test =====")
    print(f"OS: {platform.system()} {platform.release()}")
    
    checks = [
        check_python_version(),
        check_required_modules(),
        check_security_tools(),
        check_python_modules()
    ]
    
    if all(checks):
        print("\n✅ Environment looks good! You can run the toolkit.")
        print("Try: python3 workflow.py example.com")
        sys.exit(0)
    else:
        print("\n⚠️ Some issues were detected. Please fix them before using the toolkit.")
        print("Run setup_tools.sh to fix installation issues.")
        sys.exit(1)

if __name__ == "__main__":
    main()
