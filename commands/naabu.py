#!/usr/bin/env python3
import os
import json
import subprocess
import shutil
from utils import run_cmd, get_executable_path

def run_naabu(target=None, target_list=None, ports=None, exclude_ports=None, 
             threads=None, rate=None, timeout=None, json_output=False, 
             output_file=None, silent=False, additional_args=None, auto_install=True):
    """
    Run Naabu port scanner with the specified parameters.
    
    Parameters:
        target (str): Single target to scan.
        target_list (str): Path to a file containing targets.
        ports (str): Ports to scan (e.g., "80,443,8080-8090").
        exclude_ports (str): Ports to exclude from scan.
        threads (int): Number of concurrent threads.
        rate (int): Number of packets per second.
        timeout (int): Timeout in milliseconds.
        json_output (bool): Output in JSON format.
        output_file (str): Path to save the output.
        silent (bool): Run in silent mode.
        additional_args (list): Additional naabu arguments.
        auto_install (bool): Automatically install naabu if not found.
        
    Returns:
        bool: True if execution was successful, False otherwise.
    """
    # Check if naabu is available, install if needed
    if not check_naabu():
        if auto_install:
            print("🔧 Naabu not found. Attempting automatic installation...")
            if not auto_install_naabu():
                print("❌ Failed to install Naabu automatically.")
                return False
        else:
            print("❌ Naabu is not installed. Please install it first or set auto_install=True.")
            return False
    
    if not target and not target_list:
        print("Error: Either target or target_list must be specified.")
        return False
    
    if target_list and not os.path.isfile(target_list):
        print(f"Error: Target list file '{target_list}' not found.")
        return False
    
    cmd = ["naabu"]
    
    if target:
        cmd.extend(["-host", target])
    if target_list:
        cmd.extend(["-l", target_list])
    if ports:
        cmd.extend(["-p", ports])
    if exclude_ports:
        cmd.extend(["-exclude-ports", exclude_ports])
    if threads:
        cmd.extend(["-c", str(threads)])
    if rate:
        cmd.extend(["-rate", str(rate)])
    if timeout:
        cmd.extend(["-timeout", str(timeout)])
    if json_output:
        cmd.append("-json")
    if output_file:
        cmd.extend(["-o", output_file])
    if silent:
        cmd.append("-silent")
    
    # Add any additional arguments
    if additional_args:
        cmd.extend(additional_args)
    
    # Always use connect scan mode for better compatibility across systems
    if "--scan-type" not in cmd and "-scan-type" not in cmd:
        if "--connect" not in cmd and "-connect" not in cmd:
            if "--so" not in cmd and "-so" not in cmd and "--syn" not in cmd and "-syn" not in cmd:
                cmd.append("-scan-type")
                cmd.append("connect")
                print("Using connect scan mode for better cross-platform compatibility")

    # Run with retry for better resilience
    success = run_cmd(cmd, retry=1)
    if not success:
        print("Failed to execute Naabu. Please check the parameters and try again.")
        return False
    
    return True

def parse_naabu_results(output_file, json_format=False):
    """
    Parse the Naabu output file and return the results.
    
    Parameters:
        output_file (str): Path to the Naabu output file.
        json_format (bool): Whether the output file is in JSON format.
        
    Returns:
        list: Parsed results, or None if parsing failed.
    """
    if not os.path.isfile(output_file):
        print(f"Error: Naabu output file '{output_file}' not found.")
        return None
    
    try:
        results = []
        with open(output_file, 'r') as f:
            if json_format:
                try:
                    # Try parsing as a single JSON array
                    content = f.read()
                    if content.strip().startswith('[') and content.strip().endswith(']'):
                        results = json.loads(content)
                    else:
                        # Parse as JSON lines
                        f.seek(0)  # Go back to the beginning of the file
                        for line in f:
                            try:
                                results.append(json.loads(line.strip()))
                            except json.JSONDecodeError:
                                # Skip invalid JSON lines
                                continue
                except json.JSONDecodeError:
                    # Fall back to line-by-line parsing
                    f.seek(0)  # Go back to the beginning of the file
                    for line in f:
                        try:
                            results.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            # Skip invalid JSON lines
                            continue
            else:
                results = []
                for line in f:
                    line = line.strip()
                    if line:
                        results.append(line)
                        
        return results
    except Exception as e:
        print(f"Error parsing Naabu results: {e}")
        return None

def check_naabu():
    """
    Check if naabu is installed and available in the PATH.
    
    Returns:
        bool: True if naabu is installed and working, False otherwise.
    """
    naabu_path = get_executable_path("naabu")
    if not naabu_path:
        print("Naabu not found in PATH or in ~/go/bin.")
        return False
        
    try:
        # Try running a simple command to check if naabu is working
        result = subprocess.run([naabu_path, "-version"], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        
        if result.returncode == 0:
            print(f"Naabu is available: {result.stdout.strip()}")
            return True
        else:
            print("Naabu is installed but not working correctly.")
            return False
    except Exception as e:
        print(f"Error checking naabu: {e}")
        return False


def get_naabu_capabilities():
    """
    Detect naabu capabilities by checking version and supported arguments.
    
    Returns:
        dict: Dictionary containing capabilities information
    """
    capabilities = {
        "version": None,
        "scan_types": [],
    }
    
    naabu_path = get_executable_path("naabu")
    if not naabu_path:
        return capabilities
    
    try:
        # Get version
        version_output = subprocess.run([naabu_path, "-version"], 
                                     capture_output=True, 
                                     text=True, 
                                     timeout=5).stdout.strip()
        capabilities["version"] = version_output
        
        # Check for scan types
        help_output = subprocess.run([naabu_path, "-h"], 
                                   capture_output=True, 
                                   text=True, 
                                   timeout=5).stdout
                                   
        if "-scan-type" in help_output:
            if "SYN" in help_output and "CONNECT" in help_output:
                capabilities["scan_types"] = ["SYN", "CONNECT"]
            else:
                capabilities["scan_types"] = ["CONNECT"]  # Default fallback
    except Exception as e:
        print(f"Error detecting naabu capabilities: {e}")
    
    return capabilities

def auto_install_naabu():
    """
    Automatically install naabu port scanner on Linux systems.
    
    Returns:
        bool: True if installation was successful, False otherwise.
    """
    print("🔧 Starting automatic installation of Naabu...")
    
    # Check if already installed and working
    if check_naabu():
        print("✅ Naabu is already installed and working!")
        return True
    
    # Check if Go is installed
    if not shutil.which("go"):
        print("❌ Go is not installed. Please install Go first.")
        print("   You can use the autoinstall.py script to install Go automatically.")
        return False
    
    try:
        print("📦 Installing Naabu using Go...")
        
        # Install naabu using go install
        cmd = ["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"❌ Failed to install Naabu: {result.stderr}")
            return False
        
        print("✅ Naabu installed successfully!")
        
        # Verify installation
        if check_naabu():
            print("✅ Naabu installation verified and working!")
            
            # Add ~/go/bin to PATH if not already there
            go_bin_path = os.path.expanduser("~/go/bin")
            current_path = os.environ.get("PATH", "")
            if go_bin_path not in current_path:
                os.environ["PATH"] = f"{go_bin_path}:{current_path}"
                print(f"📝 Added {go_bin_path} to PATH for this session")
            
            return True
        else:
            print("❌ Naabu installation completed but verification failed")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Installation timed out. Please check your internet connection.")
        return False
    except Exception as e:
        print(f"❌ Error during installation: {e}")
        return False