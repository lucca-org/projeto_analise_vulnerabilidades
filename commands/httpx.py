import os
import json
import subprocess
import platform
import shutil
from utils import run_cmd, get_executable_path

def run_httpx(target=None, target_list=None, output_file=None, json_output=False,
             title=False, status_code=False, tech_detect=False, web_server=False,
             follow_redirects=False, silent=False, timeout=None, threads=None,
             additional_args=None, auto_install=True):
    """
    Run HTTPX tool with the specified parameters.
    
    Parameters:
        target (str): Single target to scan.
        target_list (str): Path to a file containing targets or a URL string (converted to a temporary file).
        output_file (str): Path to save the output.
        json_output (bool): Output in JSON format.
        title (bool): Extract title of the page.
        status_code (bool): Extract status code.
        tech_detect (bool): Extract technologies.
        web_server (bool): Extract web server.
        follow_redirects (bool): Follow redirects.
        silent (bool): Run in silent mode.
        timeout (int): Timeout in seconds.
        threads (int): Number of threads to use.
        additional_args (list): Additional httpx arguments.
        auto_install (bool): Automatically install HTTPX if not found.
        
    Returns:
        bool: True if execution was successful, False otherwise.
    """
    
    # Check if httpx is available, install if needed
    if not check_httpx():
        if auto_install:
            print("🔧 HTTPX not found. Attempting automatic installation...")
            if not auto_install_httpx():
                print("❌ Failed to install HTTPX automatically.")
                return False
        else:
            print("❌ HTTPX is not installed. Please install it first or set auto_install=True.")
            return False    
    # Get httpx path after ensuring it's installed
    httpx_path = get_executable_path("httpx")
    if not httpx_path:
        print("❌ HTTPX installation verification failed - executable not found in PATH")
        return False
    
    # Validate parameters
    if not target and not target_list:
        print("Error: Either target or target_list must be specified.")
        return False
    
    if target_list:
        if not os.path.isfile(target_list):
            # If it's a direct URL, create a temporary file
            if target_list.startswith(('http://', 'https://')):
                try:
                    temp_file = "temp_targets.txt"
                    with open(temp_file, "w") as f:
                        f.write(target_list)
                    target_list = temp_file
                    print(f"Created temporary target file: {temp_file}")
                except Exception as e:
                    print(f"Error creating temporary file: {e}")
                    return False
            else:
                print(f"Error: Target list file '{target_list}' not found.")
                return False
    
    # Build the command using the found httpx path
    cmd = [httpx_path]
    
    if target:
        cmd.extend(["-u", target])
    if target_list:
        cmd.extend(["-l", target_list])
    if output_file:
        cmd.extend(["-o", output_file])
    if json_output:
        cmd.append("-json")
    if title:
        cmd.append("-title")
    if status_code:
        cmd.append("-status-code")
    if tech_detect:
        cmd.append("-tech-detect")
    if web_server:
        cmd.append("-web-server")
    if follow_redirects:
        cmd.append("-follow-redirects")
    if silent:
        cmd.append("-silent")
    if timeout:
        cmd.extend(["-timeout", str(timeout)])
    if threads:
        cmd.extend(["-threads", str(threads)])
    
    # Add any additional arguments
    if additional_args:
        cmd.extend(additional_args)
    
    # Print command for debugging
    if not silent:
        print(f"Running: {' '.join(cmd)}")
    
    # Run with retry for better resilience
    success = run_cmd(cmd, retry=1)
    if not success:
        print("Failed to execute HTTPX. Please check the parameters and try again.")
        return False
    
    return True

def parse_httpx_results(output_file, json_format=False):
    """
    Parse the HTTPX output file and return the results.
    
    Parameters:
        output_file (str): Path to the HTTPX output file.
        json_format (bool): Whether the output file is in JSON format.
        
    Returns:
        list: Parsed results, or None if parsing failed.
    """
    if not os.path.isfile(output_file):
        print(f"Error: HTTPX output file '{output_file}' not found.")
        return None
    
    try:
        results = []
        with open(output_file, 'r') as f:
            if json_format:
                for line in f:
                    try:
                        results.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        # Skip invalid JSON lines
                        continue
            else:
                results = [line.strip() for line in f.readlines()]
        return results
    except Exception as e:
        print(f"Error parsing HTTPX results: {e}")
        return None

def check_httpx():
    """
    Check if httpx is installed and available in the PATH.
    
    Returns:
        bool: True if httpx is installed and working, False otherwise.
    """
    httpx_path = get_executable_path("httpx")
    if not httpx_path:
        # Special handling for common Go installation path that might not be in PATH
        go_bin_httpx = os.path.expanduser("~/go/bin/httpx")
        if os.path.exists(go_bin_httpx) and os.access(go_bin_httpx, os.X_OK):
            print(f"httpx found at {go_bin_httpx} but not in PATH.")
            print("Adding ~/go/bin to PATH for this session.")
            os.environ["PATH"] += os.pathsep + os.path.dirname(go_bin_httpx)
            httpx_path = go_bin_httpx
        else:
            print("httpx not found in PATH or in common locations.")
            print("Checked locations:")
            print("  - System PATH")
            print("  - ~/go/bin/httpx")
            print("  - ~/.local/bin/httpx")
            print("  - /usr/local/bin/httpx")
            print("  - /usr/bin/httpx")
            return False
        
    try:
        # Try running a simple command to check if httpx is working
        result = subprocess.run([httpx_path, "-version"], 
                              capture_output=True, 
                              text=True, 
                              timeout=10)
        
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"httpx is available at {httpx_path}: {version}")
            return True
        else:
            print(f"httpx is installed at {httpx_path} but not working correctly.")
            print(f"Error output: {result.stderr}")
            return False
    except FileNotFoundError:
        print(f"httpx executable found at {httpx_path} but cannot be executed.")
        return False
    except subprocess.TimeoutExpired:
        print(f"httpx at {httpx_path} timed out during version check.")
        return False
    except Exception as e:
        print(f"Error checking httpx at {httpx_path}: {e}")
        return False

def get_httpx_capabilities():
    """Get information about HTTPX capabilities based on its installation."""
    capabilities = {
        "version": None,
        "available_flags": []
    }
    
    httpx_path = get_executable_path("httpx")
    if not httpx_path:
        return capabilities
    
    try:
        # Get version
        process = subprocess.run([httpx_path, "-version"], capture_output=True, text=True, timeout=10)
        if process.returncode == 0 and process.stdout:
            capabilities["version"] = process.stdout.strip()
        
        # Get help to determine available flags
        process = subprocess.run([httpx_path, "-h"], capture_output=True, text=True, timeout=10)
        if process.returncode == 0 and process.stdout:
            help_text = process.stdout
            # Parse flags from help text
            for line in help_text.split("\n"):
                if line.strip().startswith("-"):
                    flag = line.split()[0].strip()
                    capabilities["available_flags"].append(flag)
    except Exception as e:
        print(f"Error checking HTTPX capabilities: {e}")
    
    return capabilities

def auto_install_httpx():
    """
    Automatically install HTTPX on Linux systems.
    
    Returns:
        bool: True if installation was successful, False otherwise.
    """
    print("🔧 Starting automatic installation of HTTPX...")
    
    # Check if already installed and working
    if check_httpx():
        print("✅ HTTPX is already installed and working!")
        return True
    
    # Check if Go is installed
    if not shutil.which("go"):
        print("❌ Go is not installed. Please install Go first.")
        print("   You can use the autoinstall.py script to install Go automatically.")
        return False
    
    try:
        print("📦 Installing HTTPX using Go...")
        
        # Install httpx using go install
        cmd = ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"❌ Failed to install HTTPX: {result.stderr}")
            return False
        
        print("✅ HTTPX installed successfully!")
        
        # Verify installation
        if check_httpx():
            print("✅ HTTPX installation verified and working!")
            
            # Add ~/go/bin to PATH if not already there
            go_bin_path = os.path.expanduser("~/go/bin")
            current_path = os.environ.get("PATH", "")
            if go_bin_path not in current_path:
                os.environ["PATH"] = f"{go_bin_path}:{current_path}"
                print(f"📝 Added {go_bin_path} to PATH for this session")
            
            return True
        else:
            print("❌ HTTPX installation completed but verification failed")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Installation timed out. Please check your internet connection.")
        return False
    except Exception as e:
        print(f"❌ Error during installation: {e}")
        return False