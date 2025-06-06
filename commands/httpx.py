import os
import sys
import json
import subprocess
import platform
import shutil

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from utils import run_cmd, get_executable_path
except ImportError:
    print("Warning: Could not import security tool wrappers (No module named 'utils')")
    print("Make sure you've run setup_tools.sh to install all required components.")
    # Provide fallback functions with compatible signatures
    def run_cmd(cmd, shell=False, check=False, use_sudo=False, timeout=300, retry=1, silent=False):
        try:
            if isinstance(cmd, str):
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check, timeout=timeout)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_executable_path(cmd):
        # Check standard PATH
        path = shutil.which(cmd)
        if path:
            return path
        
        # Check ~/go/bin directory
        go_bin_path = os.path.expanduser(f"~/go/bin/{cmd}")
        if os.path.exists(go_bin_path):
            return go_bin_path
        
        return None

def run_httpx(target=None, target_list=None, output_file=None, json_output=False,
             title=False, status_code=False, tech_detect=False, web_server=False,
             follow_redirects=False, silent=False, timeout=None, threads=None,
             additional_args=None, auto_install=True):
    """
    Run HTTPX tool with the specified parameters.
    
    Parameters:
        target (str): Single target to scan.
        target_list (str): Path to a file containing targets or a URL string.
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
    
    if target_list and not os.path.isfile(target_list):
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
        print("httpx not found in PATH or in ~/go/bin.")
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
            return False
    except Exception as e:
        print(f"Error checking httpx at {httpx_path}: {e}")
        return False

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

def get_httpx_version():
    """
    Get the installed version of httpx.
    
    Returns:
        str: Version string if successful, None otherwise.
    """
    httpx_path = get_executable_path("httpx")
    
    if not httpx_path:
        return None
    
    try:
        cmd = [httpx_path, "-version"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Extract version from output
            version_line = result.stdout.strip()
            return version_line
        else:
            return None
    except Exception:
        return None

def get_httpx_capabilities():
    """
    Get httpx capabilities and version information.
    
    Returns:
        dict: Dictionary containing httpx capabilities.
    """
    capabilities = {
        "available": False,
        "version": None,
        "installation_path": None,
        "features": []
    }
    
    httpx_path = get_executable_path("httpx")
    if httpx_path:
        capabilities["available"] = True
        capabilities["installation_path"] = httpx_path
        
        # Get version
        version = get_httpx_version()
        if version:
            capabilities["version"] = version
        
        # Basic features that httpx supports
        capabilities["features"] = [
            "HTTP/HTTPS probing",
            "Custom headers",
            "Follow redirects",
            "JSON output",
            "Rate limiting",
            "Timeout control",
            "Status code filtering"
        ]
    
    return capabilities