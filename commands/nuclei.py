import os
import json
import subprocess
import shutil
from utils import run_cmd, get_executable_path

def run_nuclei(target=None, target_list=None, templates=None, tags=None, severity=None,
              output_file=None, jsonl=False, silent=False, store_resp=False, 
              headers=None, variables=None, rate_limit=None, timeout=None, 
              additional_args=None, auto_install=True):
    """
    Run Nuclei vulnerability scanner with the specified parameters.
    
    Parameters:
        target (str): Single target to scan.
        target_list (str): Path to a file containing targets or a URL string (e.g., "http://example.com/targets").
        templates (str): Custom templates or template directory.
        tags (str): Tags to include templates by (e.g., "cve,wordpress").
        severity (str): Filter templates by severity (e.g., "critical,high").
        output_file (str): Path to save the output.
        jsonl (bool): Output in JSONL format.
        silent (bool): Run in silent mode.
        store_resp (bool): Store HTTP request/responses in output directory.
        headers (list): Custom headers to add to all requests.
        variables (dict): Custom variables for templates.
        rate_limit (int): Maximum number of requests per second.
        timeout (int): Timeout in seconds for HTTP requests.
        additional_args (list): Additional nuclei arguments.
        auto_install (bool): Automatically install Nuclei if not found.
        
    Returns:
        bool: True if execution was successful, False otherwise.
    """
    # Check if nuclei is available, install if needed
    if not check_nuclei():
        if auto_install:
            print("🔧 Nuclei not found. Attempting automatic installation...")
            if not auto_install_nuclei():
                print("❌ Failed to install Nuclei automatically.")
                return False
        else:
            print("❌ Nuclei is not installed. Please install it first or set auto_install=True.")
            return False
    
    if not target and not target_list:
        print("Error: Either target or target_list must be specified.")
        return False
    
    if target_list and not os.path.isfile(target_list):
        print(f"Error: Target list file '{target_list}' not found.")
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
            return False
    
    cmd = ["nuclei"]

    if target:
        cmd.extend(["-u", target])
    if target_list:
        cmd.extend(["-l", target_list])
    if templates:
        cmd.extend(["-t", templates])
    if tags:
        cmd.extend(["-tags", tags])
    if severity:
        cmd.extend(["-severity", severity])
    if output_file:
        cmd.extend(["-o", output_file])
    if jsonl:
        cmd.append("-jsonl")
    if silent:
        cmd.append("-silent")
    if store_resp:
        cmd.append("-store-resp")
    if headers:
        for header in headers:
            cmd.extend(["-H", header])
    if variables:
        # Detect supported flag for template variables
        supported_flag = "-var"
        try:
            help_output = subprocess.run(["nuclei", "-h"], capture_output=True, text=True, timeout=5).stdout
            if "-var" not in help_output:
                supported_flag = "-V"
        except Exception as e:
            print(f"Error detecting supported flag for variables: {e}")
            supported_flag = "-V"  # Default to '-V' if detection fails

        for key, value in variables.items():
            cmd.extend([supported_flag, f"{key}={value}"])
    if rate_limit:
        cmd.extend(["-rate-limit", str(rate_limit)])
    if timeout:
        cmd.extend(["-timeout", str(timeout)])
    
    # Add any additional arguments
    if additional_args:
        cmd.extend(additional_args)

    # Run with retry for better resilience
    success = run_cmd(cmd, retry=1)
    if not success:
        print("Failed to execute Nuclei. Please check the parameters and try again.")
        return False
    
    return True

def update_nuclei_templates():
    """Update Nuclei templates to the latest version."""
    print("Updating Nuclei templates...")
    return run_cmd(["nuclei", "-update-templates"])

def parse_nuclei_results(output_file, jsonl_format=False):
    """
    Parse Nuclei results from an output file.
    
    Parameters:
        output_file (str): Path to the Nuclei output file.
        jsonl_format (bool): Whether the output is in JSONL format.
        
    Returns:
        list: Parsed results or None if parsing failed.
    """
    if not os.path.isfile(output_file):
        print(f"Error: Output file '{output_file}' not found.")
        return None
    
    try:
        with open(output_file, 'r') as f:
            if jsonl_format:
                # For JSONL, read line by line
                results = []
                for line in f:
                    if line.strip():
                        results.append(json.loads(line))
                return results
            else:
                # Simple line-by-line parsing for text format
                return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error parsing Nuclei results: {e}")
        return None

def check_nuclei():
    """
    Check if nuclei is installed and available in the PATH.
    
    Returns:
        bool: True if nuclei is installed and working, False otherwise.
    """
    nuclei_path = get_executable_path("nuclei")
    if not nuclei_path:
        print("nuclei not found in PATH or in ~/go/bin.")
        return False
        
    try:
        # Try running a simple command to check if nuclei is working
        result = subprocess.run([nuclei_path, "-version"], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        
        if result.returncode == 0:
            print(f"nuclei is available: {result.stdout.strip()}")
            return True
        else:
            print("nuclei is installed but not working correctly.")
            return False
    except Exception as e:
        print(f"Error checking nuclei: {e}")
        return False

def get_nuclei_capabilities():
    """Get information about nuclei capabilities based on its installation."""
    capabilities = {
        "version": "unknown",
        "templates_count": 0,
        "features": []
    }
    
    try:
        # Get version
        version_output = subprocess.run(["nuclei", "--version"], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=5).stdout
        
        if version_output:
            capabilities["version"] = version_output.strip()
        
        # Get installed templates count
        templates_output = subprocess.run(["nuclei", "-tl"], 
                                        capture_output=True, 
                                        text=True, 
                                        timeout=10).stdout
        
        if templates_output:
            # Try to count templates
            try:
                templates_lines = templates_output.strip().split('\n')
                capabilities["templates_count"] = len(templates_lines)
            except:
                pass
        
        # Check for advanced features
        help_output = subprocess.run(["nuclei", "-h"], 
                                   capture_output=True, 
                                   text=True, 
                                   timeout=5).stdout
        
        features = []
        if "-headless" in help_output:
            features.append("headless")
        if "-fuzzing" in help_output:
            features.append("fuzzing")
        if "-system-resolvers" in help_output:
            features.append("system-resolvers")
        if "-stats" in help_output:
            features.append("stats")
            
        capabilities["features"] = features
        return capabilities
    except Exception as e:
        print(f"Error getting nuclei capabilities: {e}")
        return capabilities

def auto_install_nuclei():
    """
    Automatically install Nuclei vulnerability scanner on Linux systems.
    
    Returns:
        bool: True if installation was successful, False otherwise.
    """
    print("🔧 Starting automatic installation of Nuclei...")
    
    # Check if already installed and working
    if check_nuclei():
        print("✅ Nuclei is already installed and working!")
        return True
    
    # Check if Go is installed
    if not shutil.which("go"):
        print("❌ Go is not installed. Please install Go first.")
        print("   You can use the scripts/autoinstall.py script to install Go automatically.")
        return False
    
    try:
        print("📦 Installing Nuclei using Go...")
        
        # Install nuclei using go install
        cmd = ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"❌ Failed to install Nuclei: {result.stderr}")
            # Try alternative installation command for older versions
            print("🔄 Trying alternative installation method...")
            cmd = ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                print(f"❌ Alternative installation also failed: {result.stderr}")
                return False
        
        print("✅ Nuclei installed successfully!")
        
        # Verify installation
        if check_nuclei():
            print("✅ Nuclei installation verified and working!")
            
            # Add ~/go/bin to PATH if not already there
            go_bin_path = os.path.expanduser("~/go/bin")
            current_path = os.environ.get("PATH", "")
            if go_bin_path not in current_path:
                os.environ["PATH"] = f"{go_bin_path}:{current_path}"
                print(f"📝 Added {go_bin_path} to PATH for this session")
            
            # Update nuclei templates
            print("📋 Updating Nuclei templates...")
            update_nuclei_templates()
            
            return True
        else:
            print("❌ Nuclei installation completed but verification failed")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Installation timed out. Please check your internet connection.")
        return False
    except Exception as e:
        print(f"❌ Error during installation: {e}")
        return False