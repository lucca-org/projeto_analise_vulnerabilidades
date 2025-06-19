import os
import sys
import json
import subprocess
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

def run_nuclei(target=None, target_list=None, templates=None, tags=None, severity=None,
              output_file=None, jsonl=False, save_output=False, tool_silent=False, store_resp=False, 
              headers=None, variables=None, rate_limit=None, timeout=None, 
              additional_args=None, auto_install=True):
    """
    Run Nuclei vulnerability scanner with the specified parameters.
    Real-time output is ALWAYS shown to the user.
    
    Parameters:
        target (str): Single target to scan.
        target_list (str): Path to a file containing targets or a URL string.
        templates (str): Custom templates or template directory.
        tags (str): Tags to include templates by.
        severity (str): Filter templates by severity.
        output_file (str): Path to save the output (only used if save_output=True).
        jsonl (bool): Output in JSONL format when saving to file.
        save_output (bool): Save output to file (real-time output always shown).
        tool_silent (bool): Make nuclei tool itself run silently (no verbose headers).
        store_resp (bool): Store HTTP responses for matches.
        headers (str): Custom headers for HTTP requests.
        variables (str): Define variables for templates.
        rate_limit (int): Requests per second limit.
        timeout (int): Timeout for requests in seconds.
        additional_args (list): Additional command-line arguments.
        auto_install (bool): Whether to attempt auto-installation if nuclei is not found.
    
    Returns:
        bool: True if nuclei executed successfully, False otherwise.
    """
      # Get nuclei executable path
    nuclei_path = get_executable_path("nuclei")
    
    if not nuclei_path:
        if auto_install:
            print("Nuclei not found. Installing...")
            if install_nuclei():
                nuclei_path = get_executable_path("nuclei")
            
        if not nuclei_path:
            print("Error: Nuclei is not installed or not found in PATH")
            print("Please install nuclei manually or run the setup script.")
            return False
    
    # Build nuclei command
    cmd = [nuclei_path]
    
    # Add target parameters
    if target:
        cmd.extend(["-u", target])
    elif target_list:
        if target_list.startswith(('http://', 'https://')):
            # If target_list is a URL, use it directly as target
            cmd.extend(["-u", target_list])
        else:
            # If target_list is a file path
            if os.path.exists(target_list):
                cmd.extend(["-l", target_list])
            else:
                print(f"Error: Target list file not found: {target_list}")
                return False
    else:
        print("Error: Either target or target_list must be specified")
        return False
      # Add template parameters
    if templates:
        if os.path.exists(templates):
            cmd.extend(["-t", templates])
        else:
            # Could be a template name or tag
            cmd.extend(["-t", templates])
    
    if tags:
        cmd.extend(["-tags", tags])
    
    if severity:
        cmd.extend(["-s", severity])  # Use short flag for severity
    
    # Output configuration - ALWAYS show real-time, optionally save to fileif save_output and output_file:
        cmd.extend(["-o", output_file])
        if jsonl:
            cmd.append("-jsonl")
        print(f"Output will be saved to: {output_file}")
    
    # Tool behavior options
    if tool_silent:
        cmd.append("-silent")  # Only suppress nuclei's verbose headers, not results
    
    if store_resp:
        cmd.append("-store-resp")
    
    # Request configuration
    if headers:
        cmd.extend(["-H", headers])
    
    if variables:
        cmd.extend(["-var", variables])
    
    if rate_limit:
        cmd.extend(["-rl", str(rate_limit)])
    
    if timeout:
        cmd.extend(["-timeout", str(timeout)])
    
    # Add additional arguments
    if additional_args:
        cmd.extend(additional_args)
      # Execute nuclei with real-time output
    print(f"Running: {' '.join(cmd)}")
    print("Real-time output: ENABLED")
    print("=" * 60)
    
    try:
        # Use run_cmd without silent flag to show real-time output
        result = run_cmd(cmd, timeout=timeout or 3600, check=False, silent=False)
        
        print("=" * 60)
        if result:
            print("Nuclei scan completed successfully!")
            if save_output and output_file:
                print(f"Results saved to: {output_file}")
        else:
            print("Nuclei scan failed or encountered issues.")
        
        return result
    except Exception as e:
        print(f"Error running nuclei: {e}")
        return False

def install_nuclei():
    """
    Install nuclei using go install.
    
    Returns:
        bool: True if installation was successful, False otherwise.
    """
    try:
        print("Installing nuclei...")
        install_cmd = ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"]
        
        result = run_cmd(install_cmd, timeout=300)
        if result:
            print("Nuclei installed successfully!")
            return True
        else:
            print("Failed to install nuclei using go install")
            return False
    except Exception as e:
        print(f"Error installing nuclei: {e}")
        return False

def nuclei_update_templates():
    """
    Update nuclei templates to latest version.
    
    Returns:
        bool: True if update was successful, False otherwise.
    """
    nuclei_path = get_executable_path("nuclei")
    
    if not nuclei_path:
        print("Error: Nuclei is not installed")
        return False
    
    try:
        print("Updating nuclei templates...")
        
        cmd = [nuclei_path, '-update-templates', '-silent']
        
        result = run_cmd(cmd, timeout=300, silent=False)  # Show update progress
        
        if result:
            print("Nuclei templates updated successfully!")
            return True
        else:
            print("Failed to update nuclei templates")
            print("You can update templates manually later with: nuclei -update-templates")
            return False
    except Exception as e:
        print(f"Error updating nuclei templates: {e}")
        print("You can update templates manually later with: nuclei -update-templates")
        return False

def get_nuclei_version():
    """
    Get the installed version of nuclei.
    
    Returns:
        str: Version string if successful, None otherwise.
    """
    nuclei_path = get_executable_path("nuclei")
    
    if not nuclei_path:
        return None
    
    try:
        cmd = [nuclei_path, "-version"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Extract version from output
            version_line = result.stdout.strip()
            return version_line
        else:
            return None
    except Exception:
        return None

def list_nuclei_templates(tags=None, severity=None):
    """
    List available nuclei templates.
    
    Parameters:
        tags (str): Filter templates by tags.
        severity (str): Filter templates by severity.
    
    Returns:
        bool: True if listing was successful, False otherwise.
    """
    nuclei_path = get_executable_path("nuclei")
    
    if not nuclei_path:
        print("Error: Nuclei is not installed")
        return False
    
    try:
        cmd = [nuclei_path, "-tl"]
        
        if tags:
            cmd.extend(["-tags", tags])
        
        if severity:
            cmd.extend(["-severity", severity])
        
        result = run_cmd(cmd, timeout=60, silent=False)  # Show template list
        return result
    except Exception as e:
        print(f"Error listing nuclei templates: {e}")
        return False

def check_nuclei():
    """
    Check if nuclei is available and working.
    
    Returns:
        bool: True if nuclei is available, False otherwise.
    """
    nuclei_path = get_executable_path("nuclei")
    if not nuclei_path:
        return False
    
    try:
        cmd = [nuclei_path, "-version"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False

def get_nuclei_capabilities():
    """
    Get nuclei capabilities and version information.
    
    Returns:
        dict: Dictionary containing nuclei capabilities.
    """
    capabilities = {
        "available": False,
        "version": None,
        "templates_updated": False,
        "installation_path": None
    }
    
    nuclei_path = get_executable_path("nuclei")
    if nuclei_path:
        capabilities["available"] = True
        capabilities["installation_path"] = nuclei_path
        
        # Get version
        version = get_nuclei_version()
        if version:
            capabilities["version"] = version
        
        # Check if templates directory exists (basic check)
        home_dir = os.path.expanduser("~")
        nuclei_templates_dir = os.path.join(home_dir, "nuclei-templates")
        if os.path.exists(nuclei_templates_dir):
            capabilities["templates_updated"] = True
    
    return capabilities

def update_nuclei_templates():
    """
    Update nuclei templates (alias for nuclei_update_templates).
    
    Returns:
        bool: True if update was successful, False otherwise.
    """
    return nuclei_update_templates()

# Convenience function for common scanning scenarios
def quick_nuclei_scan(target, output_file=None, severity="medium,high,critical", save_output=False):
    """
    Perform a quick nuclei scan with common settings.
    
    Parameters:
        target (str): Target to scan.
        output_file (str): Optional output file.
        severity (str): Severity filter for templates.
        save_output (bool): Whether to save output to file.
    
    Returns:
        bool: True if scan completed successfully, False otherwise.
    """
    return run_nuclei(
        target=target,
        severity=severity,
        output_file=output_file,
        jsonl=True if output_file else False,
        save_output=save_output,
        tool_silent=True
    )

if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description="Nuclei vulnerability scanner wrapper")
    parser.add_argument("-u", "--target", help="Target URL")
    parser.add_argument("-l", "--list", help="Target list file")
    parser.add_argument("-t", "--templates", help="Templates to use")
    parser.add_argument("--tags", help="Template tags")
    parser.add_argument("-s", "--severity", help="Severity filter")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--jsonl", action="store_true", help="JSONL output")
    parser.add_argument("--save-output", action="store_true", help="Save output to file")
    parser.add_argument("--tool-silent", action="store_true", help="Make nuclei tool run silently")
    parser.add_argument("--update", action="store_true", help="Update templates")
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--install", action="store_true", help="Install nuclei")
    
    args = parser.parse_args()
    
    if args.install:
        install_nuclei()
    elif args.update:
        nuclei_update_templates()
    elif args.version:
        version = get_nuclei_version()
        if version:
            print(version)
        else:
            print("Nuclei not found or version could not be determined")
    elif args.target or args.list:
        run_nuclei(
            target=args.target,
            target_list=args.list,
            templates=args.templates,
            tags=args.tags,
            severity=args.severity,
            output_file=args.output,
            jsonl=args.jsonl,
            save_output=args.save_output,
            tool_silent=args.tool_silent
        )
    else:
        parser.print_help()
