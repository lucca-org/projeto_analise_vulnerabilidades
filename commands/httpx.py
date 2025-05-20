import os
import json
import subprocess
from utils import run_cmd

def run_httpx(target=None, target_list=None, output_file=None, json_output=False,
             title=False, status_code=False, tech_detect=False, web_server=False,
             follow_redirects=False, silent=False, timeout=None, threads=None,
             additional_args=None):
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
        
    Returns:
        bool: True if execution was successful, False otherwise.
    """
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
    
    cmd = ["httpx"]
    
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
    """Check if HTTPX is installed."""
    try:
        result = run_cmd(["httpx", "-version"], retry=0)
        return result
    except:
        return False

def get_httpx_capabilities():
    """Get information about HTTPX capabilities based on its installation."""
    capabilities = {
        "version": None,
        "available_flags": []
    }
    
    try:
        # Get version
        process = subprocess.run(["httpx", "-version"], capture_output=True, text=True)
        if process.returncode == 0 and process.stdout:
            capabilities["version"] = process.stdout.strip()
        
        # Get help to determine available flags
        process = subprocess.run(["httpx", "-h"], capture_output=True, text=True)
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