from utils import run_cmd
import os
import json

def run_nuclei(target=None, target_list=None, templates=None, tags=None, severity=None,
              output_file=None, jsonl=False, silent=False, store_resp=False, 
              headers=None, variables=None, rate_limit=None, timeout=None, additional_args=None):
    """
    Run Nuclei vulnerability scanner with the specified parameters.
    
    Parameters:
        target (str): Single target to scan.
        target_list (str): Path to a file containing targets.
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
        
    Returns:
        bool: True if execution was successful, False otherwise.
    """
    if not target and not target_list:
        print("Error: Either target or target_list must be specified.")
        return False
    
    if target_list and not os.path.isfile(target_list):
        print(f"Error: Target list file '{target_list}' not found.")
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
        for key, value in variables.items():
            # Check if '-var' is supported, otherwise use '-V'
            try:
                if run_cmd(["nuclei", "-h"]).find("-var") != -1:
                    cmd.extend(["-var", f"{key}={value}"])
                else:
                    cmd.extend(["-V", f"{key}={value}"])
            except Exception as e:
                print(f"Error checking Nuclei flags: {e}")
                return False
    if rate_limit:
        cmd.extend(["-rate-limit", str(rate_limit)])
    if timeout:
        cmd.extend(["-timeout", str(timeout)])
    
    # Add any additional arguments
    if additional_args:
        cmd.extend(additional_args)

    success = run_cmd(cmd)
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
    """Check if Nuclei is installed."""
    return run_cmd(["nuclei", "--version"])