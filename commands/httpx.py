from utils import run_cmd
import os
import json

def run_httpx(target_list, silent=False, output_file=None, output_format="txt", title=False, 
             status_code=False, tech_detect=False, web_server=False, follow_redirects=False, 
             additional_args=None):
    """
    Run httpx with the specified parameters.
    
    Parameters:
        target_list (str): Path to a file containing target URLs or IPs.
        silent (bool): Run httpx in silent mode.
        output_file (str): Path to save the output.
        output_format (str): Format to save the output (txt, json, csv).
        title (bool): Display page title.
        status_code (bool): Display status code.
        tech_detect (bool): Detect web technologies.
        web_server (bool): Display web server name.
        follow_redirects (bool): Follow HTTP redirects.
        additional_args (list): Additional httpx arguments.
        
    Returns:
        bool: True if execution was successful, False otherwise.
    """
    if not os.path.isfile(target_list):
        print(f"Error: Target list file '{target_list}' not found.")
        return False
    
    cmd = ["httpx", "-l", target_list]

    if silent:
        cmd.append("-silent")
    if output_file:
        cmd.extend(["-o", output_file])
        # Set output format if specified
        if output_format.lower() in ["json", "csv"]:
            cmd.append(f"-{output_format.lower()}")
    if title:
        cmd.append("-title")
    if status_code:
        cmd.append("-sc")
    if tech_detect:
        cmd.append("-tech-detect")
    if web_server:
        cmd.append("-web-server")
    if follow_redirects:
        cmd.append("-follow-redirects")
    
    # Add any additional arguments
    if additional_args:
        cmd.extend(additional_args)

    success = run_cmd(cmd)
    if not success:
        print("Failed to execute httpx. Please check the parameters and try again.")
        return False
    
    return True

def parse_httpx_results(output_file, output_format="txt"):
    """
    Parse httpx results from an output file.
    
    Parameters:
        output_file (str): Path to the httpx output file.
        output_format (str): Format of the output file (txt, json, csv).
        
    Returns:
        list: Parsed results or None if parsing failed.
    """
    if not os.path.isfile(output_file):
        print(f"Error: Output file '{output_file}' not found.")
        return None
    
    try:
        with open(output_file, 'r') as f:
            if output_format.lower() == "json":
                # For JSON, read line by line as it might be in JSON Lines format
                results = []
                for line in f:
                    if line.strip():
                        results.append(json.loads(line))
                return results
            elif output_format.lower() == "csv":
                # Simple CSV parsing
                import csv
                results = []
                reader = csv.DictReader(f)
                for row in reader:
                    results.append(row)
                return results
            else:  # Default txt format
                # Simple line-by-line parsing for text format
                return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error parsing httpx results: {e}")
        return None

def check_httpx():
    """Check if httpx is installed."""
    return run_cmd(["httpx", "--version"])