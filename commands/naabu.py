from utils import run_cmd
import os
import json

def run_naabu(target=None, target_list=None, ports=None, exclude_ports=None, 
             threads=None, rate=None, timeout=None, json_output=False, 
             output_file=None, silent=False, additional_args=None):
    """
    Run Naabu port scanner with the specified parameters.
    
    Parameters:
        target (str): Single target to scan.
        target_list (str): Path to a file containing targets.
        ports (str): Ports to scan (e.g., "80,443,8080-8090").
        exclude_ports (str): Ports to exclude from scan.
        threads (int): Number of concurrent threads.
        rate (int): Number of packets per second to send.
        timeout (int): Timeout in milliseconds.
        json_output (bool): Output in JSON format.
        output_file (str): Path to save the output.
        silent (bool): Run in silent mode.
        additional_args (list): Additional naabu arguments.
        
    Returns:
        bool: True if execution was successful, False otherwise.
    """
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

    success = run_cmd(cmd)
    if not success:
        print("Failed to execute Naabu. Please check the parameters and try again.")
        return False
    
    return True

def parse_naabu_results(output_file, json_format=False):
    """
    Parse Naabu results from an output file.
    
    Parameters:
        output_file (str): Path to the Naabu output file.
        json_format (bool): Whether the output is in JSON format.
        
    Returns:
        dict or list: Parsed results or None if parsing failed.
    """
    if not os.path.isfile(output_file):
        print(f"Error: Output file '{output_file}' not found.")
        return None
    
    try:
        with open(output_file, 'r') as f:
            if json_format:
                # For JSON, read line by line as it might be in JSON Lines format
                results = []
                for line in f:
                    if line.strip():
                        results.append(json.loads(line))
                return results
            else:
                # Simple line-by-line parsing for text format
                return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error parsing Naabu results: {e}")
        return None

def check_naabu():
    """Check if Naabu is installed."""
    return run_cmd(["naabu", "--version"])