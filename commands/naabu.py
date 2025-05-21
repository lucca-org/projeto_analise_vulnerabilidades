#!/usr/bin/env python3
import os
import json
import subprocess
from utils import run_cmd

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
        rate (int): Number of packets per second.
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
    
    # Check if this is a CGO-disabled version and add connect flag if needed
    try:
        naabu_help_output = subprocess.run(["naabu", "-h"], capture_output=True, text=True).stdout
        # If this is a CGO-disabled naabu, it can only use connect scan mode
        if "-scan-type" in naabu_help_output and "--connect" not in cmd and "-connect" not in cmd:
            if "--so" not in cmd and "-so" not in cmd and "--syn" not in cmd and "-syn" not in cmd:
                cmd.append("-scan-type")
                cmd.append("connect")
                print("Note: Using connect scan mode since this is likely a CGO-disabled Naabu build")
    except Exception as e:
        print(f"Warning: Could not detect Naabu capabilities: {e}")

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
    """Check if Naabu is installed."""
    try:
        result = run_cmd(["naabu", "-version"], retry=0)
        return result
    except:
        return False

def get_naabu_capabilities():
    """Get information about naabu capabilities based on its installation."""
    capabilities = {
        "version": None,
        "scan_types": [],
        "is_cgo_enabled": False
    }
    
    try:
        # Get version
        process = subprocess.run(["naabu", "-version"], capture_output=True, text=True)
        if process.returncode == 0 and process.stdout:
            capabilities["version"] = process.stdout.strip()
        
        # Check if SYN scan is available (requires CGO)
        process = subprocess.run(["naabu", "-h"], capture_output=True, text=True)
        if process.returncode == 0 and process.stdout:
            help_text = process.stdout
            
            # Check scan types
            if "-scan-type" in help_text:
                for line in help_text.split("\n"):
                    if "-scan-type" in line:
                        types_part = line.split("-scan-type", 1)[1]
                        if "SYN" in types_part:
                            capabilities["scan_types"].append("SYN")
                            capabilities["is_cgo_enabled"] = True
                        if "CONNECT" in types_part:
                            capabilities["scan_types"].append("CONNECT")
    except Exception as e:
        print(f"Error checking Naabu capabilities: {e}")
    
    return capabilities