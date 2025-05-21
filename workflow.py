#!/usr/bin/env python3
"""
workflow.py - Automated vulnerability scanning workflow.
This script orchestrates the complete workflow using naabu, httpx, and nuclei tools.
"""

import os
import sys
import argparse
import datetime
import json
import time
import signal
from pathlib import Path
import traceback
from typing import Optional, Dict, List, Any, Union, Tuple
from commands import naabu, httpx, nuclei
from utils import run_cmd, check_network, create_directory_if_not_exists, get_executable_path

# Create commands directory if it doesn't exist
commands_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "commands")
if not os.path.exists(commands_dir):
    os.makedirs(commands_dir, exist_ok=True)
    # Create __init__.py if it doesn't exist
    init_path = os.path.join(commands_dir, "__init__.py")
    if not os.path.exists(init_path):
        with open(init_path, "w") as f:
            f.write('# This file makes the commands directory a proper Python package\n')

# Try to import reporter if available
try:
    from reporter import generate_report
    REPORTER_AVAILABLE = True
except ImportError:
    REPORTER_AVAILABLE = False
    print("Reporter module not found. Basic reports will be generated.")

def create_output_directory(target_name: str) -> Optional[str]:
    """Create a timestamped output directory."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"results_{target_name}_{timestamp}"
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    except Exception as e:
        print(f"Error creating output directory: {e}")
        return None

def signal_handler(sig, frame):
    """Handle CTRL+C gracefully."""
    print("\n[!] Scan interrupted by user. Partial results may be available.")
    sys.exit(130)  # Standard exit code for SIGINT

def run_full_scan(target: str, output_dir: str, ports: Optional[str] = None, 
                 templates: Optional[str] = None, tags: str = "cve", 
                 severity: str = "critical,high", verbose: bool = False, 
                 timeout: int = 3600) -> bool:
    """
    Run the complete vulnerability scanning workflow with robust error handling.
    
    Parameters:
        target (str): Target to scan (IP or domain).
        output_dir (str): Directory to save all results.
        ports (str): Ports to scan with naabu.
        templates (str): Templates to use with nuclei.
        tags (str): Tags to use with nuclei.
        severity (str): Severity filter for nuclei.
        verbose (bool): Display verbose output.
        timeout (int): Maximum time for the full scan in seconds.
    
    Returns:
        bool: True if workflow completed successfully, False otherwise.
    """
    print(f"[+] Starting full scan on {target}")
    print(f"[+] Results will be saved to {output_dir}")
    
    success = True
    start_time = time.time()
    
    try:
        # Step 1: Port scanning with naabu
        print("\n[+] Step 1: Port scanning with naabu")
        ports_output = os.path.join(output_dir, "ports.txt")
        ports_json = os.path.join(output_dir, "ports.json")
        
        # Check if naabu is installed and get its capabilities
        naabu_capabilities = naabu.get_naabu_capabilities()
        naabu_args = ["--json", "-o", ports_json]
        
        # Check if naabu is installed
        naabu_path = get_executable_path("naabu")
        if not naabu_path:
            print("[!] Naabu not found in PATH. Checking for alternative installation...")
            # Try with go/bin path
            naabu_path = os.path.expanduser("~/go/bin/naabu")
            if not os.path.exists(naabu_path):
                print("[!] Naabu not installed. Please install it first.")
                return False
            
        # If SYN scan is available, use it for better performance
        if naabu_capabilities.get("scan_types") and "SYN" in naabu_capabilities.get("scan_types", []):
            naabu_args.extend(["--scan-type", "SYN"])
        
        naabu_success = naabu.run_naabu(
            target=target,
            ports=ports or "top-1000",
            output_file=ports_output,
            json_output=True,
            silent=not verbose,
            additional_args=naabu_args
        )
        
        if not naabu_success:
            print("[!] Naabu port scan had issues. Continuing with available results.")
            success = False
        else:
            print(f"[+] Port scan results saved to {ports_output}")
            
            # Check if scan timeout is approaching
            if time.time() - start_time > timeout * 0.3:  # Using 30% of total time
                print("[!] Port scanning took longer than expected. Adjusting remaining steps.")
        
        # Continue only if ports file exists and is not empty
        if not os.path.exists(ports_output) or os.path.getsize(ports_output) == 0:
            print("[!] No ports found or ports file is empty. Creating a default one with common ports.")
            with open(ports_output, "w") as f:
                f.write(f"{target}:80\n{target}:443\n")
        
        # Step 2: HTTP service detection with httpx
        print("\n[+] Step 2: HTTP service detection with httpx")
        http_output = os.path.join(output_dir, "http_services.txt")
        http_json = os.path.join(output_dir, "http_services.json")
        
        # Check if httpx is installed
        httpx_path = get_executable_path("httpx")
        if not httpx_path:
            print("[!] httpx not found in PATH. Checking for alternative installation...")
            # Try with go/bin path
            httpx_path = os.path.expanduser("~/go/bin/httpx")
            if not os.path.exists(httpx_path):
                print("[!] httpx not installed. Please install it first.")
                success = False
                # Continue with a basic default for the next step
                with open(http_output, "w") as f:
                    f.write(f"http://{target}\nhttps://{target}\n")
        else:
            httpx_success = httpx.run_httpx(
                target_list=ports_output,
                output_file=http_output,
                title=True,
                status_code=True,
                tech_detect=True,
                web_server=True,
                follow_redirects=True,
                silent=not verbose,
                additional_args=["--json", "-o", http_json]
            )
            
            if not httpx_success:
                print("[!] HTTPX service detection had issues. Continuing with available results.")
                success = False
            else:
                print(f"[+] HTTP service detection results saved to {http_output}")
                
                # Check if scan timeout is approaching
                if time.time() - start_time > timeout * 0.6:  # Using 60% of total time
                    print("[!] HTTP service detection took longer than expected. Adjusting remaining steps.")
        
        # Continue only if http file exists and is not empty
        if not os.path.exists(http_output) or os.path.getsize(http_output) == 0:
            print("[!] No HTTP services found or services file is empty. Creating a default one.")
            with open(http_output, "w") as f:
                f.write(f"http://{target}\nhttps://{target}\n")
        
        # Step 3: Vulnerability scanning with nuclei
        print("\n[+] Step 3: Vulnerability scanning with nuclei")
        vuln_output = os.path.join(output_dir, "vulnerabilities.txt")
        vuln_json = os.path.join(output_dir, "vulnerabilities.jsonl")
        
        # Check if nuclei is installed
        nuclei_path = get_executable_path("nuclei")
        if not nuclei_path:
            print("[!] nuclei not found in PATH. Checking for alternative installation...")
            # Try with go/bin path
            nuclei_path = os.path.expanduser("~/go/bin/nuclei")
            if not os.path.exists(nuclei_path):
                print("[!] nuclei not installed. Please install it first.")
                success = False
                # Create an empty file for consistency
                with open(vuln_output, "w") as f:
                    f.write("# No vulnerabilities scanned - nuclei not installed\n")
        else:
            # Create output directory for storing responses
            nuclei_resp_dir = os.path.join(output_dir, "nuclei_responses")
            create_directory_if_not_exists(nuclei_resp_dir)
            
            # Determine if we need to adjust scanning due to time constraints
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time < timeout * 0.3:  # Less than 30% of time remaining
                print("[!] Limited time remaining for vulnerability scanning. Using focused scan.")
                # Use a more focused scan if time is limited
                if templates is None:
                    templates = "cves"  # Only scan for CVEs
                if tags is None or tags == "cve":
                    tags = "cve,rce,critical" # Focus on critical issues
                severity = "critical,high"    # Focus on high severity
            
            # Prepare nuclei arguments
            nuclei_args = [
                "-jsonl", 
                "-o", vuln_json, 
                "-irr", 
                "-stats", 
                "-me", nuclei_resp_dir
            ]
            
            # If time is very limited, add rate limiting to avoid overwhelming the target
            if remaining_time < timeout * 0.2:
                nuclei_args.extend(["-rate-limit", "50"])
            
            nuclei_success = nuclei.run_nuclei(
                target_list=http_output,
                templates=templates,
                tags=tags,
                severity=severity,
                output_file=vuln_output,
                jsonl=True,
                store_resp=True,
                silent=not verbose,
                additional_args=nuclei_args
            )
            
            if not nuclei_success:
                print("[!] Nuclei vulnerability scan had issues.")
                success = False
            else:
                print(f"[+] Vulnerability scan results saved to {vuln_output}")
        
        # Step 4: Generate summary report
        print("\n[+] Step 4: Generating summary report")
        
        if REPORTER_AVAILABLE:
            summary_success = generate_report(output_dir, target)
            if not summary_success:
                print("[!] Advanced report generation had issues. Falling back to basic summary.")
                summary_success = generate_basic_summary_report(output_dir, target)
        else:
            summary_success = generate_basic_summary_report(output_dir, target)
        
        if not summary_success:
            print("[!] Summary report generation had issues.")
            success = False
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        success = False
    except Exception as e:
        print(f"\n[!] Error during scan: {str(e)}")
        if verbose:
            traceback.print_exc()
        success = False
    finally:
        # Always create at least a basic report if we have results
        if os.path.exists(output_dir) and not os.path.exists(os.path.join(output_dir, "summary.txt")):
            try:
                generate_basic_summary_report(output_dir, target)
            except Exception as e:
                if verbose:
                    print(f"[!] Could not create basic report: {e}")
    
    elapsed_time = time.time() - start_time
    print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds ({elapsed_time/60:.2f} minutes)")
    
    if success:
        print("\n[+] Full scan completed successfully!")
    else:
        print("\n[+] Full scan completed with some issues.")
    
    print(f"[+] All results saved to {output_dir}")
    return success

def generate_basic_summary_report(output_dir: str, target: str) -> bool:
    """Generate a basic summary report of all findings."""
    summary_file = os.path.join(output_dir, "summary.txt")
    
    try:
        # Gather statistics
        ports_json = os.path.join(output_dir, "ports.json")
        http_json = os.path.join(output_dir, "http_services.json")
        vuln_json = os.path.join(output_dir, "vulnerabilities.jsonl")
        
        port_count = 0
        http_count = 0
        vuln_count = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        # Count open ports
        if os.path.exists(ports_json):
            try:
                with open(ports_json, 'r') as f:
                    for line in f:
                        if line.strip():
                            port_count += 1
            except Exception as e:
                print(f"[!] Warning: Could not parse ports JSON: {e}")
        
        # Count HTTP services
        if os.path.exists(http_json):
            try:
                with open(http_json, 'r') as f:
                    for line in f:
                        if line.strip():
                            http_count += 1
            except Exception as e:
                print(f"[!] Warning: Could not parse HTTP services JSON: {e}")
        
        # Count vulnerabilities by severity
        if os.path.exists(vuln_json):
            try:
                with open(vuln_json, 'r') as f:
                    for line in f:
                        if line.strip():
                            vuln_count += 1
                            try:
                                data = json.loads(line)
                                severity = data.get("info", {}).get("severity", "").lower()
                                if severity == "critical":
                                    critical_count += 1
                                elif severity == "high":
                                    high_count += 1
                                elif severity == "medium":
                                    medium_count += 1
                                elif severity == "low":
                                    low_count += 1
                            except json.JSONDecodeError:
                                pass
            except Exception as e:
                print(f"[!] Warning: Could not parse vulnerabilities JSONL: {e}")
        
        # Write the summary report
        with open(summary_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write(f"VULNERABILITY SCAN SUMMARY FOR {target}\n")
            f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("FINDINGS SUMMARY:\n")
            f.write(f"Open ports detected: {port_count}\n")
            f.write(f"HTTP services detected: {http_count}\n")
            f.write(f"Total vulnerabilities found: {vuln_count}\n")
            f.write(f"  - Critical severity: {critical_count}\n")
            f.write(f"  - High severity: {high_count}\n")
            f.write(f"  - Medium severity: {medium_count}\n")
            f.write(f"  - Low severity: {low_count}\n\n")
            
            # Add recommendation based on findings
            if critical_count > 0 or high_count > 0:
                f.write("RECOMMENDATIONS:\n")
                f.write("The scan detected critical/high severity vulnerabilities that require immediate attention!\n")
                f.write("Please review the detailed findings in the 'vulnerabilities.txt' file and take appropriate remediation steps.\n\n")
            
            f.write("FILES OVERVIEW:\n")
            f.write("- ports.txt: List of open ports\n")
            f.write("- http_services.txt: Detected HTTP services\n")
            f.write("- vulnerabilities.txt: Detailed vulnerability findings\n")
            f.write("- nuclei_responses/: Directory containing HTTP requests/responses for detected vulnerabilities\n\n")
            
            f.write("=" * 60 + "\n")
            f.write("End of Summary Report\n")
        
        print(f"[+] Summary report generated: {summary_file}")
        return True
    except Exception as e:
        print(f"[-] Error generating summary report: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Automated vulnerability scanning workflow')
    parser.add_argument('target', help='Target to scan (IP or domain)')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80,443,8000-9000)')
    parser.add_argument('-t', '--templates', help='Custom nuclei templates (default: uses built-in templates)')
    parser.add_argument('--tags', default='cve', help='Nuclei template tags (default: cve)')
    parser.add_argument('--severity', default='critical,high', help='Vulnerability severity filter (default: critical,high)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output-dir', help='Custom output directory')
    parser.add_argument('--update-templates', action='store_true', help='Update nuclei templates before scanning')
    parser.add_argument('--timeout', type=int, default=3600, help='Maximum scan time in seconds (default: 3600)')
    parser.add_argument('--report-only', help='Generate report for existing results directory')
    
    args = parser.parse_args()
    
    # Set up signal handler for graceful exit on CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # If only generating a report for existing results
    if args.report_only:
        if not os.path.isdir(args.report_only):
            print(f"[-] Results directory not found: {args.report_only}")
            sys.exit(1)
        
        print(f"[+] Generating report for existing results in {args.report_only}")
        
        if REPORTER_AVAILABLE:
            success = generate_report(args.report_only, args.target)
            if success:
                print("[+] Report generated successfully!")
                sys.exit(0)
            else:
                print("[-] Report generation failed.")
                sys.exit(1)
        else:
            success = generate_basic_summary_report(args.report_only, args.target)
            if success:
                print("[+] Basic summary report generated successfully!")
                sys.exit(0)
            else:
                print("[-] Report generation failed.")
                sys.exit(1)
    
    # Check network connectivity
    if not check_network():
        print("[-] No network connectivity. Please check your connection and try again.")
        sys.exit(1)
      # Check if required tools are installed
    tool_checks = []
    
    print("[+] Checking required tools...")
    
    # Check naabu
    naabu_ok = naabu.check_naabu()
    tool_checks.append(naabu_ok)
    
    # Check httpx
    httpx_ok = httpx.check_httpx()
    tool_checks.append(httpx_ok)
    
    # Check nuclei
    nuclei_ok = nuclei.check_nuclei()
    tool_checks.append(nuclei_ok)
    
    if not all(tool_checks):
        print("[-] One or more required tools are not installed.")
        print("[*] Please run the setup script: ./setup_tools.sh")
        sys.exit(1)
    
    print("[+] All required tools are installed.")
    
    # Update nuclei templates if requested
    if args.update_templates:
        print("[+] Updating nuclei templates...")
        if not nuclei.update_nuclei_templates():
            print("[-] Failed to update nuclei templates. Continuing with existing templates.")
    
    # Create output directory
    output_dir = args.output_dir
    if not output_dir:
        target_name = args.target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
        output_dir = create_output_directory(target_name)
    
    if not output_dir:
        print("[-] Failed to create output directory. Exiting.")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    if not create_directory_if_not_exists(output_dir):
        print("[-] Failed to create output directory. Exiting.")
        sys.exit(1)
    
    # Run the full scan
    try:
        success = run_full_scan(
            target=args.target,
            output_dir=output_dir,
            ports=args.ports,
            templates=args.templates,
            tags=args.tags,
            severity=args.severity,
            verbose=args.verbose,
            timeout=args.timeout
        )
        
        if not success:
            print("[-] Scan workflow completed with some issues. Review the output for details.")
            sys.exit(2)  # Use exit code 2 to indicate partial success
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user. Partial results may be available in the output directory.")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        print(f"[-] An unexpected error occurred: {str(e)}")
        sys.exit(1)
    
    print("[+] Scan completed successfully!")
    sys.exit(0)

if __name__ == "__main__":
    main()