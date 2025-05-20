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
from commands import naabu, httpx, nuclei
from utils import run_cmd, check_network

def create_output_directory(target_name):
    """Create a timestamped output directory."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"results_{target_name}_{timestamp}"
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    except Exception as e:
        print(f"Error creating output directory: {e}")
        return None

def run_full_scan(target, output_dir, ports=None, templates=None, tags="cve", 
                 severity="critical,high", verbose=False):
    """
    Run the complete vulnerability scanning workflow.
    
    Parameters:
        target (str): Target to scan (IP or domain).
        output_dir (str): Directory to save all results.
        ports (str): Ports to scan with naabu.
        templates (str): Templates to use with nuclei.
        tags (str): Tags to use with nuclei.
        severity (str): Severity filter for nuclei.
        verbose (bool): Display verbose output.
    
    Returns:
        bool: True if workflow completed successfully, False otherwise.
    """
    print(f"[+] Starting full scan on {target}")
    print(f"[+] Results will be saved to {output_dir}")
    
    # Step 1: Port scanning with naabu
    print("\n[+] Step 1: Port scanning with naabu")
    ports_output = os.path.join(output_dir, "ports.txt")
    ports_json = os.path.join(output_dir, "ports.json")
    
    if not naabu.run_naabu(
        target=target,
        ports=ports or "top-1000",
        output_file=ports_output,
        json_output=True,
        silent=not verbose,
        additional_args=["-json", "-o", ports_json]
    ):
        print("[-] Naabu port scan failed. Exiting.")
        return False
    
    print(f"[+] Port scan results saved to {ports_output}")
    
    # Step 2: HTTP service detection with httpx
    print("\n[+] Step 2: HTTP service detection with httpx")
    http_output = os.path.join(output_dir, "http_services.txt")
    http_json = os.path.join(output_dir, "http_services.json")
    
    if not httpx.run_httpx(
        target_list=ports_output,
        output_file=http_output,
        title=True,
        status_code=True,
        tech_detect=True,
        web_server=True,
        follow_redirects=True,
        silent=not verbose,
        additional_args=["-json", "-o", http_json]
    ):
        print("[-] HTTPX service detection failed. Exiting.")
        return False
    
    print(f"[+] HTTP service detection results saved to {http_output}")
    
    # Step 3: Vulnerability scanning with nuclei
    print("\n[+] Step 3: Vulnerability scanning with nuclei")
    vuln_output = os.path.join(output_dir, "vulnerabilities.txt")
    vuln_json = os.path.join(output_dir, "vulnerabilities.jsonl")
    
    # Create output directory for storing responses
    nuclei_resp_dir = os.path.join(output_dir, "nuclei_responses")
    os.makedirs(nuclei_resp_dir, exist_ok=True)
    
    if not nuclei.run_nuclei(
        target_list=http_output,
        templates=templates,
        tags=tags,
        severity=severity,
        output_file=vuln_output,
        jsonl=True,
        store_resp=True,
        silent=not verbose,
        additional_args=["-jsonl", "-o", vuln_json, "-irr", "-stats", "-me", nuclei_resp_dir]
    ):
        print("[-] Nuclei vulnerability scan failed.")
        # Continue anyway since we might have partial results
    
    print(f"[+] Vulnerability scan results saved to {vuln_output}")
    
    # Step 4: Generate summary report
    print("\n[+] Step 4: Generating summary report")
    generate_summary_report(output_dir, target)
    
    print("\n[+] Full scan completed successfully!")
    print(f"[+] All results saved to {output_dir}")
    return True

def generate_summary_report(output_dir, target):
    """Generate a summary report of all findings."""
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
            except:
                pass
        
        # Count HTTP services
        if os.path.exists(http_json):
            try:
                with open(http_json, 'r') as f:
                    for line in f:
                        if line.strip():
                            http_count += 1
            except:
                pass
        
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
                            except:
                                pass
            except:
                pass
        
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
            f.write(f"- ports.txt: List of open ports\n")
            f.write(f"- http_services.txt: Detected HTTP services\n")
            f.write(f"- vulnerabilities.txt: Detailed vulnerability findings\n")
            f.write(f"- nuclei_responses/: Directory containing HTTP requests/responses for detected vulnerabilities\n\n")
            
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
    
    args = parser.parse_args()
    
    # Check network connectivity
    if not check_network():
        print("[-] No network connectivity. Please check your connection and try again.")
        sys.exit(1)
    
    # Create output directory
    output_dir = args.output_dir
    if not output_dir:
        target_name = args.target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
        output_dir = create_output_directory(target_name)
    
    if not output_dir:
        print("[-] Failed to create output directory. Exiting.")
        sys.exit(1)
    
    # Run the full scan
    success = run_full_scan(
        target=args.target,
        output_dir=output_dir,
        ports=args.ports,
        templates=args.templates,
        tags=args.tags,
        severity=args.severity,
        verbose=args.verbose
    )
    
    if not success:
        print("[-] Scan workflow completed with errors. Please check the output logs.")
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    main()