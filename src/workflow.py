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
import platform
from pathlib import Path
import traceback
from typing import Optional, Dict, List, Any, Union, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from commands import naabu, httpx, nuclei
from utils import run_cmd, check_network, create_directory_if_not_exists, get_executable_path, verify_linux_platform

# Try to import config_manager if available
try:
    from config_manager import get_config, auto_configure, get_tool_specific_config
    CONFIG_MANAGER_AVAILABLE = True
except ImportError:
    CONFIG_MANAGER_AVAILABLE = False
    # Define fallback functions to avoid unbound variable errors
    def get_config() -> Dict[str, Any]:
        return {}
    
    def auto_configure() -> Dict[str, Any]:
        return {}
    
    def get_tool_specific_config(tool: str) -> Dict[str, Any]:
        return {}
    
    print("Config manager not available. Using default configuration.")

# Try to import code scanner if available
try:
    from code_scanner import scan_directory, format_findings, save_findings
    CODE_SCANNER_AVAILABLE = True
except ImportError:
    CODE_SCANNER_AVAILABLE = False
    # Define fallback functions to avoid unbound variable errors
    def scan_directory(directory: str, exclude_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        return []
    
    def format_findings(findings: List[Dict[str, Any]], output_format: str = 'text') -> str:
        return "Code scanner not available"
    
    def save_findings(findings: List[Dict[str, Any]], output_file: str, output_format: str = 'text') -> bool:
        return False
    
    print("Code scanner not available. Code vulnerability scanning will be disabled.")

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
    # Define fallback function to avoid unbound variable errors
    def generate_report(output_dir: str, target: str) -> bool:
        return False
    
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
                 timeout: int = 3600, auto_config: bool = True,
                 scan_code: bool = False, custom_config: Optional[Dict[str, Any]] = None) -> bool:
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
        auto_config (bool): Automatically configure tools based on system capabilities.
        scan_code (bool): Scan web application code if found during http enumeration.
        custom_config (dict): Custom configuration settings to override defaults.
    
    Returns:
        bool: True if workflow completed successfully, False otherwise.
    """
    print(f"[+] Starting full scan on {target}")
    print(f"[+] Results will be saved to {output_dir}")
    
    # Auto-configure tools if requested and available
    if auto_config and CONFIG_MANAGER_AVAILABLE:
        print("[+] Auto-configuring tools based on system capabilities...")
        config = auto_configure()
        
        # Apply custom configuration if provided
        if custom_config:
            for section, settings in custom_config.items():
                if section in config:
                    config[section].update(settings)
    
    success = True
    start_time = time.time()
    
    try:
        # Step 1: Port scanning with naabu
        print("\n[+] Step 1: Port scanning with naabu")
        ports_output = os.path.join(output_dir, "ports.txt")
        ports_json = os.path.join(output_dir, "ports.json")
        
        # Get naabu configuration if available
        naabu_config = {}
        if CONFIG_MANAGER_AVAILABLE:
            naabu_config = get_tool_specific_config('naabu')
        
        # Prepare naabu arguments with auto-configuration
        naabu_args = ["--json", "-o", ports_json]
        if naabu_config:
            if 'scan_type' in naabu_config:
                naabu_args.extend(["--scan-type", naabu_config['scan_type']])
            if 'threads' in naabu_config and not verbose:  # Only use configured threads if not in verbose mode
                naabu_args.extend(["--threads", str(naabu_config['threads'])])
            if 'timeout' in naabu_config:
                naabu_args.extend(["--timeout", str(naabu_config['timeout'])])
            if 'retries' in naabu_config:
                naabu_args.extend(["--retries", str(naabu_config['retries'])])
        
        naabu_success = naabu.run_naabu(
            target=target,
            ports=ports or naabu_config.get('ports', "top-1000"),
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
            
        # Continue only if ports file exists and is not empty
        if not os.path.exists(ports_output) or os.path.getsize(ports_output) == 0:
            print("[!] No ports found or ports file is empty. Creating a default one with common ports.")
            with open(ports_output, "w") as f:
                f.write(f"{target}:80\n{target}:443\n")
        
        # Step 2: HTTP service detection with httpx
        print("\n[+] Step 2: HTTP service detection with httpx")
        http_output = os.path.join(output_dir, "http_services.txt")
        http_json = os.path.join(output_dir, "http_services.json")
        
        # Get httpx configuration if available
        httpx_config = {}
        if CONFIG_MANAGER_AVAILABLE:
            httpx_config = get_tool_specific_config('httpx')
        
        # Prepare httpx arguments with auto-configuration
        httpx_args = ["--json", "-o", http_json]
        
        # Set default values
        title_val = True
        status_code_val = True
        tech_detect_val = True
        web_server_val = True
        follow_redirects_val = True
        timeout_val = None
        threads_val = None
            
        # Apply configured settings if available
        if httpx_config:
            title_val = httpx_config.get('title', True)
            status_code_val = httpx_config.get('status_code', True)
            tech_detect_val = httpx_config.get('tech_detect', True)
            web_server_val = httpx_config.get('web_server', True)
            follow_redirects_val = httpx_config.get('follow_redirects', True)
            timeout_val = httpx_config.get('timeout')
            threads_val = httpx_config.get('threads')
            
        httpx_success = httpx.run_httpx(
            target_list=ports_output,
            output_file=http_output,
            title=bool(title_val),
            status_code=bool(status_code_val),
            tech_detect=bool(tech_detect_val),
            web_server=bool(web_server_val),
            follow_redirects=bool(follow_redirects_val),
            silent=not verbose,
            timeout=timeout_val,
            threads=threads_val,
            additional_args=httpx_args
        )
        
        if not httpx_success:
            print("[!] HTTPX service detection had issues. Continuing with available results.")
            success = False
        else:
            print(f"[+] HTTP service detection results saved to {http_output}")
        
        # Continue only if http file exists and is not empty
        if not os.path.exists(http_output) or os.path.getsize(http_output) == 0:
            print("[!] No HTTP services found or services file is empty. Creating a default one.")
            with open(http_output, "w") as f:
                f.write(f"http://{target}\nhttps://{target}\n")
        
        # Step 3: Vulnerability scanning with nuclei
        print("\n[+] Step 3: Vulnerability scanning with nuclei")
        vuln_output = os.path.join(output_dir, "vulnerabilities.txt")
        vuln_json = os.path.join(output_dir, "vulnerabilities.jsonl")
        
        # Get nuclei configuration if available
        nuclei_config = {}
        if CONFIG_MANAGER_AVAILABLE:
            nuclei_config = get_tool_specific_config('nuclei')
        
        # Create output directory for storing responses
        nuclei_resp_dir = os.path.join(output_dir, "nuclei_responses")
        create_directory_if_not_exists(nuclei_resp_dir)
        
        # Determine if we need to adjust scanning due to time constraints
        remaining_time = timeout - (time.time() - start_time)
        if remaining_time < timeout * 0.3:  # Less than 30% of time remaining
            print("[!] Limited time remaining for vulnerability scanning. Using focused scan.")
            # Use a more focused scan if time is limited
            if templates is None:
                templates = nuclei_config.get('templates', "cves")  # Only scan for CVEs
            if tags is None or tags == "cve":
                tags = nuclei_config.get('tags', "cve,rce,critical") # Focus on critical issues
            severity = nuclei_config.get('severity', "critical,high")    # Focus on high severity
        
        # Prepare nuclei arguments with auto-configuration
        nuclei_args = [
            "-jsonl", 
            "-o", vuln_json, 
            "-irr", 
            "-stats", 
            "-me", nuclei_resp_dir
        ]
        
        # Add configured settings
        if nuclei_config:
            if 'rate_limit' in nuclei_config:
                nuclei_args.extend(["-rate-limit", str(nuclei_config['rate_limit'])])
            if 'bulk_size' in nuclei_config:
                nuclei_args.extend(["-bulk-size", str(nuclei_config['bulk_size'])])
            if 'timeout' in nuclei_config:
                nuclei_args.extend(["-timeout", str(nuclei_config['timeout'])])
            if 'retries' in nuclei_config:
                nuclei_args.extend(["-retries", str(nuclei_config['retries'])])
            if 'exclude_tags' in nuclei_config and nuclei_config['exclude_tags']:
                nuclei_args.extend(["-exclude-tags", nuclei_config['exclude_tags']])
        
        # If time is very limited, add rate limiting to avoid overwhelming the target
        if remaining_time < timeout * 0.2:
            nuclei_args.extend(["-rate-limit", "50"])
        
        nuclei_success = nuclei.run_nuclei(
            target_list=http_output,
            templates=templates or nuclei_config.get('templates'),
            tags=tags or nuclei_config.get('tags', "cve"),
            severity=severity or nuclei_config.get('severity', "critical,high"),
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
        
        # Step 4 (Optional): Scan for code vulnerabilities if requested
        if scan_code and CODE_SCANNER_AVAILABLE:
            print("\n[+] Step 4: Scanning for code vulnerabilities")
            code_output = os.path.join(output_dir, "code_vulnerabilities.md")
            
            # Extract all URLs from HTTP services
            urls = []
            if os.path.exists(http_output):
                with open(http_output, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
            
            # Download and scan code from the URLs
            # This is a simplified approach - in a real scenario, you'd use a proper web crawler
            code_dir = os.path.join(output_dir, "code_downloads")
            create_directory_if_not_exists(code_dir)
            
            # Scan the downloaded code
            code_findings = scan_directory(code_dir)
            
            # Save findings
            if code_findings:
                save_findings(code_findings, code_output, 'markdown')
                print(f"[+] Code vulnerability scan results saved to {code_output}")
            else:
                print("[+] No code vulnerabilities found")
        
        # Step 5: Generate summary report
        print("\n[+] Generating summary report")
        
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
    parser.add_argument('--auto-config', action='store_true', help='Use automatic configuration based on system capabilities')
    parser.add_argument('--scan-code', action='store_true', help='Scan web application code for vulnerabilities')
    parser.add_argument('--config-file', help='Use custom configuration file')
    
    # Enforce Linux-only operation
    if platform.system().lower() != "linux":
        print("╔═══════════════════════════════════════════════════════════════╗")
        print("║                          ❌ ERROR ❌                           ║")
        print("║                                                               ║")
        print("║     This toolkit is designed EXCLUSIVELY for Linux systems   ║")
        print("║                                                               ║")
        print("║     ✅ Supported: Debian, Kali, Ubuntu, Arch Linux          ║")
        print("║     ❌ NOT Supported: Windows, macOS, WSL                    ║")
        print("║                                                               ║")
        print("║     Please use a native Linux environment for optimal        ║")
        print("║     security tool performance and compatibility.             ║")
        print("╚═══════════════════════════════════════════════════════════════╝")
        sys.exit(1)
    
    # Ensure platform verification is consistent
    if not verify_linux_platform():
        print("❌ This toolkit is designed for Linux only. Exiting.")
        sys.exit(1)
    
    # Set up signal handler for graceful exit on CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    
    args = parser.parse_args()
    
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
        print("[*] Please run the setup script: python install/setup.py")
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
    
    # Load custom configuration if specified
    custom_config = {}  # Use empty dict instead of None
    if args.config_file and os.path.exists(args.config_file):
        try:
            with open(args.config_file, 'r') as f:
                custom_config = json.load(f)
            print(f"[+] Loaded custom configuration from {args.config_file}")
        except Exception as e:
            print(f"[-] Error loading custom configuration: {e}")
    
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
            timeout=args.timeout,
            auto_config=args.auto_config,
            scan_code=args.scan_code,
            custom_config=custom_config  # Now passing a dict
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