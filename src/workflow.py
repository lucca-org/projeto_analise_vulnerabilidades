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
import socket
import subprocess

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
                 scan_code: bool = False, custom_config: Optional[Dict[str, Any]] = None,
                 stealth: bool = False) -> bool:
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
        stealth (bool): Use stealth mode for scanning to reduce detection risk.
    
    Returns:
        bool: True if workflow completed successfully, False otherwise.
    """
    print(f"[+] Starting full scan on {target}")
    if stealth:
        print("[+] STEALTH MODE ENABLED - Using slower but more discreet scanning techniques")
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
        
        # Apply stealth mode settings if enabled
        if stealth:
            # Configure naabu for stealth operation
            naabu_args.extend([
                "-rate", "10",  # Very slow packet rate
                "-c", "25",     # Lower connection pool size
                "-scan-type", "syn",  # SYN scan is generally more stealthy
                "-retries", "1",      # Fewer retries to avoid triggering alerts
                "-warm-up-time", "5", # Add warm-up time to avoid immediate full connections
                "-ping", "false"      # Skip ping to be more discreet
            ])
        elif naabu_config:
            # Apply normal configuration if not in stealth mode
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
        
        # Initialize all variables to avoid "possibly unbound" errors
        title_val = True
        status_code_val = True
        tech_detect_val = True
        web_server_val = True
        follow_redirects_val = True
        timeout_val = None
        threads_val = None
        
        # Apply stealth mode settings if enabled
        if stealth:
            # Configure httpx for stealth operation
            httpx_args.extend([
                "-rate-limit", "5",   # Very low rate limit
                "-retries", "1",      # Fewer retries
                "-timeout", "10",     # Shorter timeout
                "-delay", "5s",       # Add delay between requests
                "-random-agent",      # Use random user-agents to avoid fingerprinting
                "-no-fingerprint"     # Skip extensive fingerprinting which can be noisy
            ])
            title_val = False         # Disable extra feature probing in stealth mode
            status_code_val = True
            tech_detect_val = False   # Technology detection can be noisy
            web_server_val = False    # Web server detection can be noisy
            follow_redirects_val = True
            timeout_val = 10          # Set timeout value explicitly in stealth mode
            threads_val = 5           # Set threads value explicitly in stealth mode
        elif httpx_config:
            # Apply configured settings if available
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
        
        # Apply stealth mode settings if enabled
        if stealth:
            # Configure nuclei for stealth operation
            nuclei_args.extend([
                "-rate-limit", "5",        # Very low rate limit
                "-bulk-size", "5",         # Small bulk size
                "-concurrency", "5",       # Low concurrency
                "-timeout", "5",           # Short timeout
                "-retries", "1",           # Fewer retries
                "-headless-options", "delay=1000",  # Add delay for headless operations
                "-headless-workers", "1",  # Only one headless worker
                "-no-interactsh",          # Disable interactsh to avoid callbacks
                "-no-meta",                # Avoid additional metadata requests
                "-scan-strategy", "host-spray" # Host-based scan strategy is more discreet
            ])
            
            # In stealth mode, focus on passive templates when possible
            if templates is None:
                nuclei_args.extend(["-tags", "passive,cve"])
            
            # Skip some noisy tags in stealth mode
            nuclei_args.extend(["-exclude-tags", "fuzzing,dos,brute-force"])
        elif nuclei_config:
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

def check_network_connectivity():
    """Check if network connection is available, with bypass option."""
    # Check for network override flag
    override_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_override')
    if os.path.exists(override_path):
        print("[!] Network connectivity check bypassed (override flag detected)")
        return True
        
    try:
        # Try multiple connectivity checks
        
        # Method 1: Try to connect to a reliable DNS server
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except (socket.timeout, socket.error):
            pass
            
        # Method 2: Try to resolve a domain
        try:
            socket.gethostbyname("www.google.com")
            return True
        except socket.gaierror:
            pass
            
        # Method 3: Try to ping localhost or gateway
        try:
            # Try localhost first
            if subprocess.run(["ping", "-c", "1", "-W", "1", "127.0.0.1"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                return True
                
            # Try common gateway
            if subprocess.run(["ping", "-c", "1", "-W", "1", "192.168.1.1"], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                return True
        except:
            pass
            
        # All checks failed
        print("No network connection detected. Please check your internet connection.")
        print("To bypass this check, run: python src/network_test.py --create-override")
        return False
    except Exception as e:
        print(f"Error checking network: {e}")
        return False

def check_tool_availability(tool_name, common_paths=None):
    """
    Check if a tool is available in any of the common installation paths.
    
    Args:
        tool_name: Name of the tool to check
        common_paths: List of common installation paths to check for the tool
        
    Returns:
        tuple: (bool, str) - Whether the tool is available and its path
    """
    # Default common paths if none provided
    if common_paths is None:
        common_paths = [
            f"/usr/bin/{tool_name}",
            f"/usr/local/bin/{tool_name}",
            f"/root/go/bin/{tool_name}",
            f"~/go/bin/{tool_name}",
            f"{os.path.expanduser('~')}/go/bin/{tool_name}",
            f"{os.path.expanduser('~')}/.local/bin/{tool_name}"
        ]
    
    # First check if tool is in PATH
    path_result = get_executable_path(tool_name)
    if path_result:
        # Test if the tool actually works
        try:
            # Run with --version or -version to check if it works
            for flag in ["--version", "-version", "-v", "--help", "-h"]:
                result = subprocess.run(
                    [path_result, flag], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    timeout=5
                )
                if result.returncode == 0:
                    return True, path_result
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            # Tool exists but might not be working properly
            pass
    
    # Then check common paths
    for path in common_paths:
        expanded_path = os.path.expanduser(path)
        if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
            try:
                # Try to run the tool to verify it works
                for flag in ["--version", "-version", "-v", "--help", "-h"]:
                    result = subprocess.run(
                        [expanded_path, flag], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                    if result.returncode == 0:
                        return True, expanded_path
            except (subprocess.SubprocessError, OSError, FileNotFoundError):
                # Tool exists but might not be working properly
                continue
    
    return False, None

def main():
    """Main entry point for the vulnerability scanning workflow."""
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
    parser.add_argument('--force-tools', action='store_true', help='Force continue even if tools check fails')
    parser.add_argument('-s', '--stealth', action='store_true', help='Enable stealth mode for more discreet scanning')
    
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
    if not check_network_connectivity():
        print("[-] No network connectivity. Please check your connection and try again.")
        sys.exit(1)
    
    # Check if required tools are installed
    tools_found = True
    
    print("[+] Checking required tools...")
    
    # Check naabu with common paths
    naabu_paths = [
        "/usr/bin/naabu",
        "/usr/local/bin/naabu",
        "/root/go/bin/naabu",
        "~/go/bin/naabu",
        f"{os.path.expanduser('~')}/go/bin/naabu"
    ]
    naabu_ok, naabu_path = check_tool_availability("naabu", naabu_paths)
    if naabu_ok:
        print(f"  ✅ naabu: Available at {naabu_path}")
    else:
        print("  ❌ naabu: Not found. Required for port scanning.")
        tools_found = False
    
    # Check httpx with common paths
    httpx_paths = [
        "/usr/bin/httpx",
        "/usr/local/bin/httpx",
        "/root/go/bin/httpx",
        "~/go/bin/httpx",
        f"{os.path.expanduser('~')}/go/bin/httpx"
    ]
    httpx_ok, httpx_path = check_tool_availability("httpx", httpx_paths)
    if httpx_ok:
        print(f"  ✅ httpx: Available at {httpx_path}")
    else:
        print("  ❌ httpx: Not found or not working. Required for HTTP service detection.")
        tools_found = False
    
    # Check nuclei with common paths
    nuclei_paths = [
        "/usr/bin/nuclei",
        "/usr/local/bin/nuclei",
        "/root/go/bin/nuclei",
        "~/go/bin/nuclei",
        f"{os.path.expanduser('~')}/go/bin/nuclei"
    ]
    nuclei_ok, nuclei_path = check_tool_availability("nuclei", nuclei_paths)
    if nuclei_ok:
        print(f"  ✅ nuclei: Available at {nuclei_path}")
    else:
        print("  ❌ nuclei: Not found. Required for vulnerability scanning.")
        tools_found = False
    
    if not tools_found and not args.force_tools:
        print("[-] One or more required tools are not installed or not working correctly.")
        print("[*] Please run the setup script: python install/setup.py")
        print("[*] Or use --force-tools to continue anyway (not recommended)")
        sys.exit(1)
    elif not tools_found and args.force_tools:
        print("[!] Continuing with missing tools (--force-tools enabled). Expect errors!")
    else:
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
            custom_config=custom_config,
            stealth=args.stealth
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