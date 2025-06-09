#!/usr/bin/env python3
"""
workflow.py - Automated vulnerability scanning workflow.
This script orchestrates individual tool execution using naabu, httpx, and nuclei tools.
"""

import os
import sys
import argparse
import datetime
import json
import time
import signal
import platform
import subprocess
import shutil
import socket
from pathlib import Path
from typing import Optional, Dict, List, Any, Union, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from commands import naabu, httpx, nuclei
    from utils import run_cmd, check_network, create_directory_if_not_exists, get_executable_path, verify_linux_platform
    COMMANDS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import security tool modules: {e}")
    COMMANDS_AVAILABLE = False
    
    # Provide fallback functions
    class MockTool:
        @staticmethod
        def run_naabu(*args, **kwargs):
            print("Error: naabu module not available")
            return False
        @staticmethod
        def run_httpx(*args, **kwargs):
            print("Error: httpx module not available")
            return False
        @staticmethod
        def run_nuclei(*args, **kwargs):
            print("Error: nuclei module not available")
            return False
    
    naabu = httpx = nuclei = MockTool()
    
    def check_network() -> bool:
        return True
    
    def create_directory_if_not_exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            return True
        except Exception:
            return False
    
    def get_executable_path(cmd):
        return shutil.which(cmd)
    
    def verify_linux_platform():
        return platform.system().lower() == "linux"

# Try to import config_manager if available
try:
    from config_manager import get_config, auto_configure, get_tool_specific_config
    CONFIG_MANAGER_AVAILABLE = True
except ImportError:
    CONFIG_MANAGER_AVAILABLE = False
    def get_config() -> Dict[str, Any]:
        return {}
    def auto_configure() -> Dict[str, Any]:
        return {}
    def get_tool_specific_config(tool: str) -> Dict[str, Any]:
        return {}

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
    print("\nWARNING: Scan interrupted by user. Partial results may be available.")
    sys.exit(130)

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
                print(f"WARNING: Could not parse ports JSON: {e}")
        
        # Count HTTP services
        if os.path.exists(http_json):
            try:
                with open(http_json, 'r') as f:
                    for line in f:
                        if line.strip():
                            http_count += 1
            except Exception as e:
                print(f"WARNING: Could not parse HTTP services JSON: {e}")
        
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
                print(f"WARNING: Could not parse vulnerabilities JSONL: {e}")

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
        
        print(f"Summary report generated: {summary_file}")
        return True
    except Exception as e:
        print(f"Error generating summary report: {e}")
        return False

def check_tool_availability(tool_name, common_paths=None):
    """Check if a tool is available in any of the common installation paths."""
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
        try:
            for flag in ["--version", "-version", "-v", "--help", "-h"]:
                try:
                    result = subprocess.run(
                        [path_result, flag], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                    if result.returncode == 0:
                        return True, path_result
                except:
                    continue
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            pass
    
    # Then check common paths
    for path in common_paths:
        expanded_path = os.path.expanduser(path)
        if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
            try:
                for flag in ["--version", "-version", "-v", "--help", "-h"]:
                    try:
                        result = subprocess.run(
                            [expanded_path, flag], 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            timeout=5
                        )
                        if result.returncode == 0:
                            return True, expanded_path
                    except:
                        continue
            except (subprocess.SubprocessError, OSError, FileNotFoundError):
                continue
    
    return False, None

def get_port_specification(port_spec: str) -> Optional[str]:
    """
    Convert common port specifications to naabu-compatible port ranges.
    
    Args:
        port_spec (str): Port specification like "top-100", "top-1000", "all", or specific ports
    
    Returns:
        Optional[str]: Naabu-compatible port specification, or None to use naabu defaults
    """
    if port_spec == "top-100":
        # Top 100 most common ports
        return "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
    elif port_spec == "top-1000":
        # Use naabu's default top 1000 ports by not specifying -p at all
        return None
    elif port_spec == "all":
        # All ports 1-65535
        return "1-65535"
    else:
        # Return as-is for custom port specifications
        return port_spec

def run_individual_tools(args, tool_paths: Dict[str, str], output_dir: str) -> bool:
    """Run individual tool based on command line flag (only one tool at a time)."""
    success = True
    target = args.host or args.target

    if not target:
        print("No target specified. Use -host or provide target as positional argument.")
        return False

    # Only allow one tool at a time
    tools_selected = sum([args.naabu, args.httpx, args.nuclei])
    if tools_selected == 0:
        print("No tool selected. Use -naabu, -httpx, or -nuclei flag.")
        return False
    elif tools_selected > 1:
        print("Only one tool can be run at a time. Please select either -naabu, -httpx, or -nuclei.")
        return False

    print(f"Running selected tool on target: {target}")
    print(f"Real-time output: ENABLED")
    print(f"Save to files: {'YES' if args.save_output else 'NO'}")
    if args.save_output:
        print(f"Results will be saved to: {output_dir}")
        if args.json_output:
            print(f"JSON format: ENABLED")
    else:
        print(f"Output will be displayed in real-time only (not saved)")    # NAABU
    if args.naabu:
        print(f"\nStarting naabu port scan...")

        if args.save_output:
            ports_output = os.path.join(output_dir, "ports.txt")
            ports_json = os.path.join(output_dir, "ports.json") if args.json_output else None
        else:
            ports_output = None
            ports_json = None        # Always apply port specification mapping, whether from args or default
        if args.ports:
            ports_to_scan = args.ports
        else:
            ports_to_scan = "top-1000"
        
        # Apply port specification mapping to convert common specs to naabu-compatible formats
        mapped_ports = get_port_specification(ports_to_scan)

        naabu_args = ["-v"]

        # Fix: Proper JSON output handling for naabu
        if args.save_output and args.json_output and ports_json:
            naabu_args.extend(["-json", "-o", ports_json])
        elif args.save_output and ports_output:
            naabu_args.extend(["-o", ports_output])

        if args.stealth:
            naabu_args.extend([
                "-rate", "10",
                "-c", "25",
                "-scan-type", "syn",
                "-retries", "1"
            ])
        else:            naabu_args.extend([
                "-rate", "1000",
                "-c", "50"
            ])

        naabu_success = naabu.run_naabu(
            target=target,
            ports=mapped_ports,
            output_file=ports_output if not args.json_output else ports_json,
            json_output=bool(args.save_output and args.json_output),
            save_output=args.save_output,
            tool_silent=False,            additional_args=naabu_args
        )

        print(f"\nNaabu scan completed!")

        if naabu_success:
            if args.save_output:
                output_file = ports_json if args.json_output else ports_output
                if output_file and os.path.exists(output_file):
                    file_size = os.path.getsize(output_file)
                    if file_size > 0:
                        print(f"Results saved to {output_file} ({file_size} bytes)")
                    else:
                        print("No open ports found")
                else:
                    print("Output file was not created")
                    success = False
            else:
                print("Real-time scan output was displayed above")
                print("Results were not saved to files (as requested)")
        else:
            print("Naabu scan failed.")
            success = False

    # HTTPX
    elif args.httpx:
        print(f"\nStarting httpx service detection...")

        if args.save_output:
            http_output = os.path.join(output_dir, "http_services.txt")
            http_json = os.path.join(output_dir, "http_services.json") if args.json_output else None
        else:
            http_output = None
            http_json = None

        httpx_input = target
        print(f"Target: {httpx_input}")

        httpx_args = ["-v"]

        # Fix: Proper JSON output handling for httpx
        if args.save_output and args.json_output and http_json:
            httpx_args.extend(["-json", "-o", http_json])
        elif args.save_output and http_output:
            httpx_args.extend(["-o", http_output])

        if args.stealth:
            httpx_args.extend([
                "-rate-limit", "5",
                "-retries", "1",
                "-timeout", "10",
                "-delay", "5s"
            ])
        else:
            httpx_args.extend([                
                "-rate-limit", "150",
                "-timeout", "5"
            ])

        httpx_success = httpx.run_httpx(
            target_list=httpx_input,
            output_file=http_json if args.json_output else http_output,
            title=True,
            status_code=True,
            tech_detect=not args.stealth,
            web_server=not args.stealth,
            follow_redirects=True,
            save_output=args.save_output,
            tool_silent=False,
            additional_args=httpx_args        )

        print(f"\nHTTPX scan completed!")

        if httpx_success:
            if args.save_output:
                output_file = http_json if args.json_output else http_output
                if output_file and os.path.exists(output_file):
                    file_size = os.path.getsize(output_file)
                    if file_size > 0:
                        print(f"Results saved to {output_file} ({file_size} bytes)")
                    else:
                        print("No HTTP services found")
                else:
                    print("Output file was not created")
                    success = False
            else:
                print("Real-time scan output was displayed above")
                print("Results were not saved to files (as requested)")
        else:
            print("HTTPX scan failed.")
            success = False

    # NUCLEI
    elif args.nuclei:
        print(f"\nStarting nuclei vulnerability scan...")

        if args.save_output:
            vuln_output = os.path.join(output_dir, "vulnerabilities.txt")
            vuln_json = os.path.join(output_dir, "vulnerabilities.jsonl") if args.json_output else None
        else:
            vuln_output = None
            vuln_json = None

        # Handle target input for nuclei
        if not target.startswith(('http://', 'https://')):
            print(f"Target doesn't specify protocol. Testing both HTTP and HTTPS...")
            nuclei_targets = [f"http://{target}", f"https://{target}"]
            
            if args.save_output:
                target_file = os.path.join(output_dir, "nuclei_targets.txt")
                with open(target_file, 'w') as f:
                    for t in nuclei_targets:
                        f.write(f"{t}\n")
                nuclei_input = target_file
                print(f"Created target file: {target_file}")
            else:
                # For real-time only, use the first URL  
                nuclei_input = nuclei_targets[0]
            
            print(f"Testing URLs: {', '.join(nuclei_targets)}")
        else:
            nuclei_input = target
            print(f"Target: {nuclei_input}")

        # Prepare nuclei arguments
        nuclei_args = ["-v", "-stats"]
        
        if args.save_output:
            nuclei_resp_dir = os.path.join(output_dir, "nuclei_responses")
            create_directory_if_not_exists(nuclei_resp_dir)
            nuclei_args.extend(["-store-resp", "-store-resp-dir", nuclei_resp_dir])

        if args.stealth:
            nuclei_args.extend([
                "-rate-limit", "5",
                "-bulk-size", "5", 
                "-concurrency", "5",
                "-timeout", "5",
                "-retries", "1",
                "-exclude-tags", "fuzzing,dos,brute-force",
                "-no-interactsh"
            ])
        else:
            nuclei_args.extend([
                "-rate-limit", "50",
                "-bulk-size", "10",
                "-concurrency", "10", 
                "-timeout", "10"
            ])

        # Use the new nuclei.run_nuclei function with proper parameters
        if os.path.isfile(nuclei_input):
            nuclei_success = nuclei.run_nuclei(
                target_list=nuclei_input,
                templates=args.templates,
                tags=args.tags,
                severity=args.severity,
                output_file=vuln_json if args.json_output else vuln_output,
                jsonl=bool(args.json_output),
                save_output=args.save_output,
                tool_silent=False,
                store_resp=bool(args.save_output),
                additional_args=nuclei_args
            )
        else:
            nuclei_success = nuclei.run_nuclei(
                target=nuclei_input,
                templates=args.templates,
                tags=args.tags,
                severity=args.severity,
                output_file=vuln_json if args.json_output else vuln_output,
                jsonl=bool(args.json_output),
                save_output=args.save_output,
                tool_silent=False,
                store_resp=bool(args.save_output),
                additional_args=nuclei_args
            )

        print(f"\n Nuclei scan completed!")

        if nuclei_success:
            if args.save_output:
                output_file = vuln_json if args.json_output else vuln_output
                if output_file and os.path.exists(output_file):
                    file_size = os.path.getsize(output_file)
                    if file_size > 0:
                        print(f" Results saved to {output_file} ({file_size} bytes)")
                    else:
                        print("WARNING: No vulnerabilities found")
                else:
                    print("WARNING: Output file was not created")
                    success = False
            else:
                print(" Real-time scan output was displayed above")
                print(" Results were not saved to files (as requested)")
        else:
            print(" Nuclei scan failed.")
            success = False

    return success

def check_network_connectivity():
    """Check if network connection is available, with bypass option."""
    # Check for network override flag - Fix: Use correct path relative to workflow.py
    override_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'network_override')
    if os.path.exists(override_path):
        print("WARNING: Network connectivity check bypassed (override flag detected)")
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
        except Exception:
            pass
            
        # All checks failed
        print("No network connection detected. Please check your internet connection.")
        print("To bypass this check, create file: touch network_override")
        return False
    except Exception as e:
        print(f"Error checking network: {e}")
        return False

def main():
    """Main entry point for the vulnerability scanning workflow."""
    parser = argparse.ArgumentParser(description='Individual tool vulnerability scanning')
    
    # Target specification
    parser.add_argument('target', nargs='?', help='Target to scan (IP or domain)')
    parser.add_argument('-host', '--host', help='Target host to scan (alternative to positional target)')
    
    # Tool selection flags (only one allowed at a time)
    parser.add_argument('-naabu', '--naabu', action='store_true', help='Run naabu port scanner')
    parser.add_argument('-httpx', '--httpx', action='store_true', help='Run httpx service detection')
    parser.add_argument('-nuclei', '--nuclei', action='store_true', help='Run nuclei vulnerability scanner')
    
    # Tool-specific options
    parser.add_argument('-p', '--ports', help='Ports to scan with naabu (e.g., 80,443,8000-9000)')
    parser.add_argument('-t', '--templates', help='Custom nuclei templates (default: uses built-in templates)')
    parser.add_argument('--tags', default='cve', help='Nuclei template tags (default: cve)')
    parser.add_argument('--severity', default='critical,high', help='Vulnerability severity filter (default: critical,high)')
    
    # Output options
    parser.add_argument('-o', '--output-dir', help='Custom output directory')
    parser.add_argument('--save-output', action='store_true', help='Save scan output to files (separate from real-time display)')
    parser.add_argument('--json-output', action='store_true', help='Save output in JSON format (requires --save-output)')
    
    # Workflow options
    parser.add_argument('--update-templates', action='store_true', help='Update nuclei templates before scanning')
    parser.add_argument('--timeout', type=int, default=3600, help='Maximum scan time in seconds (default: 3600)')
    parser.add_argument('--force-tools', action='store_true', help='Force continue even if tools check fails')
    parser.add_argument('-s', '--stealth', action='store_true', help='Enable stealth mode for more discreet scanning')
    
    # Enforce Linux-only operation
    if platform.system().lower() != "linux":
        print("╔═══════════════════════════════════════════════════════════════╗")
        print("║                             ERROR                             ║")
        print("║                                                               ║")
        print("║     This toolkit is designed EXCLUSIVELY for Linux systems    ║")
        print("║                                                               ║")
        print("║          Supported: Debian, Kali, Ubuntu, Arch Linux          ║")
        print("║          NOT Supported: Windows, macOS, WSL                   ║")
        print("║                                                               ║")
        print("║     Please use a native Linux environment for optimal         ║")
        print("║     security tool performance and compatibility.              ║")
        print("╚═══════════════════════════════════════════════════════════════╝")
        sys.exit(1)
    
    if not verify_linux_platform():
        print("This toolkit is designed for Linux only. Exiting.")
        sys.exit(1)
    
    # Set up signal handler for graceful exit on CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    
    args = parser.parse_args()
    
    # Validate JSON output flag
    if args.json_output and not args.save_output:
        print("Warning: --json-output requires --save-output flag. JSON output will be ignored.")
        args.json_output = False
    
    # Check network connectivity
    print(" Checking network connectivity...")
    if not check_network_connectivity():
        print(" Network connectivity check failed.")
        print(" Some features may not work without internet access.")
        response = input("Continue anyway? [y/N]: ")

        # Fix: Handle empty response (default to 'n' if no input)
        if response.strip().lower() not in ['y', 'yes']:
            print(" Scan cancelled.")
            sys.exit(1)
    
    # Handle template updates
    if args.update_templates:
        print(" Updating nuclei templates...")
        try:
            result = subprocess.run(['nuclei', '-update-templates'], check=True)
            print(" Templates updated successfully.")
        except Exception as e:
            print(f" Template update failed: {e}")
            if not args.force_tools:
                sys.exit(1)
    
    # Determine target
    target = args.host or args.target
    if not target:
        print(" No target specified. Use -host argument or provide target as positional argument.")
        print("Example: python workflow.py -naabu -host example.com")
        sys.exit(1)
    
    # Check tool availability
    tools_to_check = []
    if args.naabu:
        tools_to_check.append('naabu')
    elif args.httpx:
        tools_to_check.append('httpx')
    elif args.nuclei:
        tools_to_check.append('nuclei')
    else:
        print(" No tool selected. Use -naabu, -httpx, or -nuclei flag.")
        sys.exit(1)
    
    print(" Checking tool availability...")
    tool_paths = {}
    missing_tools = []
    
    for tool in tools_to_check:
        available, path = check_tool_availability(tool)
        if available:
            tool_paths[tool] = path
            print(f" {tool}: Available at {path}")
        else:
            missing_tools.append(tool)
            print(f" {tool}: Not found")
    
    if missing_tools and not args.force_tools:
        print(f" Missing tools: {', '.join(missing_tools)}")
        print(" Install missing tools or use --force-tools to continue anyway.")
        sys.exit(1)
    
    # Create output directory if saving output
    if args.save_output:
        if args.output_dir:
            output_dir = args.output_dir
            os.makedirs(output_dir, exist_ok=True)
        else:
            target_name = target.replace('/', '_').replace(':', '_')
            output_dir = create_output_directory(target_name)
            if not output_dir:
                print(" Failed to create output directory.")
                sys.exit(1)
    else:
        output_dir = os.getcwd()  # Use current directory for temporary files
    
    # Run the selected tool
    print(f"\n Starting scan of {target}")
    print(f" Scan start time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    start_time = time.time()
    
    try:
        success = run_individual_tools(args, tool_paths, output_dir)
    except KeyboardInterrupt:
        print("\nWARNING: Scan interrupted by user.")
        success = False
    except Exception as e:
        print(f"\nWARNING: Unexpected error: {e}")
        success = False
    
    elapsed_time = time.time() - start_time
    print(f"\n Scan completed in {elapsed_time:.2f} seconds")
    
    # Generate summary if saving output and scan was successful
    if args.save_output and success:
        print(" Generating summary report...")
        generate_basic_summary_report(output_dir, target)
    
    if success:
        print(" Scan completed successfully!")
    else:
        print("WARNING: Scan completed with issues.")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
