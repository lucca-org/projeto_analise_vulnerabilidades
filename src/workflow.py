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
import urllib.request
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

# Enhanced Real-time Output Functions
def print_status_header(tool_name: str, target: str, action: str = "scan"):
    """Print a formatted status header for tool execution."""
    print("\n" + "═" * 80)
    print(f"{tool_name.upper()} {action.upper()}")
    print("═" * 80)
    print(f"Target: {target}")
    print(f"Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 80)
    sys.stdout.flush()

def print_progress_indicator(message: str, symbol: str = "*"):
    """Print a progress indicator with timestamp."""
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {symbol} {message}")
    sys.stdout.flush()

def run_with_realtime_output(cmd: List[str], output_file: Optional[str] = None, 
                           tool_name: str = "Tool") -> Tuple[bool, str]:
    """
    Execute a command with enhanced real-time output streaming.
    
    Args:
        cmd: Command and arguments to execute
        output_file: Optional file to save output to
        tool_name: Name of the tool for display purposes
        
    Returns:
        Tuple of (success, captured_output)
    """
    captured_output = []
    process = None
    
    try:
        print_progress_indicator(f"Executing: {' '.join(cmd[:3])}...")
        
        # Start the process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Stream output line by line
        line_count = 0
        while True:
            if process.stdout is None:
                break
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()
                if line:  # Only process non-empty lines
                    line_count += 1
                      # Add colored prefixes for better visibility
                    if any(keyword in line.lower() for keyword in ['error', 'failed', 'timeout']):
                        formatted_line = f"[ERROR] {line}"
                    elif any(keyword in line.lower() for keyword in ['found', 'detected', 'open']):
                        formatted_line = f"[FOUND] {line}"
                    elif any(keyword in line.lower() for keyword in ['scanning', 'probing', 'testing']):
                        formatted_line = f"[SCAN] {line}"
                    else:
                        formatted_line = f"[INFO] {line}"
                    
                    print(formatted_line)
                    sys.stdout.flush()
                    
                    # Capture for file output
                    captured_output.append(line)
                    
                    # Show progress every 50 lines
                    if line_count % 50 == 0:
                        print_progress_indicator(f"Processed {line_count} lines...")
        
        # Wait for process to complete
        return_code = process.wait()
        
        # Final status
        if return_code == 0:
            print_progress_indicator(f"{tool_name} completed successfully", "SUCCESS")
        else:
            print_progress_indicator(f"{tool_name} completed with exit code {return_code}", "WARNING")
        
        # Save to file if requested
        if output_file and captured_output:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(captured_output))
                print_progress_indicator(f"Output saved to: {output_file}", "SAVED")
            except Exception as e:
                print_progress_indicator(f"Failed to save output: {e}", "ERROR")
        
        return return_code == 0, '\n'.join(captured_output)
        
    except subprocess.TimeoutExpired:
        print_progress_indicator("Command timed out", "TIMEOUT")
        if process:
            process.kill()
        return False, '\n'.join(captured_output)
    except KeyboardInterrupt:
        print_progress_indicator("Interrupted by user", "STOP")
        if process:
            process.terminate()
        return False, '\n'.join(captured_output)
    except Exception as e:
        print_progress_indicator(f"Execution error: {e}", "ERROR")
        return False, '\n'.join(captured_output)

def stream_command_output(cmd: List[str], output_file: Optional[str] = None) -> Tuple[bool, str]:
    """
    Stream command output in real-time with improved formatting.
    
    Args:
        cmd: Command to execute
        output_file: Optional file to save output
        
    Returns:
        Tuple of (success, output_content)
    """
    output_lines = []
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        start_time = time.time()
        last_update = start_time
        
        if process.stdout is not None:
            for line in iter(process.stdout.readline, ''):
                if process.stdout is None:
                    break
                current_time = time.time()
                line = line.rstrip()
                
                if line:
                    # Add timestamp prefix for verbose output
                    elapsed = current_time - start_time
                    time_prefix = f"[{elapsed:6.1f}s]"
                      # Color code based on content
                    if 'error' in line.lower() or 'failed' in line.lower():
                        display_line = f"{time_prefix} [ERROR] {line}"
                    elif 'found' in line.lower() or 'detected' in line.lower():
                        display_line = f"{time_prefix} [FOUND] {line}"
                    elif any(word in line.lower() for word in ['scanning', 'probing', 'testing', 'checking']):
                        display_line = f"{time_prefix} [SCAN] {line}"
                    else:
                        display_line = f"{time_prefix} [INFO] {line}"
                    
                    print(display_line)
                    sys.stdout.flush()
                    output_lines.append(line)
                    
                    # Progress indicator every 10 seconds
                    if current_time - last_update >= 10:
                        print_progress_indicator(f"Still running... ({len(output_lines)} lines processed)")
                        last_update = current_time
        
        return_code = process.wait()
        
        # Save output if requested
        if output_file and output_lines:
            with open(output_file, 'w') as f:
                f.write('\n'.join(output_lines))
        
        return return_code == 0, '\n'.join(output_lines)
                
    except Exception as e:
        print(f"[ERROR] Error executing command: {e}")
        return False, '\n'.join(output_lines)

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

def create_comprehensive_report_file(output_dir: str, target: str) -> str:
    """Create a comprehensive report file and return its path."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file = os.path.join(output_dir, "comprehensive_scan_report.txt")
    
    # Initialize the comprehensive report file
    with open(report_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("COMPREHENSIVE VULNERABILITY SCAN REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Start Time: {timestamp}\n")
        f.write("=" * 80 + "\n\n")
    
    return report_file

def append_to_comprehensive_report(report_file: str, tool_name: str, content: str, success: bool):
    """Append tool results to the comprehensive report file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(report_file, 'a') as f:
        f.write("-" * 60 + "\n")
        f.write(f"{tool_name.upper()} SCAN RESULTS\n")
        f.write(f"Completion Time: {timestamp}\n")
        f.write(f"Status: {'SUCCESS' if success else 'FAILED'}\n")
        f.write("-" * 60 + "\n")
        
        if content.strip():
            f.write(content)
            f.write("\n")
        else:
            f.write("No results found or scan failed.\n")
        
        f.write("\n" + "-" * 60 + "\n\n")

def finalize_comprehensive_report(report_file: str, target: str, overall_success: bool):
    """Finalize the comprehensive report with summary statistics."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Read the report to analyze results
    with open(report_file, 'r') as f:
        content = f.read()
    
    # Simple result counting from the report content
    port_count = content.count("open") if "NAABU SCAN RESULTS" in content else 0
    http_count = content.count("http") + content.count("https") if "HTTPX SCAN RESULTS" in content else 0
    vuln_count = content.count("[") if "NUCLEI SCAN RESULTS" in content else 0  # Simple vulnerability indicator count
    
    # Append final summary
    with open(report_file, 'a') as f:
        f.write("=" * 80 + "\n")
        f.write("SCAN SUMMARY\n")
        f.write("=" * 80 + "\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Completion Time: {timestamp}\n")
        f.write(f"Overall Status: {'SUCCESS' if overall_success else 'COMPLETED WITH ISSUES'}\n\n")
        
        f.write("ESTIMATED FINDINGS:\n")
        if "NAABU SCAN RESULTS" in content:
            f.write(f"- Open ports detected: ~{port_count}\n")
        if "HTTPX SCAN RESULTS" in content:
            f.write(f"- HTTP services detected: ~{http_count}\n")
        if "NUCLEI SCAN RESULTS" in content:
            f.write(f"- Potential vulnerabilities found: ~{vuln_count}\n")
        
        f.write("\nNOTE: These are estimated counts from text analysis.\n")
        f.write("Review the detailed results above for accurate information.\n\n")
        
        if vuln_count > 0:
            f.write("RECOMMENDATIONS:\n")
            f.write("Potential vulnerabilities detected! Please review the detailed findings above\n")
            f.write("and take appropriate remediation steps.\n\n")
        
        f.write("=" * 80 + "\n")
        f.write("End of Comprehensive Scan Report\n")
        f.write("=" * 80 + "\n")

def signal_handler(sig, frame):
    """Handle CTRL+C gracefully."""
    print("\nWARNING: Scan interrupted by user. Partial results may be available.")
    sys.exit(130)

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
        print(f"Output will be displayed in real-time only (not saved)")

    # Create comprehensive report file if saving output
    comprehensive_report = None
    if args.save_output:
        comprehensive_report = create_comprehensive_report_file(output_dir, target)
        print(f"Comprehensive report will be saved to: {comprehensive_report}")

    # NAABU
    if args.naabu:
        print(f"\nStarting naabu port scan...")

        # Always apply port specification mapping, whether from args or default
        if args.ports:
            ports_to_scan = args.ports
        else:
            ports_to_scan = "top-1000"
        
        # Apply port specification mapping to convert common specs to naabu-compatible formats
        mapped_ports = get_port_specification(ports_to_scan)

        naabu_args = ["-v"]

        # For comprehensive report, always capture output
        
        # Display port scanning information
        if mapped_ports is None:
            print(f"Port range: Top 1000 most common ports (naabu default)")
        elif ports_to_scan == "top-100":
            print(f"Port range: Top 100 most common ports")
        elif ports_to_scan == "all":
            print(f"Port range: All ports (1-65535)")
        else:
            print(f"Port range: {ports_to_scan}")
        
        print(f"Target: {target}")

        naabu_args = ["-v"]        # For comprehensive report, always capture output
        temp_output = None
        if args.save_output:
            temp_output = os.path.join(output_dir, "temp_naabu_output.txt")
            naabu_args.extend(["-o", temp_output])

        if args.stealth:
            # Don't add -o here, let run_naabu handle it        if args.stealth:
            naabu_args.extend([
                "-rate", "10",
                "-c", "25",
                "-scan-type", "syn",
                "-retries", "1",
                "-warm-up-time", "2"  # Add warm-up time for stability
            ])
        else:
            naabu_args.extend([
                "-rate", "1000",
                "-c", "50",
                "-warm-up-time", "2"  # Add warm-up time for stability
            ])

        print_status_header("naabu", target, "port scan")
          # Build command with proper None handling and additional safety parameters
        naabu_cmd = ["naabu", "-host", target]
        if mapped_ports:
            naabu_cmd.extend(["-p", mapped_ports])
        
        # Add output options
        if args.json_output:
            naabu_cmd.append("-json")
        elif temp_output:
            naabu_cmd.extend(["-o", temp_output])
        
        # Add the naabu arguments
        naabu_cmd.extend(naabu_args)
        
        # Add additional safety parameters for better compatibility
        naabu_cmd.extend([
            "-silent",  # Reduce verbose output for cleaner display
            "-no-color"  # Disable colors for better log parsing
        ])
        
        print(f"Executing command: {' '.join(naabu_cmd)}")
        
        naabu_success, naabu_output = run_with_enhanced_realtime_output(
            cmd=naabu_cmd,
            output_file=temp_output,
            tool_name="Naabu"
        )

        print(f"\nNaabu scan completed!")

        if naabu_success:
            if args.save_output and comprehensive_report:
                # Read temporary output and append to comprehensive report
                naabu_content = ""
                if temp_output and os.path.exists(temp_output):
                    with open(temp_output, 'r') as f:
                        naabu_content = f.read()
                    os.remove(temp_output)  # Clean up temp file
                
                append_to_comprehensive_report(comprehensive_report, "NAABU", naabu_content, True)
                
                if naabu_content.strip():
                    print(f"Port scan results added to comprehensive report")
                else:
                    print("No open ports found")
            else:
                print("Real-time scan output was displayed above")
                print("Results were not saved to files (as requested)")
        else:
            print("Naabu scan failed.")
            if args.save_output and comprehensive_report:
                append_to_comprehensive_report(comprehensive_report, "NAABU", "Scan failed", False)
            success = False

    # HTTPX
    elif args.httpx:
        print(f"\nStarting httpx service detection...")

        httpx_input = target
        print(f"Target: {httpx_input}")

        httpx_args = ["-v"]        # For comprehensive report, always capture output
        temp_output = None
        if args.save_output:
            temp_output = os.path.join(output_dir, "temp_httpx_output.txt")
            httpx_args.extend(["-o", temp_output])

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

        print_status_header("httpx", target, "service detection")
        
        # Build command with proper handling of conditionals
        httpx_cmd = [
            "httpx",
            "-u", httpx_input,
            "-title",
            "-status-code",
            "-follow-redirects"
        ]
        
        if not args.stealth:
            httpx_cmd.extend(["-tech-detect", "-web-server"])
        
        if args.json_output:
            httpx_cmd.append("-json")
        elif temp_output:
            httpx_cmd.extend(["-o", temp_output])
            
        httpx_cmd.extend(httpx_args)        
        httpx_success, httpx_output = run_with_enhanced_realtime_output(
            cmd=httpx_cmd,
            output_file=temp_output,
            tool_name="HTTPX"
        )

        print(f"\nHTTPX scan completed!")

        if httpx_success:
            if args.save_output and comprehensive_report:
                # Read temporary output and append to comprehensive report
                httpx_content = ""
                if temp_output and os.path.exists(temp_output):
                    with open(temp_output, 'r') as f:
                        httpx_content = f.read()
                    os.remove(temp_output)  # Clean up temp file
                
                append_to_comprehensive_report(comprehensive_report, "HTTPX", httpx_content, True)
                
                if httpx_content.strip():
                    print(f"HTTP service detection results added to comprehensive report")
                else:
                    print("No HTTP services found")
            else:
                print("Real-time scan output was displayed above")
                print("Results were not saved to files (as requested)")
        else:
            print("HTTPX scan failed.")
            if args.save_output and comprehensive_report:
                append_to_comprehensive_report(comprehensive_report, "HTTPX", "Scan failed", False)
            success = False

    # NUCLEI
    elif args.nuclei:
        print(f"\nStarting nuclei vulnerability scan...")

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
        
        # For comprehensive report, always capture output
        temp_output = None
        if args.save_output:
            temp_output = os.path.join(output_dir, "temp_nuclei_output.txt")
            nuclei_args.extend(["-o", temp_output])
            
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

        print_status_header("nuclei", target, "vulnerability scan")
        
        # Build nuclei command properly
        if os.path.isfile(nuclei_input):
            nuclei_cmd = ["nuclei", "-l", nuclei_input]
        else:
            nuclei_cmd = ["nuclei", "-u", nuclei_input]
        
        # Add template specification
        if args.templates:
            nuclei_cmd.extend(["-t", args.templates])
            
        # Add tags and severity
        nuclei_cmd.extend(["-tags", args.tags])
        nuclei_cmd.extend(["-severity", args.severity])
        
        # Add output options
        if args.json_output:
            nuclei_cmd.append("-jsonl")
        elif temp_output:
            nuclei_cmd.extend(["-o", temp_output])
            
        # Add additional arguments
        nuclei_cmd.extend(nuclei_args)        
        nuclei_success, nuclei_output = run_with_enhanced_realtime_output(
            cmd=nuclei_cmd,
            output_file=temp_output,
            tool_name="Nuclei"
        )

        print(f"\n Nuclei scan completed!")

        if nuclei_success:
            if args.save_output and comprehensive_report:
                # Read temporary output and append to comprehensive report
                nuclei_content = ""
                if temp_output and os.path.exists(temp_output):
                    with open(temp_output, 'r') as f:
                        nuclei_content = f.read()
                    os.remove(temp_output)  # Clean up temp file
                
                append_to_comprehensive_report(comprehensive_report, "NUCLEI", nuclei_content, True)
                
                if nuclei_content.strip():
                    print(f" Vulnerability scan results added to comprehensive report")
                else:
                    print("WARNING: No vulnerabilities found")
            else:
                print(" Real-time scan output was displayed above")
                print(" Results were not saved to files (as requested)")
        else:
            print(" Nuclei scan failed.")
            if args.save_output and comprehensive_report:
                append_to_comprehensive_report(comprehensive_report, "NUCLEI", "Scan failed", False)
            success = False

    # Finalize comprehensive report if saving output
    if args.save_output and comprehensive_report:
        finalize_comprehensive_report(comprehensive_report, target, success)

    return success

def analyze_tool_output(line: str, tool_name: str) -> dict:
    """
    Analyze tool output line and extract relevant information.
    
    Args:
        line: Output line from the tool
        tool_name: Name of the tool (naabu, httpx, nuclei)
        
    Returns:
        Dictionary with analysis results
    """
    analysis = {
        'line_type': 'info',
        'severity': 'low',
        'contains_finding': False,
        'keywords': []
    }
    
    line_lower = line.lower()
    
    if tool_name.lower() == 'naabu':
        if 'open' in line_lower:
            analysis['line_type'] = 'finding'
            analysis['contains_finding'] = True
            analysis['severity'] = 'medium'
            analysis['keywords'] = ['port', 'open']
        elif 'error' in line_lower or 'timeout' in line_lower:
            analysis['line_type'] = 'error'
            analysis['severity'] = 'high'
        elif 'scanning' in line_lower or 'probing' in line_lower:
            analysis['line_type'] = 'progress'
    
    elif tool_name.lower() == 'httpx':
        if any(code in line for code in ['200', '201', '301', '302', '403', '404']):
            analysis['line_type'] = 'finding'
            analysis['contains_finding'] = True
            analysis['severity'] = 'medium'
            analysis['keywords'] = ['http', 'response']
        elif 'error' in line_lower or 'failed' in line_lower:
            analysis['line_type'] = 'error'
            analysis['severity'] = 'high'
        elif 'title:' in line_lower or 'server:' in line_lower:
            analysis['line_type'] = 'info'
            analysis['contains_finding'] = True
            analysis['keywords'] = ['metadata']
    
    elif tool_name.lower() == 'nuclei':
        if any(sev in line_lower for sev in ['critical', 'high', 'medium', 'low']):
            analysis['line_type'] = 'vulnerability'
            analysis['contains_finding'] = True
            if 'critical' in line_lower:
                analysis['severity'] = 'critical'
            elif 'high' in line_lower:
                analysis['severity'] = 'high'
            elif 'medium' in line_lower:
                analysis['severity'] = 'medium'
            analysis['keywords'] = ['vulnerability', 'security']
        elif 'error' in line_lower or 'failed' in line_lower:
            analysis['line_type'] = 'error'
            analysis['severity'] = 'high'
        elif 'templates loaded' in line_lower or 'scanning' in line_lower:
            analysis['line_type'] = 'progress'
    
    return analysis

def format_output_with_analytics(line: str, tool_name: str, line_count: int) -> str:
    """
    Format output line with enhanced analytics and visual indicators.
    
    Args:
        line: Raw output line
        tool_name: Name of the tool
        line_count: Current line number
        
    Returns:
        Formatted line with visual indicators
    """
    analysis = analyze_tool_output(line, tool_name)
      # Choose emoji and color based on analysis
    if analysis['line_type'] == 'vulnerability':
        if analysis['severity'] == 'critical':
            prefix = "[CRITICAL]"
        elif analysis['severity'] == 'high':
            prefix = "[HIGH]"
        elif analysis['severity'] == 'medium':
            prefix = "[MEDIUM]"
        else:
            prefix = "[LOW]"
    elif analysis['line_type'] == 'finding':
        prefix = "[FOUND]"
    elif analysis['line_type'] == 'error':
        prefix = "[ERROR]"
    elif analysis['line_type'] == 'progress':
        prefix = "[PROGRESS]"
    else:
        prefix = "[INFO]"
    
    # Add line number for easy reference
    line_num_str = f"[{line_count:04d}]"
    
    return f"{prefix} {line_num_str} {line}"

def display_live_statistics(stats: dict, tool_name: str):
    """
    Display live statistics during scan execution.
    
    Args:
        stats: Dictionary containing scan statistics
        tool_name: Name of the current tool
    """
    print(f"\nLive Statistics for {tool_name.upper()}:")
    print(f"   Lines processed: {stats.get('total_lines', 0)}")
    print(f"   Findings: {stats.get('findings', 0)}")
    print(f"   Errors: {stats.get('errors', 0)}")
    if tool_name.lower() == 'nuclei':
        print(f"   Vulnerabilities: {stats.get('vulnerabilities', 0)}")
        print(f"   Critical: {stats.get('critical', 0)} | High: {stats.get('high', 0)} | Medium: {stats.get('medium', 0)}")
    print("─" * 50)
    sys.stdout.flush()

def run_with_enhanced_realtime_output(cmd: List[str], output_file: Optional[str] = None, 
                                    tool_name: str = "Tool") -> Tuple[bool, str]:
    """
    Execute a command with enhanced real-time output streaming and analytics.
    
    Args:
        cmd: Command and arguments to execute
        output_file: Optional file to save output to
        tool_name: Name of the tool for display purposes
        
    Returns:
        Tuple of (success, captured_output)
    """
    captured_output = []
    process = None
    stats = {
        'total_lines': 0,
        'findings': 0,
        'errors': 0,
        'vulnerabilities': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    
    try:
        print_progress_indicator(f"Executing: {' '.join(cmd[:3])}...")
        
        # Start the process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Stream output line by line with enhanced analytics
        last_stats_update = time.time()
        while True:
            if process.stdout is None:
                break
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()
                if line:  # Only process non-empty lines
                    stats['total_lines'] += 1
                    
                    # Analyze the line
                    analysis = analyze_tool_output(line, tool_name)
                    
                    # Update statistics
                    if analysis['contains_finding']:
                        stats['findings'] += 1
                    if analysis['line_type'] == 'error':
                        stats['errors'] += 1
                    if analysis['line_type'] == 'vulnerability':
                        stats['vulnerabilities'] += 1
                        stats[analysis['severity']] += 1
                    
                    # Format and display the line
                    formatted_line = format_output_with_analytics(line, tool_name, stats['total_lines'])
                    print(formatted_line)
                    sys.stdout.flush()
                    
                    # Capture for file output
                    captured_output.append(line)
                    
                    # Show progress and statistics every 30 lines or 15 seconds
                    current_time = time.time()
                    if (stats['total_lines'] % 30 == 0) or (current_time - last_stats_update >= 15):
                        display_live_statistics(stats, tool_name)
                        last_stats_update = current_time
        
        # Wait for process to complete
        return_code = process.wait()
          # Final status and statistics
        print("\n" + "═" * 60)
        if return_code == 0:
            print_progress_indicator(f"{tool_name} completed successfully", "SUCCESS")
        else:
            print_progress_indicator(f"{tool_name} completed with exit code {return_code}", "WARNING")
        
        # Show final statistics
        print(f"\nFinal {tool_name.upper()} Statistics:")
        print(f"   Total lines processed: {stats['total_lines']}")
        print(f"   Total findings: {stats['findings']}")
        print(f"   Total errors: {stats['errors']}")
        if tool_name.lower() == 'nuclei' and stats['vulnerabilities'] > 0:
            print(f"   Vulnerabilities found: {stats['vulnerabilities']}")
            print(f"   Severity breakdown:")
            print(f"     Critical: {stats['critical']}")
            print(f"     High: {stats['high']}")
            print(f"     Medium: {stats['medium']}")
            print(f"     Low: {stats['low']}")
        print("═" * 60)
        
        # Save to file if requested
        if output_file and captured_output:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(captured_output))
                print_progress_indicator(f"Output saved to: {output_file}", "SAVED")
            except Exception as e:
                print_progress_indicator(f"Failed to save output: {e}", "ERROR")
        
        return return_code == 0, '\n'.join(captured_output)
    
    except subprocess.TimeoutExpired:
        print_progress_indicator("Command timed out", "TIMEOUT")
        if process:
            process.kill()
        return False, '\n'.join(captured_output)
    except KeyboardInterrupt:
        print_progress_indicator("Interrupted by user", "STOP")
        print(f"\nPartial Statistics:")
        display_live_statistics(stats, tool_name)
        if process:
            process.terminate()
        return False, '\n'.join(captured_output)
    except Exception as e:
        print_progress_indicator(f"Execution error: {e}", "ERROR")
        return False, '\n'.join(captured_output)

def check_network_connectivity():
    """Check if network connection is available - required for all scans."""
    print("Testing network connectivity...")
    
    # Method 1: Try to connect to reliable DNS servers
    dns_servers = [
        ("8.8.8.8", 53),      # Google DNS
        ("1.1.1.1", 53),      # Cloudflare DNS
        ("208.67.222.222", 53) # OpenDNS
    ]
    
    for dns_host, dns_port in dns_servers:
        try:
            print(f"  Trying to connect to {dns_host}:{dns_port}...")
            socket.create_connection((dns_host, dns_port), timeout=5)
            print(f"  ✓ Successfully connected to {dns_host}")
            return True
        except (socket.timeout, socket.error, OSError) as e:
            print(f"  ✗ Failed to connect to {dns_host}: {e}")
            continue
    
    # Method 2: Try to resolve common domains
    test_domains = ["google.com", "github.com", "cloudflare.com"]
    for domain in test_domains:
        try:
            print(f"  Trying to resolve {domain}...")
            socket.gethostbyname(domain)
            print(f"  ✓ Successfully resolved {domain}")
            return True
        except socket.gaierror as e:
            print(f"  ✗ Failed to resolve {domain}: {e}")
            continue
    
    # Method 3: Try ping with proper Linux parameters
    ping_targets = ["8.8.8.8", "1.1.1.1", "127.0.0.1"]
    for target in ping_targets:
        try:
            print(f"  Trying to ping {target}...")
            # Use -c for count, -W for timeout in seconds (Linux standard)
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "3", target], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                timeout=10
            )
            if result.returncode == 0:
                print(f"  ✓ Successfully pinged {target}")
                return True
            else:
                print(f"  ✗ Ping to {target} failed (return code: {result.returncode})")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError) as e:
            print(f"  ✗ Ping command failed for {target}: {e}")
            continue
      # Method 4: Try HTTP connectivity test
    try:
        print("  Trying HTTP connectivity test...")
        urllib.request.urlopen('http://www.google.com', timeout=10)
        print("  ✓ HTTP connectivity test successful")
        return True
    except Exception as e:
        print(f"  ✗ HTTP connectivity test failed: {e}")
    
    # All methods failed
    print("\n[ERROR] All network connectivity tests failed!")
    print("Possible issues:")
    print("  - No internet connection")
    print("  - Firewall blocking outbound connections")
    print("  - DNS resolution problems")
    print("  - Network interface not configured")
    print("\nNetwork connectivity is required for security scanning operations.")
    print("Please check your network configuration and try again.")
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
      # Check network connectivity (disabled)
    print("Network connectivity check")
    print("Note: Network connectivity check has been disabled for testing purposes.")
    
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
    
    # Show comprehensive report location if saving output and scan was successful
    if args.save_output and success:
        comprehensive_report_file = os.path.join(output_dir, "comprehensive_scan_report.txt")
        if os.path.exists(comprehensive_report_file):
            print(f" Comprehensive scan report saved to: {comprehensive_report_file}")
            file_size = os.path.getsize(comprehensive_report_file)
            print(f" Report size: {file_size} bytes")
        else:
            print(" WARNING: Comprehensive report was not created")
    
    if success:
        print(" Scan completed successfully!")
    else:
        print("WARNING: Scan completed with issues.")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
