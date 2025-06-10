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

def print_progress_indicator(message: str, symbol: str = "*", color: Optional[str] = None):
    """Print a progress indicator with timestamp and optional color."""
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    
    # Add color coding for different message types
    if color == "green" or symbol == "SUCCESS":
        prefix = "\033[92m[SUCCESS]\033[0m"
    elif color == "red" or symbol == "ERROR":
        prefix = "\033[91m[ERROR]\033[0m"
    elif color == "yellow" or symbol == "WARNING":
        prefix = "\033[93m[WARNING]\033[0m"
    elif color == "blue" or symbol == "INFO":
        prefix = "\033[94m[INFO]\033[0m"
    elif symbol == "FOUND":
        prefix = "\033[95m[FOUND]\033[0m"
    elif symbol == "SCAN":
        prefix = "\033[96m[SCAN]\033[0m"
    elif symbol == "SAVED":
        prefix = "\033[92m[SAVED]\033[0m"
    elif symbol == "TIMEOUT":
        prefix = "\033[93m[TIMEOUT]\033[0m"
    elif symbol == "STOP":
        prefix = "\033[91m[STOP]\033[0m"
    else:
        prefix = f"[{symbol}]"
    
    print(f"[{timestamp}] {prefix} {message}")
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
                    
                    # Add colored prefixes for better visibility with improved categorization
                    line_lower = line.lower()
                    if any(keyword in line_lower for keyword in ['error', 'failed', 'timeout', 'exception']):
                        formatted_line = f"\033[91m[ERROR]\033[0m {line}"
                    elif any(keyword in line_lower for keyword in ['found', 'detected', 'open', 'discovered']):
                        formatted_line = f"\033[95m[FOUND]\033[0m {line}"
                    elif any(keyword in line_lower for keyword in ['scanning', 'probing', 'testing', 'analyzing']):
                        formatted_line = f"\033[96m[SCAN]\033[0m {line}"
                    elif any(keyword in line_lower for keyword in ['vulnerable', 'critical', 'high']):
                        formatted_line = f"\033[91m[VULN]\033[0m {line}"
                    elif any(keyword in line_lower for keyword in ['warning', 'warn']):
                        formatted_line = f"\033[93m[WARN]\033[0m {line}"
                    elif any(keyword in line_lower for keyword in ['info', 'loaded', 'using', 'started']):
                        formatted_line = f"\033[94m[INFO]\033[0m {line}"
                    else:
                        formatted_line = f"[DATA] {line}"
                    
                    print(formatted_line)
                    sys.stdout.flush()
                    
                    # Capture for file output (original line without formatting)
                    captured_output.append(line)
                    
                    # Show progress every 50 lines with more informative message
                    if line_count % 50 == 0:
                        print_progress_indicator(f"Processed {line_count} lines of output...")
                    
                    # Show periodic statistics for long-running scans
                    if line_count % 100 == 0:
                        findings_count = len([l for l in captured_output if any(kw in l.lower() for kw in ['found', 'open', 'vulnerable'])])
                        print_progress_indicator(f"Status: {line_count} lines, {findings_count} potential findings detected")
        
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
                      # Progress indicator every 10 seconds with enhanced statistics
                    if current_time - last_update >= 10:
                        summary = create_realtime_summary(output_lines, "Command")
                        print_progress_indicator(f"Still running... {summary}")
                        last_update = current_time
                    
                    # Show detailed statistics every 100 lines
                    if len(output_lines) % 100 == 0 and len(output_lines) > 0:
                        display_scan_statistics(output_lines, "Command")
        
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
    
    # Initialize the comprehensive report file with enhanced header
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("           COMPREHENSIVE VULNERABILITY SCAN REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Target: {target}\n")
        f.write(f"Scan Start Time: {timestamp}\n")
        f.write(f"Generated by: MTScan Linux Vulnerability Analysis Toolkit\n")
        f.write(f"Platform: {platform.system()} {platform.release()}\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("SCAN OVERVIEW:\n")
        f.write("-" * 40 + "\n")
        f.write("This report contains results from automated security scanning tools:\n")
        f.write("- Naabu: Port scanning and service discovery\n")
        f.write("- Httpx: HTTP service enumeration and analysis\n")
        f.write("- Nuclei: Vulnerability detection and security testing\n")
        f.write("\nEach section below contains detailed results from the respective tools.\n")
        f.write("Results are presented in chronological order of execution.\n\n")
    
    return report_file

def append_to_comprehensive_report(report_file: str, tool_name: str, content: str, success: bool):
    """Append tool results to the comprehensive report file with enhanced formatting."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(report_file, 'a', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write(f"{tool_name.upper()} SCAN RESULTS\n")
        f.write("=" * 80 + "\n")
        f.write(f"Tool: {tool_name}\n")
        f.write(f"Completion Time: {timestamp}\n")
        f.write(f"Status: {'SUCCESS' if success else 'FAILED'}\n")
        f.write(f"Output Length: {len(content.splitlines()) if content else 0} lines\n")
        f.write("-" * 80 + "\n")
        
        if content and content.strip():
            # Add some basic analysis of the content
            lines = content.splitlines()
            findings = []
            errors = []
            
            for line in lines:
                line_lower = line.lower()
                if any(kw in line_lower for kw in ['open', 'found', 'vulnerable', 'detected']):
                    findings.append(line)
                elif any(kw in line_lower for kw in ['error', 'failed', 'timeout']):
                    errors.append(line)
            
            f.write(f"SUMMARY:\n")
            f.write(f"- Total output lines: {len(lines)}\n")
            f.write(f"- Potential findings: {len(findings)}\n")
            f.write(f"- Errors/warnings: {len(errors)}\n")
            f.write("-" * 40 + "\n\n")
            
            if findings:
                f.write("KEY FINDINGS:\n")
                for i, finding in enumerate(findings[:10], 1):  # Show top 10 findings
                    f.write(f"{i:2d}. {finding}\n")
                if len(findings) > 10:
                    f.write(f"    ... and {len(findings) - 10} more findings\n")
                f.write("\n")
            
            f.write("DETAILED OUTPUT:\n")
            f.write("-" * 40 + "\n")
            f.write(content)
            f.write("\n")
        else:
            f.write("NO OUTPUT: Scan completed but no results were generated.\n")
            f.write("This could indicate:\n")
            f.write("- No findings were discovered\n")
            f.write("- The target was not responsive\n")
            f.write("- The scan parameters were too restrictive\n")
        
        f.write("\n" + "=" * 80 + "\n\n")

def finalize_comprehensive_report(report_file: str, target: str, overall_success: bool):
    """Finalize the comprehensive report with summary statistics and recommendations."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Read the report to analyze results
    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Enhanced result counting and analysis
    naabu_executed = "NAABU SCAN RESULTS" in content
    httpx_executed = "HTTPX SCAN RESULTS" in content
    nuclei_executed = "NUCLEI SCAN RESULTS" in content
    
    # Count various findings with better detection
    port_findings = []
    http_findings = []
    vuln_findings = []
    
    lines = content.splitlines()
    for line in lines:
        line_lower = line.lower()
        if 'open' in line_lower and any(port in line for port in [':', '/']):
            port_findings.append(line.strip())
        elif any(proto in line_lower for proto in ['http://', 'https://']):
            http_findings.append(line.strip())
        elif any(vuln in line_lower for vuln in ['critical', 'high', 'medium', 'low', 'cve-']):
            vuln_findings.append(line.strip())
    
    # Remove duplicates
    port_findings = list(set(port_findings))
    http_findings = list(set(http_findings))
    vuln_findings = list(set(vuln_findings))
    
    # Append enhanced final summary
    with open(report_file, 'a', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("                      EXECUTIVE SUMMARY\n")
        f.write("=" * 80 + "\n")
        f.write(f"Target Analyzed: {target}\n")
        f.write(f"Scan Completion: {timestamp}\n")
        f.write(f"Overall Status: {'SUCCESS' if overall_success else 'COMPLETED WITH ISSUES'}\n")
        f.write(f"Report Generated: {os.path.basename(report_file)}\n\n")
        
        f.write("TOOLS EXECUTED:\n")
        f.write("-" * 40 + "\n")
        f.write(f"- Naabu (Port Scanner): {'YES' if naabu_executed else 'NO'}\n")
        f.write(f"- Httpx (HTTP Analysis): {'YES' if httpx_executed else 'NO'}\n")
        f.write(f"- Nuclei (Vulnerability Scanner): {'YES' if nuclei_executed else 'NO'}\n\n")
        
        f.write("FINDINGS SUMMARY:\n")
        f.write("-" * 40 + "\n")
        f.write(f"- Open Ports Detected: {len(port_findings)}\n")
        f.write(f"- HTTP Services Found: {len(http_findings)}\n")
        f.write(f"- Security Issues Identified: {len(vuln_findings)}\n\n")
        
        if port_findings:
            f.write("TOP OPEN PORTS:\n")
            for i, port in enumerate(port_findings[:5], 1):
                f.write(f"  {i}. {port}\n")
            if len(port_findings) > 5:
                f.write(f"  ... and {len(port_findings) - 5} more ports\n")
            f.write("\n")
        
        if http_findings:
            f.write("HTTP SERVICES:\n")
            for i, http in enumerate(http_findings[:5], 1):
                f.write(f"  {i}. {http}\n")
            if len(http_findings) > 5:
                f.write(f"  ... and {len(http_findings) - 5} more services\n")
            f.write("\n")
        
        if vuln_findings:
            f.write("SECURITY CONCERNS:\n")
            for i, vuln in enumerate(vuln_findings[:5], 1):
                f.write(f"  {i}. {vuln}\n")
            if len(vuln_findings) > 5:
                f.write(f"  ... and {len(vuln_findings) - 5} more issues\n")
            f.write("\n")
        
        # Risk assessment and recommendations
        risk_level = "LOW"
        if len(vuln_findings) > 5:
            risk_level = "HIGH"
        elif len(vuln_findings) > 0 or len(port_findings) > 10:
            risk_level = "MEDIUM"
        
        f.write("RISK ASSESSMENT:\n")
        f.write("-" * 40 + "\n")
        f.write(f"Overall Risk Level: {risk_level}\n")
        f.write(f"Based on: {len(port_findings)} open ports, {len(http_findings)} HTTP services, {len(vuln_findings)} security issues\n\n")
        
        f.write("RECOMMENDATIONS:\n")
        f.write("-" * 40 + "\n")
        if vuln_findings:
            f.write("1. IMMEDIATE: Review and address identified security vulnerabilities\n")
            f.write("2. Review exposed services and close unnecessary ports\n")
            f.write("3. Implement proper security controls and monitoring\n")
        elif port_findings:
            f.write("1. Review exposed services and close unnecessary ports\n")
            f.write("2. Ensure proper access controls are in place\n")
            f.write("3. Regular security scanning is recommended\n")
        else:
            f.write("1. Continue regular security assessments\n")
            f.write("2. Monitor for new services and exposures\n")
            f.write("3. Maintain security best practices\n")
        
        f.write("\n")
        f.write("NOTE: This is an automated security assessment. Manual verification\n")
        f.write("of findings is recommended for accurate risk evaluation.\n\n")
        
        f.write("=" * 80 + "\n")
        f.write(f"End of Comprehensive Security Report - Generated on {timestamp}\n")
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
        return "top-100"
    elif port_spec == "top-1000":
        # Return None to use naabu's default top-1000 ports
        return None
    elif port_spec == "all":
        return "1-65535"
    else:
        # Assume it's a specific port range like "80,443,8000-9000"
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

        # For comprehensive report, always capture output
        temp_output = None
        if args.save_output:
            temp_output = os.path.join(output_dir, "temp_naabu_output.txt")        # Initialize naabu arguments - don't use verbose mode since we'll use silent mode
        naabu_args = []
        if args.stealth:
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

def display_scan_statistics(output_lines: List[str], tool_name: str):
    """Display comprehensive statistics about scan output in real-time."""
    if not output_lines:
        print_progress_indicator("No output data to analyze", "INFO")
        return
    
    # Analyze output content
    total_lines = len(output_lines)
    findings = []
    errors = []
    warnings = []
    info_lines = []
    
    for line in output_lines:
        line_lower = line.lower()
        if any(kw in line_lower for kw in ['found', 'open', 'vulnerable', 'detected', 'discovered']):
            findings.append(line)
        elif any(kw in line_lower for kw in ['error', 'failed', 'timeout', 'exception']):
            errors.append(line)
        elif any(kw in line_lower for kw in ['warning', 'warn']):
            warnings.append(line)
        else:
            info_lines.append(line)
    
    # Display statistics
    print(f"\n{'-' * 60}")
    print(f"REAL-TIME {tool_name.upper()} STATISTICS")
    print(f"{'-' * 60}")
    print(f"Total Output Lines: {total_lines}")
    print(f"Findings Detected:  {len(findings)}")
    print(f"Errors/Failures:    {len(errors)}")
    print(f"Warnings:           {len(warnings)}")
    print(f"Info/Data Lines:    {len(info_lines)}")
    
    if findings:
        print(f"\nRECENT FINDINGS (Last 3):")
        for i, finding in enumerate(findings[-3:], 1):
            print(f"  {i}. {finding[:80]}{'...' if len(finding) > 80 else ''}")
    
    if errors:
        print(f"\nRECENT ERRORS (Last 2):")
        for i, error in enumerate(errors[-2:], 1):
            print(f"  {i}. {error[:80]}{'...' if len(error) > 80 else ''}")
    
    print(f"{'-' * 60}")

def create_realtime_summary(captured_output: List[str], tool_name: str) -> str:
    """Create a real-time summary of scan progress and findings."""
    if not captured_output:
        return "No output captured yet."
    
    total_lines = len(captured_output)
    findings_count = len([line for line in captured_output if any(kw in line.lower() for kw in ['found', 'open', 'vulnerable'])])
    errors_count = len([line for line in captured_output if any(kw in line.lower() for kw in ['error', 'failed'])])
    
    summary = f"Lines: {total_lines} | Findings: {findings_count} | Errors: {errors_count}"
    
    # Add tool-specific insights
    if tool_name.lower() == 'naabu':
        ports_found = len([line for line in captured_output if 'open' in line.lower()])
        summary += f" | Open Ports: {ports_found}"
    elif tool_name.lower() == 'httpx':
        http_responses = len([line for line in captured_output if any(code in line for code in ['200', '301', '302', '403', '404'])])
        summary += f" | HTTP Responses: {http_responses}"
    elif tool_name.lower() == 'nuclei':
        vulns = len([line for line in captured_output if any(sev in line.lower() for sev in ['critical', 'high', 'medium'])])
        summary += f" | Vulnerabilities: {vulns}"
    
    return summary

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
          # Show enhanced final statistics with tool-specific insights
        print(f"\nFINAL {tool_name.upper()} SCAN RESULTS:")
        print(f"{'=' * 60}")
        print(f"Total Output Lines:     {stats['total_lines']}")
        print(f"Findings Detected:      {stats['findings']}")
        print(f"Errors Encountered:     {stats['errors']}")
        
        if tool_name.lower() == 'nuclei' and stats['vulnerabilities'] > 0:
            print(f"Vulnerabilities Found:  {stats['vulnerabilities']}")
            print(f"\nSeverity Breakdown:")
            print(f"  Critical: {stats['critical']}")
            print(f"  High:     {stats['high']}")
            print(f"  Medium:   {stats['medium']}")
            print(f"  Low:      {stats['low']}")
            
            # Risk assessment
            if stats['critical'] > 0:
                print(f"\nRISK LEVEL: CRITICAL - Immediate attention required!")
            elif stats['high'] > 0:
                print(f"\nRISK LEVEL: HIGH - Address high-severity issues promptly")
            elif stats['medium'] > 0:
                print(f"\nRISK LEVEL: MEDIUM - Review and remediate when possible")
            else:
                print(f"\nRISK LEVEL: LOW - Monitor and maintain security posture")
        
        elif tool_name.lower() == 'naabu':
            ports_found = len([line for line in captured_output if 'open' in line.lower()])
            print(f"Open Ports Found:       {ports_found}")
            if ports_found > 0:
                print(f"\nPort Security Notice: Review exposed services and close unnecessary ports")
        
        elif tool_name.lower() == 'httpx':
            http_services = len([line for line in captured_output if any(code in line for code in ['200', '301', '302'])])
            print(f"HTTP Services Found:    {http_services}")
            if http_services > 0:
                print(f"\nHTTP Security Notice: Review web services for security configurations")
        
        # Overall assessment
        if stats['errors'] > stats['findings']:
            print(f"\nSCAN STATUS: Multiple errors detected - results may be incomplete")
        elif stats['findings'] == 0:
            print(f"\nSCAN STATUS: No significant findings - target appears secure")
        else:
            print(f"\nSCAN STATUS: Scan completed with findings - review results above")
        print("═" * 60)
        
        # Save to file if requested with enhanced formatting
        if output_file and captured_output:
            try:
                # Use enhanced output file creation for better reports
                if create_enhanced_output_file(output_file, captured_output, tool_name, stats):
                    print_progress_indicator(f"Enhanced output saved to: {output_file}", "SAVED")
                else:
                    # Fallback to simple output if enhanced fails
                    with open(output_file, 'w', encoding='utf-8') as f:
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

def create_enhanced_output_file(output_file: str, captured_output: List[str], tool_name: str, stats: dict) -> bool:
    """Create an enhanced output file with statistics and analysis."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write("=" * 80 + "\n")
            f.write(f"{tool_name.upper()} SCAN OUTPUT REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {timestamp}\n")
            f.write(f"Tool: {tool_name}\n")
            f.write(f"Total Lines: {len(captured_output)}\n")
            f.write("=" * 80 + "\n\n")
            
            # Statistics Summary
            if stats:
                f.write("SCAN STATISTICS:\n")
                f.write("-" * 40 + "\n")
                f.write(f"Total Output Lines: {stats.get('total_lines', 0)}\n")
                f.write(f"Findings: {stats.get('findings', 0)}\n")
                f.write(f"Errors: {stats.get('errors', 0)}\n")
                f.write(f"Vulnerabilities: {stats.get('vulnerabilities', 0)}\n")
                f.write("-" * 40 + "\n\n")
            
            # Key Findings Section
            findings = [line for line in captured_output if any(kw in line.lower() for kw in ['found', 'open', 'vulnerable', 'detected'])]
            if findings:
                f.write("KEY FINDINGS:\n")
                f.write("-" * 40 + "\n")
                for i, finding in enumerate(findings, 1):
                    f.write(f"{i:3d}. {finding}\n")
                f.write("-" * 40 + "\n\n")
            
            # Errors Section
            errors = [line for line in captured_output if any(kw in line.lower() for kw in ['error', 'failed', 'timeout'])]
            if errors:
                f.write("ERRORS AND WARNINGS:\n")
                f.write("-" * 40 + "\n")
                for i, error in enumerate(errors, 1):
                    f.write(f"{i:3d}. {error}\n")
                f.write("-" * 40 + "\n\n")
            
            # Complete Output
            f.write("COMPLETE OUTPUT LOG:\n")
            f.write("=" * 80 + "\n")
            for i, line in enumerate(captured_output, 1):
                f.write(f"{i:4d}: {line}\n")
            
            # Footer
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"End of {tool_name.upper()} Report - Generated {timestamp}\n")
            f.write("=" * 80 + "\n")
        
        return True
    except Exception as e:
        print_progress_indicator(f"Failed to create enhanced output file: {e}", "ERROR")
        return False

def check_network_connectivity():
    """Check if network connection is available - required for all scans."""
    print("Testing network connectivity...")
      # Method 1: Try to connect to reliable DNS servers
    dns_servers = [
        ("8.8.8.8", 53),      # Google DNS
        ("1.1.1.1", 53),      # Cloudflare DNS
        ("208.67.222.222", 53), # OpenDNS
        ("9.9.9.9", 53)       # Quad9 DNS
    ]
    
    for dns_host, dns_port in dns_servers:
        try:
            print(f"  Trying to connect to {dns_host}:{dns_port}...")
            with socket.create_connection((dns_host, dns_port), timeout=5) as sock:
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
    ping_targets = ["8.8.8.8", "1.1.1.1"]  # Removed localhost as it doesn't test internet connectivity
    for target in ping_targets:
        try:
            print(f"  Trying to ping {target}...")
            # Use -c for count, -W for timeout in seconds (Linux standard)
            # Added -q for quiet mode to reduce output
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "3", "-q", target], 
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
    http_urls = [
        'https://www.google.com',
        'https://github.com', 
        'https://1.1.1.1'
    ]
    for url in http_urls:
        try:
            print(f"  Trying HTTP connectivity test to {url}...")
            urllib.request.urlopen(url, timeout=10)
            print(f"  ✓ HTTP connectivity test successful to {url}")
            return True
        except Exception as e:
            print(f"  ✗ HTTP connectivity test failed for {url}: {e}")
            continue
      # All methods failed
    print("\n[ERROR] All network connectivity tests failed!")
    print("Possible issues:")
    print("  - No internet connection")
    print("  - Firewall blocking outbound connections")
    print("  - DNS resolution problems")
    print("  - Network interface not configured")
    print("  - Proxy configuration required")
    print("\nNetwork connectivity is required for security scanning operations.")
    print("Please check your network configuration and try again.")
    print("\nTroubleshooting steps:")
    print("  1. Check if you can browse the internet normally")
    print("  2. Verify DNS settings (try: nslookup google.com)")
    print("  3. Check for corporate firewall/proxy settings")
    print("  4. Ensure ports 53, 80, and 443 are not blocked")
    return False

def check_network_override() -> bool:
    """Check if network override flag exists to bypass connectivity checks."""
    override_path = Path(__file__).parent / 'network_override'
    if override_path.exists():
        print("  Network override flag found - bypassing connectivity checks")
        return True
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
    if not check_network_connectivity() and not check_network_override():
        print(" Network connectivity check failed.")
        print(" Some features may not work without internet access.")
        response = input("Continue anyway? [y/N]: ")

        # Handle empty response (default to 'n' if no input)
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
