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
        prefix = "[SUCCESS]"
    elif color == "red" or symbol == "ERROR":
        prefix = "[ERROR]"
    elif color == "yellow" or symbol == "WARNING":
        prefix = "[WARNING]"
    elif color == "blue" or symbol == "INFO":
        prefix = "[INFO]"
    elif symbol == "FOUND":
        prefix = "[FOUND]"
    elif symbol == "SCAN":
        prefix = "[SCAN]"
    elif symbol == "SAVED":
        prefix = "[SAVED]"
    elif symbol == "TIMEOUT":
        prefix = "[TIMEOUT]"
    elif symbol == "STOP":
        prefix = "[STOP]"
    else:
        prefix = "[INFO]"
    
    print(f"[{timestamp}] {prefix} {message}")
    sys.stdout.flush()

def run_with_clean_output_only(cmd: List[str], output_file: Optional[str] = None, 
                             tool_name: str = "Tool") -> Tuple[bool, str]:
    """
    Execute a command silently and capture only clean results for graphics usage.
    No real-time output, just clean structured data.
    
    Args:
        cmd: Command and arguments to execute
        output_file: Optional file to save clean output to
        tool_name: Name of the tool for display purposes
        
    Returns:
        Tuple of (success, captured_output)
    """
    captured_output = []
    process = None
    
    try:
        print(f"[{tool_name}] Starting scan (silent mode for clean output)...")
        
        # Validate command
        if not cmd or not cmd[0]:
            print(f"[{tool_name}] ERROR: Invalid command provided")
            return False, ""
        
        # Check if executable exists
        if not shutil.which(cmd[0]) and not os.path.exists(cmd[0]):
            print(f"[{tool_name}] ERROR: Executable not found: {cmd[0]}")
            return False, ""
        
        # Start process with silent configuration
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,  # Separate stderr to avoid noise
            universal_newlines=True,
            bufsize=1,
            cwd=os.getcwd()
        )
        
        # Capture all output without displaying
        stdout, stderr = process.communicate()
        return_code = process.returncode
          # Process stdout lines and filter for clean results
        if stdout:
            lines = stdout.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and not is_noise_line(line):
                    captured_output.append(line)
        
        # Determine if scan was successful
        # For HTTPx, no results can be expected if no web services are running
        scan_successful = return_code == 0 or (tool_name.upper() == "HTTPX" and return_code != 0 and len(captured_output) == 0)
        
        # Show completion status
        if scan_successful:
            if len(captured_output) > 0:
                print(f"[{tool_name}] Scan completed successfully - {len(captured_output)} results found")
            else:
                if tool_name.upper() == "HTTPX":
                    print(f"[{tool_name}] Scan completed successfully - No HTTP services found on target")
                else:
                    print(f"[{tool_name}] Scan completed successfully - No results found")
        else:
            print(f"[{tool_name}] Scan completed with errors - {len(captured_output)} results")
            # Add any relevant error info
            if stderr and stderr.strip():
                error_lines = [line.strip() for line in stderr.strip().split('\n') if line.strip()]
                relevant_errors = [line for line in error_lines if is_relevant_error(line)]
                if relevant_errors:
                    print(f"[{tool_name}] Errors: {'; '.join(relevant_errors[:3])}")          # Save clean output to file in graphics-ready format
        if output_file and captured_output:
            try:
                # Use graphics formatting for the saved file
                save_graphics_ready_results(captured_output, output_file, tool_name.lower(), "target")
            except Exception as e:
                print(f"[{tool_name}] Failed to save output: {e}")
        
        return scan_successful, '\n'.join(captured_output)
        
    except subprocess.TimeoutExpired:
        print(f"[{tool_name}] Command timed out")
        if process:
            process.kill()
        return False, '\n'.join(captured_output)
    except KeyboardInterrupt:
        print(f"[{tool_name}] Interrupted by user")
        if process:
            process.terminate()
        return False, '\n'.join(captured_output)
    except Exception as e:
        print(f"[{tool_name}] Execution failed: {e}")
        if process:
            process.terminate()
        return False, '\n'.join(captured_output)

def is_noise_line(line: str) -> bool:
    """
    Check if a line is noise/verbose output that should be filtered out.
    Only keep actual scan results for graphics usage.
    
    Args:
        line: Line to check
        
    Returns:
        True if line should be filtered out
    """
    if not line or not line.strip():
        return True
    
    line = line.strip()
    line_lower = line.lower()
    
    # Filter out common noise patterns
    noise_patterns = [
        # Progress and status messages
        'starting', 'finished', 'loading', 'initializing', 'progress:',
        'scanning', 'processing', 'completed', 'templates loaded',
        'using', 'target', 'configuration', 'version', 'author',
        'license', 'website', 'update', 'projectdiscovery.io',
        
        # Log level indicators
        '[inf]', '[wrn]', '[err]', '[dbg]', '[info]', '[debug]', '[warn]',
        
        # Performance/config messages
        'rate limit', 'concurrency', 'threads', 'timeout', 'retries',
        'maximum', 'minimum', 'bulk-size', 'templates excluded',
        
        # Visual elements and decorations
        '════', '────', '▶', '✓', '✗', '⚠', '│', '┌', '┐', '└', '┘',
        
        # Generic status words that don't indicate results
        'stats', 'current progress', 'scan completed', 'execution completed',
        'templates loaded for', 'new templates added', 'templates available',
        
        # Nuclei specific noise
        'templates loaded in', 'templates clustered into', 'requests made',
        'matched at', 'templates executed', 'no results found',
          # Httpx specific noise  
        'input processed', 'running httpx', 'probe finished', 'httpx', 'started',
        'finished at', 'requests sent', 'responses received', 'test complete',
        
        # Naabu specific noise
        'packets sent', 'ports scanned', 'host discovery', 'syn scan',
        'connect scan', 'interface selected'
    ]
    
    # Check for noise patterns
    for pattern in noise_patterns:
        if pattern in line_lower:
            return True
    
    # Filter out lines that are just URLs without results
    if line.startswith(('http://', 'https://')) and len(line.split()) == 1:
        # This is likely just a URL being processed, not a result
        return True
    
    # Filter out lines that are just IP addresses without port info
    if ':' not in line and all(c.isdigit() or c == '.' for c in line.replace(' ', '')):
        return True
    
    # Filter out empty brackets or minimal content
    if line.strip() in ['[]', '{}', '()', '--', '==', '||']:
        return True
    
    # Keep lines that look like actual results
    result_indicators = [
        # Port results (IP:PORT)
        r'\d+\.\d+\.\d+\.\d+:\d+',
        # HTTP results with status codes
        r'http[s]?://.*\s+\[\d+\]',
        # Vulnerability findings
        r'\[.*\].*http[s]?://',
        # Technology detection
        r'http[s]?://.*\s+\[.*\]'
    ]
    
    import re
    for pattern in result_indicators:
        if re.search(pattern, line):
            return False
    
    # If line contains actual findings keywords, keep it
    finding_keywords = ['open', 'closed', 'filtered', 'critical', 'high', 'medium', 'low', 
                       'vulnerable', 'cve-', 'apache', 'nginx', 'iis', 'tomcat']
    
    if any(keyword in line_lower for keyword in finding_keywords):
        # But only if it's not just a status message
        if not any(noise in line_lower for noise in ['loading', 'using', 'starting', 'found template']):
            return False
    
    # Default: filter out (most lines are noise in verbose output)
    return True

def is_relevant_error(line: str) -> bool:
    """
    Check if an error line contains relevant information.
    
    Args:
        line: Error line to check
        
    Returns:
        True if error is relevant
    """
    relevant_errors = [
        'connection refused',
        'timeout',
        'permission denied',
        'not found',
        'failed to',
        'error:',
        'unable to'
    ]
    
    line_lower = line.lower()
    return any(error.lower() in line_lower for error in relevant_errors)

def run_with_enhanced_realtime_output(cmd: List[str], output_file: Optional[str] = None, 
                                    tool_name: str = "Tool") -> Tuple[bool, str]:
    """
    Execute a command with enhanced real-time output streaming and robust error handling.
    
    Args:
        cmd: Command and arguments to execute
        output_file: Optional file to save output to
        tool_name: Name of the tool for display purposes
        
    Returns:
        Tuple of (success, captured_output)
    """
    captured_output = []
    process = None
    line_count = 0
    
    try:
        print_progress_indicator(f"Starting {tool_name} execution", "SCAN")
        
        # Validate command
        if not cmd or not cmd[0]:
            print_progress_indicator("Invalid command provided", "ERROR")
            return False, ""
            
        # Check if executable exists
        if not shutil.which(cmd[0]) and not os.path.exists(cmd[0]):
            print_progress_indicator(f"Executable not found: {cmd[0]}", "ERROR")
            return False, ""
        
        # Start process with proper configuration
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
            cwd=os.getcwd()
        )
        
        print_progress_indicator(f"Process started with PID: {process.pid}", "INFO")
          # Stream output in real-time
        while True:
            if process.stdout is None:
                break
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()
                line_count += 1
                
                # Display line immediately
                print(line)
                captured_output.append(line)
                
                # Show progress every 50 lines
                if line_count % 50 == 0:
                    print_progress_indicator(f"Processed {line_count} lines of output...", "INFO")
                
                # Show periodic statistics for long-running scans
                if line_count % 100 == 0:
                    findings_count = len([l for l in captured_output if any(kw in l.lower() for kw in ['found', 'open', 'vulnerable'])])
                    print_progress_indicator(f"Status: {line_count} lines, {findings_count} potential findings detected", "INFO")
        
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
        print_progress_indicator(f"Execution failed: {e}", "ERROR")
        if process:
            process.terminate()
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
    """Create a timestamped output directory with error handling."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitize target name for directory
    safe_target = "".join(c for c in target_name if c.isalnum() or c in '-_.')
    output_dir = f"results_{safe_target}_{timestamp}"
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        print_progress_indicator(f"Created output directory: {output_dir}", "INFO")
        return output_dir
    except Exception as e:
        print_progress_indicator(f"Failed to create output directory: {e}", "ERROR")
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
        line_lower = line.lower().strip()
        
        # Only look for findings in actual tool output sections, not in headers or static text
        if line_lower.startswith(('=', '-', 'tool:', 'completion time:', 'status:', 'output length:', 'no output:', 'this could indicate:', 'scan overview:', 'this report contains', 'each section below', 'results are presented')):
            continue
            
        # Port findings - look for specific port patterns
        if ('open' in line_lower or 'listening' in line_lower) and any(port_pattern in line for port_pattern in [':', '/tcp', '/udp', 'port ']):
            port_findings.append(line.strip())
        # HTTP findings - look for actual HTTP service responses
        elif any(proto in line_lower for proto in ['http://', 'https://']) and not line_lower.startswith('testing urls:'):
            http_findings.append(line.strip())
        # Vulnerability findings - look for actual vulnerability indicators, not just severity words in headers
        elif any(vuln_indicator in line_lower for vuln_indicator in ['cve-', '[critical]', '[high]', '[medium]', '[low]', 'vulnerability found', 'exploit available']) and not any(header in line_lower for header in ['security issues identified:', 'vulnerability scanner:', 'security concerns:']):
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
    if not port_spec:
        # Return None to use naabu's default behavior
        return None
          # Handle legacy "top-N" format from interactive menu
    if port_spec.startswith("top-"):
        try:
            # Extract N from "top-N" format
            num_ports = port_spec.split("-")[1]
            # Validate the number is reasonable for naabu (max 1000 for stability)
            num_ports_int = int(num_ports)
            if num_ports_int > 1000:
                print(f"Warning: {num_ports_int} is a large number of ports. Limiting to 1000 for better performance.")
                return "1000"
            elif num_ports_int < 1:
                print(f"Warning: Invalid port count {num_ports_int}. Using default 100.")
                return "100"
            # We'll return the number as a string, it will be used with -top-ports flag
            return num_ports
        except (IndexError, ValueError):
            # If parsing fails, use default behavior
            print("Warning: Failed to parse port specification. Using default 100 ports.")
            return "100"
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
        print(f"\nStarting naabu port scan...")        # Port specification logic - prioritize explicit --ports over --top-ports to avoid conflicts
        if args.ports:
            # If specific ports are provided via -p/--ports, use those
            ports_to_scan = args.ports
        elif args.top_ports:
            # If top ports are specified via --top-ports, format them as "top-N"
            ports_to_scan = f"top-{args.top_ports}"
        else:
            # Default to top 1000 ports if nothing specified
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
            temp_output = os.path.join(output_dir, "temp_naabu_output.txt")        # Initialize naabu arguments for enhanced real-time output
        naabu_args = []  # Don't add -v here to avoid duplicates - it's added later
        if args.stealth:
            naabu_args.extend([
                "-rate", "10",
                "-c", "25",
                "-scan-type", "syn",
                "-retries", "1",                "-warm-up-time", "2"  # Add warm-up time for stability
            ])
        else:
            # Set default values, but allow user-specified values to override
            default_rate = "1000"
            default_threads = "50"
            
            # Use user-specified values if provided, otherwise use defaults
            if args.rate:
                naabu_args.extend(["-rate", str(args.rate)])
            else:
                naabu_args.extend(["-rate", default_rate])
            
            if args.threads:
                naabu_args.extend(["-c", str(args.threads)])
            else:
                naabu_args.extend(["-c", default_threads])
            
            naabu_args.extend(["-warm-up-time", "2"])  # Add warm-up time for stability
          # Add other user-specified naabu flags (but skip threads and rate since we handled them above)
        # Skip threads and rate since we handled them above to avoid duplicates
        # Validate and add other flags, ensuring no None values are passed
        if args.exclude_ports:
            naabu_args.extend(["-exclude-ports", args.exclude_ports])
        if args.scan_type:
            naabu_args.extend(["-scan-type", args.scan_type])
        if args.naabu_timeout and args.naabu_timeout is not None:
            naabu_args.extend(["-timeout", str(args.naabu_timeout)])
        if args.naabu_retries and args.naabu_retries is not None:
            naabu_args.extend(["-retries", str(args.naabu_retries)])
        
        # We'll handle top ports below with mapped_ports to avoid duplicate flags        # Comment out to prevent duplicate -top-ports flags
        #if args.top_ports:
        #    naabu_args.extend(["-top-ports", str(args.top_ports)])
        
        if args.source_port and args.source_port is not None:
            naabu_args.extend(["-source-port", str(args.source_port)])
        if args.interface:
            naabu_args.extend(["-interface", args.interface])
        if args.host_discovery:
            naabu_args.append("-Pn")
        if args.ping:
            naabu_args.append("-ping")
        if args.no_ping:
            naabu_args.append("-no-ping")
        if args.naabu_debug:
            naabu_args.append("-debug")
        if args.tool_silent:
            naabu_args.append("-silent")
        if args.timeout and args.timeout is not None:
            # Limit timeout to reasonable values (max 60 seconds = 60000 ms)
            timeout_ms = min(args.timeout * 1000, 60000)
            naabu_args.extend(["-timeout", str(timeout_ms)])  # Convert to milliseconds

        print_status_header("naabu", target, "port scan")
        
        # Get the actual path to naabu executable
        naabu_path = get_executable_path("naabu")
        if not naabu_path:
            print("ERROR: naabu not found in PATH or standard locations")
            print("Expected locations: /usr/bin/naabu, /root/go/bin/naabu, ~/go/bin/naabu")
            if args.save_output and comprehensive_report:
                append_to_comprehensive_report(comprehensive_report, "NAABU", "Tool not found in expected locations", False)
            return False
        
        print(f"Using naabu from: {naabu_path}")
        # Enhanced naabu command with better verbose output
        naabu_cmd = [naabu_path, "-host", target]  # Don't add -v here yet
        
        # Handle port specification, distinguishing between top ports and specific ports
        # NOTE: We ensure only ONE port flag (-p or -top-ports) is ever used to avoid conflicts
        if mapped_ports:
            if ports_to_scan.startswith("top-"):
                # Use -top-ports flag for top-N format
                naabu_cmd.extend(["-top-ports", mapped_ports])
                print(f"Using top {mapped_ports} ports")
            else:
                # Use -p flag for specific port ranges
                naabu_cmd.extend(["-p", mapped_ports])
                print(f"Using specific ports: {mapped_ports}")
        
        # Add scan type for better output consistency
        if not args.stealth:
            naabu_cmd.extend(["-scan-type", "connect"])  # Connect scan shows more details
        
        # Add verbose flag only once, here
        naabu_cmd.append("-v")        # Add output options
        if args.naabu_json or args.json_output:
            naabu_cmd.append("-json")
        elif args.naabu_csv:
            naabu_cmd.append("-csv")
        elif temp_output:
            naabu_cmd.extend(["-o", temp_output])
        
        # Add the naabu arguments
        naabu_cmd.extend(naabu_args)
        
        # Add conditional parameters based on stealth mode
        if args.stealth:
            # In stealth mode, reduce output and disable colors
            naabu_cmd.extend([
                "-silent",  # Reduce verbose output for cleaner display in stealth mode
                "-no-color"  # Disable colors for better log parsing
            ])
        else:
            # In normal mode, only disable colors for better log parsing but keep verbose output
            naabu_cmd.extend([
                "-no-color"  # Disable colors for better log parsing
            ])
        
        print(f"Executing command: {' '.join(naabu_cmd)}")
        
        naabu_success, naabu_output = run_with_clean_output_only(
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
            success = False    # HTTPX
    elif args.httpx:
        print(f"\nStarting httpx service detection...")

        httpx_input = target
        print(f"Target: {httpx_input}")

        # Base httpx arguments
        httpx_args = []        # For maximum compatibility, only add essential flags
        # Remove all potentially incompatible flags for now
          # For comprehensive report, always capture output
        temp_output = None
        if args.save_output:
            temp_output = os.path.join(output_dir, "temp_httpx_output.txt")        # Configure performance settings based on stealth mode or user preferences
        # Temporarily disable all performance flags for compatibility testing
        if args.stealth:
            # Use minimal flags for stealth mode
            pass  # No flags for now
        else:
            # Use minimal flags for normal mode to avoid compatibility issues
            pass  # No flags for now
        
        print_status_header("httpx", target, "service detection")
        
        # Get the actual path to httpx executable
        httpx_path = get_executable_path("httpx")
        if not httpx_path:            
            print("ERROR: httpx not found in PATH or standard locations")
            print("Expected locations: /usr/bin/httpx, /root/go/bin/httpx, ~/go/bin/httpx")
            if args.save_output and comprehensive_report:
                append_to_comprehensive_report(comprehensive_report, "HTTPX", "Tool not found in expected locations", False)
            return False
        
        print(f"Using httpx from: {httpx_path}")
        
        # Build base command - for single target, pass directly without a flag
        httpx_cmd = [httpx_path, httpx_input]
        
        # Add user-specified detection options with valid flags
        if args.title:
            httpx_cmd.append("-title")
        
        if args.status_code:
            httpx_cmd.append("-status-code")
        
        if args.tech_detect:
            httpx_cmd.append("-tech-detect")
        
        if args.web_server:
            httpx_cmd.append("-server")
        
        if args.follow_redirects:
            httpx_cmd.append("-follow-redirects")
        
        if args.content_length:
            httpx_cmd.append("-content-length")
        
        if args.response_time:
            httpx_cmd.append("-response-time")
        
        # Add HTTP method if specified
        if args.method:
            httpx_cmd.extend(["-method", args.method])
        
        # Add custom User-Agent if specified
        if args.user_agent:
            httpx_cmd.extend(["-H", f"User-Agent: {args.user_agent}"])
        
        # Add custom headers if specified
        if args.headers:
            for header in args.headers.split(','):
                httpx_cmd.extend(["-H", header.strip()])
          # Add filtering options with full flag names
        if args.filter_code:
            httpx_cmd.extend(["-filter-code", args.filter_code])
        
        if args.filter_length:
            httpx_cmd.extend(["-filter-length", args.filter_length])
        
        if args.match_code:
            httpx_cmd.extend(["-match-code", args.match_code])
        
        if args.match_length:
            httpx_cmd.extend(["-match-length", args.match_length])
        
        # Add proxy if specified
        if args.proxy:
            httpx_cmd.extend(["-http-proxy", args.proxy])
        
        # Add redirect options with full flag names
        if args.disable_redirects:
            httpx_cmd.append("-no-follow-redirects")
        
        if args.max_redirects:
            httpx_cmd.extend(["-max-redirects", str(args.max_redirects)])
          # Default behavior for non-stealth mode (maintain backward compatibility)
        # Use minimal flags to avoid compatibility issues
        if not args.stealth and not any([args.title, args.status_code, args.tech_detect, args.web_server]):
            # Don't add any default flags for maximum compatibility
            pass        # Add output options
        if args.httpx_json or args.json_output:
            httpx_cmd.append("-json")
        elif args.httpx_csv:
            httpx_cmd.append("-csv")
        elif temp_output:
            httpx_cmd.extend(["-o", temp_output])
          # Add all other arguments
        httpx_cmd.extend(httpx_args)
        
        httpx_success, httpx_output = run_with_clean_output_only(
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
                    print("No HTTP services detected on target - this is normal if no web servers are running")
            else:
                if httpx_output.strip():
                    print("Real-time scan output was displayed above")
                    print("Results were not saved to files (as requested)")
                else:
                    print("No HTTP services detected on target - this is normal if no web servers are running")
        else:
            print("HTTPX scan encountered errors.")
            if args.save_output and comprehensive_report:
                append_to_comprehensive_report(comprehensive_report, "HTTPX", "Scan encountered errors", False)
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

        # Base nuclei arguments
        nuclei_args = []
        
        # Add verbose output if not in tool-silent mode
        if not args.tool_silent:
            nuclei_args.append("-v")
        
        # Add stats unless explicitly disabled
        nuclei_args.append("-stats")
        
        # For comprehensive report, always capture output
        temp_output = None
        if args.save_output:
            temp_output = os.path.join(output_dir, "temp_nuclei_output.txt")
              # Store responses if user specified or default behavior
            if args.store_resp:
                nuclei_resp_dir = os.path.join(output_dir, "nuclei_responses")
                create_directory_if_not_exists(nuclei_resp_dir)
                nuclei_args.extend(["-store-resp", "-store-resp-dir", nuclei_resp_dir])        # Configure performance settings based on stealth mode or user preferences
        if args.stealth:
            nuclei_args.extend([
                "-rl", "5",
                "-bs", "5", 
                "-c", "5",
                "-timeout", "5",
                "-retries", "1",
                "-et", "fuzzing,dos,brute-force",
                "-ni"
            ])
        else:
            # Use user-specified concurrency or default
            if args.concurrency:
                nuclei_args.extend(["-c", str(args.concurrency)])
            else:
                nuclei_args.extend(["-c", "10"])
            
            # Use user-specified rate limit or default
            if args.nuclei_rate_limit:
                nuclei_args.extend(["-rl", str(args.nuclei_rate_limit)])
            else:
                nuclei_args.extend(["-rl", "50"])
            
            # Use user-specified timeout or default
            if args.nuclei_timeout:
                nuclei_args.extend(["-timeout", str(args.nuclei_timeout)])
            else:
                nuclei_args.extend(["-timeout", "10"])
            
            # Use user-specified retries
            if args.nuclei_retries:
                nuclei_args.extend(["-retries", str(args.nuclei_retries)])
            
            # Use user-specified parallel processing
            if args.parallel_processing:
                nuclei_args.extend(["-bs", str(args.parallel_processing)])
            else:
                nuclei_args.extend(["-bs", "10"])

        print_status_header("nuclei", target, "vulnerability scan")
        
        # Get the actual path to nuclei executable
        nuclei_path = get_executable_path("nuclei")
        if not nuclei_path:
            print("ERROR: nuclei not found in PATH or standard locations")
            print("Expected locations: /usr/bin/nuclei, /root/go/bin/nuclei, ~/go/bin/nuclei")
            if args.save_output and comprehensive_report:
                append_to_comprehensive_report(comprehensive_report, "NUCLEI", "Tool not found in expected locations", False)
            return False
        
        print(f"Using nuclei from: {nuclei_path}")
        
        # Build nuclei command properly
        if os.path.isfile(nuclei_input):
            nuclei_cmd = [nuclei_path, "-l", nuclei_input]
        else:
            nuclei_cmd = [nuclei_path, "-u", nuclei_input]        # Add template specification - user-specified templates take precedence
        templates_added = False
        if args.templates:
            # Handle different template formats
            if args.templates.startswith('/') or os.path.exists(args.templates):
                # Absolute path or existing file/directory
                nuclei_cmd.extend(["-t", args.templates])
            elif '/' in args.templates:
                # Relative path like 'cves/' or 'technologies/'
                nuclei_cmd.extend(["-t", args.templates])
            else:
                # Template name or tag - let nuclei handle it
                nuclei_cmd.extend(["-t", args.templates])
            templates_added = True
        elif args.template_path:
            nuclei_cmd.extend(["-t", args.template_path])
            templates_added = True
        
        # If no specific templates specified, use default comprehensive set
        if not templates_added:
            # Use a good default set of templates for comprehensive scanning
            default_templates = [
                "cves/",
                "vulnerabilities/",
                "exposures/",
                "technologies/",
                "misconfiguration/",
                "default-logins/"
            ]
            for template in default_templates:
                nuclei_cmd.extend(["-t", template])
          # Add tags - user-specified or default
        if args.tags:
            nuclei_cmd.extend(["-tags", args.tags])
        
        # Add severity - user-specified or default
        if args.severity:
            nuclei_cmd.extend(["-s", args.severity])
        
        # Add exclusion options
        if args.exclude_tags:
            nuclei_cmd.extend(["-et", args.exclude_tags])
        
        if args.exclude_templates:
            nuclei_cmd.extend(["-exclude-templates", args.exclude_templates])
        
        if args.exclude_matchers:
            nuclei_cmd.extend(["-exclude-matchers", args.exclude_matchers])
        
        # Add HTTP options
        if args.proxy:
            nuclei_cmd.extend(["-proxy", args.proxy])
        
        if args.disable_redirects:
            nuclei_cmd.append("-dr")
        
        if args.max_redirects:
            nuclei_cmd.extend(["-maxr", str(args.max_redirects)])
        
        # Add custom headers
        if args.custom_headers:
            for header in args.custom_headers.split(','):
                nuclei_cmd.extend(["-H", header.strip()])
        
        # Add custom variables
        if args.vars:
            nuclei_cmd.extend(["-var", args.vars])
        
        # Add Interactsh options
        if args.interactsh_server:
            nuclei_cmd.extend(["-iserver", args.interactsh_server])
        
        if args.no_interactsh:
            nuclei_cmd.append("-ni")
        
        if args.interactsh_token:
            nuclei_cmd.extend(["-itoken", args.interactsh_token])
        
        if args.nuclei_user_agent:
            nuclei_cmd.extend(["-user-agent", args.nuclei_user_agent])
        
        if args.custom_headers:
            for header in args.custom_headers.split(','):
                nuclei_cmd.extend(["-H", header.strip()])
        
        # Add Interactsh options
        if args.interactsh_server:
            nuclei_cmd.extend(["-interactsh-server", args.interactsh_server])
        
        if args.no_interactsh:
            nuclei_cmd.append("-no-interactsh")
        
        if args.interactsh_token:
            nuclei_cmd.extend(["-interactsh-token", args.interactsh_token])
        
        # Add response storage options
        if args.store_resp_dir:
            nuclei_cmd.extend(["-store-resp-dir", args.store_resp_dir])
        
        # Add custom variables if specified
        if args.vars:
            nuclei_cmd.extend(["-var", args.vars])
          # Add output options
        if args.nuclei_json or args.json_output:
            nuclei_cmd.append("-jsonl")
        elif args.nuclei_csv:
            nuclei_cmd.append("-csv")
        elif temp_output:
            nuclei_cmd.extend(["-o", temp_output])
          # Add export options
        if args.markdown_export:
            nuclei_cmd.extend(["-markdown-export", args.markdown_export])
        
        if args.sarif_export:
            nuclei_cmd.extend(["-sarif-export", args.sarif_export])
              # Add all other arguments
        nuclei_cmd.extend(nuclei_args)
        
        nuclei_success, nuclei_output = run_with_clean_output_only(
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
        'keywords': [],
        'port_info': None,
        'progress_info': None    }
    
    line_lower = line.lower()
    
    if tool_name.lower() == 'naabu':
        # Use enhanced naabu parsing for better port detection
        port_details = parse_naabu_realtime_output(line)
        
        # Extract specific port information for enhanced real-time display
        import re
        port_match = re.search(r':(\d+)', line)
        if port_match:
            analysis['port_info'] = port_match.group(1)
        
        # Use the enhanced parser results
        if port_details['port']:
            analysis['port_info'] = port_details['port']
        
        # Extract port ranges being scanned
        port_range_match = re.search(r'(\d+)-(\d+)', line)
        if port_range_match:
            analysis['port_range'] = f"{port_range_match.group(1)}-{port_range_match.group(2)}"
            analysis['keywords'].append('port_range')
        
        # Extract single port being tested
        single_port_match = re.search(r'port (\d+)', line_lower)
        if single_port_match:
            analysis['port_info'] = single_port_match.group(1)
            analysis['keywords'].append('single_port')
        
        # Enhanced detection based on parser results
        if port_details['type'] == 'progress':
            analysis['line_type'] = 'progress'
            analysis['progress_info'] = 'port_scan'
            analysis['scanning_activity'] = 'active_port_scan'
            if port_details.get('port_range'):
                analysis['port_range'] = port_details['port_range']
        elif port_details['type'] == 'connection':
            analysis['line_type'] = 'progress'
            analysis['progress_info'] = 'port_connect'
            analysis['scanning_activity'] = 'connection_attempt'
        elif port_details['type'] == 'result' and port_details['status'] == 'open':
            analysis['line_type'] = 'finding'
            analysis['contains_finding'] = True
            analysis['severity'] = 'medium'
            analysis['keywords'] = ['port', 'open']
        elif port_details['type'] == 'result' and port_details['status'] in ['closed', 'filtered']:
            analysis['line_type'] = 'info'
            analysis['keywords'] = ['port', 'status']
        elif port_details['type'] == 'summary':
            analysis['line_type'] = 'progress'
            analysis['progress_info'] = 'scan_summary'
        # Fallback to original detection patterns
        elif any(phrase in line_lower for phrase in ['scanning port', 'probing port', 'testing port']):
            analysis['line_type'] = 'progress'
            analysis['progress_info'] = 'port_scan'
            analysis['scanning_activity'] = 'active_port_scan'
        elif any(phrase in line_lower for phrase in ['connecting to', 'attempting connection']):
            analysis['line_type'] = 'progress'
            analysis['progress_info'] = 'port_connect'
            analysis['scanning_activity'] = 'connection_attempt'
        elif 'open' in line_lower:
            analysis['line_type'] = 'finding'
            analysis['contains_finding'] = True
            analysis['severity'] = 'medium'
            analysis['keywords'] = ['port', 'open']
        elif 'closed' in line_lower or 'filtered' in line_lower:
            analysis['line_type'] = 'info'
            analysis['keywords'] = ['port', 'status']
        elif 'error' in line_lower or 'timeout' in line_lower:
            analysis['line_type'] = 'error'
            analysis['severity'] = 'high'
        elif any(word in line_lower for word in ['scanning', 'probing', 'testing', 'connecting']):
            analysis['line_type'] = 'progress'
            analysis['progress_info'] = 'port_scan'
        elif 'sent' in line_lower and 'packets' in line_lower:
            analysis['line_type'] = 'progress'
            analysis['progress_info'] = 'sending_packets'
        elif 'host' in line_lower and ('up' in line_lower or 'down' in line_lower):
            analysis['line_type'] = 'info'
            analysis['keywords'] = ['host_status']
        elif 'starting scan' in line_lower or 'scan started' in line_lower:
            analysis['line_type'] = 'progress'
            analysis['progress_info'] = 'scan_start'
        elif 'completed' in line_lower or 'finished' in line_lower:
            analysis['line_type'] = 'progress'
            analysis['progress_info'] = 'scan_complete'
    
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
    
    # Add timestamp for better tracking
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    
    # Choose prefix based on analysis - NO EMOJIS
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
        if tool_name.lower() == 'naabu' and analysis.get('port_info'):
            prefix = f"[PORT OPEN] Port {analysis['port_info']}"
        else:
            prefix = "[FOUND]"
    elif analysis['line_type'] == 'error':
        prefix = "[ERROR]"
    elif analysis['line_type'] == 'progress':
        if tool_name.lower() == 'naabu':
            if analysis.get('progress_info') == 'port_scan':
                if analysis.get('port_info'):
                    prefix = f"[SCANNING PORT {analysis['port_info']}]"
                elif analysis.get('port_range'):
                    prefix = f"[SCANNING RANGE {analysis['port_range']}]"
                else:
                    prefix = "[SCANNING]"
            elif analysis.get('progress_info') == 'port_connect':
                prefix = "[CONNECTING]"
            elif analysis.get('progress_info') == 'sending_packets':
                prefix = "[SENDING]"
            else:
                prefix = "[PROGRESS]"
        else:
            prefix = "[PROGRESS]"
    else:
        prefix = "[INFO]"
    
    # Add line number and timestamp for easy reference
    line_ref = f"[{timestamp}][{line_count:04d}]"
    
    # Special formatting for naabu port information
    if tool_name.lower() == 'naabu' and (analysis.get('port_info') or analysis.get('port_range')):
        if analysis.get('scanning_activity'):
            return f"{prefix} {line_ref} Port activity detected: {line}"
        else:
            return f"{prefix} {line_ref} {line}"
    else:
        return f"{prefix} {line_ref} {line}"

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
    parser.add_argument('-nuclei', '--nuclei', action='store_true', help='Run nuclei vulnerability scanner')    # Tool-specific options
    parser.add_argument('-p', '--ports', help='Ports to scan with naabu (e.g., 80,443,8000-9000)')
    parser.add_argument('-t', '--templates', help='Custom nuclei templates (default: uses built-in templates)')
    parser.add_argument('--tags', default='cve', help='Nuclei template tags (default: cve)')
    parser.add_argument('--severity', default='critical,high', help='Vulnerability severity filter (default: critical,high)')
    
    # Naabu-specific options
    parser.add_argument('--threads', type=int, help='Number of concurrent threads for naabu')
    parser.add_argument('--rate', type=int, help='Packets per second rate for naabu')
    parser.add_argument('--exclude-ports', help='Ports to exclude from naabu scan')
    parser.add_argument('--scan-type', choices=['syn', 'connect'], help='Naabu scan type')
    parser.add_argument('--naabu-timeout', type=int, help='Timeout per port scan in milliseconds')
    parser.add_argument('--naabu-retries', type=int, help='Number of retries for failed ports')
    parser.add_argument('--top-ports', help='Number of top ports to scan (e.g., 1000)')
    parser.add_argument('--source-port', type=int, help='Source port for naabu scan')
    parser.add_argument('--interface', help='Network interface to use')
    parser.add_argument('--host-discovery', action='store_true', help='Enable host discovery')
    parser.add_argument('--ping', action='store_true', help='Use ping for host discovery')
    parser.add_argument('--no-ping', action='store_true', help='Skip ping discovery')
    parser.add_argument('--naabu-debug', action='store_true', help='Enable debug output for naabu')
    parser.add_argument('--naabu-json', action='store_true', help='JSON output for naabu')
    parser.add_argument('--naabu-csv', action='store_true', help='CSV output for naabu')
      # HTTPX-specific options
    parser.add_argument('--title', action='store_true', help='Extract page titles with httpx')
    parser.add_argument('--status-code', action='store_true', help='Show HTTP status codes with httpx')
    parser.add_argument('--tech-detect', action='store_true', help='Enable technology detection with httpx')
    parser.add_argument('--web-server', action='store_true', help='Show web server information with httpx')
    parser.add_argument('--follow-redirects', action='store_true', help='Follow HTTP redirects with httpx')
    parser.add_argument('--rate-limit', type=int, help='Rate limit (requests per second)')
    parser.add_argument('--headers', help='Custom HTTP headers')
    parser.add_argument('--content-length', action='store_true', help='Show content length')
    parser.add_argument('--response-time', action='store_true', help='Show response time')
    parser.add_argument('--httpx-timeout', type=int, help='HTTP timeout in seconds')
    parser.add_argument('--httpx-threads', type=int, help='Number of HTTP threads')
    parser.add_argument('--httpx-retries', type=int, help='Number of HTTP retries')
    parser.add_argument('--method', help='HTTP method to use (GET, POST, etc.)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--filter-code', help='Filter by HTTP status codes')
    parser.add_argument('--filter-length', help='Filter by content length')
    parser.add_argument('--match-code', help='Match specific HTTP status codes')
    parser.add_argument('--match-length', help='Match specific content lengths')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--httpx-json', action='store_true', help='JSON output for httpx')
    parser.add_argument('--httpx-csv', action='store_true', help='CSV output for httpx')
      # Nuclei-specific options
    parser.add_argument('--concurrency', type=int, help='Number of concurrent templates for nuclei')
    parser.add_argument('--vars', help='Custom variables for nuclei templates')
    parser.add_argument('--store-resp', action='store_true', help='Store HTTP responses for nuclei')
    parser.add_argument('--template-path', help='Custom template directory path')
    parser.add_argument('--exclude-tags', help='Exclude templates with specific tags')
    parser.add_argument('--exclude-templates', help='Exclude specific templates')
    parser.add_argument('--exclude-severity', help='Exclude templates with specific severity')
    parser.add_argument('--exclude-matchers', help='Exclude templates with specific matchers')
    parser.add_argument('--parallel-processing', type=int, help='Number of parallel template processing')
    parser.add_argument('--nuclei-rate-limit', type=int, help='Rate limit for nuclei requests')
    parser.add_argument('--nuclei-timeout', type=int, help='Timeout for nuclei requests')
    parser.add_argument('--nuclei-retries', type=int, help='Number of retries for nuclei')
    parser.add_argument('--proxy', help='HTTP proxy for nuclei')
    parser.add_argument('--disable-redirects', action='store_true', help='Disable HTTP redirects')
    parser.add_argument('--max-redirects', type=int, help='Maximum number of redirects')
    parser.add_argument('--nuclei-user-agent', help='Custom User-Agent for nuclei')
    parser.add_argument('--custom-headers', help='Custom headers for nuclei')
    parser.add_argument('--interactsh-server', help='Custom Interactsh server URL')
    parser.add_argument('--no-interactsh', action='store_true', help='Disable Interactsh integration')
    parser.add_argument('--interactsh-token', help='Interactsh server token')
    parser.add_argument('--store-resp-dir', help='Directory to store responses')
    parser.add_argument('--include-rr', action='store_true', help='Include request/response data')
    parser.add_argument('--nuclei-json', action='store_true', help='JSON output for nuclei')
    parser.add_argument('--nuclei-csv', action='store_true', help='CSV output for nuclei')
    parser.add_argument('--markdown-export', help='Export results in Markdown format')
    parser.add_argument('--sarif-export', help='Export results in SARIF format')
    
    # General tool options
    parser.add_argument('--tool-silent', action='store_true', help='Run tools in silent mode')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    # Output options
    parser.add_argument('-o', '--output-dir', help='Custom output directory')
    parser.add_argument('--save-output', action='store_true', help='Save scan output to files (separate from real-time display)')
    parser.add_argument('--json-output', action='store_true', help='Save output in JSON format (requires --save-output)')
      # Workflow options
    parser.add_argument('--update-templates', action='store_true', help='Update nuclei templates before scanning')
    parser.add_argument('--timeout', type=int, default=None, help='Maximum scan time in seconds (optional - no timeout by default)')
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
        print("║              NOT Supported: Windows, macOS, WSL               ║")
        print("║                                                               ║")
        print("║        Please use a native Linux environment for optimal      ║")
        print("║           security tool performance and compatibility.        ║")
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

def parse_naabu_realtime_output(line: str) -> dict:
    """
    Enhanced parser for naabu real-time output to detect port scanning activity.
    
    Args:
        line: Raw output line from naabu
        
    Returns:
        Dictionary with parsed port information
    """
    import re
    
    port_info = {
        'type': 'unknown',
        'port': None,
        'host': None,
        'status': None,
        'protocol': None,
        'service': None
    }
    
    line_lower = line.lower().strip()
    
    # Pattern 1: Direct port results (host:port format)
    port_result_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
    if port_result_match:
        port_info['type'] = 'result'
        port_info['host'] = port_result_match.group(1)
        port_info['port'] = port_result_match.group(2)
        if 'open' in line_lower:
            port_info['status'] = 'open'
        elif 'closed' in line_lower:
            port_info['status'] = 'closed'
        elif 'filtered' in line_lower:
            port_info['status'] = 'filtered'
    
    # Pattern 2: Scanning progress indicators
    elif any(keyword in line_lower for keyword in ['scanning', 'probing', 'testing']):
        port_info['type'] = 'progress'
        # Extract port being scanned
        port_scan_match = re.search(r'port[s]?\s+(\d+)', line_lower)
        if port_scan_match:
            port_info['port'] = port_scan_match.group(1)
        # Extract port range
        range_match = re.search(r'(\d+)-(\d+)', line)
        if range_match:
            port_info['port_range'] = f"{range_match.group(1)}-{range_match.group(2)}"
    
    # Pattern 3: Connection attempts
    elif any(keyword in line_lower for keyword in ['connecting', 'connect']):
        port_info['type'] = 'connection'
        port_match = re.search(r':(\d+)', line)
        if port_match:
            port_info['port'] = port_match.group(1)
    
    # Pattern 4: Host discovery
    elif 'host' in line_lower and ('up' in line_lower or 'down' in line_lower):
        port_info['type'] = 'host_discovery'
        if 'up' in line_lower:
            port_info['status'] = 'up'
        else:
            port_info['status'] = 'down'
    
    # Pattern 5: Statistics and summaries
    elif any(keyword in line_lower for keyword in ['found', 'discovered', 'total']):
        port_info['type'] = 'summary'
        # Extract numbers
        numbers = re.findall(r'\d+', line)
        if numbers:
            port_info['count'] = numbers[0]
    
    return port_info

def format_results_for_graphics(results: List[str], tool_type: str) -> List[str]:
    """
    Format clean results specifically for graphics/visualization usage.
    
    Args:
        results: List of clean result lines
        tool_type: Type of tool (naabu, httpx, nuclei)
        
    Returns:
        List of formatted result lines
    """
    formatted_results = []
    
    for line in results:
        line = line.strip()
        if not line:
            continue
            
        if tool_type.lower() == 'naabu':
            # Format: IP:PORT or HOST:PORT
            if ':' in line and any(c.isdigit() for c in line):
                # Clean up any extra whitespace or characters
                formatted_line = ' '.join(line.split())
                formatted_results.append(formatted_line)
                
        elif tool_type.lower() == 'httpx':
            # Format: URL [STATUS] [TITLE] [TECH]
            if line.startswith(('http://', 'https://')):
                formatted_line = ' '.join(line.split())
                formatted_results.append(formatted_line)
                
        elif tool_type.lower() == 'nuclei':
            # Format: [SEVERITY] [TEMPLATE] URL
            if '[' in line and ']' in line and any(proto in line for proto in ['http://', 'https://']):
                formatted_line = ' '.join(line.split())
                formatted_results.append(formatted_line)
    
    return formatted_results

def save_graphics_ready_results(results: List[str], output_file: str, tool_type: str, target: str):
    """
    Save clean results to file in a format optimized for graphics processing.
    No real-time output noise, just structured data for visualization.
    
    Args:
        results: List of clean result lines
        output_file: Path to output file
        tool_type: Type of tool (naabu, httpx, nuclei)
        target: Target that was scanned
    """
    try:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(output_file, 'w') as f:
            # Write clean header for graphics processing
            f.write(f"# {tool_type.upper()} SCAN RESULTS\n")
            f.write(f"# Target: {target}\n")
            f.write(f"# Timestamp: {timestamp}\n")
            f.write(f"# Total Results: {len(results)}\n")
            f.write(f"# Format: Clean data for graphics processing\n")
            f.write("#" + "="*60 + "\n\n")
            
            # Write tool-specific format headers
            if tool_type.lower() == 'naabu':
                f.write("# PORT SCAN RESULTS\n")
                f.write("# Format: IP:PORT or HOST:PORT\n")
                f.write("#" + "-"*40 + "\n")
                
            elif tool_type.lower() == 'httpx':
                f.write("# HTTP SERVICE RESULTS\n") 
                f.write("# Format: URL [STATUS] [TITLE] [TECH]\n")
                f.write("#" + "-"*40 + "\n")
                
            elif tool_type.lower() == 'nuclei':
                f.write("# VULNERABILITY SCAN RESULTS\n")
                f.write("# Format: [SEVERITY] [TEMPLATE] URL\n")
                f.write("#" + "-"*40 + "\n")
            
            # Write clean results without any noise
            for result in results:
                f.write(result + "\n")
                
            # Add footer for completeness
            f.write(f"\n# End of {tool_type.upper()} results\n")
            f.write(f"# Scan completed at {timestamp}\n")
                
        print(f"[{tool_type.upper()}] Clean results saved to: {output_file}")
        
    except Exception as e:
        print(f"[{tool_type.upper()}] Error saving graphics-ready results: {e}")
