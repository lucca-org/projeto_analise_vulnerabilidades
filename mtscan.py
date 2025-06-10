#!/usr/bin/env python3
"""
mtscan.py - Multi Tool Scan Interactive Menu
Main interface for the Linux Vulnerability Analysis Toolkit
"""

import os
import sys
import platform
import subprocess
import datetime
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Try to import utils for tool detection
try:
    from utils import get_executable_path
    UTILS_AVAILABLE = True
except ImportError:
    UTILS_AVAILABLE = False
    def get_executable_path(cmd):
        """Fallback function if utils not available."""
        try:
            result = subprocess.run(['which', cmd], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except:
            pass
        return None

# Ensure we're running on Linux
if platform.system().lower() != "linux":
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                             ERROR                             ║")
    print("║                                                               ║")
    print("║     This toolkit is designed EXCLUSIVELY for Linux systems    ║")
    print("║                                                               ║")
    print("║      Supported: Debian, Kali, Ubuntu, Arch Linux              ║")
    print("║      NOT Supported: Windows, macOS, WSL                       ║")
    print("║                                                               ║")
    print("║     Please use a native Linux environment for optimal         ║")
    print("║     security tool performance and compatibility.              ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    sys.exit(1)

def clear_screen():
    """Clear the terminal screen."""
    os.system('clear')

def print_banner():
    """Print the MTScan banner."""
    print("╔══════════════════════════════════════════════════════════════════════════╗")
    print("║                                                                          ║")
    print("║          ███╗   ███╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗          ║")
    print("║          ████╗ ████║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║          ║")
    print("║          ██╔████╔██║   ██║   ███████╗██║     ███████║██╔██╗ ██║          ║")
    print("║          ██║╚██╔╝██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║          ║")
    print("║          ██║ ╚═╝ ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║          ║")
    print("║          ╚═╝     ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝          ║")
    print("║                                                                          ║")
    print("║                   Multi Tool Scan - Interactive Menu                     ║")
    print("║                  Linux Vulnerability Analysis Toolkit                    ║")
    print("║                                                                          ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝")
    print()

def find_tool_path(tool_name):
    """Find tool path using multiple methods to handle different installations."""
    # Common installation paths (order matters - prefer system packages first)
    search_paths = [
        f"/usr/bin/{tool_name}",           # System package (apt, yum, etc.)
        f"/usr/local/bin/{tool_name}",     # Manual system-wide installation
        f"/snap/bin/{tool_name}",          # Snap package
        f"{os.path.expanduser('~')}/go/bin/{tool_name}",  # User Go installation
        f"/root/go/bin/{tool_name}",       # Root Go installation
        f"{os.path.expanduser('~')}/.local/bin/{tool_name}",  # Local user installation
        f"/opt/{tool_name}/{tool_name}",   # Custom installation directory
    ]
    
    # Special case for Kali Linux httpx
    if tool_name == "httpx":
        search_paths.insert(1, "/usr/bin/httpx-toolkit")
    
    # First try using utils if available
    if UTILS_AVAILABLE:
        path_result = get_executable_path(tool_name)
        if path_result and verify_tool_works(path_result):
            return path_result
    
    # Fallback: try to find in PATH
    try:
        result = subprocess.run(['which', tool_name], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            tool_path = result.stdout.strip()
            if verify_tool_works(tool_path):
                return tool_path
    except:
        pass
    
    # Then check common paths
    for path in search_paths:
        expanded_path = os.path.expanduser(path)
        if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
            if verify_tool_works(expanded_path):
                return expanded_path
    
    # Additional check for Go tools in current user's GOPATH
    try:
        gopath_result = subprocess.run(['go', 'env', 'GOPATH'], capture_output=True, text=True, timeout=5)
        if gopath_result.returncode == 0:
            gopath = gopath_result.stdout.strip()
            go_tool_path = os.path.join(gopath, 'bin', tool_name)
            if os.path.exists(go_tool_path) and verify_tool_works(go_tool_path):
                return go_tool_path
    except:
        pass
    
    return None

def verify_tool_works(tool_path):
    """Verify that a tool actually works by running a simple command."""
    try:
        # Try common version/help flags
        for flag in ["--version", "-version", "-v", "--help", "-h"]:
            try:
                result = subprocess.run([tool_path, flag], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return True
            except:
                continue
        return False
    except:
        return False

def check_tools_status():
    """Check the status of required tools with flexible path detection."""
    tools = ['naabu', 'httpx', 'nuclei']
    status = {}
    
    for tool in tools:
        tool_path = find_tool_path(tool)
        status[tool] = {
            'installed': tool_path is not None,
            'path': tool_path
        }
    
    return status

def print_tools_status():
    """Print the current status of tools."""
    print("TOOL STATUS:")
    print("=" * 50)
    
    status = check_tools_status()
    
    for tool, info in status.items():
        if info['installed']:
            print(f"  [OK] {tool}: Available at {info['path']}")
        else:
            print(f"  [MISSING] {tool}: Not found")
    
    all_installed = all(info['installed'] for info in status.values())
    
    if not all_installed:
        missing_tools = [tool for tool, info in status.items() if not info['installed']]
        print(f"\nMissing tools: {', '.join(missing_tools)}")
        print("Note: Tools may be installed in Go paths. Checking extended locations...")
        
        # Additional detailed check for missing tools
        for tool in missing_tools:
            extended_locations = [
                f"{os.path.expanduser('~')}/go/bin/{tool}",
                f"/root/go/bin/{tool}",
                f"/usr/local/go/bin/{tool}"
            ]
            
            found_extended = False
            for location in extended_locations:
                if os.path.exists(location):
                    print(f"    Found {tool} at {location} (not in PATH)")
                    found_extended = True
                    break
            
            if not found_extended:
                print(f"    {tool} not found in extended locations")
        
        print("\nTo fix PATH issues, run:")
        print("   export PATH=$PATH:~/go/bin")
        print("   # Or add to ~/.bashrc: echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc")
        print("\nRun option [7] to install missing tools.")  # Fix: Corrected option number
    else:
        print("\nAll tools are installed and ready!")
    
    print()

def print_main_menu():
    """Print the main menu options."""
    print("SCANNING OPTIONS:")
    print("=" * 50)
    print("  [1] Port Scan (naabu)")
    print("  [2] HTTP Service Detection (httpx)")
    print("  [3] Vulnerability Scan (nuclei)")
    print()
    print("MANAGEMENT OPTIONS:")
    print("=" * 50)
    print("  [4] View Previous Results")
    print("  [5] Update Nuclei Templates")
    print("  [6] Tool Configuration")
    print("  [7] Install/Update Tools")
    print("  [8] Help & Documentation")
    print("  [0] Exit")
    print()

def get_target_input():
    """Get target input from user."""
    while True:
        target = input("Enter target (IP/domain): ").strip()
        if target:
            return target
        print("Please enter a valid target.")

def get_ports_input():
    """Get ports input for naabu scan."""
    print("\nPort Selection:")
    print("  [1] Top 100 ports")
    print("  [2] Top 1000 ports (default)")
    print("  [3] All ports (1-65535)")
    print("  [4] Number of ports to scan")
    
    while True:
        choice = input("\nSelect option [1-4]: ")

        if choice == "1":
            return "top-100"
        elif choice == "2" or choice == "":
            return "top-1000"
        elif choice == "3":
            return "1-65535"
        elif choice == "4":
            while True:
                try:
                    num_ports = input("Enter number of ports to scan (e.g., 30000): ").strip()
                    port_count = int(num_ports)
                    if port_count > 0 and port_count <= 65535:
                        return f"top-{port_count}"
                    else:
                        print("Please enter a number between 1 and 65535.")
                except ValueError:
                    print("Please enter a valid number.")
        else:
            print("Invalid option. Please select 1-4.")

def get_scan_options():
    """Get additional scan options."""
    options = {}
    
    # Stealth mode
    stealth = input("Enable stealth mode? [y/N]: ").strip().lower()
    options['stealth'] = stealth in ['y', 'yes']
    
    # Save output (separate from real-time display)
    save_output = input("Save scan output to files? [Y/n]: ").strip().lower()
    options['save_output'] = save_output not in ['n', 'no']

    # JSON output (only relevant if saving output)
    if options['save_output']:
        json_output = input("Save output in JSON format? [y/N]: ").strip().lower()
        options['json_output'] = json_output in ['y', 'yes']
    else:
        options['json_output'] = False
    
    return options

def run_scan(scan_type, target, **kwargs):
    """Run a scan with enhanced real-time output and detailed progress information."""
    import datetime
    import threading
    import time
    
    cmd = ["python3", "src/workflow.py"]
    
    # Add tool-specific flag
    if scan_type == "naabu":
        cmd.extend(["-naabu"])
    elif scan_type == "httpx":
        cmd.extend(["-httpx"])
    elif scan_type == "nuclei":
        cmd.extend(["-nuclei"])
    
    # Add target
    cmd.extend(["-host", target])
    
    # Add options
    if kwargs.get('ports'):
        cmd.extend(["-p", kwargs['ports']])
    
    if kwargs.get('stealth'):
        cmd.append("-s")
    
    # Save output flag (separate from verbose display)
    if kwargs.get('save_output'):
        cmd.append("--save-output")
    
    # JSON output only if saving output
    if kwargs.get('json_output') and kwargs.get('save_output'):
        cmd.append("--json-output")
    
    # Enhanced pre-scan information
    print(f"\n{'='*80}")
    print(f"STARTING {scan_type.upper()} SCAN")
    print(f"{'='*80}")
    print(f"Target: {target}")
    print(f"Tool: {scan_type}")
    print(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Show scan configuration
    print(f"\nSCAN CONFIGURATION:")
    print(f"  Real-time output: ENABLED")
    print(f"  Save to files: {'YES' if kwargs.get('save_output') else 'NO'}")
    if kwargs.get('save_output'):
        print(f"  JSON format: {'YES' if kwargs.get('json_output') else 'NO'}")
    print(f"  Stealth mode: {'YES' if kwargs.get('stealth') else 'NO'}")
    if kwargs.get('ports'):
        print(f"  Port range: {kwargs['ports']}")
    
    # Show tool-specific information
    if scan_type == "naabu":
        print(f"\nNAABU PORT SCAN DETAILS:")
        print(f"  Purpose: Discover open ports on target")
        print(f"  Output: Port numbers and services")
        if kwargs.get('stealth'):
            print(f"  Mode: Stealth (slower, more discreet)")
        else:
            print(f"  Mode: Standard (faster scanning)")
    elif scan_type == "httpx":
        print(f"\nHTTPX SERVICE DETECTION DETAILS:")
        print(f"  Purpose: Discover HTTP/HTTPS services")
        print(f"  Output: URLs, status codes, titles, technologies")
        print(f"  Features: Title extraction, technology detection")
    elif scan_type == "nuclei":
        print(f"\nNUCLEI VULNERABILITY SCAN DETAILS:")
        print(f"  Purpose: Detect security vulnerabilities")
        print(f"  Templates: Built-in vulnerability templates")
        print(f"  Output: Vulnerability findings with details")
    
    print(f"\nEXECUTING COMMAND:")
    print(f"  {' '.join(cmd)}")
    print(f"\n{'='*80}")
    print(f"REAL-TIME SCAN OUTPUT:")
    print(f"{'='*80}")
    
    # Variables to track scan progress
    start_time = time.time()
    output_lines = []
    last_activity = time.time()
    process = None  # Initialize process variable
    
    def show_progress():
        """Show periodic progress updates during scan."""
        while process and process.poll() is None:
            elapsed = time.time() - start_time
            print(f"\n[PROGRESS] Scan running for {elapsed:.1f} seconds...")
            time.sleep(30)  # Update every 30 seconds
    
    try:
        # Start the scan process with real-time output streaming
        process = subprocess.Popen(
            cmd, 
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Start progress thread
        progress_thread = threading.Thread(target=show_progress, daemon=True)
        progress_thread.start()
        
        # Stream output in real-time (check if stdout is not None)
        if process.stdout:
            for line in process.stdout:
                line = line.rstrip()
                if line:
                    print(line)
                    output_lines.append(line)
                    last_activity = time.time()
                    
                    # Highlight important findings
                    if any(keyword in line.lower() for keyword in ['open', 'found', 'vulnerable', 'critical', 'high']):
                        print(f">>> FINDING: {line}")
        
        # Wait for process to complete
        return_code = process.wait()
        
        # Final scan summary
        elapsed_total = time.time() - start_time
        print(f"\n{'='*80}")
        print(f"SCAN COMPLETION SUMMARY")
        print(f"{'='*80}")
        print(f"Tool: {scan_type.upper()}")
        print(f"Target: {target}")
        print(f"Total duration: {elapsed_total:.1f} seconds")
        print(f"Return code: {return_code}")
        print(f"Output lines: {len(output_lines)}")
        
        if return_code == 0:
            print(f"Status: SCAN COMPLETED SUCCESSFULLY!")
        elif return_code == 2:
            print(f"Status: SCAN COMPLETED WITH SOME ISSUES")
        else:
            print(f"Status: SCAN FAILED")
        
        # Show findings summary
        findings = [line for line in output_lines if any(keyword in line.lower() for keyword in ['open', 'found', 'vulnerable'])]
        if findings:
            print(f"\nKEY FINDINGS SUMMARY:")
            print(f"  Total findings: {len(findings)}")
            for i, finding in enumerate(findings[:5], 1):
                print(f"  {i}. {finding[:100]}{'...' if len(finding) > 100 else ''}")
            if len(findings) > 5:
                print(f"  ... and {len(findings) - 5} more findings")
        
        if kwargs.get('save_output'):
            print(f"\nFILE OUTPUT INFORMATION:")
            print(f"Results have been saved to the results directory.")
            # Find and display the results directory
            try:
                result_dirs = [item for item in os.listdir('.') if os.path.isdir(item) and item.startswith('results_')]
                if result_dirs:
                    latest_dir = max(result_dirs, key=lambda x: os.path.getmtime(x))
                    print(f"Latest results directory: {latest_dir}")
                    comprehensive_report = os.path.join(latest_dir, "comprehensive_scan_report.txt")
                    if os.path.exists(comprehensive_report):
                        file_size = os.path.getsize(comprehensive_report)
                        print(f"Comprehensive report: {comprehensive_report} ({file_size} bytes)")
                        print(f"Use option [4] to view previous results.")
            except OSError as e:
                print(f"Could not list results directories: {e}")
        else:
            print(f"\nOutput was displayed in real-time only (not saved to files).")
        
        print(f"{'='*80}")
        input("\nPress Enter to continue...")
        
    except KeyboardInterrupt:
        print(f"\n\n{'='*80}")
        print(f"SCAN INTERRUPTED BY USER")
        print(f"{'='*80}")
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()
        print(f"Scan was stopped after {time.time() - start_time:.1f} seconds")
        input("Press Enter to continue...")
    except Exception as e:
        print(f"\n{'='*80}")
        print(f"SCAN ERROR")
        print(f"{'='*80}")
        print(f"Error running scan: {e}")
        print(f"Command: {' '.join(cmd)}")
        input("Press Enter to continue...")

def view_results():
    """View previous scan results."""
    clear_screen()
    print_banner()
    print("PREVIOUS SCAN RESULTS:")
    print("=" * 50)
    
    # Find all result directories
    result_dirs = []
    for item in os.listdir('.'):
        if os.path.isdir(item) and item.startswith('results_'):
            result_dirs.append(item)
    
    if not result_dirs:
        print("No previous scan results found.")
        input("\nPress Enter to continue...")
        return
    
    # Sort by modification time (newest first)
    result_dirs.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    # Display results
    for i, result_dir in enumerate(result_dirs[:10], 1):  # Show last 10
        stat = os.stat(result_dir)
        mod_time = datetime.datetime.fromtimestamp(stat.st_mtime)
        print(f"  [{i}] {result_dir} - {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    print(f"\n  [0] Back to main menu")
    
    while True:
        choice = input("\nSelect result to view [0-{}]: ".format(len(result_dirs[:10]))).strip()
        
        if choice == "0":
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(result_dirs[:10]):
                view_result_details(result_dirs[idx])
                return
            else:
                print("Invalid selection.")
        except ValueError:
            print("Please enter a valid number.")

def view_result_details(result_dir):
    """View details of a specific result directory."""
    clear_screen()
    print_banner()
    print(f"SCAN RESULTS: {result_dir}")
    print("=" * 60)
    
    # Look for the comprehensive report file
    comprehensive_report = os.path.join(result_dir, "comprehensive_scan_report.txt")
    
    try:
        if os.path.exists(comprehensive_report):
            print("COMPREHENSIVE SCAN REPORT:")
            print("-" * 40)
            with open(comprehensive_report, 'r') as f:
                content = f.read()
                print(content)
        else:
            # Fallback: show directory contents if comprehensive report not found
            print("Directory contents:")
            files = os.listdir(result_dir)
            for file in sorted(files):
                file_path = os.path.join(result_dir, file)
                if os.path.isfile(file_path):
                    size = os.path.getsize(file_path)
                    print(f"    {file} ({size} bytes)")
                elif os.path.isdir(file_path):
                    print(f"    {file}/")
            
            print("\nNote: No comprehensive_scan_report.txt found.")
            print("This might be an older scan result or incomplete scan.")
        
    except Exception as e:
        print(f"Error reading results: {e}")
    
    input("\nPress Enter to continue...")

def update_templates():
    """Update nuclei templates."""
    clear_screen()
    print_banner()
    print("UPDATING NUCLEI TEMPLATES:")
    print("=" * 50)
    
    try:
        print("Running: nuclei -update-templates")
        result = subprocess.run(["nuclei", "-update-templates"], 
                              timeout=300,  # 5 minute timeout
                              capture_output=False)  # Show output in real-time
        
        if result.returncode == 0:
            print("Templates updated successfully!")
        else:
            print("Template update completed with warnings.")
    
    except subprocess.TimeoutExpired:
        print("Template update timed out after 5 minutes.")
        print("You can try updating manually later: nuclei -update-templates")
    except FileNotFoundError:
        print("nuclei command not found. Please ensure it's installed and in PATH.")
        print("Try: export PATH=$PATH:~/go/bin")
    except Exception as e:
        print(f"Template update failed: {e}")
    
    input("\nPress Enter to continue...")

def show_help():
    """Show help and documentation."""
    clear_screen()
    print_banner()
    print("HELP & DOCUMENTATION:")
    print("=" * 50)
    print()
    print("TOOL DESCRIPTIONS:")
    print("  • naabu   - Fast port scanner for network reconnaissance")
    print("  • httpx   - HTTP toolkit for service discovery and analysis")
    print("  • nuclei  - Vulnerability scanner with 5000+ templates")
    print()
    print("SCAN TYPES:")
    print("  • Port Scan      - Discover open ports on target")
    print("  • HTTP Detection - Find HTTP services and gather info")
    print("  • Vuln Scan      - Check for known vulnerabilities")
    print()
    print("OPTIONS:")
    print("  • Stealth Mode   - Slower, more discreet scanning")
    print("  • Save Output    - Save results to files")
    print("  • JSON Output    - Machine-readable output format")
    print()
    print("DOCUMENTATION:")
    print("  • README.md      - General overview and quick start")
    print("  • docs/USAGE.md  - Detailed usage examples")
    print("  • docs/INSTALL.md - Installation instructions")
    print()
    print("GETTING STARTED:")
    print("  • Run: python mtscan.py")
    print("  • Or: python src/workflow.py <target>")
    print()
    print("EXAMPLES:")
    print("  Target formats:")
    print("    • 192.168.1.100")
    print("    • example.com")
    print("    • https://target.com")
    print()
    
    input("Press Enter to continue...")

def install_tools():
    """Run the installation script."""
    clear_screen()
    print_banner()
    print("INSTALLING/UPDATING TOOLS:")
    print("=" * 50)
    
    if not os.path.exists("install/setup.py"):
        print("Installation script not found at install/setup.py")
        print("Expected structure:")
        print("  ./install/setup.py")
        input("\nPress Enter to continue...")
        return
    
    try:
        print("Running installation script...")
        # Try without sudo first, then with sudo if needed
        try:
            result = subprocess.run(["python3", "install/setup.py"], 
                                  timeout=1800)  # 30 minute timeout
        except subprocess.TimeoutExpired:
            print("Installation timed out after 30 minutes.")
            result = subprocess.CompletedProcess(args=[], returncode=1)
        except PermissionError:
            print("Permission denied, trying with sudo...")
            try:
                result = subprocess.run(["sudo", "python3", "install/setup.py"], 
                                      timeout=1800)
            except subprocess.TimeoutExpired:
                print("Installation timed out after 30 minutes.")
                result = subprocess.CompletedProcess(args=[], returncode=1)
        
        if result.returncode == 0:
            print("Installation completed successfully!")
        else:
            print("Installation completed with some issues.")
        
    except Exception as e:
        print(f"Installation failed: {e}")
    
    input("\nPress Enter to continue...")

def main():
    """Main menu loop."""
    while True:
        clear_screen()
        print_banner()
        print_tools_status()
        print_main_menu()
        
        choice = input("Select option [0-8]: ").strip()
        
        if choice == "0":
            print("\nGoodbye!")
            break
        elif choice == "1":
            # Port Scan (naabu)
            target = get_target_input()
            ports = get_ports_input()
            options = get_scan_options()
            run_scan("naabu", target, ports=ports, **options)
        elif choice == "2":
            # HTTP Service Detection (httpx)
            target = get_target_input()
            options = get_scan_options()
            run_scan("httpx", target, **options)
        elif choice == "3":
            # Vulnerability Scan (nuclei)
            target = get_target_input()
            options = get_scan_options()
            run_scan("nuclei", target, **options)
        elif choice == "4":
            view_results()
        elif choice == "5":
            update_templates()
        elif choice == "6":
            print("\nTool Configuration")
            print("Configuration options will be available in future updates.")
            input("Press Enter to continue...")
        elif choice == "7":
            install_tools()
        elif choice == "8":
            show_help()
        else:
            print("Invalid option. Please select 0-8.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)