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
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None

# Ensure we're running on Linux
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

def clear_screen():
    """Clear the terminal screen."""
    os.system('clear')

def print_banner():
    """Print the MTScan banner."""
    print("╔══════════════════════════════════════════════════════════════════════════╗")
    print("║                                                                          ║")
    print("║  ███╗   ███╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗                ║")
    print("║  ████╗ ████║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║                ║")
    print("║  ██╔████╔██║   ██║   ███████╗██║     ███████║██╔██╗ ██║                ║")
    print("║  ██║╚██╔╝██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║                ║")
    print("║  ██║ ╚═╝ ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║                ║")
    print("║  ╚═╝     ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                ║")
    print("║                                                                          ║")
    print("║                   Multi Tool Scan - Interactive Menu                    ║")
    print("║                 Linux Vulnerability Analysis Toolkit                    ║")
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
            path = result.stdout.strip()
            if verify_tool_works(path):
                return path
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
            if gopath:
                go_tool_path = os.path.join(gopath, 'bin', tool_name)
                if os.path.isfile(go_tool_path) and os.access(go_tool_path, os.X_OK):
                    if verify_tool_works(go_tool_path):
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
                result = subprocess.run(
                    [tool_path, flag], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
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
    print("🔧 TOOL STATUS:")
    print("=" * 50)
    
    status = check_tools_status()
    
    for tool, info in status.items():
        if info['installed']:
            print(f"  ✅ {tool.ljust(10)} - Available at {info['path']}")
        else:
            print(f"  ❌ {tool.ljust(10)} - Not installed")
    
    all_installed = all(info['installed'] for info in status.values())
    
    if not all_installed:
        missing_tools = [tool for tool, info in status.items() if not info['installed']]
        print(f"\n⚠️  Missing tools: {', '.join(missing_tools)}")
        print("💡 Note: Tools may be installed in Go paths. Checking extended locations...")
        
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
                    print(f"    🔍 Found {tool} at {location} (not in PATH)")
                    found_extended = True
                    break
            
            if not found_extended:
                print(f"    ❌ {tool} not found in extended locations")
        
        print("\n🔧 To fix PATH issues, run:")
        print("   export PATH=$PATH:~/go/bin")
        print("   # Or add to ~/.bashrc: echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc")
        print("\n⚠️  Run option [8] to install missing tools.")
    else:
        print("\n✅ All tools are installed and ready!")
    
    print()

def print_main_menu():
    """Print the main menu options."""
    print("🎯 SCANNING OPTIONS:")
    print("=" * 50)
    print("  [1] Port Scan (naabu)")
    print("  [2] HTTP Service Detection (httpx)")
    print("  [3] Vulnerability Scan (nuclei)")
    print("  [4] Full Scan (all tools)")
    print()
    print("🔧 MANAGEMENT OPTIONS:")
    print("=" * 50)
    print("  [5] View Previous Results")
    print("  [6] Update Nuclei Templates")
    print("  [7] Tool Configuration")
    print("  [8] Install/Update Tools")
    print("  [9] Help & Documentation")
    print("  [0] Exit")
    print()

def get_target_input():
    """Get target input from user."""
    while True:
        target = input("🎯 Enter target (IP/domain): ").strip()
        if target:
            return target
        print("❌ Please enter a valid target.")

def get_ports_input():
    """Get ports input for naabu scan."""
    print("\n📋 Port Selection:")
    print("  [1] Top 100 ports")
    print("  [2] Top 1000 ports (default)")
    print("  [3] All ports (1-65535)")
    print("  [4] Custom ports")
    
    while True:
        choice = input("\nSelect option [1-4]: ")

        if choice == "1":
            return "top-100"
        elif choice == "2" or choice == "":
            return "top-1000"
        elif choice == "3":
            return "1-65535"
        elif choice == "4":
            ports = input("Enter custom ports (e.g., 80,443,8080 or 1-1000): ").strip()
            if ports:
                return ports
            print("❌ Please enter valid ports.")
        else:
            print("❌ Invalid choice. Please select 1-4.")

def get_scan_options():
    """Get additional scan options."""
    options = {}
    
    # Stealth mode
    stealth = input("🥷 Enable stealth mode? [y/N]: ").strip().lower()
    options['stealth'] = stealth in ['y', 'yes']
    
    # Verbose output
    verbose = input("📢 Enable verbose output? [y/N]: ")

    options['verbose'] = verbose in ['y', 'yes']
    
    # JSON output
    json_output = input("📄 Enable JSON output? [y/N]: ").strip().lower()
    options['json_output'] = json_output in ['y', 'yes']
    
    return options

def ensure_results_directory():
    """Ensure the results directory exists."""
    results_dir = "scan_results"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
        print(f"📁 Created results directory: {results_dir}")
    return results_dir

def create_scan_session_dir(target, scan_type):
    """Create a unique directory for this scan session."""
    results_dir = ensure_results_directory()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # Clean target name for filename
    clean_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    session_name = f"{scan_type}_{clean_target}_{timestamp}"
    session_dir = os.path.join(results_dir, session_name)
    os.makedirs(session_dir, exist_ok=True)
    return session_dir

def run_scan(scan_type, target, **kwargs):
    """Run a scan with the specified parameters."""
    # Create session directory for results
    session_dir = create_scan_session_dir(target, scan_type)
    
    cmd = ["sudo", "python", "src/workflow.py"]
    
    # Add tool-specific flag
    if scan_type == "naabu":
        cmd.extend(["-naabu"])
    elif scan_type == "httpx":
        cmd.extend(["-httpx"])
    elif scan_type == "nuclei":
        cmd.extend(["-nuclei"])
    elif scan_type == "full":
        # Full scan doesn't use individual tool flags
        pass
    
    # Add target
    cmd.extend(["-host", target])
    
    # Add output directory
    cmd.extend(["-o", session_dir])
    
    # Add options
    if kwargs.get('ports'):
        cmd.extend(["-p", kwargs['ports']])
    
    if kwargs.get('stealth'):
        cmd.append("-s")
    
    if kwargs.get('verbose'):
        cmd.append("-v")
    
    if kwargs.get('json_output'):
        cmd.append("--json-output")
    
    print(f"\n🚀 Starting {scan_type} scan on {target}...")
    print(f"📂 Results will be saved to: {session_dir}")
    print(f"📋 Command: {' '.join(cmd)}")
    print("=" * 60)
    
    try:
        # Run the scan from root directory
        result = subprocess.run(cmd, cwd=os.getcwd())
        
        print("\n" + "=" * 60)
        if result.returncode == 0:
            print("✅ Scan completed successfully!")
            print(f"📊 Results saved in: {session_dir}")
            
            # Create a simple summary file
            create_scan_summary(session_dir, scan_type, target, kwargs)
            
        elif result.returncode == 2:
            print("⚠️  Scan completed with some issues.")
        else:
            print("❌ Scan failed.")
        
        # Show quick results preview
        show_quick_results_preview(session_dir)
        
        input("\nPress Enter to continue...")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user.")
        input("Press Enter to continue...")
    except Exception as e:
        print(f"\n❌ Error running scan: {e}")
        input("Press Enter to continue...")

def create_scan_summary(session_dir, scan_type, target, options):
    """Create a summary file for the scan."""
    summary_path = os.path.join(session_dir, "scan_summary.txt")
    
    with open(summary_path, 'w') as f:
        f.write(f"MTScan Results Summary\n")
        f.write(f"=" * 40 + "\n\n")
        f.write(f"Scan Type: {scan_type}\n")
        f.write(f"Target: {target}\n")
        f.write(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Session Directory: {session_dir}\n\n")
        
        f.write("Options:\n")
        for key, value in options.items():
            f.write(f"  {key}: {value}\n")
        
        f.write(f"\nFiles in this session:\n")
        try:
            for file in os.listdir(session_dir):
                if file != "scan_summary.txt":
                    file_path = os.path.join(session_dir, file)
                    if os.path.isfile(file_path):
                        size = os.path.getsize(file_path)
                        f.write(f"  - {file} ({size} bytes)\n")
        except:
            f.write("  (Error reading session files)\n")

def show_quick_results_preview(session_dir):
    """Show a quick preview of scan results."""
    print(f"\n📊 QUICK RESULTS PREVIEW:")
    print("=" * 40)
    
    try:
        files = [f for f in os.listdir(session_dir) if os.path.isfile(os.path.join(session_dir, f))]
        
        if not files:
            print("  No result files found.")
            return
        
        for file in sorted(files):
            file_path = os.path.join(session_dir, file)
            size = os.path.getsize(file_path)
            print(f"  📄 {file} ({size} bytes)")
            
            # Show preview for text files
            if file.endswith(('.txt', '.json')) and size > 0 and size < 10000:
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        lines = content.strip().split('\n')
                        if len(lines) > 0:
                            print(f"      Preview: {lines[0][:80]}...")
                            if len(lines) > 1:
                                print(f"      ({len(lines)} total lines)")
                except:
                    pass
        
    except Exception as e:
        print(f"  Error reading results: {e}")

def view_results():
    """View previous scan results."""
    clear_screen()
    print_banner()
    print("📊 PREVIOUS SCAN RESULTS:")
    print("=" * 50)
    
    results_base_dir = "scan_results"
    
    if not os.path.exists(results_base_dir):
        print("No scan results directory found.")
        print(f"Results will be created in: {results_base_dir}/")
        input("\nPress Enter to continue...")
        return
    
    # Find all result directories
    result_dirs = []
    try:
        for item in os.listdir(results_base_dir):
            item_path = os.path.join(results_base_dir, item)
            if os.path.isdir(item_path):
                result_dirs.append(item)
    except:
        print("Error reading results directory.")
        input("\nPress Enter to continue...")
        return
    
    if not result_dirs:
        print("No previous scan results found.")
        input("\nPress Enter to continue...")
        return
    
    # Sort by modification time (newest first)
    result_dirs.sort(key=lambda x: os.path.getmtime(os.path.join(results_base_dir, x)), reverse=True)
    
    # Display results
    for i, result_dir in enumerate(result_dirs[:15], 1):  # Show last 15
        full_path = os.path.join(results_base_dir, result_dir)
        stat = os.stat(full_path)
        mod_time = datetime.datetime.fromtimestamp(stat.st_mtime)
        
        # Parse scan info from directory name
        parts = result_dir.split('_')
        if len(parts) >= 3:
            scan_type = parts[0]
            target = parts[1]
            print(f"  [{i:2}] {scan_type.upper()} scan of {target}")
            print(f"      📅 {mod_time.strftime('%Y-%m-%d %H:%M:%S')} | 📁 {result_dir}")
        else:
            print(f"  [{i:2}] {result_dir} - {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if i % 5 == 0:  # Add spacing every 5 entries
            print()
    
    print(f"\n  [0] Back to main menu")
    
    while True:
        choice = input(f"\nSelect result to view [0-{min(15, len(result_dirs))}]: ").strip()
        
        if choice == "0":
            return
        
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(result_dirs[:15]):
                selected_dir = result_dirs[choice_idx]
                full_path = os.path.join(results_base_dir, selected_dir)
                view_result_details(full_path, selected_dir)
                return
            else:
                print("❌ Invalid choice.")
        except ValueError:
            print("❌ Please enter a number.")

def view_result_details(result_path, result_name):
    """View details of a specific result directory."""
    clear_screen()
    print_banner()
    print(f"📊 SCAN RESULTS: {result_name}")
    print("=" * 60)
    
    # Show directory contents
    try:
        files = os.listdir(result_path)
        
        print("📁 FILES IN THIS SCAN:")
        print("-" * 30)
        
        for file in sorted(files):
            file_path = os.path.join(result_path, file)
            if os.path.isfile(file_path):
                size = os.path.getsize(file_path)
                mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                print(f"  📄 {file}")
                print(f"      Size: {size} bytes | Modified: {mod_time.strftime('%H:%M:%S')}")
                
                # Show content preview for small files
                if file.endswith(('.txt', '.json')) and size > 0 and size < 5000:
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read().strip()
                            if content:
                                lines = content.split('\n')
                                print(f"      Content: {len(lines)} lines")
                                if len(lines) <= 3:
                                    for line in lines:
                                        print(f"        {line[:100]}")
                                else:
                                    print(f"        {lines[0][:100]}...")
                                    print(f"        ... ({len(lines)-2} more lines) ...")
                                    print(f"        {lines[-1][:100]}")
                    except:
                        print("      (Preview unavailable)")
                print()
            elif os.path.isdir(file_path):
                print(f"  📁 {file}/")
        
        # Show summary if available
        summary_path = os.path.join(result_path, "scan_summary.txt")
        if os.path.exists(summary_path):
            print("\n📋 SCAN SUMMARY:")
            print("=" * 40)
            try:
                with open(summary_path, 'r') as f:
                    print(f.read())
            except:
                print("Error reading summary file.")
        
        print(f"\n📂 Full path: {result_path}")
        
    except Exception as e:
        print(f"❌ Error reading results: {e}")
    
    print(f"\n💡 To view files manually: ls -la {result_path}")
    input("\nPress Enter to continue...")

def update_templates():
    """Update nuclei templates."""
    clear_screen()
    print_banner()
    print("🔄 UPDATING NUCLEI TEMPLATES:")
    print("=" * 50)
    
    try:
        cmd = ["sudo", "python", "src/workflow.py", "--update-templates", "-host", "127.0.0.1"]
        print("📋 Running: nuclei -update-templates")
        result = subprocess.run(cmd)
        
        if result.returncode == 0:
            print("✅ Templates updated successfully!")
        else:
            print("❌ Template update failed.")
    
    except Exception as e:
        print(f"❌ Error updating templates: {e}")
    
    input("\nPress Enter to continue...")

def show_help():
    """Show help and documentation."""
    clear_screen()
    print_banner()
    print("📚 HELP & DOCUMENTATION:")
    print("=" * 50)
    print()
    print("🎯 TOOL DESCRIPTIONS:")
    print("  • naabu   - Fast port scanner for network reconnaissance")
    print("  • httpx   - HTTP toolkit for service discovery and analysis")
    print("  • nuclei  - Vulnerability scanner with 5000+ templates")
    print()
    print("🔧 SCAN TYPES:")
    print("  • Port Scan      - Discover open ports on target")
    print("  • HTTP Detection - Find HTTP services and gather info")
    print("  • Vuln Scan      - Check for known vulnerabilities")
    print("  • Full Scan      - Complete assessment (all tools)")
    print()
    print("⚙️  OPTIONS:")
    print("  • Stealth Mode   - Slower, more discreet scanning")
    print("  • Verbose        - Show detailed scan progress")
    print("  • JSON Output    - Machine-readable output format")
    print()
    print("📖 DOCUMENTATION:")
    print("  • README.md      - General overview and quick start")
    print("  • docs/USAGE.md  - Detailed usage examples")
    print("  • docs/INSTALL.md - Installation instructions")
    print()
    print("🚀 GETTING STARTED:")
    print("  • Run: python mtscan.py")
    print("  • Or: python src/workflow.py <target>")
    print()
    print("🌐 EXAMPLES:")
    print("  Target formats:")
    print("    • 192.168.1.100")
    print("    • example.com")
    print("    • https://target.com")
    print("    • 192.168.1.0/24 (for full scan)")
    print()
    
    input("Press Enter to continue...")

def install_tools():
    """Run the installation script."""
    clear_screen()
    print_banner()
    print("🔧 INSTALLING/UPDATING TOOLS:")
    print("=" * 50)
    
    if not os.path.exists("install/setup.py"):
        print("❌ Installation script not found!")
        print("Please ensure install/setup.py exists.")
        input("\nPress Enter to continue...")
        return
    
    try:
        print("🚀 Running installation script...")
        cmd = ["sudo", "python", "install/setup.py"]
        result = subprocess.run(cmd)
        
        if result.returncode == 0:
            print("\n✅ Installation completed successfully!")
        else:
            print("\n❌ Installation failed or completed with errors.")
        
    except Exception as e:
        print(f"\n❌ Error running installation: {e}")
    
    input("\nPress Enter to continue...")

def main():
    """Main menu loop."""
    # Ensure results directory exists at startup
    ensure_results_directory()
    
    while True:
        clear_screen()
        print_banner()
        print_tools_status()
        print_main_menu()
        
        choice = input("🎯 Select an option [0-9]: ").strip()
        
        if choice == "1":
            # Port scan with naabu
            target = get_target_input()
            ports = get_ports_input()
            options = get_scan_options()
            run_scan("naabu", target, ports=ports, **options)
            
        elif choice == "2":
            # HTTP service detection with httpx
            target = get_target_input()
            options = get_scan_options()
            run_scan("httpx", target, **options)
            
        elif choice == "3":
            # Vulnerability scan with nuclei
            target = get_target_input()
            options = get_scan_options()
            run_scan("nuclei", target, **options)
            
        elif choice == "4":
            # Full scan
            target = get_target_input()
            options = get_scan_options()
            run_scan("full", target, **options)
            
        elif choice == "5":
            # View previous results
            view_results()
            
        elif choice == "6":
            # Update nuclei templates
            update_templates()
            
        elif choice == "7":
            # Tool configuration (placeholder)
            clear_screen()
            print_banner()
            print("🔧 TOOL CONFIGURATION:")
            print("=" * 50)
            print("Configuration management coming soon!")
            print("For now, you can modify settings in:")
            print("  • src/workflow.py")
            print("  • Individual tool modules in src/commands/")
            input("\nPress Enter to continue...")
            
        elif choice == "8":
            # Install/update tools
            install_tools()
            
        elif choice == "9":
            # Help & documentation
            show_help()
            
        elif choice == "0":
            # Exit
            clear_screen()
            print("Thank you for using MTScan!")
            print("Stay secure! 🛡️")
            sys.exit(0)
            
        else:
            print("❌ Invalid choice. Please select 0-9.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nGoodbye! 👋")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
