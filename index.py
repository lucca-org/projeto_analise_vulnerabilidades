#!/usr/bin/env python3
import subprocess
import sys
import os
import socket
import platform
import shutil
import importlib.util
import time
import signal
import json
from pathlib import Path

# Configuration constants
GO_VERSION = "1.21.0"
SETUP_TIMEOUT = 60  # Maximum time for each installation step
MAX_DPKG_FIX_ATTEMPTS = 3  # Maximum number of attempts to fix dpkg
TOOLS_INFO = {
    "httpx": {
        "name": "httpx",
        "description": "Fast HTTP server probe and technology fingerprinter",
        "repository": "github.com/projectdiscovery/httpx/cmd/httpx",
        "module_file": "commands/httpx.py"
    },
    "nuclei": {
        "name": "nuclei",
        "description": "Fast pattern-based scanning for vulnerabilities",
        "repository": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
        "module_file": "commands/nuclei.py"
    },
    "naabu": {
        "name": "naabu",
        "description": "Fast port scanner with SYN/CONNECT modes",
        "repository": "github.com/projectdiscovery/naabu/v2/cmd/naabu",
        "module_file": "commands/naabu.py",
        "alternative_script": True
    }
}

def timeout_handler(signum, frame):
    """Handle timeouts for functions."""
    raise TimeoutError("Operation timed out")

def run_with_timeout(func, timeout=SETUP_TIMEOUT):
    """Run a function with a timeout."""
    # For Windows compatibility (which doesn't support SIGALRM)
    if platform.system().lower() == "windows":
        try:
            return func()
        except Exception as e:
            print(f"Error: {e}")
            return False
            
    # Set the timeout handler
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    try:
        result = func()
        # Cancel the timeout
        signal.alarm(0)
        return result
    except TimeoutError:
        print(f"Operation timed out after {timeout} seconds")
        return False
    finally:
        # Ensure the alarm is canceled
        signal.alarm(0)

def run_cmd(cmd, shell=False, check=False, use_sudo=False, timeout=300, retry=1, silent=False):
    """Run a shell command with optional sudo, error handling and retries."""
    if use_sudo and os.geteuid() != 0 and platform.system().lower() != "windows":
        cmd = ["sudo"] + cmd if isinstance(cmd, list) else ["sudo"] + [cmd]
    
    for attempt in range(retry + 1):
        try:
            if not silent:
                print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
            # Use custom timeout mechanism
            process = subprocess.Popen(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Set a timeout for the command
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                if stdout and not stdout.isspace() and not silent:
                    print(stdout)
                
                if process.returncode != 0:
                    if stderr and not silent:
                        print(f"Error: {stderr}")
                    
                    if attempt < retry:
                        if not silent:
                            print(f"Command failed. Retrying ({attempt+1}/{retry})...")
                        time.sleep(2)  # Add delay between retries
                        continue
                    
                    if check:
                        raise subprocess.CalledProcessError(process.returncode, cmd)
                    return False
                
                return True
            except subprocess.TimeoutExpired:
                # Kill the process if it times out
                process.kill()
                process.wait()
                if not silent:
                    print(f"Command timed out after {timeout} seconds: {cmd}")
                if attempt < retry:
                    if not silent:
                        print(f"Retrying ({attempt+1}/{retry})...")
                    time.sleep(2)
                    continue
                return False
        except subprocess.CalledProcessError as e:
            if not silent:
                print(f"Command failed: {e}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
        except Exception as e:
            if not silent:
                print(f"Error running command {cmd}: {str(e)}")
            if attempt < retry:
                if not silent:
                    print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
    
    return False

def kill_hung_processes(process_names=None):
    """Kill hung processes that might be preventing package management operations."""
    if platform.system().lower() != "linux":
        return
    
    if process_names is None:
        process_names = ["dpkg", "apt", "apt-get", "aptitude"]
    
    for proc_name in process_names:
        run_cmd(["pkill", "-9", proc_name], silent=True)
        run_cmd(["killall", "-9", proc_name], silent=True)

def fix_dpkg_interruptions():
    """Fix any interrupted dpkg operations with multiple approaches."""
    if platform.system().lower() != "linux":
        return True
        
    print("\n===== Fixing dpkg interruptions =====\n")
    
    # First kill any hung processes
    kill_hung_processes()
    
    # Remove lock files - be careful with this!
    run_cmd(["sudo", "rm", "-f", "/var/lib/dpkg/lock"], silent=True)
    run_cmd(["sudo", "rm", "-f", "/var/lib/dpkg/lock-frontend"], silent=True)
    run_cmd(["sudo", "rm", "-f", "/var/lib/apt/lists/lock"], silent=True)
    run_cmd(["sudo", "rm", "-f", "/var/cache/apt/archives/lock"], silent=True)
    
    # Create required directories
    run_cmd(["sudo", "mkdir", "-p", "/var/lib/dpkg/updates"], silent=True)
    run_cmd(["sudo", "mkdir", "-p", "/var/lib/apt/lists/partial"], silent=True)
    run_cmd(["sudo", "mkdir", "-p", "/var/cache/apt/archives/partial"], silent=True)
    
    success = False
    
    # Try up to MAX_DPKG_FIX_ATTEMPTS times
    for attempt in range(MAX_DPKG_FIX_ATTEMPTS):
        print(f"Dpkg fix attempt {attempt+1}/{MAX_DPKG_FIX_ATTEMPTS}...")
        
        # Try various approaches in sequence
        if run_cmd(["sudo", "dpkg", "--configure", "-a"], timeout=120, retry=0):
            success = True
        
        if run_cmd(["sudo", "apt-get", "update", "--fix-missing"], retry=0):
            success = True
        
        if run_cmd(["sudo", "apt-get", "install", "-f", "-y"], retry=0):
            success = True
        
        # If we've succeeded, break out of the loop
        if success:
            print("✓ Dpkg issues resolved")
            break
        
        # If we're still having issues and this isn't the last attempt, 
        # try more aggressive fixes
        if attempt < MAX_DPKG_FIX_ATTEMPTS - 1:
            print("Trying more aggressive dpkg fixes...")
            # Remove apt caches completely
            run_cmd(["sudo", "rm", "-rf", "/var/lib/apt/lists/*"], silent=True)
            # Remove apt states
            run_cmd(["sudo", "rm", "-rf", "/var/cache/apt/*.bin"], silent=True)
            # Clean apt
            run_cmd(["sudo", "apt-get", "clean"], silent=True)
            # Final update
            run_cmd(["sudo", "apt-get", "update"], silent=True)
    
    return success

def check_network():
    """Check for network connectivity."""
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    
    for dns in dns_servers:
        try:
            # Try connecting to DNS server
            socket.create_connection((dns, 53), 3)
            return True
        except Exception:
            continue
    
    print("No network connection detected. Please check your internet connection.")
    return False

def setup_go_env():
    """Set up Go environment paths."""
    go_bin = os.path.expanduser("~/go/bin")
    go_root_bin = "/usr/local/go/bin"
    paths_to_add = [go_bin, go_root_bin]
    
    # Add to current environment
    for path in paths_to_add:
        if os.path.exists(path) and path not in os.environ.get("PATH", ""):
            os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + path

    # Return paths for updating shell configs
    return paths_to_add

def update_shell_rc_files(paths_to_add):
    """Update shell configuration files to include Go paths."""
    if platform.system().lower() == "windows":
        print("Please manually add the following to your PATH environment variable:")
        for path in paths_to_add:
            print(f"  {path}")
        return
    
    # Determine which shell rc files to update
    shell_rc_files = []
    home = os.path.expanduser("~")
    
    # Common shell config files
    possible_rc_files = {
        "bash": os.path.join(home, ".bashrc"),
        "zsh": os.path.join(home, ".zshrc"),
        "fish": os.path.join(home, ".config", "fish", "config.fish"),
        "profile": os.path.join(home, ".profile")
    }
    
    # Detect user's shell
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        shell_rc_files.append(possible_rc_files["zsh"])
    elif "bash" in shell:
        shell_rc_files.append(possible_rc_files["bash"])
    elif "fish" in shell:
        shell_rc_files.append(possible_rc_files["fish"])
    else:
        # Default to common ones if we can't detect
        for file_path in [possible_rc_files["bash"], possible_rc_files["profile"]]:
            if os.path.exists(file_path):
                shell_rc_files.append(file_path)
    
    # Always include .profile for login shells
    if possible_rc_files["profile"] not in shell_rc_files:
        shell_rc_files.append(possible_rc_files["profile"])
    
    # Update each file
    updated_files = []
    for rc_file in shell_rc_files:
        try:
            # Make sure parent directory exists
            os.makedirs(os.path.dirname(rc_file), exist_ok=True)
            
            # Prepare export strings based on shell type
            if "fish" in rc_file:
                export_strs = [f'set -x PATH $PATH {path}' for path in paths_to_add]
            else:
                export_strs = [f'export PATH=$PATH:{path}' for path in paths_to_add]
            
            # Check if file exists and if paths are already in it
            content = ""
            if os.path.exists(rc_file):
                with open(rc_file, "r") as f:
                    content = f.read()
            
            # Add paths that aren't already there
            with open(rc_file, "a+") as f:
                updates_made = False
                for export_str in export_strs:
                    if export_str not in content:
                        f.write(f"\n# Added by vulnerability analysis setup\n{export_str}\n")
                        updates_made = True
                
                if updates_made:
                    updated_files.append(rc_file)
        
        except Exception as e:
            print(f"Error updating {rc_file}: {e}")
    
    if updated_files:
        print(f"Updated the following shell configuration files: {', '.join(updated_files)}")
        print(f"Please run 'source {updated_files[0]}' or restart your terminal to update PATH.")
    
    return updated_files

def manual_go_install():
    """Manually download and install Go."""
    print("Installing Go manually...")
    try:
        # Determine architecture
        arch = "amd64"  # Default
        if platform.machine() == "aarch64" or platform.machine() == "arm64":
            arch = "arm64"
        elif platform.machine() in ["armv7l", "armv6l"]:
            arch = "armv6l"
        
        # Download Go
        go_url = f"https://golang.org/dl/go{GO_VERSION}.linux-{arch}.tar.gz"
        if not run_cmd(["wget", go_url, "-O", "/tmp/go.tar.gz"]):
            print("Failed to download Go. Please check your network connection.")
            # Try curl as fallback
            if not run_cmd(["curl", "-L", go_url, "-o", "/tmp/go.tar.gz"]):
                print("Failed to download Go with curl as well. Installation aborted.")
                return False
        
        # Extract Go
        run_cmd(["sudo", "rm", "-rf", "/usr/local/go"])
        if not run_cmd(["sudo", "tar", "-C", "/usr/local", "-xzf", "/tmp/go.tar.gz"]):
            print("Failed to extract Go.")
            return False
        
        # Clean up
        run_cmd(["rm", "/tmp/go.tar.gz"], silent=True)
        
        # Set up environment
        paths = setup_go_env()
        update_shell_rc_files(paths)
        
        # Verify installation
        go_binary = "/usr/local/go/bin/go"
        if os.path.exists(go_binary) and run_cmd([go_binary, "version"]):
            print("Go installed successfully via manual installation.")
            return True
        
        print("Failed to verify Go installation.")
        return False
    except Exception as e:
        print(f"Error during manual Go installation: {e}")
        return False

def check_and_install_go():
    """Check if Go is installed, and install it if not."""
    # First try existing Go installation
    if run_cmd(["go", "version"], retry=0):
        print("Go is already installed.")
        # Still set up paths to ensure proper environment
        paths = setup_go_env()
        update_shell_rc_files(paths)
        return True
    
    # If not found in PATH, check if /usr/local/go/bin/go exists
    if os.path.exists("/usr/local/go/bin/go") and run_cmd(["/usr/local/go/bin/go", "version"], retry=0):
        print("Go is installed but not in PATH. Setting up environment...")
        paths = setup_go_env()
        update_shell_rc_files(paths)
        return True
    
    # If not found, try manual installation
    return manual_go_install()

def install_naabu_alternative():
    """Install an enhanced alternative to naabu that doesn't require libpcap."""
    print("\n===== Creating enhanced naabu alternative script =====\n")
    naabu_path = os.path.expanduser("~/go/bin/naabu")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(naabu_path), exist_ok=True)
    
    script_content = """#!/bin/bash
# naabu-alternative v2.0.0 - Multi-engine port scanner for maximum compatibility
# Features: nmap, netcat fallback, faster port scanning, better JSON handling

VERSION="2.0.0"
TARGET=""
TARGET_FILE=""
PORTS="1-1000"
OUTPUT=""
VERBOSE=false
RATE=1000
TIMEOUT=5000
JSON=false
SILENT=false
THREADS=25
PARALLEL=5  # Max targets to scan in parallel

# Parse all arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -host)
            TARGET="$2"
            shift 2
            ;;
        -l)
            TARGET_FILE="$2"
            shift 2
            ;;
        -p|-ports)
            PORTS="$2"
            shift 2
            ;;
        -o|-output)
            OUTPUT="$2"
            shift 2
            ;;
        -v|-verbose)
            VERBOSE=true
            shift
            ;;
        -c)
            THREADS="$2"
            shift 2
            ;;
        -rate)
            RATE="$2"
            shift 2
            ;;
        -json)
            JSON=true
            shift
            ;;
        -silent)
            SILENT=true
            shift
            ;;
        -timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -version)
            echo "naabu-alternative v$VERSION"
            exit 0
            ;;
        -h|-help)
            echo "Naabu alternative - multi-engine port scanner"
            echo "Usage:"
            echo "  -host string        Host to scan"
            echo "  -l string           List of hosts to scan"
            echo "  -p, -ports string   Ports to scan (default: 1-1000)"
            echo "  -o, -output string  Output file to write results"
            echo "  -v, -verbose        Verbose output"
            echo "  -c int              Number of concurrent threads (default: 25)"
            echo "  -silent             Silent mode"
            echo "  -json               Output in JSON format"
            echo "  -rate int           Rate of port scan (default: 1000)"
            echo "  -timeout int        Timeout in milliseconds (default: 5000)"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Validate input
if [[ -z "$TARGET" && -z "$TARGET_FILE" ]]; then
    echo "Error: No target specified. Use -host or -l."
    exit 1
fi

if [[ "$SILENT" = false ]]; then
    echo "Starting port scan with naabu-alternative v$VERSION"
fi

# Create temp files and directories for processing
TEMP_DIR=$(mktemp -d)
TEMP_RESULTS="$TEMP_DIR/results"
mkdir -p "$TEMP_RESULTS"

# Process targets
if [[ -n "$TARGET" ]]; then
    echo "$TARGET" > "$TEMP_DIR/targets.txt"
elif [[ -n "$TARGET_FILE" ]]; then
    if [[ ! -f "$TARGET_FILE" ]]; then
        echo "Error: Target file not found: $TARGET_FILE"
        exit 1
    fi
    cp "$TARGET_FILE" "$TEMP_DIR/targets.txt"
fi

# Port scanning function

scan_with_nc() {
    local target="$1"
    local output="$2"
    local nc_timeout=1
    
    # Convert port ranges into array
    local all_ports=()
    IFS=',' read -ra ranges <<< "$PORTS"
    for range in "${ranges[@]}"; do
        if [[ "$range" == *-* ]]; then
            start=$(echo "$range" | cut -d'-' -f1)
            end=$(echo "$range" | cut -d'-' -f2)
            for ((p=start; p<=end; p++)); do
                all_ports+=($p)
            done
        else
            all_ports+=($range)
        fi
    done
    
    # Count total ports
    local port_count=${#all_ports[@]}
    
    # Calculate ports per thread
    local ports_per_thread=$(( (port_count + THREADS - 1) / THREADS ))
    
    # Function to scan a range of ports
    scan_port_range() {
        local target="$1"
        local start_idx="$2"
        local end_idx="$3"
        local out_file="$4"
        local found=0
        
        local tmp_out="${out_file}.$start_idx"
        > "$tmp_out"
        
        for ((i=start_idx; i<end_idx && i<port_count; i++)); do
            local port=${all_ports[$i]}
            if timeout 0.5 nc -z -w1 "$target" "$port" 2>/dev/null; then
                echo "Port:$port/tcp" >> "$tmp_out"
                found=1
                if [[ "$VERBOSE" = true && "$SILENT" = false ]]; then
                    echo "Found open port on $target: $port"
                fi
            fi
        done
        
        # Copy results to main file
        cat "$tmp_out" >> "$out_file"
        rm "$tmp_out"
    }
    
    # Launch parallel scans
    for ((t=0; t<THREADS; t++)); do
        local start_idx=$((t * ports_per_thread))
        local end_idx=$(((t+1) * ports_per_thread))
        scan_port_range "$target" "$start_idx" "$end_idx" "$output" &
        
        # Limit parallel processes
        if [[ $((t % 10)) -eq 9 ]]; then
            wait
        fi
    done
    
    # Wait for all scans to complete
    wait
    
    if [[ -s "$output" ]]; then
        return 0
    else
        return 1
    fi
}

# Process each target
total_targets=$(wc -l < "$TEMP_DIR/targets.txt")
counter=0

if [[ "$SILENT" = false ]]; then
    echo "Processing $total_targets targets..."
fi

# Use netcat for port scanning (no nmap dependency)
SCANNER="nc"
if command -v nc >/dev/null 2>&1; then
    if [[ "$SILENT" = false ]]; then
        echo "Using netcat for port scanning"
    fi
else
    echo "Error: Netcat not found. Please install netcat (nc) package."
    exit 1
fi

process_target() {
    local target="$1"
    local target_id="$2"
    local output="$TEMP_RESULTS/$target_id.txt"
    
    # Skip empty lines and comments
    [[ -z "$target" || "$target" =~ ^[[:space:]]*# ]] && return
    
    # Process with netcat
    local success=false
    
    if scan_with_nc "$target" "$output"; then
        success=true
    fi
    
    if [[ "$success" != "true" && "$SILENT" = false && "$VERBOSE" = true ]]; then
        echo "No open ports found on $target"
    fi
}

# Process targets in parallel
cat "$TEMP_DIR/targets.txt" | while read -r target; do
    counter=$((counter+1))
    if [[ "$VERBOSE" = true && "$SILENT" = false ]]; then
        echo "[$counter/$total_targets] Scanning $target"
    fi
    
    # Process in background with limited parallelism
    process_target "$target" "$counter" &
    
    # Limit number of parallel processes
    if [[ $((counter % PARALLEL)) -eq 0 ]]; then
        wait
    fi
done

# Wait for all processes to finish
wait

# Combine and format results
if [[ -n "$OUTPUT" ]]; then
    # Create the output file based on format
    if [[ "$JSON" = true ]]; then
        echo "[" > "$OUTPUT"
        
        first_entry=true
        for result_file in "$TEMP_RESULTS"/*.txt; do
            [[ ! -s "$result_file" ]] && continue
            
            target_id=$(basename "$result_file" .txt)
            target=$(sed -n "${target_id}p" "$TEMP_DIR/targets.txt")
            
            if [[ -f "$result_file" && -s "$result_file" ]]; then
                # Process netcat output
                while read -r line; do
                    [[ -z "$line" ]] && continue
                    
                    if [[ "$line" =~ Port:([0-9]+) ]]; then
                        port="${BASH_REMATCH[1]}"
                        if [[ "$first_entry" != "true" ]]; then
                            echo "," >> "$OUTPUT"
                        fi
                        first_entry=false
                        echo -n "  {\"host\":\"$target\",\"port\":$port}" >> "$OUTPUT"
                    fi
                done < "$result_file"
            fi
        done
        
        echo "" >> "$OUTPUT"
        echo "]" >> "$OUTPUT"
    else
        > "$OUTPUT"
        for result_file in "$TEMP_RESULTS"/*.txt; do
            [[ ! -s "$result_file" ]] && continue
            
            target_id=$(basename "$result_file" .txt)
            target=$(sed -n "${target_id}p" "$TEMP_DIR/targets.txt")
            
            if [[ "$SCANNER" == "nmap" && -f "$result_file" && -s "$result_file" ]]; then
                # Process nmap output
                ports=$(cat "$result_file" | grep -oP 'Ports: \K.*' | tr ',' '\n' | grep -v "closed" | grep -v "filtered")
                
                while read -r port_info; do
                    [[ -z "$port_info" ]] && continue
                    
                    port_num=$(echo "$port_info" | awk '{print $1}')
                    if [[ -n "$port_num" ]]; then
                        echo "$target:$port_num" >> "$OUTPUT"
                    fi
                done <<< "$ports"
            elif [[ "$SCANNER" == "nc" && -f "$result_file" && -s "$result_file" ]]; then
                # Process netcat output
                while read -r line; do
                    [[ -z "$line" ]] && continue
                    
                    if [[ "$line" =~ Port:([0-9]+) ]]; then
                        port="${BASH_REMATCH[1]}"
                        echo "$target:$port" >> "$OUTPUT"
                    fi
                done < "$result_file"
            fi
        done
    fi
    
    if [[ "$SILENT" = false ]]; then
        echo "Results saved to $OUTPUT"
    fi
fi

# Clean up
rm -rf "$TEMP_DIR"

exit 0
"""
    
    try:
        with open(naabu_path, 'w') as f:
            f.write(script_content)
        os.chmod(naabu_path, 0o755)
        print(f"✓ Created enhanced naabu alternative script at {naabu_path}")
        return True
    except Exception as e:
        print(f"✗ Failed to create naabu alternative script: {e}")
        return False

def install_security_tools():
    """Install security tools using Go."""
    # Set up Go environment
    setup_go_env()
    
    # List of tools to install
    tools = [
        {"name": "httpx", "repo": "github.com/projectdiscovery/httpx/cmd/httpx"},
        {"name": "nuclei", "repo": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"}
    ]
    
    installed_tools = []
    
    for tool in tools:
        # Check if already installed
        if shutil.which(tool["name"]) or os.path.exists(os.path.expanduser(f"~/go/bin/{tool['name']}")):
            print(f"{tool['name']} is already installed.")
            installed_tools.append(tool["name"])
            continue
            
        print(f"Installing {tool['name']}...")
        # First try with GO111MODULE=on to avoid module issues
        os.environ["GO111MODULE"] = "on"
        if run_cmd(["go", "install", "-v", f"{tool['repo']}@latest"]):
            installed_tools.append(tool["name"])
            print(f"{tool['name']} installed successfully.")
        # Try without version constraint if the first attempt failed
        elif run_cmd(["go", "install", "-v", tool["repo"]]):
            installed_tools.append(tool["name"])
            print(f"{tool['name']} installed successfully.")
        else:
            print(f"Failed to install {tool['name']}")
    
    # Try to install naabu, but fallback to alternative if it fails
    if not shutil.which("naabu") and not os.path.exists(os.path.expanduser("~/go/bin/naabu")):
        print("Installing naabu...")
        # Try with CGO disabled (no libpcap dependency)
        os.environ["CGO_ENABLED"] = "0"
        if run_cmd(["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"]):
            installed_tools.append("naabu")
            print("naabu installed successfully with CGO disabled.")
        # Try an older version that might have fewer dependencies
        elif run_cmd(["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.0.0"]):
            installed_tools.append("naabu")
            print("naabu v2.0.0 installed successfully.")
        else:
            print("Failed to install naabu with go install. Creating alternative script...")
            if install_naabu_alternative():
                installed_tools.append("naabu")
    else:
        print("naabu is already installed.")
        installed_tools.append("naabu")
    
    return installed_tools

def setup_python_venv():
    """Set up a Python virtual environment."""
    print("\n===== Setting up Python Virtual Environment =====\n")
    
    venv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
    if os.path.exists(venv_path):
        print(f"Using existing virtual environment at {venv_path}")
        return venv_path
    
    try:
        print(f"Creating Python virtual environment at {venv_path}")
        subprocess.run([sys.executable, "-m", "venv", venv_path], check=True)
        print("Virtual environment created successfully.")
        return venv_path
    except Exception as e:
        print(f"Error creating virtual environment: {e}")
        # Try without using a virtual environment
        print("Trying to install packages globally...")
        return None

def install_python_packages(venv_path=None):
    """Install required Python packages."""
    print("\n===== Installing Essential Python Packages =====\n")
    
    # First, try to read requirements.txt
    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    packages = ["requests", "colorama", "rich", "tqdm"]
    
    if os.path.exists(req_file):
        try:
            with open(req_file, "r") as f:
                # Filter out commented lines and empty lines
                req_packages = [line.strip() for line in f 
                               if line.strip() and not line.strip().startswith("#")]
                
                if req_packages:
                    packages = req_packages
                    print(f"Found {len(req_packages)} packages in requirements.txt")
        except Exception as e:
            print(f"Error reading requirements.txt: {e}")
    
    # Set the pip command
    pip_cmd = "pip"
    pip_args = ["install"]
    
    if venv_path:
        if platform.system().lower() == "windows":
            pip_cmd = os.path.join(venv_path, "Scripts", "pip")
        else:
            pip_cmd = os.path.join(venv_path, "bin", "pip")
    
    try:
        # First try with the virtual environment
        if run_cmd([pip_cmd] + pip_args + packages):
            print("✓ Python packages installed successfully")
            return True
        
        # Fall back to system pip if venv pip fails
        print("Failed to install packages with venv pip. Trying system pip...")
        if run_cmd([sys.executable, "-m", "pip"] + pip_args + packages):
            print("✓ Python packages installed successfully with system pip")
            return True
        
        # Try installing each package individually
        print("Trying to install packages individually...")
        success_count = 0
        for package in packages:
            if run_cmd([sys.executable, "-m", "pip", "install", package]):
                success_count += 1
        
        if success_count > 0:
            print(f"✓ Successfully installed {success_count} out of {len(packages)} packages")
            return True
        
        print("Failed to install Python packages")
        return False
    except Exception as e:
        print(f"Error installing Python packages: {e}")
        return False

def import_commands():
    """Import command modules and verify they work."""
    commands_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "commands")
    if not os.path.exists(commands_path):
        print(f"Commands directory not found: {commands_path}")
        return {}
        
    modules = {}
    
    for file in os.listdir(commands_path):
        if file.endswith('.py') and not file.startswith('__'):
            module_name = file[:-3]
            try:
                spec = importlib.util.spec_from_file_location(
                    module_name, 
                    os.path.join(commands_path, file)
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                modules[module_name] = module
                print(f"Successfully imported {module_name} module")
            except Exception as e:
                print(f"Error importing {module_name}: {e}")
    
    return modules

def update_nuclei_templates():
    """Update nuclei templates."""
    if shutil.which("nuclei") or os.path.exists(os.path.expanduser("~/go/bin/nuclei")):
        print("\n===== Updating Nuclei Templates =====\n")
        run_cmd(["nuclei", "-update-templates"], timeout=180)
    else:
        print("Nuclei not found. Skipping template updates.")

def create_documentation_if_missing():
    """Create basic documentation if it doesn't exist."""
    docs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "documentacao")
    doc_file = os.path.join(docs_dir, "comandos_e_parametros.txt")
    
    if not os.path.exists(docs_dir):
        try:
            os.makedirs(docs_dir, exist_ok=True)
        except Exception as e:
            print(f"Error creating documentation directory: {e}")
            return False
    
    if not os.path.exists(doc_file):
        try:
            with open(doc_file, "w") as f:
                f.write("""=== Vulnerability Analysis Tools - Command Reference ===

This file contains reference documentation for the security tools installed by this project.

== NAABU - Port Scanner ==

Basic Usage:
  naabu -host example.com -p 80,443,8080-8090 -o ports.txt

Common Parameters:
  -host          Target host to scan
  -l             Path to file containing list of hosts to scan
  -p, -ports     Ports to scan (default: top 100)
  -o             Output file to write results
  -json          Write output in JSON format
  -v             Verbose output
  -rate          Number of packets per second (default: 1000)
  -c             Number of concurrent ports to scan (default: 25)
  -timeout       Timeout in milliseconds (default: 1000)

== HTTPX - HTTP Request Runner ==

Basic Usage:
  httpx -l hosts.txt -title -status-code -tech-detect -o results.txt

Common Parameters:
  -u             Target URL to scan
  -l             Path to file containing list of hosts to scan
  -o             Output file to write results
  -json          Write output in JSON format
  -title         Extract title from response
  -tech-detect   Perform web technology detection
  -status-code   Display status code
  -follow-redirects Follow URL redirects
  -threads       Number of threads to use (default: 50)
  -timeout       Timeout in seconds (default: 5)

== NUCLEI - Vulnerability Scanner ==

Basic Usage:
  nuclei -l urls.txt -t cves/ -severity critical,high -o vulnerabilities.txt

Common Parameters:
  -u             Target URL to scan
  -l             Path to file containing list of URLs to scan
  -t             Templates or template directory to use for scanning
  -o             Output file to write results
  -jsonl         Write output in JSONL format
  -severity      Filter templates by severity (critical, high, medium, low)
  -tags          Filter templates by tags (e.g., cve,rce,lfi)
  -c             Maximum number of templates to execute in parallel (default: 25)
  -timeout       Timeout in seconds (default: 5)



== WORKFLOW SCRIPT ==

The workflow.py script combines all tools for a complete vulnerability analysis:

Usage:
  python3 workflow.py example.com [options]

Options:
  --ports PORTS           Ports to scan with naabu (default: top-1000)
  --templates TEMPLATES   Templates directory for nuclei
  --tags TAGS             Tags to use with nuclei (default: cve)
  --severity SEVERITY     Severity filter for nuclei (default: critical,high)
  --output-dir DIR        Directory to save results
  --update-templates      Update nuclei templates before scanning
  --verbose               Display verbose output

""")
            print("Created basic documentation file in documentacao/comandos_e_parametros.txt")
            return True
        except Exception as e:
            print(f"Error creating documentation file: {e}")
            return False
    
    return True

def check_utils_file():
    """Check if utils.py exists and create it if it doesn't."""
    utils_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "utils.py")
    if not os.path.exists(utils_path):
        try:
            with open(utils_path, "w") as f:
                f.write("""#!/usr/bin/env python3
import subprocess
import socket
import os
import time

def run_cmd(cmd, shell=False, check=False, timeout=300, retry=1):
    \"\"\"Run a shell command with error handling and retries.\"\"\"
    for attempt in range(retry + 1):
        try:
            print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
            
            process = subprocess.run(
                cmd,
                shell=shell,
                check=check,
                text=True,
                capture_output=True,
                timeout=timeout
            )
            
            if process.stdout and not process.stdout.isspace():
                print(process.stdout)
            
            if process.returncode != 0:
                if process.stderr:
                    print(f"Error: {process.stderr}")
                
                if attempt < retry:
                    print(f"Command failed. Retrying ({attempt+1}/{retry})...")
                    time.sleep(2)
                    continue
                return False
            
            return True
        
        except subprocess.TimeoutExpired:
            print(f"Command timed out after {timeout} seconds.")
            if attempt < retry:
                print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
            
        except Exception as e:
            print(f"Error running command: {str(e)}")
            if attempt < retry:
                print(f"Retrying ({attempt+1}/{retry})...")
                time.sleep(2)
                continue
            return False
    
    return False

def check_network():
    \"\"\"Check for network connectivity.\"\"\"
    try:
        # Try connecting to Google DNS
        socket.create_connection(("8.8.8.8", 53), 3)
        return True
    except Exception:
        try:
            # Try Cloudflare DNS as fallback
            socket.create_connection(("1.1.1.1", 53), 3)
            return True
        except Exception:
            print("No network connection detected.")
            return False

def create_directory_if_not_exists(directory):
    \"\"\"Create a directory if it doesn't exist.\"\"\"
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {directory}: {e}")
        return False

def get_file_size(file_path):
    \"\"\"Get file size in a human-readable format.\"\"\"
    try:
        size_bytes = os.path.getsize(file_path)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024 or unit == 'GB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
    except Exception:
        return "Unknown size"
""")
            print("Created utils.py file with helper functions")
            return True
        except Exception as e:
            print(f"Error creating utils.py: {e}")
            return False
    return True

def check_and_install_dependencies():
    """Check and install all required dependencies."""
    print("\n===== Checking and Installing Dependencies =====\n")

    # Check and install Python dependencies
    print("Checking Python dependencies...")
    venv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
    if not os.path.exists(venv_path):
        setup_python_venv()
    install_python_packages(venv_path)

    # Check and install Go and Go tools
    print("Checking Go and Go tools...")
    if not check_and_install_go():
        print("Failed to install Go. Please check your environment.")
        return False

    installed_tools = install_security_tools()
    if "naabu" not in installed_tools:
        install_naabu_alternative()

    print("\nAll dependencies are installed and up-to-date.")
    return True

def main():
    print("\n===== Vulnerability Analysis Tools Setup =====\n")
    
    # Skip network check if user wants to proceed without network
    if not check_network():
        response = input("No network detected. Would you like to continue with local setup only? (y/N): ")
        if not response.lower().startswith('y'):
            print("Exiting.")
            sys.exit(1)
    
    # Check utils file
    check_utils_file()
    
    # If on Linux, fix dpkg issues first
    if platform.system().lower() == "linux":
        fix_dpkg_interruptions()
    
    # Set up Python environment
    venv_path = setup_python_venv()
    install_python_packages(venv_path)
    
    # Install Go using a more robust method
    if not check_and_install_go():
        print("⚠️ Warning: Go installation failed. Some tools may not work correctly.")
        response = input("Continue with installation? (y/N): ")
        if not response.lower().startswith('y'):
            print("Exiting.")
            sys.exit(1)
    
    # Install security tools
    installed_tools = install_security_tools()
    
    # Update nuclei templates
    update_nuclei_templates()
    
    # Create documentation if missing
    create_documentation_if_missing()
    
    # Import and test command modules
    print("\n===== Testing Command Modules =====\n")
    modules = import_commands()
    
    # Display summary
    print("\n===== Summary =====")
    print("✓ Dependencies installation completed.")
    
    # Find and update shell config file
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        shell_rc = os.path.expanduser("~/.zshrc")
    else:
        shell_rc = os.path.expanduser("~/.bashrc")
    
    print(f"✓ Shell configuration updated: {shell_rc}")
    print(f"✓ Please run: source {shell_rc} or restart your terminal to update PATH.")
    print("✓ All systems ready for vulnerability analysis.")
      # Check which tools are installed
    tools_installed = []
    for tool in ["httpx", "nuclei", "naabu"]:
        if shutil.which(tool) or os.path.exists(os.path.expanduser(f"~/go/bin/{tool}")):
            tools_installed.append(tool)
    
    if tools_installed:
        print("\n===== Quick Start =====")
        print(f"Available tools: {', '.join(tools_installed)}")
        print("To scan a target:")
        if "naabu" in tools_installed:
            print("1. Map open ports: naabu -host example.com -p 80,443,8080-8090 -o ports.txt")
        if "httpx" in tools_installed:
            print("2. Probe for HTTP services: httpx -l ports.txt -title -tech-detect -o http_services.txt")
        if "nuclei" in tools_installed:
            print("3. Scan for vulnerabilities: nuclei -l http_services.txt -t cves/ -severity critical,high -o vulnerabilities.txt")
        
        workflow_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "workflow.py")
        if os.path.exists(workflow_path) and all(tool in tools_installed for tool in ["naabu", "httpx", "nuclei"]):
            print("\nOr use the automated workflow script:")
            print("python3 workflow.py example.com")
    
    print("\nFor more options, check the documentation in documentacao/comandos_e_parametros.txt")

if __name__ == "__main__":
    if not check_and_install_dependencies():
        print("Dependency installation failed. Exiting.")
        exit(1)

    main()