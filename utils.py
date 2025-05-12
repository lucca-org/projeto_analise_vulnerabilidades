import subprocess
import os
import sys

def run_cmd(cmd, shell=False, check=False, use_sudo=False):
    """Run a shell command with optional sudo and error handling."""
    if use_sudo and os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    try:
        print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=300)
        if result.stdout:
            print(result.stdout)
        if result.stderr and result.returncode != 0:
            print(f"Error: {result.stderr}")
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"Command timed out after 300 seconds: {cmd}")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        return False
    except Exception as e:
        print(f"Error running command {cmd}: {str(e)}")
        return False

def ensure_sudo():
    """Ensure the script is running with sudo/root privileges."""
    if os.geteuid() != 0:
        print("Root privileges are required for some operations.")
        try:
            subprocess.run(["sudo", "true"], check=True)
        except Exception:
            print("Sudo access is required. Please run the script with sudo. Exiting.")
            sys.exit(1)

def check_network():
    """Check for network connectivity."""
    try:
        subprocess.run(["ping", "-c", "1", "8.8.8.8"], check=True)
        return True
    except subprocess.CalledProcessError:
        print("No network connection detected. Please connect to the internet and try again. Exiting.")
        return False