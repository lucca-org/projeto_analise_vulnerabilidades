#!/usr/bin/env python3
import subprocess
import sys
import os
import shutil
import socket
import importlib

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
            print("Sudo access is required. Exiting.")
            sys.exit(1)

def check_network():
    """Check for network connectivity."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        print("No network connection detected. Please connect to the internet and try again.")
        return False

def check_python():
    """Check if Python3 is installed."""
    return run_cmd(["python3", "--version"])

def install_python():
    print("Python3 not found. Installing Python3...")
    run_cmd(["apt-get", "update"], check=True, use_sudo=True)
    run_cmd(["apt-get", "install", "python3", "-y"], check=True, use_sudo=True)
    run_cmd(["apt-get", "install", "python3-pip", "-y"], check=True, use_sudo=True)

def check_pip3():
    """Check if pip3 is installed."""
    return run_cmd(["pip3", "--version"])

def install_pip3():
    print("pip3 not found. Installing pip3...")
    run_cmd(["apt-get", "install", "python3-pip", "-y"], check=True, use_sudo=True)

def check_pytest():
    """Check if pytest is installed."""
    try:
        import pytest  # noqa: F401
        return True
    except ImportError:
        return False

def install_pytest():
    print("pytest not found. Installing pytest...")
    run_cmd(["pip3", "install", "--user", "pytest"], check=True)
    try:
        importlib.invalidate_caches()
        import pytest  # noqa: F401
    except ImportError:
        print("Failed to import pytest after installation.")
        sys.exit(1)

def check_go():
    """Check if Go is installed."""
    return run_cmd(["go", "version"])

def install_go():
    print("Go not found. Installing Go...")
    run_cmd(["apt-get", "update"], check=True, use_sudo=True)
    run_cmd(["apt-get", "install", "golang", "-y"], check=True, use_sudo=True)
    run_cmd(["apt-get", "install", "git", "-y"], check=True, use_sudo=True)
    run_cmd(["apt-get", "install", "build-essential", "-y"], check=True, use_sudo=True)
    run_cmd(["apt-get", "install", "libpcap-dev", "-y"], check=True, use_sudo=True)

def check_naabu():
    """Check if naabu is installed."""
    return run_cmd(["naabu", "--version"])

def install_naabu():
    print("naabu not found. Installing naabu...")
    run_cmd(["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"], check=True)

def check_nuclei():
    """Check if nuclei is installed."""
    return run_cmd(["nuclei", "--version"])

def install_nuclei():
    print("nuclei not found. Installing nuclei...")
    run_cmd(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], check=True)

def check_httpx():
    """Check if httpx is installed."""
    return run_cmd(["httpx", "--version"])

def install_httpx():
    print("httpx not found. Installing httpx...")
    run_cmd(["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"], check=True)

def detect_shell_rc():
    """Detect the user's shell rc file."""
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return os.path.expanduser("~/.zshrc")
    return os.path.expanduser("~/.bashrc")

def update_path():
    """Add $HOME/go/bin to PATH in the shell rc file if not already present."""
    shell_rc = detect_shell_rc()
    export_cmd = "export PATH=$PATH:$HOME/go/bin"
    path_env = os.environ.get("PATH", "")
    if "$HOME/go/bin" in path_env or os.path.expanduser("~/go/bin") in path_env:
        print("Your PATH already contains $HOME/go/bin.")
        return
    try:
        with open(shell_rc, "a+") as f:
            f.seek(0)
            content = f.read()
            if export_cmd not in content:
                f.write(f"\n{export_cmd}\n")
                print(f"Added '{export_cmd}' to {shell_rc}")
            else:
                print(f"'{export_cmd}' already present in {shell_rc}")
        print(f"Please run: source {shell_rc} or restart your terminal to update PATH.")
    except PermissionError:
        print(f"Permission denied while updating {shell_rc}. Try running this script with sudo or update your PATH manually.")
    except Exception as e:
        print(f"Error updating PATH: {e}")

def check_and_install(name, check_func, install_func):
    """Check and install a tool or dependency."""
    try:
        if not check_func():
            install_func()
            if not check_func():
                print(f"{name} installation failed. Exiting.")
                sys.exit(1)
            print(f"{name} installed and verified.")
        else:
            print(f"{name} is already installed.")
    except Exception as e:
        print(f"Error during installation of {name}: {e}")
        sys.exit(1)

def main():
    if not check_network():
        sys.exit(1)
    ensure_sudo()

    # Check and install dependencies
    check_and_install("Python3", check_python, install_python)
    check_and_install("pip3", check_pip3, install_pip3)
    check_and_install("pytest", check_pytest, install_pytest)
    check_and_install("Go", check_go, install_go)
    check_and_install("naabu", check_naabu, install_naabu)
    check_and_install("nuclei", check_nuclei, install_nuclei)
    check_and_install("httpx", check_httpx, install_httpx)

    update_path()
    print("\nSummary:")
    print("All dependencies are installed and verified.")
    print("Installation complete. Please restart your terminal or run 'source ~/.zshrc' or 'source ~/.bashrc'.")

if __name__ == "__main__":
    main()