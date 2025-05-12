#!/usr/bin/env python3
import subprocess
import sys
import os
import socket

def run_cmd(cmd, shell=False, check=False, use_sudo=False):
    """Run a shell command with optional sudo and error handling."""
    if use_sudo:
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
        except subprocess.CalledProcessError:
            print("Sudo access is required. Please run the script with sudo. Exiting.")
            sys.exit(1)

def check_network():
    """Check for network connectivity."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        print("No network connection detected. Please connect to the internet and try again. Exiting.")
        sys.exit(1)

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
            print(f"{name} not found. Installing...")
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
        print("Network check failed. Exiting.")
        sys.exit(1)
    ensure_sudo()

    # Check and install dependencies
    check_and_install("Python3", lambda: run_cmd(["python3", "--version"]), lambda: run_cmd(["apt-get", "install", "python3", "-y"], use_sudo=True))
    check_and_install("pip3", lambda: run_cmd(["pip3", "--version"]), lambda: run_cmd(["apt-get", "install", "python3-pip", "-y"], use_sudo=True))
    check_and_install("Go", lambda: run_cmd(["go", "version"]), lambda: run_cmd(["apt-get", "install", "golang", "-y"], use_sudo=True))
    check_and_install("naabu", lambda: run_cmd(["naabu", "--version"]), lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"], use_sudo=True))
    check_and_install("nuclei", lambda: run_cmd(["nuclei", "--version"]), lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], use_sudo=True))
    check_and_install("httpx", lambda: run_cmd(["httpx", "--version"]), lambda: run_cmd(["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"], use_sudo=True))

    update_path()
    print("\nSummary:")
    print("All dependencies are installed and verified.")
    print("Installation complete. Please restart your terminal or run 'source ~/.zshrc' or 'source ~/.bashrc'.")

if __name__ == "__main__":
    main()