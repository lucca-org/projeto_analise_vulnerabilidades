#!/usr/bin/env python3
import subprocess
import sys
import os
import shutil

def run_cmd(cmd, shell=False, check=False, use_sudo=False):
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
    if os.geteuid() != 0:
        print("Root privileges are required for some operations.")
        try:
            subprocess.run(["sudo", "true"], check=True)
        except Exception:
            print("Sudo access is required. Exiting.")
            sys.exit(1)

def check_python():
    return run_cmd(["python3", "--version"])

def install_python():
    print("Python3 not found. Installing Python3...")
    run_cmd(["apt-get", "update"], check=True, use_sudo=True)
    run_cmd(["apt-get", "install", "python3", "-y"], check=True, use_sudo=True)

def check_go():
    return run_cmd(["go", "version"])

def install_go():
    print("Go not found. Installing Go...")
    run_cmd(["apt-get", "update"], check=True, use_sudo=True)
    run_cmd(["apt-get", "install", "golang", "-y"], check=True, use_sudo=True)

def check_naabu():
    return run_cmd(["naabu", "--version"])

def install_naabu():
    print("naabu not found. Installing naabu...")
    run_cmd(["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"], check=True)

def check_nuclei():
    return run_cmd(["nuclei", "--version"])

def install_nuclei():
    print("nuclei not found. Installing nuclei...")
    run_cmd(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], check=True)

def check_httpx():
    return run_cmd(["httpx", "--version"])

def install_httpx():
    print("httpx not found. Installing httpx...")
    run_cmd(["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"], check=True)

def detect_shell_rc():
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return os.path.expanduser("~/.zshrc")
    return os.path.expanduser("~/.bashrc")

def update_path():
    shell_rc = detect_shell_rc()
    export_cmd = "export PATH=$PATH:$HOME/go/bin"
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

def main():
    ensure_sudo()

    def check_and_install(name, check_func, install_func):
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

    # Check and install dependencies
    check_and_install("Python3", check_python, install_python)
    check_and_install("Go", check_go, install_go)
    check_and_install("naabu", check_naabu, install_naabu)
    check_and_install("nuclei", check_nuclei, install_nuclei)
    check_and_install("httpx", check_httpx, install_httpx)

    update_path()
    print("Installation complete. Please restart your terminal or run 'source ~/.zshrc' or 'source ~/.bashrc'.")

if __name__ == "__main__":
    main()