from utils import run_cmd

def run_naabu(target, ports=None, exclude_ports=None, threads=None, json_output=False, output_file=None, silent=False):
    """Run Naabu with the specified parameters."""
    cmd = ["naabu", "-host", target]

    if ports:
        cmd.extend(["-p", ports])
    if exclude_ports:
        cmd.extend(["-exclude-ports", exclude_ports])
    if threads:
        cmd.extend(["-c", str(threads)])
    if json_output:
        cmd.append("-json")
    if output_file:
        cmd.extend(["-o", output_file])
    if silent:
        cmd.append("-silent")

    if not run_cmd(cmd):
        print("Failed to execute Naabu. Please check the parameters and try again.")
        return False
    return True

def check_naabu():
    """Check if Naabu is installed."""
    return run_cmd(["naabu", "--version"])