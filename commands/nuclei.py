from utils import run_cmd

def run_nuclei(target=None, target_list=None, templates=None, tags=None, output_file=None, jsonl=False, silent=False, store_resp=False, headers=None, variables=None):
    """Run Nuclei with the specified parameters."""
    cmd = ["nuclei"]

    if target:
        cmd.extend(["-u", target])
    if target_list:
        cmd.extend(["-l", target_list])
    if templates:
        cmd.extend(["-t", templates])
    if tags:
        cmd.extend(["-tags", tags])
    if output_file:
        cmd.extend(["-o", output_file])
    if jsonl:
        cmd.append("-jsonl")
    if silent:
        cmd.append("-silent")
    if store_resp:
        cmd.append("-store-resp")
    if headers:
        for header in headers:
            cmd.extend(["-H", header])
    if variables:
        for key, value in variables.items():
            cmd.extend(["-V", f"{key}={value}"])

    if not run_cmd(cmd):
        print("Failed to execute Nuclei. Please check the parameters and try again.")
        return False
    return True

def check_nuclei():
    """Check if Nuclei is installed."""
    return run_cmd(["nuclei", "--version"])