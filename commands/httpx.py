from utils import run_cmd

def run_httpx(target_list, silent=False, output_file=None, title=False, status_code=False, tech_detect=False, web_server=False, follow_redirects=False):
    """Run httpx with the specified parameters."""
    cmd = ["httpx", "-l", target_list]

    if silent:
        cmd.append("-silent")
    if output_file:
        cmd.extend(["-o", output_file])
    if title:
        cmd.append("-title")
    if status_code:
        cmd.append("-sc")
    if tech_detect:
        cmd.append("-tech-detect")
    if web_server:
        cmd.append("-web-server")
    if follow_redirects:
        cmd.append("-follow-redirects")

    if not run_cmd(cmd):
        print("Failed to execute httpx. Please check the parameters and try again.")
        return False
    return True

def check_httpx():
    """Check if httpx is installed."""
    return run_cmd(["httpx", "--version"])