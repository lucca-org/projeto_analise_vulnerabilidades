#!/usr/bin/env python3
"""
Linux Vulnerability Analysis Toolkit - Main Launcher
This script provides a simple way to run the toolkit with automatic Linux checks
and proper error handling.
"""

import os
import sys
import platform
import subprocess
from pathlib import Path

# Add project root to system path
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))
sys.path.insert(0, str(project_dir / "src"))

def print_banner():
    """Display a toolkit banner."""
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║               🔥 LINUX VULNERABILITY ANALYSIS TOOLKIT 🔥                   ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)

def check_environment():
    """Check if running on Linux."""
    if platform.system().lower() != "linux":
        print("╔═══════════════════════════════════════════════════════════════╗")
        print("║                          ❌ ERROR ❌                           ║")
        print("║                                                               ║")
        print("║     This toolkit is designed EXCLUSIVELY for Linux systems   ║")
        print("║                                                               ║")
        print("║     ✅ Supported: Debian, Kali, Ubuntu, Arch Linux          ║")
        print("║     ❌ NOT Supported: Windows, macOS, WSL                    ║")
        print("║                                                               ║")
        print("║     Please run this on a native Linux environment for optimal ║")
        print("║     security tool performance and compatibility.             ║")
        print("╚═══════════════════════════════════════════════════════════════╝")
        return False
    
    return True

def main():
    """Main function."""
    print_banner()
    
    # Verify Linux environment
    if not check_environment():
        sys.exit(1)
    
    # Import main workflow module
    try:
        from src import workflow
        # Run the main workflow with all command line arguments
        workflow.main()
    except ImportError:
        print("❌ Error: Could not import workflow module.")
        print("Please run: python3 verify_installation.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()