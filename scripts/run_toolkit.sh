#!/bin/bash
# Linux Vulnerability Analysis Toolkit - Launcher Script
# Provides a simple way to run the toolkit

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Display banner
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                            ║"
echo "║               🔥 LINUX VULNERABILITY ANALYSIS TOOLKIT 🔥                   ║"
echo "║                                                                            ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"

# Check if we're on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                          ❌ ERROR ❌                           ║"
    echo "║                                                               ║"
    echo "║     This toolkit is designed EXCLUSIVELY for Linux systems   ║"
    echo "║                                                               ║"
    echo "║     ✅ Supported: Debian, Kali, Ubuntu, Arch Linux          ║"
    echo "║     ❌ NOT Supported: Windows, macOS, WSL                    ║"
    echo "║                                                               ║"
    echo "║     Please run this on a Linux system for optimal security   ║"
    echo "║     tool performance and compatibility.                      ║"
    echo "║                                                               ║"
    echo "║     REASON: The toolkit relies on Linux-specific security    ║"
    echo "║     tools (naabu, httpx, nuclei) that require native Linux   ║"
    echo "║     kernel features and system libraries.                    ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    exit 1
fi

# Change to project root directory
cd "$PROJECT_ROOT"

# Run the main workflow with all arguments
python3 src/workflow.py "$@"
