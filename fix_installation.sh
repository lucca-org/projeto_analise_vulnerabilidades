#!/bin/bash

# fix_installation.sh - Aligning with setup_tools.sh for installation fixes

set -e

# Reference setup_tools.sh for consolidated logic
if [ ! -f "setup_tools.sh" ]; then
    echo "Error: setup_tools.sh not found in the current directory."
    exit 1
fi

bash setup_tools.sh
