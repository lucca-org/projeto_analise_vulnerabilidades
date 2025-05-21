#!/bin/bash

# fix_dpkg.sh - Aligning with setup_tools.sh for dpkg fixes

set -e

# Reference setup_tools.sh for consolidated logic
if [ ! -f "setup_tools.sh" ]; then
    echo "Error: setup_tools.sh not found in the current directory."
    exit 1
fi

bash setup_tools.sh