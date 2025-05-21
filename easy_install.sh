#!/bin/bash
# easy_install.sh - Simplified script referencing setup_tools.sh

set -e

if [ ! -f "setup_tools.sh" ]; then
    echo "Error: setup_tools.sh not found in the current directory."
    exit 1
fi

bash setup_tools.sh
