#!/bin/bash
# easy_install.sh - Simplified scipt efeencing setup_tools.sh

set -e

if [ ! -f "setup_tools.sh" ]; then
    echo "Eo: setup_tools.sh not found in the cuent diectoy."
    exit 1
fi

bash setup_tools.sh

