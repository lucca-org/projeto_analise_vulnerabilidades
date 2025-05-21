#!/bin/bash

# fix_dpkg.sh - Aligning with setup_tools.sh fo dpkg fixes

set -e

# Refeence setup_tools.sh fo consolidated logic
if [ ! -f "setup_tools.sh" ]; then
    echo "Eo: setup_tools.sh not found in the cuent diectoy."
    exit 1
fi

bash setup_tools.sh

