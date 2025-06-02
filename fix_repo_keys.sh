#!/bin/bash
# fix_repo_keys.sh - Reusable script for fixing repository keys

set -e

# Colors for better output
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
NC="\033[0m" # No Color

echo -e "${BLUE}Fixing repository key issues...${NC}"

# Create keyring directory if it doesn't exist
sudo mkdir -p /etc/apt/keyrings

# Check if key already exists before trying to import
if [ -f "/etc/apt/keyrings/kali-archive-keyring.gpg" ]; then
    echo -e "${GREEN}Kali Linux archive key already exists.${NC}"
else
    echo "Importing Kali Linux archive key..."
    if command -v wget >/dev/null 2>&1; then
        wget -qO - https://archive.kali.org/archive-key.asc | sudo gpg --dearmor -o /etc/apt/keyrings/kali-archive-keyring.gpg
    elif command -v curl >/dev/null 2>&1; then
        curl -fsSL https://archive.kali.org/archive-key.asc | sudo gpg --dearmor -o /etc/apt/keyrings/kali-archive-keyring.gpg
    else
        echo -e "${RED}Neither wget nor curl is available. Cannot import key.${NC}"
        exit 1
    fi
    sudo chmod 644 /etc/apt/keyrings/kali-archive-keyring.gpg
    echo -e "${GREEN}✓ Kali Linux archive key imported${NC}"
fi
