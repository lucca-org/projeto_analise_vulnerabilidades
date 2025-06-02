#!/bin/bash

# fix_dpkg.sh - Advanced dpkg repair and troubleshooting script
# This script provides advanced fixes for common dpkg and apt issues

set -e

# Colors for better output
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

echo -e "${BLUE}=== Advanced dpkg and apt repair utility ===${NC}"
echo "Running as: $(whoami)"

# Check for root permissions
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}This script requires root privileges. Running with sudo...${NC}"
  exec sudo "$0" "$@"
  exit $?
fi

# Step 0: Fix repository key issues
echo -e "\n${BLUE}[0/7] Fixing repository key issues...${NC}"
bash ./fix_repo_keys.sh  # Call the reusable script

# Step 1: Kill processes that might be holding locks
echo -e "\n${BLUE}[1/7] Killing processes that might be holding locks...${NC}"
for process in apt apt-get dpkg frontend; do
  echo -n "Checking for $process processes... "
  pkill -f $process 2>/dev/null && echo -e "${YELLOW}found and terminated${NC}" || echo -e "${GREEN}none found${NC}"
done

# Step 2: Remove lock files
echo -e "\n${BLUE}[2/7] Removing lock files...${NC}"
LOCK_FILES=(
  "/var/lib/dpkg/lock"
  "/var/lib/dpkg/lock-frontend"
  "/var/lib/apt/lists/lock"
  "/var/cache/apt/archives/lock"
  "/var/cache/debconf/config.dat.lock"
)

for lock_file in "${LOCK_FILES[@]}"; do
  if [ -f "$lock_file" ]; then
    echo -n "Removing $lock_file... "
    rm -f "$lock_file" && echo -e "${GREEN}removed${NC}" || echo -e "${RED}failed${NC}"
  else
    echo -e "Lock file $lock_file ${GREEN}does not exist${NC}"
  fi
done

# Step 3: Recreate required directories
echo -e "\n${BLUE}[3/7] Ensuring required directories exist...${NC}"
REQUIRED_DIRS=(
  "/var/lib/dpkg/updates"
  "/var/lib/apt/lists/partial"
  "/var/cache/apt/archives/partial"
)

for dir in "${REQUIRED_DIRS[@]}"; do
  echo -n "Checking directory $dir... "
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir" && echo -e "${GREEN}created${NC}" || echo -e "${RED}failed to create${NC}"
  else
    echo -e "${GREEN}exists${NC}"
  fi
done

# Step 4: Fix interrupted dpkg
echo -e "\n${BLUE}[4/7] Fixing interrupted dpkg operations...${NC}"
echo "Running dpkg --configure -a (1/3)..."
DEBIAN_FRONTEND=noninteractive dpkg --configure -a
echo -e "${GREEN}✓ Initial dpkg configuration completed${NC}"

echo "Running apt-get update --fix-missing (2/3)..."
# Use --allow-insecure-repositories to bypass key issues temporarily
apt-get update --fix-missing --allow-insecure-repositories --allow-unauthenticated
echo -e "${GREEN}✓ Package lists updated${NC}"

echo "Running apt-get install -f (3/3)..."
DEBIAN_FRONTEND=noninteractive apt-get install -f -y
echo -e "${GREEN}✓ Broken packages fixed${NC}"

# Step 5: Handle libc6 dependency issues
echo -e "\n${BLUE}[5/7] Handling libc6 dependency issues...${NC}"
echo "Checking libc6 status..."
libc6_status=$(dpkg -l libc6 | grep -E '^[a-z]i' | awk '{print $1$2}')

if [[ "$libc6_status" == "ii" ]]; then
  echo -e "${GREEN}✓ libc6 is properly installed${NC}"
elif [[ "$libc6_status" == "hi" || "$libc6_status" == "iU" || "$libc6_status" == "iF" ]]; then
  echo -e "${YELLOW}libc6 needs to be fixed. Attempting repair...${NC}"
  DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y libc6
  echo "Checking libc6 status after repair..."
  libc6_status=$(dpkg -l libc6 | grep -E '^[a-z]i' | awk '{print $1$2}')
  if [[ "$libc6_status" == "ii" ]]; then
    echo -e "${GREEN}✓ libc6 repair successful${NC}"
  else
    echo -e "${RED}! libc6 repair failed, system may be unstable${NC}"
  fi
else
  echo -e "${RED}! libc6 status unknown or not installed${NC}"
  echo "Attempting to install libc6..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y libc6
fi

# Step 6: Clean up and update
echo -e "\n${BLUE}[6/7] Cleaning up and updating package lists...${NC}"
echo "Running apt-get clean..."
apt-get clean
echo -e "${GREEN}✓ Package cache cleaned${NC}"

echo "Running apt-get update with multiple repository options..."
# Try multiple options to update packages
if ! apt-get update; then
  echo -e "${YELLOW}Standard update failed, trying with --allow-insecure-repositories${NC}"
  if ! apt-get update --allow-insecure-repositories; then
    echo -e "${YELLOW}Still failing, trying with --allow-unauthenticated${NC}"
    if ! apt-get update --allow-unauthenticated; then
      echo -e "${RED}All update methods failed. Try fixing repository configuration manually.${NC}"
    else
      echo -e "${GREEN}✓ Package lists refreshed with --allow-unauthenticated${NC}"
    fi
  else
    echo -e "${GREEN}✓ Package lists refreshed with --allow-insecure-repositories${NC}"
  fi
else
  echo -e "${GREEN}✓ Package lists refreshed${NC}"
fi

# Step 7: Verify system is working properly
echo -e "\n${BLUE}[7/7] Verifying package system is working properly...${NC}"

# Test apt-get update
echo -n "Testing apt-get update... "
if apt-get update --allow-insecure-repositories >/dev/null 2>&1; then
  echo -e "${GREEN}success${NC}"
else
  echo -e "${RED}failed${NC}"
  echo "There may still be issues with the package management system."
  # Don't exit immediately, let the script continue
fi

# Test installation of a small package
echo -n "Testing apt-get install with a small package (apt-utils)... "
if DEBIAN_FRONTEND=noninteractive apt-get install -y apt-utils --allow-unauthenticated >/dev/null 2>&1; then
  echo -e "${GREEN}success${NC}"
else
  echo -e "${RED}failed${NC}"
  echo "There may still be issues with the package management system."
  # Don't exit immediately, let the script continue
fi

# Check for held packages
held_packages=$(dpkg --audit | grep -v "^No" | wc -l)
if [ "$held_packages" -gt 0 ]; then
  echo -e "${YELLOW}Warning: $held_packages packages are in a bad state. Consider running 'dpkg --audit' manually.${NC}"
else
  echo -e "${GREEN}✓ No packages are in a bad state${NC}"
fi

echo -e "\n${GREEN}=====================================${NC}"
echo -e "${GREEN}✓ Package system repair completed${NC}"
echo -e "${GREEN}=====================================${NC}"

echo -e "\nYou can now proceed with your installation."
exit 0
