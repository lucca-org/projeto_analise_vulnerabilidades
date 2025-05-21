#!/bin/bash
# Enhanced fix_dpkg.sh - More aggressive, systematic repair script

set -e  # Exit on error
echo "===== Enhanced dpkg repair script ====="

# Kill any hung package management processes first
echo "1. Stopping any hung package processes..."
sudo killall -9 dpkg apt apt-get aptitude 2>/dev/null || true

# Remove all locks more aggressively
echo "2. Removing all lock files..."
sudo rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock* /var/cache/apt/archives/lock* 2>/dev/null || true

# Fix the dpkg state directories
echo "3. Rebuilding state directories..."
sudo mkdir -p /var/lib/dpkg/{alternatives,info,parts,triggers,updates} 2>/dev/null || true
sudo mkdir -p /var/lib/apt/lists/partial /var/cache/apt/archives/partial 2>/dev/null || true

# If status backup exists, restore it
echo "4. Checking for status backups..."
for backup in /var/lib/dpkg/status-old /var/backups/dpkg.status.*; do
  if [ -f "$backup" ]; then
    echo "   Restoring from backup: $backup"
    sudo cp "$backup" /var/lib/dpkg/status
    break
  fi
done

# Run dpkg configure with extended timeout
echo "5. Running dpkg --configure -a..."
timeout 300 sudo dpkg --configure -a || echo "Operation timed out, continuing with next steps"

# Deep clean apt and rebuild
echo "6. Cleaning apt caches..."
sudo rm -rf /var/lib/apt/lists/* || true
sudo apt-get clean
sudo apt-get update

# Try fix broken packages
echo "7. Fixing broken packages..."
sudo apt-get -f install -y || echo "Fix install had errors, continuing..."

# Try to upgrade essential packages only
echo "8. Upgrading core system packages..."
sudo apt-get install --only-upgrade dpkg apt apt-utils -y || echo "Core upgrade had errors, continuing..."

echo "===== Repair completed ====="
echo "System should now be in a more usable state."
echo "If still having issues, you may need to run: sudo apt-get --reinstall install dpkg"