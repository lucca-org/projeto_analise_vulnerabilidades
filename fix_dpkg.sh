#!/bin/bash
# fix_dpkg.sh - Script to repair interrupted dpkg installations

echo "===== Attempting to fix dpkg interruption ====="

# Try various dpkg recovery commands with increased privileges
sudo dpkg --configure -a
sudo apt-get update --fix-missing
sudo apt-get install -f
sudo apt-get clean
sudo apt-get update

echo "===== Updating package sources ====="
sudo apt-get update

echo "===== Attempting to install libpcap alternative ====="
sudo apt-get install -y libpcap0.8-dev

echo "===== Trying with Kali-specific package names ====="
# Kali might use different package names
sudo apt-cache search libpcap | grep dev
sudo apt-get install -y libpcap-dev

echo "===== Fix complete ====="
echo "Now run your original installation script again"