#!/usr/bin/env python3
"""
Network Connectivity Test Utility for Vulnerability Analysis Toolkit
"""

import os
import sys
import socket
import subprocess
import urllib.request
import time

def test_dns():
    """Test DNS resolution."""
    print("Testing DNS resolution...")
    try:
        socket.gethostbyname("www.google.com")
        print("DNS resolution working")
        return True
    except socket.gaierror:
        print("DNS resolution failed")
        return False

def test_ping(host="8.8.8.8"):
    """Test ping to a reliable host."""
    print(f"Testing ping to {host}...")
    try:
        # Ping with timeout of 2 seconds, 2 packets
        cmd = ["ping", "-c", "2", "-W", "2", host]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print(f"Ping to {host} successful")
            return True
        else:
            print(f"Ping to {host} failed")
            return False
    except Exception as e:
        print(f"Ping test error: {e}")
        return False

def test_http():
    """Test HTTP connectivity."""
    print("Testing HTTP connectivity...")
    try:
        urllib.request.urlopen("http://www.google.com", timeout=5)
        print("HTTP connectivity working")
        return True
    except Exception as e:
        print(f"HTTP connectivity failed: {e}")
        return False

def test_local_network(network_prefix="192.168."):
    """Test connectivity to local network."""
    print(f"Testing local network connectivity ({network_prefix}x.x)...")
    local_ips = []
    
    # Try to find IP addresses in the local network
    try:
        # Get IP addresses using ip command
        ip_cmd = ["ip", "addr", "show"]
        result = subprocess.run(ip_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():
            if "inet " in line and network_prefix in line:
                ip = line.split()[1].split('/')[0]
                local_ips.append(ip)
                print(f"  Found local IP: {ip}")
    except Exception as e:
        print(f"  Error getting local IPs: {e}")
    
    # If no local IPs found, use ifconfig as backup
    if not local_ips:
        try:
            ifconfig_cmd = ["ifconfig"]
            result = subprocess.run(ifconfig_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in result.stdout.splitlines():
                if "inet " in line and network_prefix in line:
                    ip = line.split()[1]
                    local_ips.append(ip)
                    print(f"  Found local IP: {ip}")
        except Exception as e:
            print(f"  Error getting local IPs via ifconfig: {e}")
      # Test ping to default gateway
    gateway = f"{network_prefix}1.1"  # Common default gateway
    ping_result = test_ping(gateway)
    
    if local_ips or ping_result:
        print("Local network appears to be working")
        return True
    else:
        print("No local network connectivity detected")
        return False

def get_override_flag():
    """Check if override flag file exists."""
    override_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_override')
    if os.path.exists(override_path):
        print("Network override flag found - will bypass connectivity checks")
        return True
    return False

def create_override_flag():
    """Create network override flag file."""
    override_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_override')
    try:
        with open(override_path, 'w') as f:
            f.write(f"# Network check override created on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Delete this file to re-enable network connectivity checks\n")
        print(f"Created network override flag at {override_path}")
        print("Network connectivity checks will be bypassed in workflow.py")
    except Exception as e:
        print(f"Failed to create override flag: {e}")

def main():
    """Run all network tests."""
    print("=== Network Connectivity Test ===")
    
    # Check for override
    if get_override_flag():
        print("Network override flag exists. Delete the 'network_override' file to re-enable checks.")
        return
    
    # Run tests
    dns_ok = test_dns()
    ping_ok = test_ping()
    http_ok = test_http()
    local_ok = test_local_network()
      # Print summary
    print("\n=== Network Test Summary ===")
    print(f"DNS Resolution: {'PASS' if dns_ok else 'FAIL'}")
    print(f"Ping Test: {'PASS' if ping_ok else 'FAIL'}")
    print(f"HTTP Connectivity: {'PASS' if http_ok else 'FAIL'}")
    print(f"Local Network: {'PASS' if local_ok else 'FAIL'}")
    
    if any([dns_ok, ping_ok, http_ok, local_ok]):
        print("\nSome network connectivity available")
          # Offer to create override flag
        choice = input("\nWould you like to bypass network connectivity checks? (y/n): ")
        if choice.lower() == 'y':
            create_override_flag()
            print("\nTo run a scan with network check override:")
            print("python src/workflow.py <target>")
    else:
        print("\nNo network connectivity detected")
        print("\nPossible solutions:")
        print("1. Check VM network settings (NAT, Bridged, etc.)")
        print("2. Verify your physical network connection")
        print("3. If you're sure network is working and want to bypass checks:")
        print("   python src/network_test.py --create-override")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--create-override":
        create_override_flag()
    else:
        main()
