#!/bin/bash

echo "=== Fixing dpkg and installing critical dependencies ==="
sudo dpkg --configure -a

echo "=== Installing libpcap-dev with apt ==="
sudo apt-get update
sudo apt-get install -y libpcap-dev

echo "=== Verifying pcap.h installation ==="
if [ -f "/usr/include/pcap/pcap.h" ] || [ -f "/usr/include/pcap.h" ]; then
  echo "✓ pcap.h found"
else
  echo "! pcap.h not found, attempting alternative installation"
  # Try with the full development package name
  sudo apt-get install -y libpcap0.8-dev
fi

echo "=== Setting Go path ==="
export PATH=$PATH:/usr/local/go/bin:~/go/bin

echo "=== Installing security tools ==="
# Try with standard Go modules
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Try Naabu with CGO_ENABLED=0 to avoid the C dependencies
CGO_ENABLED=0 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo "=== Installation completed ==="
echo "You can now use: httpx, nuclei, and subfinder"
echo "Note: Naabu was built without pcap support, so it will use connect scan mode only"