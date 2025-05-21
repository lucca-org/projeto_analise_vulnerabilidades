#!/bin/bash
# dependency_free_install.sh - Install security tools without system package dependencies

echo "===== Installing Security Tools Without System Dependencies ====="
echo "This method bypasses dpkg/apt entirely and installs directly."

# Create directories
mkdir -p ~/security_tools/bin
mkdir -p ~/.local/bin 
mkdir -p ~/go/bin

# Add to PATH immediately and persistently
export PATH=$PATH:~/security_tools/bin:~/.local/bin:~/go/bin

# Function to set up environment
setup_env() {
  # Update shell config files
  for config_file in ~/.bashrc ~/.zshrc ~/.profile; do
    if [ -f "$config_file" ]; then
      echo 'export PATH=$PATH:~/security_tools/bin:~/.local/bin:~/go/bin:/usr/local/go/bin' >> "$config_file"
    fi
  done
  
  # Create directories for data
  mkdir -p ~/.config/nuclei/templates
  mkdir -p ~/.config/nuclei/config
  mkdir -p ~/.config/httpx
}

# Download and install Go directly 
install_go() {
  if command -v go >/dev/null; then
    echo "Go is already installed"
    return 0
  fi
  
  echo "Installing Go directly..."
  # Determine architecture
  ARCH=$(uname -m)
  if [ "$ARCH" == "x86_64" ]; then
    GOARCH="amd64"
  elif [ "$ARCH" == "aarch64" ] || [ "$ARCH" == "arm64" ]; then
    GOARCH="arm64"
  else
    echo "Architecture $ARCH not directly supported, trying amd64"
    GOARCH="amd64"
  fi
  
  wget https://go.dev/dl/go1.21.0.linux-${GOARCH}.tar.gz -O /tmp/go.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  echo "Go installed to /usr/local/go"
}

# Build tools from source with CGO disabled
build_pd_tools() {
  echo "Setting up Go environment with CGO disabled for dependency-free builds..."
  export CGO_ENABLED=0
  export GOBIN=$HOME/go/bin
  
  echo "Installing httpx..."
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  
  echo "Installing nuclei..."
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  
  echo "Installing subfinder..."
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  
  # Build naabu with connect scan mode only (no libpcap dependency)
  echo "Installing naabu (connect-only)..."
  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
}

# Create nmap-based alternative naabu script
create_naabu_alt() {
  cat > ~/go/bin/naabu-alt << 'EOF'
#!/bin/bash
# Super resilient naabu alternative using multiple methods

TARGET=""
TARGET_FILE=""
PORTS="1-1000"
OUTPUT=""
VERBOSE=false
JSON=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -host) TARGET="$2"; shift 2 ;;
        -l) TARGET_FILE="$2"; shift 2 ;;
        -p|-ports) PORTS="$2"; shift 2 ;;
        -o|-output) OUTPUT="$2"; shift 2 ;;
        -v|-verbose) VERBOSE=true; shift ;;
        -json) JSON=true; shift ;;
        *) shift ;;
    esac
done

# Function to scan with nmap
scan_with_nmap() {
    local target=$1
    local output_file=$2
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Scanning $target with nmap..."
    fi
    
    # Run nmap scan
    if ! nmap -T4 -p "$PORTS" "$target" -oG - | grep -v "^#" | grep "open" > "$output_file.tmp"; then
        echo "Nmap scan failed, trying with netcat..."
        return 1
    fi
    
    # Process results
    if [[ "$JSON" == "true" ]]; then
        echo "[" > "$output_file"
        cat "$output_file.tmp" | while read line; do
            host=$(echo "$line" | awk '{print $2}')
            ports=$(echo "$line" | grep -oP 'Ports: \K.*' | tr ',' '\n' | grep "open")
            echo "$ports" | while read port_info; do
                port=$(echo "$port_info" | awk '{print $1}')
                if [[ -n "$port" ]]; then
                    echo "  {\"host\":\"$host\",\"port\":$port}," >> "$output_file"
                fi
            done
        done
        # Fix the last line comma
        sed -i '$ s/,$//' "$output_file"
        echo "]" >> "$output_file"
    else
        cat "$output_file.tmp" | while read line; do
            host=$(echo "$line" | awk '{print $2}')
            ports=$(echo "$line" | grep -oP 'Ports: \K.*' | tr ',' '\n' | grep "open")
            echo "$ports" | while read port_info; do
                port=$(echo "$port_info" | awk '{print $1}')
                if [[ -n "$port" ]]; then
                    echo "$host:$port" >> "$output_file"
                fi
            done
        done
    fi
    
    rm -f "$output_file.tmp"
    return 0
}

# Function to scan with netcat
scan_with_nc() {
    local target=$1
    local output_file=$2
    local tmp_results=""
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Scanning $target with netcat..."
    fi
    
    # Parse port ranges
    local all_ports=()
    IFS=',' read -ra RANGES <<< "$PORTS"
    for range in "${RANGES[@]}"; do
        if [[ "$range" == *-* ]]; then
            start=$(echo "$range" | cut -d'-' -f1)
            end=$(echo "$range" | cut -d'-' -f2)
            for ((port=start; port<=end; port++)); do
                all_ports+=($port)
            done
        else
            all_ports+=($range)
        fi
    done
    
    # Scan ports with netcat
    for port in "${all_ports[@]}"; do
        if timeout 0.5 nc -z -w1 "$target" "$port" 2>/dev/null; then
            if [[ "$VERBOSE" == "true" ]]; then
                echo "Found open port: $target:$port"
            fi
            tmp_results+="$target:$port\n"
        fi
    done
    
    # Process results
    if [[ -n "$tmp_results" ]]; then
        if [[ "$JSON" == "true" ]]; then
            echo "[" > "$output_file"
            echo -e "$tmp_results" | while read -r line; do
                if [[ -n "$line" ]]; then
                    host=$(echo "$line" | cut -d':' -f1)
                    port=$(echo "$line" | cut -d':' -f2)
                    echo "  {\"host\":\"$host\",\"port\":$port}," >> "$output_file"
                fi
            done
            sed -i '$ s/,$//' "$output_file"
            echo "]" >> "$output_file"
        else
            echo -e "$tmp_results" > "$output_file"
        fi
        return 0
    else
        return 1
    fi
}

# Main scan logic
if [[ -n "$TARGET" ]]; then
    if [[ -n "$OUTPUT" ]]; then
        if command -v nmap &>/dev/null; then
            scan_with_nmap "$TARGET" "$OUTPUT" || scan_with_nc "$TARGET" "$OUTPUT"
        else
            scan_with_nc "$TARGET" "$OUTPUT"
        fi
        
        if [[ "$VERBOSE" == "true" ]]; then
            echo "Results saved to $OUTPUT"
        fi
    else
        # Output to stdout
        if command -v nmap &>/dev/null; then
            nmap -T4 -p "$PORTS" "$TARGET" | grep -E "^[0-9]+/tcp.*open" | awk '{print "'$TARGET':"$1}' | sed 's#/tcp.*##'
        else
            for port in $(echo "$PORTS" | tr ',' ' ' | tr '-' ' '); do
                if timeout 0.5 nc -z -w1 "$TARGET" "$port" 2>/dev/null; then
                    echo "$TARGET:$port"
                fi
            done
        fi
    fi
elif [[ -n "$TARGET_FILE" ]]; then
    if [[ ! -f "$TARGET_FILE" ]]; then
        echo "Error: Target list file not found: $TARGET_FILE"
        exit 1
    fi
    
    if [[ -n "$OUTPUT" ]]; then
        # Create empty output file
        > "$OUTPUT"
        if [[ "$JSON" == "true" ]]; then
            echo "[" > "$OUTPUT"
        fi
        
        # Process each target
        while read -r target; do
            [[ -z "$target" || "$target" =~ ^# ]] && continue
            
            TEMP_OUT="/tmp/naabu_scan_$RANDOM.tmp"
            if command -v nmap &>/dev/null; then
                scan_with_nmap "$target" "$TEMP_OUT" || scan_with_nc "$target" "$TEMP_OUT"
            else
                scan_with_nc "$target" "$TEMP_OUT"
            fi
            
            # Append results
            if [[ "$JSON" == "true" ]]; then
                if [[ -f "$TEMP_OUT" ]]; then
                    sed '1d;$d' "$TEMP_OUT" >> "$OUTPUT"
                    echo "," >> "$OUTPUT"
                fi
            else
                if [[ -f "$TEMP_OUT" ]]; then
                    cat "$TEMP_OUT" >> "$OUTPUT"
                fi
            fi
            
            rm -f "$TEMP_OUT"
        done < "$TARGET_FILE"
        
        if [[ "$JSON" == "true" ]]; then
            # Fix the last comma
            sed -i '$ s/,$//' "$OUTPUT"
            echo "]" >> "$OUTPUT"
        fi
        
        if [[ "$VERBOSE" == "true" ]]; then
            echo "Results saved to $OUTPUT"
        fi
    else
        # Output to stdout for each target
        while read -r target; do
            [[ -z "$target" || "$target" =~ ^# ]] && continue
            
            if command -v nmap &>/dev/null; then
                nmap -T4 -p "$PORTS" "$target" | grep -E "^[0-9]+/tcp.*open" | awk '{print "'$target':"$1}' | sed 's#/tcp.*##'
            else
                for port in $(echo "$PORTS" | tr ',' ' ' | tr '-' ' '); do
                    if timeout 0.5 nc -z -w1 "$target" "$port" 2>/dev/null; then
                        echo "$target:$port"
                    fi
                done
            fi
        done < "$TARGET_FILE"
    fi
else
    echo "Error: No target specified. Use -host or -l."
    exit 1
fi
EOF
  chmod +x ~/go/bin/naabu-alt
  
  # Create a symbolic link for default naabu
  if [ ! -f ~/go/bin/naabu ]; then
    ln -sf ~/go/bin/naabu-alt ~/go/bin/naabu
  fi
}

# Install everything
setup_env
install_go
build_pd_tools
create_naabu_alt

# Update nuclei templates
echo "Updating nuclei templates..."
~/go/bin/nuclei -update-templates || echo "Templates will be updated on first use"

echo "===== Installation Complete ====="
echo "Tools are installed in ~/go/bin:"
echo "- httpx: For probing HTTP services"
echo "- nuclei: For vulnerability scanning"
echo "- subfinder: For subdomain discovery"
echo "- naabu/naabu-alt: For port scanning"
echo ""
echo "To use these tools, run: source ~/.bashrc or open a new terminal"
echo "To test the installation, try: ~/go/bin/nuclei -version"