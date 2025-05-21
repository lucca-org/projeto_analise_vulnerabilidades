def install_naabu_alternative():
    """Install an alternative to naabu that doesn't require libpcap."""
    print("\n===== Creating naabu alternative script =====\n")
    naabu_path = os.path.expanduser("~/go/bin/naabu")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(naabu_path), exist_ok=True)
    
    script_content = """#!/bin/bash
# naabu-alternative v2.0.0 - Multi-engine port scanner for maximum compatibility
# Features: nmap, netcat fallback, faster port scanning, better JSON handling

VERSION="2.0.0"
TARGET=""
TARGET_FILE=""
PORTS="1-1000"
OUTPUT=""
VERBOSE=false
RATE=1000
TIMEOUT=5000
JSON=false
SILENT=false
THREADS=25
PARALLEL=5  # Max targets to scan in parallel

# Parse all arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -host)
            TARGET="$2"
            shift 2
            ;;
        -l)
            TARGET_FILE="$2"
            shift 2
            ;;
        -p|-ports)
            PORTS="$2"
            shift 2
            ;;
        -o|-output)
            OUTPUT="$2"
            shift 2
            ;;
        -v|-verbose)
            VERBOSE=true
            shift
            ;;
        -c)
            THREADS="$2"
            shift 2
            ;;
        -rate)
            RATE="$2"
            shift 2
            ;;
        -json)
            JSON=true
            shift
            ;;
        -silent)
            SILENT=true
            shift
            ;;
        -timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -version)
            echo "naabu-alternative v$VERSION"
            exit 0
            ;;
        -h|-help)
            echo "Naabu alternative - multi-engine port scanner"
            echo "Usage:"
            echo "  -host string        Host to scan"
            echo "  -l string           List of hosts to scan"
            echo "  -p, -ports string   Ports to scan (default: 1-1000)"
            echo "  -o, -output string  Output file to write results"
            echo "  -v, -verbose        Verbose output"
            echo "  -c int              Number of concurrent threads (default: 25)"
            echo "  -silent             Silent mode"
            echo "  -json               Output in JSON format"
            echo "  -rate int           Rate of port scan (default: 1000)"
            echo "  -timeout int        Timeout in milliseconds (default: 5000)"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Validate input
if [[ -z "$TARGET" && -z "$TARGET_FILE" ]]; then
    echo "Error: No target specified. Use -host or -l."
    exit 1
fi

if [[ "$SILENT" = false ]]; then
    echo "Starting port scan with naabu-alternative v$VERSION"
fi

# Create temp files and directories for processing
TEMP_DIR=$(mktemp -d)
TEMP_RESULTS="$TEMP_DIR/results"
mkdir -p "$TEMP_RESULTS"

if [[ -n "$TARGET" ]]; then
    echo "$TARGET" > "$TEMP_DIR/targets.txt"
elif [[ -n "$TARGET_FILE" ]]; then
    if [[ ! -f "$TARGET_FILE" ]]; then
        echo "Error: Target file not found: $TARGET_FILE"
        exit 1
    fi
    cp "$TARGET_FILE" "$TEMP_DIR/targets.txt"
fi

# Port scanning functions
scan_with_nmap() {
    local target="$1"
    local output="$2"
    local nmap_rate=$((RATE / 100))
    [[ $nmap_rate -lt 1 ]] && nmap_rate=1
    [[ $nmap_rate -gt 5 ]] && nmap_rate=5
    
    # Dynamic timing template based on rate
    local timing=3
    [[ $RATE -gt 2000 ]] && timing=4
    [[ $RATE -gt 4000 ]] && timing=5
    
    # Set max timeout
    local nmap_timeout=$((TIMEOUT / 1000))
    [[ $nmap_timeout -lt 1 ]] && nmap_timeout=1
    
    if [[ "$VERBOSE" = true ]]; then
        echo "Scanning $target with nmap T$timing..."
    fi
    
    # Run nmap scan
    if ! nmap -T$timing --host-timeout ${nmap_timeout}s --max-retries 1 -p "$PORTS" "$target" -oG - | grep -v "^#" | grep "Ports:" > "$output"; then
        return 1
    fi
    
    # Count found ports
    local port_count=$(cat "$output" | grep -oP 'Ports: \K.*' | tr ',' '\n' | grep -v "closed" | grep -v "filtered" | wc -l)
    if [[ $port_count -eq 0 ]]; then
        return 1
    fi
    
    return 0
}

scan_with_nc() {
    local target="$1"
    local output="$2"
    
    if [[ "$VERBOSE" = true ]]; then
        echo "Scanning $target with netcat..."
    fi
    
    # Process port ranges
    local all_ports=()
    IFS=',' read -ra RANGES <<< "$PORTS"
    for range in "${RANGES[@]}"; do
        if [[ "$range" == *-* ]]; then
            local start=$(echo "$range" | cut -d'-' -f1)
            local end=$(echo "$range" | cut -d'-' -f2)
            for ((port=start; port<=end; port++)); do
                all_ports+=($port)
            done
        else
            all_ports+=($range)
        fi
    done
    
    # Scan ports with netcat
    local found=0
    > "$output"
    
    # Use a subset of ports based on thread count
    local port_count=${#all_ports[@]}
    local ports_per_thread=$((port_count / THREADS + 1))
    
    # Create a function to scan a range of ports
    scan_port_range() {
        local target="$1"
        local start_idx="$2"
        local end_idx="$3"
        local out_file="$4"
        local tmp_out="${out_file}.$start_idx"
        > "$tmp_out"
        
        for ((i=start_idx; i<end_idx && i<port_count; i++)); do
            local port=${all_ports[$i]}
            if timeout 0.5 nc -z -w1 "$target" "$port" 2>/dev/null; then
                echo "Port:$port/tcp" >> "$tmp_out"
                found=1
                if [[ "$VERBOSE" = true && "$SILENT" = false ]]; then
                    echo "Found open port on $target: $port"
                fi
            fi
        done
        
        # Copy results to main file
        cat "$tmp_out" >> "$out_file"
        rm "$tmp_out"
    }
    
    # Launch parallel scans
    for ((t=0; t<THREADS; t++)); do
        local start_idx=$((t * ports_per_thread))
        local end_idx=$(((t+1) * ports_per_thread))
        scan_port_range "$target" "$start_idx" "$end_idx" "$output" &
        
        # Limit parallel processes
        if [[ $((t % 10)) -eq 9 ]]; then
            wait
        fi
    done
    
    # Wait for all scans to complete
    wait
    
    if [[ -s "$output" ]]; then
        return 0
    else
        return 1
    fi
}

# Process each target
total_targets=$(wc -l < "$TEMP_DIR/targets.txt")
counter=0

if [[ "$SILENT" = false ]]; then
    echo "Processing $total_targets targets..."
fi

# Choose best available scanner
SCANNER="none"
if command -v nmap >/dev/null 2>&1; then
    SCANNER="nmap"
    if [[ "$SILENT" = false ]]; then
        echo "Using nmap for port scanning"
    fi
elif command -v nc >/dev/null 2>&1; then
    SCANNER="nc"
    if [[ "$SILENT" = false ]]; then
        echo "Using netcat for port scanning (limited functionality)"
    fi
else
    echo "Error: No port scanning tools available. Please install nmap or netcat."
    exit 1
fi

process_target() {
    local target="$1"
    local target_id="$2"
    local output="$TEMP_RESULTS/$target_id.txt"
    
    # Skip empty lines and comments
    [[ -z "$target" || "$target" =~ ^[[:space:]]*# ]] && return
    
    # Try primary scanner first, fall back to alternative if available
    local success=false
    
    if [[ "$SCANNER" == "nmap" ]]; then
        if scan_with_nmap "$target" "$output"; then
            success=true
        elif command -v nc >/dev/null 2>&1; then
            if [[ "$VERBOSE" = true && "$SILENT" = false ]]; then
                echo "Nmap failed for $target, trying netcat..."
            fi
            if scan_with_nc "$target" "$output"; then
                success=true
            fi
        fi
    elif [[ "$SCANNER" == "nc" ]]; then
        if scan_with_nc "$target" "$output"; then
            success=true
        fi
    fi
    
    if [[ "$success" != "true" && "$SILENT" = false && "$VERBOSE" = true ]]; then
        echo "No open ports found on $target"
    fi
}

# Process targets in parallel
cat "$TEMP_DIR/targets.txt" | while read -r target; do
    counter=$((counter+1))
    if [[ "$VERBOSE" = true && "$SILENT" = false ]]; then
        echo "[$counter/$total_targets] Scanning $target"
    fi
    
    # Process in background with limited parallelism
    process_target "$target" "$counter" &
    
    # Limit number of parallel processes
    if [[ $((counter % PARALLEL)) -eq 0 ]]; then
        wait
    fi
done

# Wait for all processes to finish
wait

# Combine and format results
if [[ -n "$OUTPUT" ]]; then
    # Create the output file based on format
    if [[ "$JSON" = true ]]; then
        echo "[" > "$OUTPUT"
        
        first_entry=true
        for result_file in "$TEMP_RESULTS"/*.txt; do
            [[ ! -s "$result_file" ]] && continue
            
            target_id=$(basename "$result_file" .txt)
            target=$(sed -n "${target_id}p" "$TEMP_DIR/targets.txt")
            
            if [[ "$SCANNER" == "nmap" && -f "$result_file" && -s "$result_file" ]]; then
                # Process nmap output
                ports=$(cat "$result_file" | grep -oP 'Ports: \K.*' | tr ',' '\n' | grep -v "closed" | grep -v "filtered")
                
                while read -r port_info; do
                    [[ -z "$port_info" ]] && continue
                    
                    port_num=$(echo "$port_info" | awk '{print $1}')
                    if [[ -n "$port_num" ]]; then
                        if [[ "$first_entry" != "true" ]]; then
                            echo "," >> "$OUTPUT"
                        fi
                        first_entry=false
                        echo -n "  {\"host\":\"$target\",\"port\":$port_num}" >> "$OUTPUT"
                    fi
                done <<< "$ports"
            elif [[ "$SCANNER" == "nc" && -f "$result_file" && -s "$result_file" ]]; then
                # Process netcat output
                while read -r line; do
                    [[ -z "$line" ]] && continue
                    
                    if [[ "$line" =~ Port:([0-9]+) ]]; then
                        port="${BASH_REMATCH[1]}"
                        if [[ "$first_entry" != "true" ]]; then
                            echo "," >> "$OUTPUT"
                        fi
                        first_entry=false
                        echo -n "  {\"host\":\"$target\",\"port\":$port}" >> "$OUTPUT"
                    fi
                done < "$result_file"
            fi
        done
        
        echo "" >> "$OUTPUT"
        echo "]" >> "$OUTPUT"
    else
        > "$OUTPUT"
        for result_file in "$TEMP_RESULTS"/*.txt; do
            [[ ! -s "$result_file" ]] && continue
            
            target_id=$(basename "$result_file" .txt)
            target=$(sed -n "${target_id}p" "$TEMP_DIR/targets.txt")
            
            if [[ "$SCANNER" == "nmap" && -f "$result_file" && -s "$result_file" ]]; then
                # Process nmap output
                ports=$(cat "$result_file" | grep -oP 'Ports: \K.*' | tr ',' '\n' | grep -v "closed" | grep -v "filtered")
                
                while read -r port_info; do
                    [[ -z "$port_info" ]] && continue
                    
                    port_num=$(echo "$port_info" | awk '{print $1}')
                    if [[ -n "$port_num" ]]; then
                        echo "$target:$port_num" >> "$OUTPUT"
                    fi
                done <<< "$ports"
            elif [[ "$SCANNER" == "nc" && -f "$result_file" && -s "$result_file" ]]; then
                # Process netcat output
                while read -r line; do
                    [[ -z "$line" ]] && continue
                    
                    if [[ "$line" =~ Port:([0-9]+) ]]; then
                        port="${BASH_REMATCH[1]}"
                        echo "$target:$port" >> "$OUTPUT"
                    fi
                done < "$result_file"
            fi
        done
    fi
    
    if [[ "$SILENT" = false ]]; then
        echo "Results saved to $OUTPUT"
    fi
fi

# Clean up
rm -rf "$TEMP_DIR"

exit 0
"""
    
    try:
        with open(naabu_path, 'w') as f:
            f.write(script_content)
        os.chmod(naabu_path, 0o755)
        print(f"✓ Created enhanced naabu alternative script at {naabu_path}")
        return True
    except Exception as e:
        print(f"✗ Failed to create naabu alternative script: {e}")
        return False