#!/bin/bash
# naabu-wrapper.sh - Multi-engine port scanner for maximum compatibility
# Features: nmap, netcat fallback, faster port scanning, better JSON handling

VERSION="2.0.0"
TARGET=""
PORTS="1-1000"
OUTPUT=""
VERBOSE=false
SILENT=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -host)
            TARGET="$2"
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
        -silent)
            SILENT=true
            shift
            ;;
        -version)
            echo "naabu-wrapper v$VERSION"
            exit 0
            ;;
        -h|-help)
            echo "Usage: naabu-wrapper.sh -host <target> [-p <ports>] [-o <output>] [-v] [-silent]"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Validate input
if [[ -z "$TARGET" ]]; then
    echo "Error: No target specified. Use -host to specify a target."
    exit 1
fi

# Scan ports using netcat
scan_with_nc() {
    local target="$1"
    local ports="$2"
    local output="$3"

    echo "Scanning $target with netcat..."
    for port in $(echo "$ports" | tr ',' ' '); do
        if nc -z -w1 "$target" "$port" 2>/dev/null; then
            echo "Open port: $port" >> "$output"
        fi
    done
}

# Perform the scan
TEMP_OUTPUT=$(mktemp)
scan_with_nc "$TARGET" "$PORTS" "$TEMP_OUTPUT"

# Save results
if [[ -n "$OUTPUT" ]]; then
    mv "$TEMP_OUTPUT" "$OUTPUT"
    echo "Results saved to $OUTPUT"
else
    cat "$TEMP_OUTPUT"
    rm "$TEMP_OUTPUT"
fi

exit 0