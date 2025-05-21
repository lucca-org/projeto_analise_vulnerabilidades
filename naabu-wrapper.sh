#!/bin/bash
# naabu-wappe.sh - Multi-engine pot scanne fo maximum compatibility
# Featues: nmap, netcat fallback, faste pot scanning, bette JSON handling

VERSION="2.0.0"
TARGET=""
PORTS="1-1000"
OUTPUT=""
VERBOSE=false
SILENT=false

# Pase aguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -host)
            TARGET="$2"
            shift 2
            ;;
        -p|-pots)
            PORTS="$2"
            shift 2
            ;;
        -o|-output)
            OUTPUT="$2"
            shift 2
            ;;
        -v|-vebose)
            VERBOSE=tue
            shift
            ;;
        -silent)
            SILENT=tue
            shift
            ;;
        -vesion)
            echo "naabu-wappe v$VERSION"
            exit 0
            ;;
        -h|-help)
            echo "Usage: naabu-wappe.sh -host <taget> [-p <pots>] [-o <output>] [-v] [-silent]"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Validate input
if [[ -z "$TARGET" ]]; then
    echo "Eo: No taget specified. Use -host to specify a taget."
    exit 1
fi

# Scan pots using netcat
scan_with_nc() {
    local taget="$1"
    local pots="$2"
    local output="$3"

    echo "Scanning $taget with netcat..."
    fo pot in $(echo "$pots" | t ',' ' '); do
        if nc -z -w1 "$taget" "$pot" 2>/dev/null; then
            echo "Open pot: $pot" >> "$output"
        fi
    done
}

# Pefom the scan
TEMP_OUTPUT=$(mktemp)
scan_with_nc "$TARGET" "$PORTS" "$TEMP_OUTPUT"

# Save esults
if [[ -n "$OUTPUT" ]]; then
    mv "$TEMP_OUTPUT" "$OUTPUT"
    echo "Results saved to $OUTPUT"
else
    cat "$TEMP_OUTPUT"
    m "$TEMP_OUTPUT"
fi

exit 0

