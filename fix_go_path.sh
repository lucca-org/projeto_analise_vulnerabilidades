#!/bin/bash

# Add Go to PATH and ensure it's available immediately
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

echo "Checking Go installation..."
if go version >/dev/null 2>&1; then
    echo "✓ Go is available: $(go version)"
elif [ -f "/usr/local/go/bin/go" ]; then
    echo "Found Go at /usr/local/go/bin/go"
    /usr/local/go/bin/go version
else
    echo "× Go not found. Please install Go first."
    exit 1
fi

echo "Installing httpx using Go..."
if [ -f "/usr/local/go/bin/go" ]; then
    /usr/local/go/bin/go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
else
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
fi

if [ -f "$HOME/go/bin/httpx" ]; then
    echo "✓ httpx installed successfully at $HOME/go/bin/httpx"
    sudo ln -sf $HOME/go/bin/httpx /usr/local/bin/httpx
    echo "✓ Created symbolic link at /usr/local/bin/httpx"
else
    echo "× httpx installation failed"
fi
