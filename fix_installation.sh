#!/bin/bash

# Fix any interrupted dpkg
sudo dpkg --configure -a

# Install system dependencies needed by Naabu
sudo apt-get update
sudo apt-get install -y libpcap-dev libldns-dev build-essential python3-venv

# If Go was installed manually to /usr/local/go, add it to PATH
export PATH=$PATH:/usr/local/go/bin:~/go/bin

# Install naabu directly
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Install other security tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Update PATH in shell configuration based on the user's default shell
SHELL_CONFIG_FILE=""
if [ "$SHELL" = "/bin/bash" ]; then
	SHELL_CONFIG_FILE="$HOME/.bashrc"
elif [ "$SHELL" = "/bin/zsh" ]; then
	SHELL_CONFIG_FILE="$HOME/.zshrc"
elif [ "$SHELL" = "/bin/fish" ]; then
	SHELL_CONFIG_FILE="$HOME/.config/fish/config.fish"
else
	echo "Unsupported shell: $SHELL. Please update your PATH manually."
	exit 1
fi

echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> "$SHELL_CONFIG_FILE"
echo "Please run: source $SHELL_CONFIG_FILE"

echo "Installation completed! You may need to restart your terminal."