#!/usr/bin/env python3
"""
Enhanced integration script for the Linux Vulnerability Analysis Toolkit.
This script integrates the new autoinstall.py with existing shell scripts and setup infrastructure.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

class ToolkitIntegrator:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.scripts_dir = self.project_root / "scripts"
        self.install_dir = self.project_root / "install"
        
    def integrate_shell_scripts(self):
        """Integrate the scripts/autoinstall.py with existing shell scripts."""
        print("🔧 Integrating with existing shell scripts...")
        # Create an enhanced setup_tools.sh that calls our scripts/autoinstall.py
        enhanced_setup = self.scripts_dir / "enhanced_setup.sh"
        
        # Using UTF-8 encoding to handle special characters properly
        shell_script_content = '''#!/bin/bash
# Enhanced setup script for Linux-only environments
set -e

if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ Error: This toolkit requires Linux."
    exit 1
fi

cd "$(dirname \"${BASH_SOURCE[0]}\")/.."
python3 scripts/autoinstall.py
'''
        with open(enhanced_setup, 'w', encoding='utf-8') as f:
            f.write(shell_script_content)
        
        # Make it executable
        os.chmod(enhanced_setup, 0o755)
        print(f"✅ Created enhanced setup script: {enhanced_setup}")
        
    def create_dockerfile(self):
        """Create a Dockerfile for containerized deployment."""
        print("🐳 Creating Dockerfile for containerized deployment...")
        
        # Using UTF-8 encoding for Docker file
        dockerfile_content = '''FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y python3 python3-pip
WORKDIR /toolkit
COPY . .
CMD ["python3", "src/workflow.py", "--help"]
'''

        dockerfile_path = self.project_root / "Dockerfile"
        with open(dockerfile_path, 'w', encoding='utf-8') as f:
            f.write(dockerfile_content)
        
        print(f"✅ Created Dockerfile: {dockerfile_path}")
        
    def run_integration(self):
        """Run all integration tasks."""
        print("🔧 Starting toolkit integration...")
        
        self.integrate_shell_scripts()
        self.create_dockerfile()
        
        print("✅ Integration completed successfully!")

if __name__ == "__main__":
    integrator = ToolkitIntegrator()
    integrator.run_integration()
