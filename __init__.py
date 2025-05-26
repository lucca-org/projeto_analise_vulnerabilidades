"""
projeto_analise_vulnerabilidades - Vulnerability Analysis Toolkit

This package provides a comprehensive toolkit for security scanning including:
- Port scanning (naabu)
- HTTP service discovery (httpx)
- Vulnerability scanning (nuclei)
"""

__version__ = '1.0.0'
__author__ = 'Security Researcher'

# Configuration for the entire package
CONFIG = {
    "security_tools": ["naabu", "httpx", "nuclei"],
    "default_scan_timeout": 3600,
    "minimum_python_version": "3.8",
    "go_version": "1.21.0"
}

# Make key modules available at package level
try:
    from commands import naabu, httpx, nuclei
except ImportError:
    # During installation or when commands are not yet set up
    pass