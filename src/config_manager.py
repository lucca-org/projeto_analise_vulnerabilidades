#!/usr/bin/env python3
"""
config_manager.py - Configuration management for security tools
Handles automatic configuration, settings persistence, and validation
"""

import os
import json
import platform
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

# Import utilities
from utils import get_system_memory_gb  # Import centralized function

# Default configuration settings
DEFAULT_CONFIG = {
    "general": {
        "output_dir": "results",
        "timeout": 3600,
        "verbose": False,
        "max_threads": 25
    },
    "naabu": {
        "ports": "top-1000",
        "exclude_ports": None,
        "scan_type": "SYN",
        "threads": 25,
        "timeout": 5,
        "retries": 3
    },
    "httpx": {
        "threads": 50,
        "timeout": 5,
        "follow_redirects": True,
        "status_code": True,
        "title": True,
        "tech_detect": True,
        "web_server": True
    },
    "nuclei": {
        "templates": None,
        "tags": "cve",
        "severity": "critical,high",
        "rate_limit": 150,
        "timeout": 5,
        "retries": 2,
        "bulk_size": 25,
        "exclude_tags": "fuzz,dos"
    },
    "reporting": {
        "formats": ["json", "md", "txt"],
        "include_evidence": True,
        "max_findings": 1000
    }
}

# Config file location
CONFIG_FILE = os.path.expanduser("~/.vuln_toolkit_config.json")

def get_config() -> Dict[str, Any]:
    """
    Load configuration from file or create with defaults if not exists
    
    Returns:
        Dict containing configuration settings
    """
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Validate and merge with defaults to ensure all required keys exist
                return merge_with_defaults(config)
        except Exception as e:
            print(f"Error loading config file: {e}")
            print(f"Using default configuration")
            return DEFAULT_CONFIG.copy()
    else:
        # Create default config
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def merge_with_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure all default keys exist in the configuration by merging with defaults
    
    Args:
        config: Existing configuration dictionary
        
    Returns:
        Merged configuration with all required keys
    """
    merged = DEFAULT_CONFIG.copy()
    
    for section, settings in config.items():
        if section in merged:
            if isinstance(settings, dict):
                for key, value in settings.items():
                    if value is not None:  # Only override non-None values
                        merged[section][key] = value
    
    return merged

def save_config(config: Dict[str, Any]) -> bool:
    """
    Save configuration to file
    
    Args:
        config: Configuration dictionary to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving configuration: {e}")
        return False

def update_config(section: str, key: str, value: Any) -> bool:
    """
    Update a specific configuration setting
    
    Args:
        section: Configuration section (e.g., 'naabu', 'httpx')
        key: Setting key to update
        value: New value
        
    Returns:
        True if successful, False otherwise
    """
    config = get_config()
    
    if section not in config:
        config[section] = {}
    
    config[section][key] = value
    return save_config(config)

def auto_configure() -> Dict[str, Any]:
    """
    Automatically configure settings based on system capabilities
    
    Returns:
        Updated configuration dictionary
    """
    config = get_config()
    
    # Detect system capabilities
    cpu_count = os.cpu_count() or 4
    total_memory_gb = get_system_memory_gb()
    
    # Check for root/admin access in a platform-independent way
    is_root = False
    if platform.system() != "Windows":
        try:
            # os.geteuid() is only available on Unix-like systems
            if hasattr(os, 'geteuid'):
                is_root = os.geteuid() == 0 # type: ignore
        except AttributeError:
            # We're on a platform that doesn't support geteuid
            is_root = False
    
    # Adjust threads based on CPU count
    max_threads = max(10, min(cpu_count * 2, 50))
    config["general"]["max_threads"] = max_threads
    config["naabu"]["threads"] = min(max_threads, 25)
    config["httpx"]["threads"] = min(max_threads * 2, 50)
    
    # Adjust timeouts based on likely internet speed
    # These are conservative defaults
    config["naabu"]["timeout"] = 5
    config["httpx"]["timeout"] = 5
    config["nuclei"]["timeout"] = 7
    
    # SYN scans require root/admin, fall back to CONNECT if not available
    if is_root:
        config["naabu"]["scan_type"] = "SYN"
    else:
        config["naabu"]["scan_type"] = "CONNECT"
    
    # Configure optimized nuclei settings based on memory
    if total_memory_gb >= 8:
        config["nuclei"]["bulk_size"] = 25
        config["nuclei"]["rate_limit"] = 150
    elif total_memory_gb >= 4:
        config["nuclei"]["bulk_size"] = 20
        config["nuclei"]["rate_limit"] = 100
    else:
        config["nuclei"]["bulk_size"] = 15
        config["nuclei"]["rate_limit"] = 50
    
    # Check for custom nuclei templates
    nuclei_templates_dir = os.path.expanduser("~/nuclei-templates")
    if os.path.isdir(nuclei_templates_dir):
        config["nuclei"]["templates"] = nuclei_templates_dir
    
    # Save the auto-configured settings
    save_config(config)
    return config

def get_tool_specific_config(tool: str) -> Dict[str, Any]:
    """
    Get configuration specific to a particular tool
    
    Args:
        tool: Tool name ('naabu', 'httpx', 'nuclei')
        
    Returns:
        Tool-specific configuration dictionary
    """
    config = get_config()
    
    if tool in config:
        return config[tool]
    else:
        return {}

def generate_cmd_args(tool: str, additional_args: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Generate command-line arguments for a tool based on configuration
    
    Args:
        tool: Tool name ('naabu', 'httpx', 'nuclei')
        additional_args: Additional or override arguments
        
    Returns:
        List of command-line arguments
    """
    config = get_tool_specific_config(tool)
    args = []
    
    # Override with additional args if provided
    if additional_args:
        for key, value in additional_args.items():
            config[key] = value
    
    # Convert config to command-line args
    for key, value in config.items():
        if value is None:
            continue
            
        # Handle boolean flags
        if isinstance(value, bool):
            if value:
                args.append(f"-{key}")
        else:
            args.append(f"-{key}")
            args.append(str(value))
    
    return args

def print_current_config():
    """Print the current configuration in a readable format"""
    config = get_config()
    print("\n=== Current Configuration ===\n")
    
    for section, settings in config.items():
        print(f"[{section}]")
        for key, value in settings.items():
            print(f"  {key}: {value}")
        print()

def reset_to_defaults() -> bool:
    """Reset configuration to default values"""
    return save_config(DEFAULT_CONFIG.copy())

if __name__ == "__main__":
    print("Vulnerability Analysis Toolkit Configuration Manager")
    print("\nRunning auto-configuration based on system capabilities...")
    
    # Run auto-configuration
    config = auto_configure()
    
    print("\nConfiguration has been optimized for your system.")
    print_current_config()
    
    print("\nYou can customize these settings by editing the configuration file:")
    print(f"  {CONFIG_FILE}")
    print("\nOr by using the update_config() function in your scripts.")
