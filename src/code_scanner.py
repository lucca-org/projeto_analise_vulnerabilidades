#!/usr/bin/env python3
"""
code_scanner.py - Source code vulnerability scanner
Scans project files for security vulnerabilities and coding issues
"""

import os
import re
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple, Optional

# Vulnerability patterns to check in code files
VULNERABILITY_PATTERNS = {
    "python": [
        {
            "name": "SQL Injection",
            "pattern": r"execute\s*\(\s*[\'\"].*?\%s.*?[\'\"].*?\)",
            "severity": "high",
            "description": "Potential SQL injection vulnerability using string formatting"
        },
        {
            "name": "OS Command Injection",
            "pattern": r"os\.system\s*\(\s*(?![\'\"][^\'\"]*[\'\"])[^\)]*\)",
            "severity": "high",
            "description": "Potential OS command injection via dynamic input to os.system()"
        },
        {
            "name": "Insecure Deserialization",
            "pattern": r"pickle\.loads\s*\(",
            "severity": "high",
            "description": "Use of pickle.loads() which can lead to remote code execution"
        },
        {
            "name": "Insecure Hash Algorithm",
            "pattern": r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(",
            "severity": "medium",
            "description": "Use of weak cryptographic hash functions (MD5, SHA1)"
        },
        {
            "name": "Hard-coded Credentials",
            "pattern": r"password\s*=\s*[\'\"][^\'\"\s]+[\'\"]|api[_\-]?key\s*=\s*[\'\"][^\'\"\s]+[\'\"]",
            "severity": "high",
            "description": "Hard-coded passwords or API keys"
        },
        {
            "name": "Insecure File Permissions",
            "pattern": r"os\.chmod\s*\(.*?,\s*(?:0o*(?:7|777|666)|[rRwWxXaA\+]{2,})\s*\)",
            "severity": "medium",
            "description": "Overly permissive file permissions"
        },
        {
            "name": "Shell=True Risk",
            "pattern": r"subprocess\.[a-zA-Z]+\(.*?shell\s*=\s*True",
            "severity": "high",
            "description": "Using shell=True with subprocess functions can lead to command injection"
        },
        {
            "name": "Insecure Random",
            "pattern": r"random\.[a-zA-Z]+\s*\(",
            "severity": "low",
            "description": "Use of standard random module for security purposes (use secrets instead)"
        },
        {
            "name": "Debug Features",
            "pattern": r"DEBUG\s*=\s*True|set_trace\(\)|breakpoint\(\)",
            "severity": "medium",
            "description": "Debug features enabled in code"
        },
        {
            "name": "Sensitive Information Logging",
            "pattern": r"log(?:ger)?\.(?:debug|info|warning|error|critical)\s*\(.*?(?:password|token|secret|key).*?\)",
            "severity": "medium",
            "description": "Potentially logging sensitive information"
        }
    ],
    "javascript": [
        {
            "name": "DOM-based XSS",
            "pattern": r"(?:document\.write|innerHTML|outerHTML)\s*=",
            "severity": "high",
            "description": "Potential DOM-based XSS vulnerability"
        },
        {
            "name": "Eval Usage",
            "pattern": r"eval\s*\(",
            "severity": "high",
            "description": "Use of eval() which can lead to code injection"
        },
        {
            "name": "Hard-coded Credentials",
            "pattern": r"(?:password|apiKey|token|secret)\s*[=:]\s*[\'\"][^\'\"\s]+[\'\"]",
            "severity": "high",
            "description": "Hard-coded sensitive credentials"
        },
        {
            "name": "Insecure Storage",
            "pattern": r"localStorage\.setItem\s*\(\s*[\'\"](?:password|token|secret|key)[\'\"]",
            "severity": "medium",
            "description": "Storing sensitive information in localStorage"
        }
    ],
    "bash": [
        {
            "name": "Shell Injection",
            "pattern": r"eval.*?\$\{?[a-zA-Z0-9_]+\}?",
            "severity": "high",
            "description": "Potential shell injection vulnerability with eval"
        },
        {
            "name": "Insecure Temporary File",
            "pattern": r"(?:\/tmp\/[a-zA-Z0-9_]+)",
            "severity": "medium",
            "description": "Use of predictable temporary file names"
        }
    ]
}

# Mapping of file extensions to language
EXTENSION_MAPPING = {
    ".py": "python",
    ".js": "javascript",
    ".html": "javascript",  # HTML may contain JavaScript
    ".jsx": "javascript",
    ".ts": "javascript",  # TypeScript (using JavaScript patterns)
    ".sh": "bash",
    ".bash": "bash"
}

def scan_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Scan a single file for vulnerabilities
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        List of vulnerability findings
    """
    findings = []
    
    # Determine language based on file extension
    ext = os.path.splitext(file_path)[1].lower()
    language = EXTENSION_MAPPING.get(ext)
    
    if not language:
        return findings  # Skip unsupported file types
    
    # Check if file exists and is readable
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return findings
        
    # Get patterns for the language
    patterns = VULNERABILITY_PATTERNS.get(language, [])
    
    # Scan for each pattern
    for pattern_info in patterns:
        pattern = pattern_info["pattern"]
        matches = re.finditer(pattern, content, re.IGNORECASE)
        
        for match in matches:
            line_number = content[:match.start()].count('\n') + 1
            line_content = content.split('\n')[line_number - 1].strip()
            
            findings.append({
                "file": file_path,
                "line": line_number,
                "code": line_content,
                "pattern_name": pattern_info["name"],
                "severity": pattern_info["severity"],
                "description": pattern_info["description"],
                "language": language
            })
    
    return findings

def scan_directory(directory: str, exclude_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Recursively scan a directory for vulnerabilities
    
    Args:
        directory: Directory to scan
        exclude_dirs: List of directories to exclude
        
    Returns:
        List of vulnerability findings
    """
    if exclude_dirs is None:
        exclude_dirs = ['.git', 'venv', '.venv', 'node_modules', '__pycache__']
        
    all_findings = []
    
    for root, dirs, files in os.walk(directory):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            file_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()
            
            if ext in EXTENSION_MAPPING:
                file_findings = scan_file(file_path)
                all_findings.extend(file_findings)
    
    return all_findings

def format_findings(findings: List[Dict[str, Any]], output_format: str = 'text') -> str:
    """
    Format findings for output
    
    Args:
        findings: List of findings from scan_directory or scan_file
        output_format: Output format ('text', 'json', or 'markdown')
        
    Returns:
        Formatted findings as a string
    """
    if output_format == 'json':
        return json.dumps(findings, indent=2)
        
    elif output_format == 'markdown':
        if not findings:
            return "# Security Scan Results\n\nNo security issues found."
            
        md_output = "# Security Scan Results\n\n"
        md_output += f"**Found {len(findings)} potential security issues**\n\n"
        
        # Group by severity
        by_severity = {"high": [], "medium": [], "low": []}
        for finding in findings:
            by_severity.get(finding["severity"], []).append(finding)
            
        for severity in ["high", "medium", "low"]:
            if by_severity[severity]:
                md_output += f"## {severity.upper()} Severity Issues ({len(by_severity[severity])})\n\n"
                
                for finding in by_severity[severity]:
                    md_output += f"### {finding['pattern_name']} in {finding['file']}\n\n"
                    md_output += f"**Line {finding['line']}:** `{finding['code']}`\n\n"
                    md_output += f"**Description:** {finding['description']}\n\n"
                    md_output += "---\n\n"
        
        return md_output
        
    else:  # Default to text
        if not findings:
            return "No security issues found."
            
        text_output = f"Security Scan Results: Found {len(findings)} potential security issues\n\n"
        
        # Group by severity
        by_severity = {"high": [], "medium": [], "low": []}
        for finding in findings:
            by_severity.get(finding["severity"], []).append(finding)
            
        for severity in ["high", "medium", "low"]:
            if by_severity[severity]:
                text_output += f"{severity.upper()} Severity Issues ({len(by_severity[severity])}):\n"
                text_output += "=" * 50 + "\n\n"
                
                for finding in by_severity[severity]:
                    text_output += f"{finding['pattern_name']} in {finding['file']}\n"
                    text_output += f"Line {finding['line']}: {finding['code']}\n"
                    text_output += f"Description: {finding['description']}\n\n"
        
        return text_output

def save_findings(findings: List[Dict[str, Any]], output_file: str, output_format: str = 'text') -> bool:
    """
    Save findings to a file
    
    Args:
        findings: List of findings
        output_file: Output file path
        output_format: Output format ('text', 'json', or 'markdown')
        
    Returns:
        True if successful, False otherwise
    """
    try:
        formatted_output = format_findings(findings, output_format)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(formatted_output)
            
        return True
    except Exception as e:
        print(f"Error saving findings: {e}")
        return False

def run_external_scanners(directory: str) -> List[Dict[str, Any]]:
    """
    Run external security scanners if available
    
    Args:
        directory: Directory to scan
        
    Returns:
        List of findings from external scanners
    """
    findings = []
    
    # Try to run bandit for Python code if available
    try:
        if subprocess.run(["which", "bandit"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
            print("Running bandit for Python code...")
            
            result = subprocess.run(
                ["bandit", "-r", directory, "-f", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    bandit_data = json.loads(result.stdout)
                    for issue in bandit_data.get("results", []):
                        findings.append({
                            "file": issue.get("filename", "unknown"),
                            "line": issue.get("line_number", 0),
                            "code": issue.get("code", ""),
                            "pattern_name": issue.get("test_name", "Unknown"),
                            "severity": issue.get("issue_severity", "medium").lower(),
                            "description": issue.get("issue_text", ""),
                            "language": "python",
                            "source": "bandit"
                        })
                except json.JSONDecodeError:
                    print("Error parsing bandit output")
    except FileNotFoundError:
        pass  # bandit is not installed
    
    return findings

def main():
    parser = argparse.ArgumentParser(description='Source Code Vulnerability Scanner')
    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'markdown'], default='text',
                      help='Output format (default: text)')
    parser.add_argument('-e', '--exclude', nargs='*', default=['.git', 'venv', '.venv', 'node_modules'],
                      help='Directories to exclude from scanning')
    parser.add_argument('--external', action='store_true', help='Run external scanners if available')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path {args.path} does not exist.")
        return 1
    
    print(f"Scanning {args.path} for potential security vulnerabilities...")
    
    if os.path.isfile(args.path):
        findings = scan_file(args.path)
    else:
        findings = scan_directory(args.path, args.exclude)
        
        # Run external scanners if requested
        if args.external:
            external_findings = run_external_scanners(args.path)
            findings.extend(external_findings)
    
    # Group findings by severity for reporting
    by_severity = {"high": [], "medium": [], "low": []}
    for finding in findings:
        by_severity.get(finding["severity"], []).append(finding)
    
    # Print summary
    total_findings = len(findings)
    print(f"\nScan completed. Found {total_findings} potential security issues:")
    print(f"  - High severity: {len(by_severity['high'])}")
    print(f"  - Medium severity: {len(by_severity['medium'])}")
    print(f"  - Low severity: {len(by_severity['low'])}")
    
    # Output detailed findings
    if args.output:
        if save_findings(findings, args.output, args.format):
            print(f"\nDetailed results saved to {args.output}")
        else:
            print(f"\nError saving results to {args.output}")
    else:
        # Print to console
        print("\n" + format_findings(findings, args.format))
    
    # Return non-zero exit code if high severity issues found
    return 0 if len(by_severity['high']) == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
