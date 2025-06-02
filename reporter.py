#!/usr/bin/env python3
"""
reporter.py - Generate comprehensive security reports from scan results
"""

import os
import json
import datetime
import shutil
from pathlib import Path
import re
import traceback
import logging
from typing import Dict, List, Any, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('reporter')

# Import modules with fallback handling
try:
    import markdown # type: ignore
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False
    logger.warning("Markdown library is not installed. Install with: pip install markdown")

try:
    from utils import safe_read_json, create_directory_if_not_exists, normalize_path
    UTILS_AVAILABLE = True
except ImportError:
    UTILS_AVAILABLE = False
    logger.warning("utils.py module not found. Using internal functions.")
    
    # Fallback functions if utils.py is not available
    def safe_read_json(json_file, default=None):
        if not os.path.exists(json_file):
            logger.warning(f"File not found: {json_file}")
            return default
        try:
            with open(json_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading {json_file}: {e}")
            return default
            
    def create_directory_if_not_exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            return True
        except Exception as e:
            logger.error(f"Error creating directory {directory}: {e}")
            return False
            
    def normalize_path(path):
        return os.path.normpath(path)

# Add a warning for missing dependencies
def check_dependencies():
    missing_deps = []
    if not MARKDOWN_AVAILABLE:
        missing_deps.append("markdown")
    
    if missing_deps:
        logger.warning(f"Missing dependencies: {', '.join(missing_deps)}")
        logger.warning("Some report formats will be unavailable.")
        logger.warning(f"Install missing dependencies with: pip install {' '.join(missing_deps)}")
        return False
    return True

check_dependencies()

def parse_scan_results(output_dir: str) -> Dict[str, Any]:
    """
    Parse various output files and extract findings.
    
    Args:
        output_dir: Directory containing scan results
        
    Returns:
        Dictionary with parsed results
    """
    logger.info(f"Parsing scan results from {output_dir}")
    
    results = {
        "summary": {
            "open_ports": 0,
            "http_services": 0,
            "vulnerabilities": {
                "critical": 0,
                "high": 0, 
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0
            }
        },
        "target_info": {},
        "ports": [],
        "http_services": [],
        "vulnerabilities": []
    }
    
    # Validate the output directory exists
    if not os.path.isdir(output_dir):
        logger.error(f"Output directory does not exist: {output_dir}")
        return results
    
    # Parse target from directory name
    target_match = re.search(r'results_([^_]+)_', output_dir)
    if target_match:
        results["target_info"]["name"] = target_match.group(1)
    else:
        logger.warning(f"Could not parse target from directory name: {output_dir}")
        results["target_info"]["name"] = "unknown"
    
    results["target_info"]["scan_date"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Parse ports.json if it exists
    ports_json = os.path.join(output_dir, "ports.json")
    if os.path.exists(ports_json):
        try:
            with open(ports_json, 'r') as f:
                # Handle both JSON array format and JSONL format
                content = f.read().strip()
                if content.startswith('[') and content.endswith(']'):
                    # It's a JSON array
                    ports_data = json.loads(content)
                    results["ports"] = ports_data
                    results["summary"]["open_ports"] = len(ports_data)
                else:
                    # It's likely JSONL, parse line by line
                    f.seek(0)
                    ports_data = []
                    for line in f:
                        if line.strip():
                            try:
                                port_entry = json.loads(line)
                                ports_data.append(port_entry)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in ports.json: {line.strip()} - {str(e)}")
                    results["ports"] = ports_data
                    results["summary"]["open_ports"] = len(ports_data)
            logger.info(f"Parsed {len(results['ports'])} ports from {ports_json}")
        except Exception as e:
            logger.error(f"Error parsing ports.json: {e}")
            logger.debug(traceback.format_exc())

    # Parse http_services.json if it exists
    http_json = os.path.join(output_dir, "http_services.json")
    if os.path.exists(http_json):
        try:
            with open(http_json, 'r') as f:
                content = f.read().strip()
                if content.startswith('[') and content.endswith(']'):
                    http_data = json.loads(content)
                    results["http_services"] = http_data
                    results["summary"]["http_services"] = len(http_data)
                else:
                    # Parse line by line for JSONL format
                    f.seek(0)
                    http_data = []
                    for line in f:
                        if line.strip():
                            try:
                                service_entry = json.loads(line)
                                http_data.append(service_entry)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON in http_services.json: {line.strip()} - {str(e)}")
                    results["http_services"] = http_data
                    results["summary"]["http_services"] = len(http_data)
            logger.info(f"Parsed {len(results['http_services'])} HTTP services from {http_json}")
        except Exception as e:
            logger.error(f"Error parsing http_services.json: {e}")
            logger.debug(traceback.format_exc())
    
    # Parse vulnerabilities.jsonl if it exists
    vulns_jsonl = os.path.join(output_dir, "vulnerabilities.jsonl")
    if os.path.exists(vulns_jsonl):
        try:
            with open(vulns_jsonl, 'r') as f:
                vulns_data = []
                for line in f:
                    if line.strip():
                        try:
                            vuln_entry = json.loads(line)
                            vulns_data.append(vuln_entry)
                            
                            # Count vulnerabilities by severity
                            severity = vuln_entry.get("info", {}).get("severity", "").lower()
                            if severity in results["summary"]["vulnerabilities"]:
                                results["summary"]["vulnerabilities"][severity] += 1
                                results["summary"]["vulnerabilities"]["total"] += 1
                        except json.JSONDecodeError as e:
                            logger.warning(f"Invalid JSON in vulnerabilities.jsonl: {line.strip()} - {str(e)}")
                results["vulnerabilities"] = vulns_data
            logger.info(f"Parsed {len(results['vulnerabilities'])} vulnerabilities from {vulns_jsonl}")
        except Exception as e:
            logger.error(f"Error parsing vulnerabilities.jsonl: {e}")
            logger.debug(traceback.format_exc())

    return results


def generate_markdown_report(output_dir: str, results: Dict[str, Any]) -> bool:
    """
    Generate a Markdown report from scan results.
    
    Args:
        output_dir: Directory to save the report
        results: Parsed scan results
        
    Returns:
        True if successful, False otherwise
    """
    if not MARKDOWN_AVAILABLE:
        logger.error("Markdown library is not available. Cannot generate Markdown report.")
        return False
    
    try:
        logger.info("Generating Markdown report")
        markdown_content = f"""# Security Scan Report for {results['target_info']['name']}

## Summary
- **Target:** {results['target_info']['name']}
- **Scan Date:** {results['target_info']['scan_date']}
- **Open Ports:** {results['summary']['open_ports']}
- **HTTP Services:** {results['summary']['http_services']}
- **Total Vulnerabilities:** {results['summary']['vulnerabilities']['total']}
  - Critical: {results['summary']['vulnerabilities']['critical']}
  - High: {results['summary']['vulnerabilities']['high']}
  - Medium: {results['summary']['vulnerabilities']['medium']}
  - Low: {results['summary']['vulnerabilities']['low']}
  - Info: {results['summary']['vulnerabilities']['info']}

## Risk Assessment
"""
        
        # Add risk assessment based on findings
        if results['summary']['vulnerabilities']['critical'] > 0:
            markdown_content += "**CRITICAL RISK**: Immediate action required! Critical vulnerabilities were detected that could lead to system compromise.\n\n"
        elif results['summary']['vulnerabilities']['high'] > 0:
            markdown_content += "**HIGH RISK**: Urgent remediation needed. High severity vulnerabilities were detected.\n\n"
        elif results['summary']['vulnerabilities']['medium'] > 0:
            markdown_content += "**MEDIUM RISK**: Important issues found that should be addressed in a timely manner.\n\n"
        elif results['summary']['vulnerabilities']['low'] > 0:
            markdown_content += "**LOW RISK**: Minor issues detected that should be fixed when convenient.\n\n"
        else:
            markdown_content += "**NO SIGNIFICANT RISK**: No significant vulnerabilities were detected in this scan.\n\n"

        # Add vulnerabilities table
        if results['vulnerabilities']:
            markdown_content += "## Vulnerabilities\n\n"
            markdown_content += "| Name | Severity | URL | Description |\n"
            markdown_content += "| ---- | -------- | --- | ----------- |\n"
            
            for vuln in results['vulnerabilities']:
                name = vuln.get('info', {}).get('name', 'Unknown')
                severity = vuln.get('info', {}).get('severity', 'Unknown')
                url = vuln.get('matched', 'Unknown')
                description = vuln.get('info', {}).get('description', '').replace('\n', ' ')
                
                markdown_content += f"| {name} | {severity} | {url} | {description} |\n"
            
        # Add HTTP services table
        if results['http_services']:
            markdown_content += "\n## HTTP Services\n\n"
            markdown_content += "| URL | Status | Title | Technologies |\n"
            markdown_content += "| --- | ------ | ----- | ------------ |\n"
            
            for service in results['http_services']:
                url = service.get('url', 'Unknown')
                status = service.get('status_code', 'Unknown')
                title = service.get('title', 'Unknown').replace('|', '\\|')
                tech = ', '.join(service.get('tech', [])) if isinstance(service.get('tech', []), list) else service.get('tech', 'Unknown')
                
                markdown_content += f"| {url} | {status} | {title} | {tech} |\n"
            
        # Add ports table
        if results['ports']:
            markdown_content += "\n## Open Ports\n\n"
            markdown_content += "| Host | Port | Protocol |\n"
            markdown_content += "| ---- | ---- | -------- |\n"
            
            for port in results['ports']:
                host = port.get('host', 'Unknown')
                port_num = port.get('port', 'Unknown')
                protocol = port.get('protocol', 'tcp')
                
                markdown_content += f"| {host} | {port_num} | {protocol} |\n"
            
        # Write markdown report to file
        md_report_path = os.path.join(output_dir, 'report.md')
        with open(md_report_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        logger.info(f"Markdown report generated: {md_report_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error generating Markdown report: {e}")
        logger.debug(traceback.format_exc())
        return False


def generate_report(output_dir: str, target: str) -> bool:
    """
    Generate comprehensive reports from scan results.
    
    Args:
        output_dir: Directory containing scan results
        target: Target that was scanned
        
    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info(f"Generating comprehensive security report for {target}")
        
        # Validate output directory
        if not os.path.isdir(output_dir):
            logger.error(f"Output directory does not exist: {output_dir}")
            return False
        
        # Parse scan results
        results = parse_scan_results(output_dir)
        
        # Make sure target_info is populated
        if not results["target_info"].get("name"):
            results["target_info"]["name"] = target
            
        # Generate various report formats
        md_success = generate_markdown_report(output_dir, results)
        
        # Save results JSON for later use
        results_json_path = os.path.join(output_dir, 'results.json')
        try:
            with open(results_json_path, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results JSON saved to {results_json_path}")
        except Exception as e:
            logger.error(f"Error saving results JSON: {e}")
        
        logger.info(f"Reporting complete. Reports saved in {output_dir}")
        return md_success
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        logger.debug(traceback.format_exc())
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python reporter.py <results_directory> [target_name]")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    target_name = sys.argv[2] if len(sys.argv) > 2 else "unknown"
    
    if not os.path.isdir(results_dir):
        logger.error(f"Error: {results_dir} is not a valid directory")
        sys.exit(1)
    
    success = generate_report(results_dir, target_name)
    if not success:
        logger.error("Report generation had issues.")
        sys.exit(1)
    else:
        logger.info("Report generation completed successfully")