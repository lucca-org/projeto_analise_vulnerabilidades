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
from typing import Dict, List, Any, Optional, Union

# Try to import optional dependencies for enhanced reporting
try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False

# Add a warning for missing dependencies
def check_dependencies():
    if not JINJA_AVAILABLE:
        print("Warning: Jinja2 is not installed. HTML report generation will be disabled.")
    if not RICH_AVAILABLE:
        print("Warning: Rich is not installed. Enhanced console output will be disabled.")
    if not MARKDOWN_AVAILABLE:
        print("Warning: Markdown is not installed. Markdown report generation will be disabled.")

check_dependencies()

def parse_scan_results(output_dir: str) -> Dict[str, Any]:
    """
    Parse various output files and extract findings.
    
    Args:
        output_dir: Directory containing scan results
        
    Returns:
        Dictionary with parsed results
    """
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
    
    # Parse target from directory name
    target_match = re.search(r'results_([^_]+)_', output_dir)
    if target_match:
        results["target_info"]["name"] = target_match.group(1)
    else:
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
                            except json.JSONDecodeError:
                                pass
                    results["ports"] = ports_data
                    results["summary"]["open_ports"] = len(ports_data)
        except Exception as e:
            print(f"Error parsing ports.json: {e}")

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
                            except json.JSONDecodeError:
                                pass
                    results["http_services"] = http_data
                    results["summary"]["http_services"] = len(http_data)
        except Exception as e:
            print(f"Error parsing http_services.json: {e}")
    
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
                        except json.JSONDecodeError:
                            pass
                results["vulnerabilities"] = vulns_data
        except Exception as e:
            print(f"Error parsing vulnerabilities.jsonl: {e}")

    return results


def generate_html_report(output_dir: str, results: Dict[str, Any]) -> bool:
    """
    Generate an HTML report from scan results.
    
    Args:
        output_dir: Directory to save the report
        results: Parsed scan results
        
    Returns:
        True if successful, False otherwise
    """
    if not JINJA_AVAILABLE:
        print("Jinja2 not available. Skipping HTML report generation.")
        return False
    
    try:
        # Simple HTML template for the report
        template_str = """<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report for {{ results.target_info.name }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #2980b9;
            margin-top: 30px;
        }
        .summary {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }
        .critical {
            color: #721c24;
            background-color: #f8d7da;
            padding: 3px 8px;
            border-radius: 4px;
        }
        .high {
            color: #856404;
            background-color: #fff3cd;
            padding: 3px 8px;
            border-radius: 4px;
        }
        .medium {
            color: #0c5460;
            background-color: #d1ecf1;
            padding: 3px 8px;
            border-radius: 4px;
        }
        .low {
            color: #155724;
            background-color: #d4edda;
            padding: 3px 8px;
            border-radius: 4px;
        }
        .info {
            color: #1b1e21;
            background-color: #d6d8d9;
            padding: 3px 8px;
            border-radius: 4px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .details {
            margin-bottom: 10px;
            padding: 10px;
            border: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Target:</strong> {{ results.target_info.name }}</p>
        <p><strong>Scan Date:</strong> {{ results.target_info.scan_date }}</p>
        <p><strong>Open Ports:</strong> {{ results.summary.open_ports }}</p>
        <p><strong>HTTP Services:</strong> {{ results.summary.http_services }}</p>
        <p><strong>Total Vulnerabilities:</strong> {{ results.summary.vulnerabilities.total }}</p>
        <ul>
            <li>Critical: <span class="critical">{{ results.summary.vulnerabilities.critical }}</span></li>
            <li>High: <span class="high">{{ results.summary.vulnerabilities.high }}</span></li>
            <li>Medium: <span class="medium">{{ results.summary.vulnerabilities.medium }}</span></li>
            <li>Low: <span class="low">{{ results.summary.vulnerabilities.low }}</span></li>
            <li>Info: <span class="info">{{ results.summary.vulnerabilities.info }}</span></li>
        </ul>
    </div>

    {% if results.vulnerabilities %}
    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Severity</th>
            <th>URL</th>
            <th>Description</th>
        </tr>
        {% for vuln in results.vulnerabilities %}
        <tr>
            <td>{{ vuln.info.name }}</td>
            <td class="{{ vuln.info.severity|lower }}">{{ vuln.info.severity }}</td>
            <td>{{ vuln.matched }}</td>
            <td>{{ vuln.info.description }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}

    {% if results.http_services %}
    <h2>HTTP Services</h2>
    <table>
        <tr>
            <th>URL</th>
            <th>Status</th>
            <th>Title</th>
            <th>Technologies</th>
        </tr>
        {% for service in results.http_services %}
        <tr>
            <td>{{ service.url }}</td>
            <td>{{ service.status_code }}</td>
            <td>{{ service.title }}</td>
            <td>{{ service.tech }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}

    {% if results.ports %}
    <h2>Open Ports</h2>
    <table>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Protocol</th>
        </tr>
        {% for port in results.ports %}
        <tr>
            <td>{{ port.host }}</td>
            <td>{{ port.port }}</td>
            <td>{{ port.protocol }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}

</body>
</html>"""

        # Create HTML report
        template = Template(template_str)
        html_content = template.render(results=results)
        
        # Write HTML report to file
        html_report_path = os.path.join(output_dir, 'report.html')
        with open(html_report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML report generated: {html_report_path}")
        return True
        
    except Exception as e:
        print(f"Error generating HTML report: {e}")
        traceback.print_exc()
        return False


def generate_markdown_report(output_dir: str, results: Dict[str, Any]) -> bool:
    """
    Generate a Markdown report from scan results.
    
    Args:
        output_dir: Directory to save the report
        results: Parsed scan results
        
    Returns:
        True if successful, False otherwise
    """
    try:
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
        
        # Also generate HTML from markdown if available
        if MARKDOWN_AVAILABLE:
            html_content = markdown.markdown(markdown_content, extensions=['tables'])
            html_report_path = os.path.join(output_dir, 'report_md.html')
            with open(html_report_path, 'w', encoding='utf-8') as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
    </style>
</head>
<body>
    {html_content}
</body>
</html>""")
        
        print(f"Markdown report generated: {md_report_path}")
        return True
        
    except Exception as e:
        print(f"Error generating Markdown report: {e}")
        return False


def display_report_summary(results: Dict[str, Any]) -> None:
    """
    Display a summary of scan results to the console.
    
    Args:
        results: Parsed scan results
    """
    if RICH_AVAILABLE:
        console = Console()
        
        console.print(f"[bold blue]Security Scan Report for {results['target_info']['name']}[/bold blue]")
        console.print()
        
        # Create summary table
        table = Table(title="Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Target", results['target_info']['name'])
        table.add_row("Scan Date", results['target_info']['scan_date'])
        table.add_row("Open Ports", str(results['summary']['open_ports']))
        table.add_row("HTTP Services", str(results['summary']['http_services']))
        table.add_row("Total Vulnerabilities", str(results['summary']['vulnerabilities']['total']))
        
        console.print(table)
        
        # Display vulnerability count by severity
        vuln_table = Table(title="Vulnerabilities by Severity")
        vuln_table.add_column("Severity", style="cyan")
        vuln_table.add_column("Count", style="green")
        
        vuln_table.add_row("Critical", f"[bold red]{results['summary']['vulnerabilities']['critical']}[/bold red]")
        vuln_table.add_row("High", f"[bold orange]{results['summary']['vulnerabilities']['high']}[/bold orange]")
        vuln_table.add_row("Medium", f"[yellow]{results['summary']['vulnerabilities']['medium']}[/yellow]")
        vuln_table.add_row("Low", f"[green]{results['summary']['vulnerabilities']['low']}[/green]")
        vuln_table.add_row("Info", f"[blue]{results['summary']['vulnerabilities']['info']}[/blue]")
        
        console.print(vuln_table)
    
    else:
        # Fallback to standard print
        print("\n===== Security Scan Report =====")
        print(f"Target: {results['target_info']['name']}")
        print(f"Scan Date: {results['target_info']['scan_date']}")
        print(f"Open Ports: {results['summary']['open_ports']}")
        print(f"HTTP Services: {results['summary']['http_services']}")
        print(f"Total Vulnerabilities: {results['summary']['vulnerabilities']['total']}")
        print("  - Critical:", results['summary']['vulnerabilities']['critical'])
        print("  - High:", results['summary']['vulnerabilities']['high'])
        print("  - Medium:", results['summary']['vulnerabilities']['medium'])
        print("  - Low:", results['summary']['vulnerabilities']['low'])
        print("  - Info:", results['summary']['vulnerabilities']['info'])


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
        print("\nGenerating comprehensive security report...")
        
        # Parse scan results
        results = parse_scan_results(output_dir)
        
        # Make sure target_info is populated
        if not results["target_info"].get("name"):
            results["target_info"]["name"] = target
            
        # Display report summary
        display_report_summary(results)
        
        # Generate various report formats
        html_success = generate_html_report(output_dir, results)
        md_success = generate_markdown_report(output_dir, results)
        
        # Save results JSON for later use
        with open(os.path.join(output_dir, 'results.json'), 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nReporting complete. Reports saved in {output_dir}")
        return html_success or md_success
    
    except Exception as e:
        print(f"Error generating report: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python reporter.py <results_directory> [target_name]")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    target_name = sys.argv[2] if len(sys.argv) > 2 else "unknown"
    
    if not os.path.isdir(results_dir):
        print(f"Error: {results_dir} is not a valid directory")
        sys.exit(1)
    
    success = generate_report(results_dir, target_name)
    if not success:
        print("Report generation had issues.")
        sys.exit(1)