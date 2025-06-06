#!/usr/bin/env python3
"""
reporter.py - Generate comprehensive security reports from scan results
"""

import os
import sys
import json
import logging
import datetime
from typing import Dict, List, Any, Optional
import tempfile
import platform
import getpass
import re
import traceback
import shutil

# Configure logging
current_user = getpass.getuser()
log_directory = os.path.join(tempfile.gettempdir(), f"vulnerability_scan_{current_user}")
log_file = os.path.join(log_directory, "vulnerability_reporter.log")

# Create a logger instance
logger = logging.getLogger(__name__)

# Create user-specific log directory with appropriate permissions
try:
    if not os.path.exists(log_directory):
        os.makedirs(log_directory, exist_ok=True)
        # Set appropriate permissions for the directory
        if platform.system() == "Linux":
            import stat
            os.chmod(log_directory, stat.S_IRWXU)  # Read, write, execute for user only
except Exception as e:
    print(f"Warning: Could not create log directory: {e}")
    # Fallback to current directory
    log_directory = os.path.abspath("logs")
    if not os.path.exists(log_directory):
        os.makedirs(log_directory, exist_ok=True)
    log_file = os.path.join(log_directory, "vulnerability_reporter.log")

# Configure logging with error handling
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
        ]
    )
    
    # Try to add a file handler, but continue without it if permissions are an issue
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)
    except (PermissionError, IOError) as e:
        print(f"Warning: Could not create log file {log_file}: {e}")
        print("Continuing without file logging...")
        
except Exception as e:
    print(f"Warning: Error setting up logging: {e}")

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

# Enhanced dependency handling
try:
    from jinja2 import Template # type: ignore
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    logger.warning("Jinja2 library not available. Install: pip install jinja2")

try:
    from rich.console import Console # type: ignore
    from rich.table import Table # type: ignore
    from rich.progress import track # type: ignore
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None
    logger.warning("Rich library not available. Install: pip install rich")

import csv
import base64
import hashlib
import xml.etree.ElementTree as ET


class AdvancedReporter:
    """Enhanced reporter with multiple formats and advanced analytics."""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.console = None
        if RICH_AVAILABLE and console is not None:
            self.console = console
    
    def generate_comprehensive_report(self, results: Dict[str, Any], target: str) -> bool:
        """Generate comprehensive reports in multiple formats."""
        try:
            logger.info("Generating comprehensive security report")
            
            # Generate all report formats
            formats_generated = []
            
            # 1. Enhanced JSON Report
            if self._generate_enhanced_json(results, target):
                formats_generated.append("Enhanced JSON")
                
            # 2. Executive Summary Report
            if self._generate_executive_summary(results, target):
                formats_generated.append("Executive Summary")
                
            # 3. Technical Deep Dive
            if self._generate_technical_report(results, target):
                formats_generated.append("Technical Report")
                
            # 4. CSV Export for Analysis
            if self._generate_csv_export(results, target):
                formats_generated.append("CSV Export")
                
            # 5. XML Report for Integration
            if self._generate_xml_report(results, target):
                formats_generated.append("XML Report")
                
            # 6. Risk Assessment Matrix
            if self._generate_risk_matrix(results, target):
                formats_generated.append("Risk Matrix")
                
            logger.info(f"Generated {len(formats_generated)} report formats")
            return len(formats_generated) > 0
            
        except Exception as e:
            logger.error(f"Comprehensive report generation failed: {e}")
            return False
    
    def _generate_enhanced_json(self, results: Dict[str, Any], target: str) -> bool:
        """Generate enhanced JSON report with analytics."""
        try:
            enhanced_results = results.copy()
            
            # Add analytics
            enhanced_results["analytics"] = self._calculate_analytics(results)
            enhanced_results["risk_score"] = self._calculate_risk_score(results)
            enhanced_results["remediation_priority"] = self._prioritize_remediation(results)
            enhanced_results["compliance_status"] = self._check_compliance(results)
            
            # Add metadata
            enhanced_results["report_metadata"] = {
                "generated_at": datetime.datetime.now().isoformat(),
                "target": target,
                "report_version": "2.0",
                "reporter": "Advanced Linux Security Toolkit",
                "format": "enhanced_json"
            }
            
            # Save enhanced JSON
            json_file = os.path.join(self.output_dir, "enhanced_results.json")
            with open(json_file, 'w') as f:
                json.dump(enhanced_results, f, indent=2, default=str)
                
            logger.info(f"Enhanced JSON report: {json_file}")
            return True
            
        except Exception as e:
            logger.error(f"Enhanced JSON generation failed: {e}")
            return False
    
    def _generate_executive_summary(self, results: Dict[str, Any], target: str) -> bool:
        """Generate executive summary for management."""
        try:
            summary_file = os.path.join(self.output_dir, "executive_summary.md")
            
            # Calculate key metrics
            metrics = self._calculate_analytics(results)
            risk_score = self._calculate_risk_score(results)
            
            with open(summary_file, 'w') as f:
                f.write(f"# Executive Security Summary\n\n")
                f.write(f"**Target:** {target}  \n")
                f.write(f"**Assessment Date:** {datetime.datetime.now().strftime('%Y-%m-%d')}  \n")
                f.write(f"**Overall Risk Score:** {risk_score}/10  \n\n")
                
                # Risk Level
                if risk_score >= 8:
                    f.write("**CRITICAL RISK** - Immediate action required\n\n")
                elif risk_score >= 6:
                    f.write("**HIGH RISK** - Priority remediation needed\n\n")
                elif risk_score >= 4:
                    f.write("**MEDIUM RISK** - Address within reasonable timeframe\n\n")
                else:
                    f.write("**LOW RISK** - Maintain current security posture\n\n")
                
                # Key Findings
                f.write("## Key Findings\n\n")
                f.write(f"- **Open Ports:** {metrics.get('total_ports', 0)}\n")
                f.write(f"- **HTTP Services:** {metrics.get('total_services', 0)}\n")
                f.write(f"- **Critical Vulnerabilities:** {metrics.get('critical_vulns', 0)}\n")
                f.write(f"- **High Severity Issues:** {metrics.get('high_vulns', 0)}\n\n")
                
                # Recommendations
                f.write("## Immediate Actions Required\n\n")
                priorities = self._prioritize_remediation(results)
                for i, action in enumerate(priorities[:5], 1):
                    f.write(f"{i}. {action}\n")
                
                f.write("\n## Business Impact Assessment\n\n")
                f.write(self._assess_business_impact(results))
                
            logger.info(f"Executive summary: {summary_file}")
            return True
            
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return False
    
    def _generate_technical_report(self, results: Dict[str, Any], target: str) -> bool:
        """Generate detailed technical report."""
        try:
            tech_file = os.path.join(self.output_dir, "technical_deep_dive.md")
            
            with open(tech_file, 'w') as f:
                f.write(f"# Technical Security Assessment\n\n")
                f.write(f"**Target:** {target}  \n")
                f.write(f"**Assessment Date:** {datetime.datetime.now().isoformat()}  \n")
                f.write(f"**Tools Used:** naabu, httpx, nuclei (Linux optimized)  \n\n")
                
                # Detailed vulnerability analysis
                f.write("## Vulnerability Analysis\n\n")
                vulnerabilities = results.get("vulnerabilities", [])
                
                severity_groups = {"critical": [], "high": [], "medium": [], "low": []}
                for vuln in vulnerabilities:
                    severity = vuln.get("info", {}).get("severity", "low").lower()
                    if severity in severity_groups:
                        severity_groups[severity].append(vuln)
                
                for severity, vulns in severity_groups.items():
                    if vulns:
                        f.write(f"### {severity.upper()} Severity ({len(vulns)} findings)\n\n")
                        for vuln in vulns:
                            info = vuln.get("info", {})
                            f.write(f"**{info.get('name', 'Unknown')}**  \n")
                            f.write(f"- **Template ID:** {vuln.get('template-id', 'N/A')}  \n")
                            f.write(f"- **Matched URL:** {vuln.get('matched-at', 'N/A')}  \n")
                            f.write(f"- **Description:** {info.get('description', 'No description')}  \n")
                            
                            # Add CVE information if available
                            classification = info.get("classification", {})
                            if "cve-id" in classification:
                                f.write(f"- **CVE:** {classification['cve-id']}  \n")
                            f.write("\n")
                
            logger.info(f"Technical report: {tech_file}")
            return True
            
        except Exception as e:
            logger.error(f"Technical report generation failed: {e}")
            return False
    
    def _generate_csv_export(self, results: Dict[str, Any], target: str) -> bool:
        """Generate CSV export for analysis tools."""
        try:
            csv_file = os.path.join(self.output_dir, "vulnerability_export.csv")
            
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Headers
                writer.writerow([
                    "Target", "Vulnerability", "Severity", "CVE", "Template_ID",
                    "Matched_URL", "Description", "Classification", "Risk_Score"
                ])
                
                # Data rows
                vulnerabilities = results.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    info = vuln.get("info", {})
                    classification = info.get("classification", {})
                    
                    writer.writerow([
                        target,
                        info.get("name", "Unknown"),
                        info.get("severity", "unknown"),
                        classification.get("cve-id", "N/A"),
                        vuln.get("template-id", "N/A"),
                        vuln.get("matched-at", "N/A"),
                        info.get("description", "")[:200],  # Truncate long descriptions
                        ", ".join(classification.get("tags", [])),
                        self._calculate_individual_risk_score(vuln)
                    ])
                    
            logger.info(f"CSV export: {csv_file}")
            return True
            
        except Exception as e:
            logger.error(f"CSV export generation failed: {e}")
            return False
    
    def _generate_xml_report(self, results: Dict[str, Any], target: str) -> bool:
        """Generate XML report for tool integration."""
        try:
            root = ET.Element("security_assessment")
            root.set("target", target)
            root.set("timestamp", datetime.datetime.now().isoformat())
            
            # Add vulnerabilities
            vulns_elem = ET.SubElement(root, "vulnerabilities")
            for vuln in results.get("vulnerabilities", []):
                vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
                info = vuln.get("info", {})
                
                ET.SubElement(vuln_elem, "name").text = info.get("name", "")
                ET.SubElement(vuln_elem, "severity").text = info.get("severity", "")
                ET.SubElement(vuln_elem, "template_id").text = vuln.get("template-id", "")
                ET.SubElement(vuln_elem, "matched_url").text = vuln.get("matched-at", "")
                ET.SubElement(vuln_elem, "description").text = info.get("description", "")
                
            xml_file = os.path.join(self.output_dir, "security_report.xml")
            tree = ET.ElementTree(root)
            tree.write(xml_file, encoding="utf-8", xml_declaration=True)
            
            logger.info(f"XML report: {xml_file}")
            return True
            
        except Exception as e:
            logger.error(f"XML report generation failed: {e}")
            return False
    
    def _generate_risk_matrix(self, results: Dict[str, Any], target: str) -> bool:
        """Generate risk assessment matrix."""
        try:
            matrix_file = os.path.join(self.output_dir, "risk_matrix.md")
            
            with open(matrix_file, 'w') as f:
                f.write("# Risk Assessment Matrix\n\n")
                f.write("| Vulnerability | Severity | Likelihood | Impact | Risk Level | Priority |\n")
                f.write("|---------------|----------|------------|---------|------------|----------|\n")
                
                for vuln in results.get("vulnerabilities", []):
                    info = vuln.get("info", {})
                    severity = info.get("severity", "low")
                    likelihood = self._assess_likelihood(vuln)
                    impact = self._assess_impact(vuln)
                    risk_level = self._calculate_risk_level(severity, likelihood, impact)
                    priority = self._assign_priority(risk_level)
                    
                    f.write(f"| {info.get('name', 'Unknown')[:30]} | {severity} | {likelihood} | {impact} | {risk_level} | {priority} |\n")
                    
            logger.info(f"Risk matrix: {matrix_file}")
            return True
            
        except Exception as e:
            logger.error(f"Risk matrix generation failed: {e}")
            return False
    
    def _calculate_analytics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive analytics from scan results."""
        analytics = {
            "total_ports": len(results.get("ports", [])),
            "total_services": len(results.get("http_services", [])),
            "total_vulnerabilities": len(results.get("vulnerabilities", [])),
            "critical_vulns": 0,
            "high_vulns": 0,
            "medium_vulns": 0,
            "low_vulns": 0,
            "cve_count": 0,
            "unique_templates": set(),
            "affected_services": set()
        }
        
        # Count vulnerabilities by severity
        for vuln in results.get("vulnerabilities", []):
            severity = vuln.get("info", {}).get("severity", "low").lower()
            
            if severity == "critical":
                analytics["critical_vulns"] += 1
            elif severity == "high":
                analytics["high_vulns"] += 1
            elif severity == "medium":
                analytics["medium_vulns"] += 1
            elif severity == "low":
                analytics["low_vulns"] += 1
            
            # Count CVEs
            classification = vuln.get("info", {}).get("classification", {})
            if "cve-id" in classification:
                analytics["cve_count"] += 1
            
            # Track unique templates
            template_id = vuln.get("template-id", "")
            if template_id:
                analytics["unique_templates"].add(template_id)
            
            # Track affected services
            matched_url = vuln.get("matched-at", "")
            if matched_url:
                analytics["affected_services"].add(matched_url)
        
        # Convert sets to counts for JSON serialization
        analytics["unique_template_count"] = len(analytics["unique_templates"])
        analytics["affected_service_count"] = len(analytics["affected_services"])
        del analytics["unique_templates"]
        del analytics["affected_services"]
        
        return analytics
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score based on findings."""
        analytics = self._calculate_analytics(results)
        
        # Base score calculation
        risk_score = 0.0
        
        # Weight vulnerabilities by severity
        risk_score += analytics["critical_vulns"] * 4.0
        risk_score += analytics["high_vulns"] * 3.0
        risk_score += analytics["medium_vulns"] * 2.0
        risk_score += analytics["low_vulns"] * 1.0
        
        # Factor in exposure (ports and services)
        exposure_factor = (analytics["total_ports"] + analytics["total_services"]) * 0.1
        risk_score += exposure_factor
        
        # Factor in CVE presence
        cve_factor = analytics["cve_count"] * 0.5
        risk_score += cve_factor
        
        # Normalize to 0-10 scale
        normalized_score = min(10.0, max(0.0, risk_score))
        
        return round(normalized_score, 1)
    
    def _prioritize_remediation(self, results: Dict[str, Any]) -> List[str]:
        """Generate prioritized remediation recommendations."""
        priorities = []
        analytics = self._calculate_analytics(results)
        
        # Critical vulnerability remediation
        if analytics["critical_vulns"] > 0:
            priorities.append(f"Address {analytics['critical_vulns']} critical vulnerabilities immediately")
        
        # High severity issues
        if analytics["high_vulns"] > 0:
            priorities.append(f"Remediate {analytics['high_vulns']} high severity issues within 24-48 hours")
        
        # Service exposure
        if analytics["total_services"] > 10:
            priorities.append("Reduce HTTP service exposure by disabling unnecessary services")
        
        # Port security
        if analytics["total_ports"] > 20:
            priorities.append("Review and close unnecessary open ports")
        
        # CVE patching
        if analytics["cve_count"] > 0:
            priorities.append(f"Apply security patches for {analytics['cve_count']} known CVEs")
        
        # Medium severity issues
        if analytics["medium_vulns"] > 5:
            priorities.append(f"Plan remediation for {analytics['medium_vulns']} medium severity findings")
        
        # Security hardening
        priorities.append("Implement security hardening measures based on findings")
        
        # Monitoring
        priorities.append("Establish continuous security monitoring and scanning")
        
        return priorities[:10]  # Return top 10 priorities
    
    def _check_compliance(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Check compliance against security frameworks."""
        compliance = {
            "owasp_top10": {"score": 0, "total": 10, "issues": []},
            "nist": {"score": 0, "total": 5, "issues": []},
            "iso27001": {"score": 0, "total": 3, "issues": []}
        }
        
        vulnerabilities = results.get("vulnerabilities", [])
        
        # OWASP Top 10 compliance
        owasp_issues = 0
        for vuln in vulnerabilities:
            tags = vuln.get("info", {}).get("classification", {}).get("tags", [])
            if any("owasp" in tag.lower() for tag in tags):
                owasp_issues += 1
                compliance["owasp_top10"]["issues"].append(vuln.get("info", {}).get("name", "Unknown"))
                
        compliance["owasp_top10"]["score"] = max(0, 10 - owasp_issues)
        
        return compliance
    
    def _assess_business_impact(self, results: Dict[str, Any]) -> str:
        """Assess business impact of findings."""
        critical_count = len([v for v in results.get("vulnerabilities", []) 
                            if v.get("info", {}).get("severity", "").lower() == "critical"])
        
        if critical_count > 0:
            return ("**HIGH IMPACT** - Critical vulnerabilities could lead to:\n"
                   "- Complete system compromise\n"
                   "- Data breach and regulatory fines\n"
                   "- Business continuity disruption\n"
                   "- Reputation damage\n")
        elif len(results.get("vulnerabilities", [])) > 10:
            return ("**MEDIUM IMPACT** - Multiple vulnerabilities could result in:\n"
                   "- Partial system compromise\n"
                   "- Sensitive data exposure\n"
                   "- Service degradation\n")
        else:
            return ("**LOW IMPACT** - Findings represent minimal business risk:\n"
                   "- Limited exposure potential\n"
                   "- Standard security maintenance required\n")
    
    def _calculate_individual_risk_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate individual vulnerability risk score."""
        severity = vuln.get("info", {}).get("severity", "low").lower()
        
        score_map = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 1.0
        }
        
        base_score = score_map.get(severity, 1.0)
        
        # Adjust for CVE presence
        classification = vuln.get("info", {}).get("classification", {})
        if "cve-id" in classification:
            base_score += 1.0
            
        return min(10.0, base_score)
    
    def _assess_likelihood(self, vuln: Dict[str, Any]) -> str:
        """Assess likelihood of exploitation."""
        severity = vuln.get("info", {}).get("severity", "low").lower()
        
        if severity in ["critical", "high"]:
            return "High"
        elif severity == "medium":
            return "Medium"
        else:
            return "Low"
    
    def _assess_impact(self, vuln: Dict[str, Any]) -> str:
        """Assess impact of exploitation."""
        severity = vuln.get("info", {}).get("severity", "low").lower()
        classification = vuln.get("info", {}).get("classification", {})
        
        if severity == "critical" or "rce" in classification.get("tags", []):
            return "High"
        elif severity in ["high", "medium"]:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_risk_level(self, severity: str, likelihood: str, impact: str) -> str:
        """Calculate overall risk level."""
        if severity.lower() == "critical" or (likelihood == "High" and impact == "High"):
            return "Critical"
        elif severity.lower() == "high" or (likelihood == "High" or impact == "High"):
            return "High"
        elif severity.lower() == "medium":
            return "Medium"
        else:
            return "Low"
    
    def _assign_priority(self, risk_level: str) -> str:
        """Assign remediation priority."""
        priority_map = {
            "Critical": "P0 - Immediate",
            "High": "P1 - 24-48h",
            "Medium": "P2 - 1-2 weeks",
            "Low": "P3 - Next cycle"
        }
        return priority_map.get(risk_level, "P3 - Next cycle")


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


def generate_comprehensive_report(output_dir: str, target: str) -> bool:
    """Generate advanced comprehensive security reports."""
    try:
        logger.info(f"Generating comprehensive security report for {target}")
        
        # Parse scan results
        results = parse_scan_results(output_dir)
        
        # Initialize advanced reporter
        reporter = AdvancedReporter(output_dir)
        
        # Generate comprehensive reports
        success = reporter.generate_comprehensive_report(results, target)
        
        if success:
            logger.info("Advanced report generation completed successfully")
        else:
            logger.warning("Advanced report generation completed with issues")
            
        return success
        
    except Exception as e:
        logger.error(f"Advanced report generation failed: {e}")
        logger.debug(traceback.format_exc())
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python reporter.py <results_directory> [target_name]")
        print("This script is also importable as a module for the AdvancedReporter class")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    target_name = sys.argv[2] if len(sys.argv) > 2 else "unknown"
    
    if not os.path.isdir(results_dir):
        logger.error(f"Error: {results_dir} is not a valid directory")
        sys.exit(1)
    
    # Generate both standard and comprehensive reports
    standard_success = generate_report(results_dir, target_name)
    comprehensive_success = generate_comprehensive_report(results_dir, target_name)
    
    if not standard_success and not comprehensive_success:
        logger.error("Both report generation methods had issues.")
        sys.exit(1)
    else:
        logger.info("Report generation completed")
        if standard_success:
            logger.info("Standard report generated successfully")
        if comprehensive_success:
            logger.info("Comprehensive report generated successfully")
