import os
from typing import List
from plugins.base_plugin import Vulnerability
from core.logger import log

def render_markdown(vulnerabilities: List[Vulnerability], output_path: str):
    """
    Renders a list of vulnerabilities into a Markdown report.
    """
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    
    report_file_path = os.path.join(output_path, 'scan_report.md')
    
    content = ["# AutoVulnScan Report\n\n"]
    
    if not vulnerabilities:
        content.append("No vulnerabilities found.\n")
    else:
        for vuln in vulnerabilities:
            content.append(f"## {vuln.plugin_name} - {vuln.severity} Severity\n")
            content.append(f"**Description:** {vuln.description}\n\n")
            content.append(f"**Injection URL:** `{vuln.injection_url}`\n\n")
            content.append(f"**Trigger URL:** `{vuln.trigger_url}`\n\n")
            content.append(f"**Parameter:** `{vuln.param.get('name', 'N/A')}`\n\n")
            content.append("**Payload:**\n")
            content.append(f"```\n{vuln.payload}\n```\n\n")
            content.append("---\n\n")
            
    try:
        with open(report_file_path, 'w', encoding='utf-8') as f:
            f.write("".join(content))
        log.info(f"Markdown report successfully generated at: {report_file_path}")
    except Exception as e:
        log.error(f"Failed to generate Markdown report: {e}")



