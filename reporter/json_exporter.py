import os
import json
from typing import List
from plugins.base_plugin import Vulnerability
from core.logger import log

def export_json(vulnerabilities: List[Vulnerability], output_path: str):
    """
    Exports a list of vulnerabilities to a JSON file.
    """
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    
    report_file_path = os.path.join(output_path, 'scan_report.json')
    
    report_data = []
    for vuln in vulnerabilities:
        report_data.append({
            "plugin_name": vuln.plugin_name,
            "description": vuln.description,
            "injection_url": vuln.injection_url,
            "trigger_url": vuln.trigger_url,
            "param": vuln.param,
            "payload": vuln.payload,
            "confidence": vuln.confidence,
            "severity": vuln.severity
        })

    try:
        with open(report_file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4)
        log.info(f"JSON report successfully generated at: {report_file_path}")
    except Exception as e:
        log.error(f"Failed to generate JSON report: {e}")



