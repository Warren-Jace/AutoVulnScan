import os
from typing import List
from jinja2 import Environment, FileSystemLoader
from plugins.base_plugin import Vulnerability
from core.logger import log

def render_html(vulnerabilities: List[Vulnerability], output_path: str):
    """
    Renders a list of vulnerabilities into an HTML report.
    """
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    # Setup Jinja2 environment
    # Assumes a 'templates' directory exists alongside this script
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    env = Environment(loader=FileSystemLoader(template_dir))
    
    try:
        template = env.get_template('report_template.html')
        report_content = template.render(vulnerabilities=vulnerabilities)
        
        report_file_path = os.path.join(output_path, 'scan_report.html')
        with open(report_file_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        log.info(f"HTML report successfully generated at: {report_file_path}")

    except Exception as e:
        log.error(f"Failed to generate HTML report: {e}")

# We also need the template file for this to work.
# Let's create a basic one.

def create_template_file_if_not_exists():
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    if not os.path.exists(template_dir):
        os.makedirs(template_dir)
        
    template_path = os.path.join(template_dir, 'report_template.html')
    
    if not os.path.exists(template_path):
        template_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoVulnScan Report</title>
    <style>
        body { font-family: sans-serif; margin: 2em; }
        h1 { color: #333; }
        .vulnerability { border: 1px solid #ccc; padding: 1em; margin-bottom: 1em; border-radius: 5px; }
        .vuln-title { font-size: 1.2em; font-weight: bold; color: #d9534f; }
        .details { margin-top: 1em; }
        pre { background-color: #f5f5f5; padding: 1em; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>AutoVulnScan Report</h1>
    {% for vuln in vulnerabilities %}
    <div class="vulnerability">
        <div class="vuln-title">{{ vuln.plugin_name }} - {{ vuln.confidence }} Confidence / {{ vuln.severity }} Severity</div>
        <div class="details">
            <p><strong>Description:</strong> {{ vuln.description }}</p>
            <p><strong>Injection URL:</strong> <a href="{{ vuln.injection_url }}">{{ vuln.injection_url }}</a></p>
            <p><strong>Trigger URL:</strong> <a href="{{ vuln.trigger_url }}">{{ vuln.trigger_url }}</a></p>
            <p><strong>Injected Parameter:</strong> <code>{{ vuln.param.name }}</code></p>
            <p><strong>Payload:</strong></p>
            <pre><code>{{ vuln.payload }}</code></pre>
        </div>
    </div>
    {% else %}
    <p>No vulnerabilities found.</p>
    {% endfor %}
</body>
</html>
"""
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)
        log.info(f"Created basic HTML report template at: {template_path}")

create_template_file_if_not_exists()



