from typing import List

from plugins.base_plugin import Vulnerability
from core.logger import log
from core.config_loader import ReportingConfig
# from .html_renderer import render_html
# from .json_exporter import export_json
# from .markdown_renderer import render_markdown
# from .notification_service import send_notifications


class ReportGenerator:
    """
    Generates scan reports in various formats.
    """
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def add_vulnerability(self, vulnerability: Vulnerability):
        """
        Adds a found vulnerability to the report.
        """
        self.vulnerabilities.append(vulnerability)
        log.info(f"Vulnerability added to report: {vulnerability.plugin_name} at {vulnerability.trigger_url}")

    def generate(self, config: ReportingConfig):
        """
        Generates the final report(s) based on the configuration.
        """
        log.info(f"Generating reports in formats: {config.format}")
        if not self.vulnerabilities:
            log.info("No vulnerabilities found, skipping report generation.")
            return

        for fmt in config.format:
            if fmt == 'html':
                self._generate_html(config.path)
            elif fmt == 'json':
                self._generate_json(config.path)
            # Add other formats like md here
        log.info(f"Reports saved to directory: {config.path}")

    def _generate_html(self, path: str):
        # Placeholder for HTML report generation
        log.debug(f"Generating HTML report at {path}...")

    def _generate_json(self, path: str):
        # Placeholder for JSON report generation
        log.debug(f"Generating JSON report at {path}...")
