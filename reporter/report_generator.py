from typing import List, Set
import os
from plugins.base_plugin import Vulnerability
from core.logger import log
from core.config_loader import ReportingConfig
from .html_renderer import render_html
from .json_exporter import export_json
from .markdown_renderer import render_markdown
# from .notification_service import send_notifications


class ReportGenerator:
    """
    Generates scan reports in various formats.
    """
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.crawled_urls: Set[str] = set()
        self.parameterized_urls: Set[str] = set()

    def add_vulnerability(self, vulnerability: Vulnerability):
        """
        Adds a found vulnerability to the report.
        """
        self.vulnerabilities.append(vulnerability)
        log.info(f"Vulnerability added to report: {vulnerability.plugin_name} at {vulnerability.trigger_url}")

    def set_crawled_urls(self, urls: Set[str]):
        """
        Sets the set of all crawled URLs.
        """
        self.crawled_urls = urls

    def set_parameterized_urls(self, urls: Set[str]):
        """
        Sets the set of all URLs with parameters.
        """
        self.parameterized_urls = urls
    
    def generate(self, config: ReportingConfig):
        """
        Generates the final report(s) based on the configuration.
        """
        os.makedirs(config.path, exist_ok=True)
        
        self._save_urls_to_file(self.crawled_urls, os.path.join(config.path, "crawled_urls.txt"))
        self._save_urls_to_file(self.parameterized_urls, os.path.join(config.path, "parameterized_urls.txt"))

        if not self.vulnerabilities:
            log.info("No vulnerabilities were found to generate a report.")
            return

        log.info(f"Found {len(self.vulnerabilities)} vulnerabilities. Generating reports in formats: {config.format}")
        for fmt in config.format:
            if fmt == 'html':
                render_html(self.vulnerabilities, config.path)
            elif fmt == 'json':
                export_json(self.vulnerabilities, config.path)
            elif fmt == 'md':
                render_markdown(self.vulnerabilities, config.path)
        log.info(f"Reports saved to directory: {config.path}")

    def _save_urls_to_file(self, urls: Set[str], file_path: str):
        if not urls:
            return
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                for url in sorted(list(urls)):
                    f.write(url + '\\n')
            log.info(f"Successfully saved {len(urls)} URLs to {file_path}")
        except IOError as e:
            log.error(f"Failed to save URLs to {file_path}: {e}")
