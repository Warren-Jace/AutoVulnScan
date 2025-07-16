from typing import List
from discovery.headless_browser import HeadlessBrowser
from plugins.base_plugin import BasePlugin, Vulnerability

class XSSPlugin(BasePlugin):
    """
    XSS detection plugin that uses a headless browser to detect alerts.
    """

    @property
    def name(self) -> str:
        return "xss"

    def __init__(self, headless_browser: HeadlessBrowser):
        super().__init__()
        self.headless_browser = headless_browser

    async def scan(self, url: str) -> List[Vulnerability]:
        """
        Scans a given URL for XSS vulnerabilities by detecting alert pop-ups.

        Args:
            url: The URL to scan.

        Returns:
            A list of vulnerabilities found.
        """
        vulnerabilities: List[Vulnerability] = []
        alert_contents = await self.headless_browser.check_url_for_alert(url)
        
        for alert_content in alert_contents:
            if "avs-taint-" in alert_content:
                taint_id = alert_content.strip()
                vuln = Vulnerability(
                    plugin_name="XSS",
                    description=f"Taint-tracked alert detected with ID: {taint_id}",
                    injection_url="", # This will be filled by the orchestrator
                    trigger_url=url,
                    param={"name": "", "taint_id": taint_id}, # Pass taint_id here
                    payload="", # This will be filled by the orchestrator
                    confidence="High",
                    severity="High"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities



