import asyncio
from typing import Set, Dict, Any
import httpx
from core.config_loader import Settings
from core.logger import log
from discovery.url_collector import URLCollector
from extractor.param_extractor import ParamExtractor
from payload.generator import PayloadGenerator
from plugins.xss_plugin import XSSPlugin
from discovery.headless_browser import HeadlessBrowser
from reporter.report_generator import ReportGenerator


class Orchestrator:
    """
    Coordinates the entire scanning process.
    """

    def __init__(self, settings: Settings):
        """
        Initializes the Orchestrator with the given configuration.
        """
        self.settings = settings
        self.url_collector = URLCollector(str(settings.target.url), max_depth=settings.target.depth)
        self.param_extractor = ParamExtractor()
        self.payload_generator = PayloadGenerator(settings.ai_module)
        self.headless_browser = HeadlessBrowser()
        self.xss_plugin = XSSPlugin(headless_browser=self.headless_browser)
        self.http_client = httpx.AsyncClient(
            timeout=settings.scanner.timeout,
            verify=False # Defaulting to False as it's not in scanner config
        )
        self.report_generator = ReportGenerator()

        self.phase = "discover"  # discover -> inject -> detect
        self.discovered_urls: Set[str] = set()
        self.taint_map: Dict[str, Dict[str, Any]] = {}

    async def start(self):
        """
        Starts the scanning process.
        """
        log.info(f"Starting scan for target: {self.settings.target.url}")
        log.info("="*50)
        log.info("Phase 1: URL Discovery")
        self.phase = "discover"
        self.discovered_urls = await self.url_collector.collect()
        log.info(f"Discovery phase complete. Found {len(self.discovered_urls)} URLs.")

        log.info("="*50)
        log.info("Phase 2: Injection")
        self.phase = "inject"
        # In injection phase, we re-crawl to submit forms and params
        injection_tasks = [self._scan_url(url) for url in self.discovered_urls]
        await asyncio.gather(*injection_tasks)
        log.info(f"Injection phase complete. Taint map size: {len(self.taint_map)}")

        log.info("="*50)
        log.info("Phase 3: Detection")
        self.phase = "detect"
        detection_tasks = [self._scan_url(url) for url in self.discovered_urls]
        await asyncio.gather(*detection_tasks)

        log.info("="*50)
        log.info("Generating report...")
        self.report_generator.generate(self.settings.reporting)
        log.info("Scan finished.")

    async def _scan_url(self, url: str):
        if self.phase == "inject":
            log.debug(f"Scanning URL for injection: {url}")
            try:
                # First, get the page content
                response = await self.http_client.get(url, follow_redirects=True)
                response.raise_for_status()
                html_content = response.text

                # Extract URL params and forms
                injection_targets = self.param_extractor.extract(url, html_content)

                for target in injection_targets:
                    if target['type'] == 'url':
                        await self._inject_url_params(target)
                    elif target['type'] == 'form':
                        await self._inject_form(target)

            except httpx.RequestError as e:
                log.warning(f"Request failed during injection scan for {url}: {e}")
            except Exception as e:
                log.error(f"An unexpected error occurred during injection scan for {url}: {e}")

        elif self.phase == "detect":
            log.debug(f"Scanning URL for detection: {url}")
            vulnerabilities = await self.xss_plugin.scan(url)
            for vuln in vulnerabilities:
                # Extract taint_id from the param dictionary
                taint_id = vuln.param.get("taint_id")
                if taint_id and taint_id in self.taint_map:
                    # Enrich vulnerability data with injection point info
                    injection_info = self.taint_map[taint_id]
                    vuln.injection_url = injection_info.get("url", "")
                    vuln.param['name'] = injection_info.get("param", "")
                    vuln.payload = injection_info.get("payload", "")
                    
                    log.critical(f"Confirmed Stored XSS! Taint ID: {taint_id}, Injection: {vuln.injection_url}, Param: {vuln.param['name']}")
                
                self.report_generator.add_vulnerability(vuln)

    async def _inject_url_params(self, target: Dict[str, Any]):
        base_url = target['url'].split('?')[0]
        original_params = {p['name']: p['value'] for p in target['params']}

        for param_to_inject in target['params']:
            payload, taint_id = self.payload_generator.generate_xss_payload()

            # Create a copy of the params and inject the payload
            injected_params = original_params.copy()
            injected_params[param_to_inject['name']] = payload

            try:
                req = self.http_client.build_request("GET", base_url, params=injected_params)
                log.info(f"Injecting GET param: {param_to_inject['name']} at {req.url}")
                await self.http_client.send(req)

                self.taint_map[taint_id] = {
                    "url": str(req.url),
                    "param": param_to_inject['name'],
                    "payload": payload,
                    "type": "url"
                }
            except httpx.RequestError as e:
                log.warning(f"Failed to inject GET parameter {param_to_inject['name']} at {base_url}: {e}")

    async def _inject_form(self, target: Dict[str, Any]):
        form_url = target['url']
        method = target['method']
        
        for param_to_inject in target['params']:
            payload, taint_id = self.payload_generator.generate_xss_payload()

            # Prepare form data
            form_data = {}
            # Assign payload to the parameter we are currently injecting
            form_data[param_to_inject['name']] = payload
            
            # Fill other parameters with default values (can be improved later)
            for p in target['params']:
                if p['name'] != param_to_inject['name']:
                    form_data[p['name']] = "AutoVulnScanDefault"

            try:
                if method == 'post':
                    log.info(f"Injecting POST form: to {form_url} with param {param_to_inject['name']}")
                    await self.http_client.post(form_url, data=form_data)
                else:  # 'get'
                    log.info(f"Injecting GET form: to {form_url} with param {param_to_inject['name']}")
                    await self.http_client.get(form_url, params=form_data)
                
                self.taint_map[taint_id] = {
                    "url": form_url,
                    "param": param_to_inject['name'],
                    "payload": payload,
                    "type": "form",
                    "method": method
                }
            except httpx.RequestError as e:
                log.warning(f"Failed to inject form to {form_url} with method {method.upper()}: {e}")
