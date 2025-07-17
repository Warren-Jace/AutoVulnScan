import asyncio
import json
import random
from typing import Dict, Any, Optional, List, Set

from urllib.parse import urlparse
import httpx
from redis.asyncio import Redis as AsyncRedis

from core.config_loader import Settings
from core.logger import log
from core.redis_client import RedisClient
from discovery.url_collector import URLCollector
from extractor.param_extractor import ParamExtractor
from payload.generator import PayloadGenerator
from plugins.xss_plugin import XSSPlugin
from discovery.headless_browser import HeadlessBrowser
from reporter.report_generator import ReportGenerator

# Define Redis keys for state management
URLS_KEY = "scan:discovered_urls"
TAINT_MAP_KEY = "scan:taint_map"


class Orchestrator:
    """
    Coordinates the entire scanning process using Redis for state persistence.
    """

    def __init__(self, settings: Settings):
        """
        Initializes the Orchestrator with the given configuration.
        """
        self.settings = settings
        transport = httpx.AsyncHTTPTransport(retries=settings.scanner.retries)
        
        cookies_dict = {}
        if settings.target.auth and settings.target.auth.type == "cookie":
            cookies_dict = {
                cookie.split('=')[0].strip(): cookie.split('=', 1)[1].strip()
                for cookie in settings.target.auth.value.split(';')
            }

        self.http_client = httpx.AsyncClient(
            transport=transport,
            timeout=settings.scanner.timeout,
            cookies=cookies_dict,
            verify=False,
            follow_redirects=True
        )

        self.param_extractor = ParamExtractor()
        self.payload_generator = PayloadGenerator(settings.ai_module)
        
        # Prepare cookies for Playwright
        pw_cookies = []
        if settings.target.auth and settings.target.auth.type == "cookie":
            domain = urlparse(str(settings.target.url)).netloc
            for name, value in cookies_dict.items():
                pw_cookies.append({"name": name, "value": value, "domain": domain, "path": "/"})
        
        self.headless_browser = HeadlessBrowser(cookies=pw_cookies)
        self.xss_plugin = XSSPlugin(headless_browser=self.headless_browser)
        self.report_generator = ReportGenerator()
        self.redis: Optional[RedisClient] = None
        self.url_collector: Optional[URLCollector] = None

    def _get_random_headers(self) -> Dict[str, str]:
        if not self.settings.scanner.user_agents:
            return {}
        return {"User-Agent": random.choice(self.settings.scanner.user_agents)}

    async def _clear_redis_for_fresh_scan(self):
        if self.redis:
            log.info("Starting fresh scan, clearing Redis data.")
            # Keys are managed by respective components, but Orchestrator can signal a clear
            await self.redis.delete("avs:crawled_urls")
            await self.redis.delete("avs:uncrawled_urls")
            await self.redis.delete("avs:discovered_params")
            await self.redis.delete(TAINT_MAP_KEY)

    async def start(self):
        """
        Starts the scanning process, ensuring authentication is shared.
        """
        try:
            self.redis = await RedisClient.create(self.settings.redis.url)
            if self.settings.advanced.dry_run:
                await self._clear_redis_for_fresh_scan()
        except Exception as e:
            log.warning(f"Could not connect to Redis: {e}. State will not be persisted.")
            self.redis = None

        self.url_collector = URLCollector(
            http_client=self.http_client,
            redis=self.redis,
            headless_browser=self.headless_browser
        )
        
        log.info(f"Starting scan for target: {self.settings.target.url}")
        
        await self.headless_browser.start()
        try:
            # Phase 1: Discovery - Collect URLs and identify potential injection points
            injection_points = await self._perform_discovery()

            # Phase 2: Injection - Inject payloads into discovered points
            await self._perform_injection(injection_points)
            
            # Phase 3: Detection - Check for vulnerabilities resulting from injections
            await self._perform_detection()

            # --- Reporting ---
            log.info("="*50)
            log.info("Generating report...")
            await self._generate_reports()
            log.info("Scan finished.")

        finally:
            log.info("Closing headless browser.")
            await self.headless_browser.stop()

    async def _perform_discovery(self) -> List[Dict[str, Any]]:
        """
        Phase 1: Crawl the target and extract potential injection points.
        This phase ONLY collects information, no injections are performed.
        """
        log.info("="*50)
        log.info("Phase 1: Discovery - Collecting URLs and Parameters")
        assert self.url_collector is not None, "URLCollector not initialized"
        await self.url_collector.collect_urls(str(self.settings.target.url))
        
        crawled_urls = set()
        if self.redis:
            crawled_urls = await self.redis.smembers("avs:crawled_urls")
            # Sync back to the collector's in-memory set for consistency
            self.url_collector.crawled_urls = crawled_urls
        else:
            crawled_urls = self.url_collector.crawled_urls
            
        log.info(f"Discovery phase complete. Found {len(crawled_urls)} URLs.")

        all_injection_points = []
        for url in crawled_urls:
            try:
                headers = self._get_random_headers()
                response = await self.http_client.get(url, headers=headers, follow_redirects=True)
                response.raise_for_status()  # Raise an exception for bad status codes
                
                html_content = response.text
                injection_points = self.param_extractor.extract(url, html_content)
                all_injection_points.extend(injection_points)
                
            except httpx.HTTPStatusError as e:
                log.warning(f"HTTP error during parameter extraction for {url}: {e}")
            except httpx.RequestError as e:
                log.warning(f"Request failed during parameter extraction for {url}: {e}")
        
        log.info(f"Found {len(all_injection_points)} potential injection points.")
        if self.redis:
            # Store for potential reuse or analysis
            await self.redis.set("avs:discovered_params", json.dumps(all_injection_points))
        return all_injection_points

    async def _perform_injection(self, injection_points: List[Dict[str, Any]]):
        """
        Phase 2: Inject payloads into the identified injection points.
        """
        log.info("="*50)
        log.info(f"Phase 2: Injection - Testing {len(injection_points)} injection points")
        
        injection_tasks = []
        for point in injection_points:
            if point['type'] == 'url':
                injection_tasks.append(self._inject_url_params(point))
            elif point['type'] == 'form':
                injection_tasks.append(self._inject_form(point))
        
        await asyncio.gather(*injection_tasks)
        
        taint_map_size = await self.redis.hlen(TAINT_MAP_KEY) if self.redis else 0
        log.info(f"Injection phase complete. Taint map size: {taint_map_size}")

    async def _perform_detection(self):
        """
        Phase 3: Re-crawl the site to detect if any injected payloads were triggered.
        """
        log.info("="*50)
        log.info("Phase 3: Detection - Checking for triggered payloads")
        
        assert self.url_collector is not None, "URLCollector not initialized"
        all_urls_for_detection = self.url_collector.crawled_urls
        detection_tasks = []
        for url in all_urls_for_detection:
            log.debug(f"Scanning URL for detection: {url}")
            vulnerabilities = await self.xss_plugin.scan(url)
            for vuln in vulnerabilities:
                taint_id = vuln.param.get("taint_id")
                if taint_id and self.redis:
                    taint_info_json = await self.redis.hget(TAINT_MAP_KEY, taint_id)
                    if taint_info_json:
                        injection_info = json.loads(taint_info_json)
                        log.critical(f"<red>Stored XSS Detected! Initial injection at: {injection_info.get('url')}, reflected at: {url}</red>")
                        vuln.injection_url = injection_info.get("url", "")
                        vuln.param['name'] = injection_info.get("param", "")
                        vuln.payload = injection_info.get("payload", "")
                        self.report_generator.add_vulnerability(vuln)

    async def _generate_reports(self):
        """
        Collects final data and generates all specified reports.
        """
        if self.url_collector:
            self.report_generator.set_crawled_urls(self.url_collector.crawled_urls)
            
            parameterized_urls = set()
            # This logic should be improved to use the injection points data
            for url in self.url_collector.crawled_urls:
                if '?' in url and '=' in url.split('?')[1]:
                    parameterized_urls.add(url)
            self.report_generator.set_parameterized_urls(parameterized_urls)
        
        self.report_generator.generate(self.settings.reporting)

    async def _inject_url_params(self, target: Dict[str, Any]):
        if not self.redis:
            return
        base_url = target['url'].split('?')[0]
        original_params = {p['name']: p['value'] for p in target['params']}
        for param_to_inject in target['params']:
            payload, taint_id = self.payload_generator.generate_xss_payload()
            injected_params = original_params.copy()
            injected_params[param_to_inject['name']] = payload
            try:
                headers = self._get_random_headers()
                req = self.http_client.build_request("GET", base_url, params=injected_params, headers=headers)
                log.info(f"Injecting GET param: {param_to_inject['name']} at {req.url}")
                
                # Send the request and immediately check for vulnerabilities
                await self.http_client.send(req)
                await self._check_for_vulnerabilities(str(req.url), taint_id, "url", param_to_inject['name'], payload)

            except httpx.RequestError as e:
                log.warning(f"Failed to inject GET parameter {param_to_inject['name']} at {base_url}: {e}")

    async def _inject_form(self, target: Dict[str, Any]):
        if not self.redis:
            return
        form_url = target['url']
        method = target['method']
        for param_to_inject in target['params']:
            payload, taint_id = self.payload_generator.generate_xss_payload()
            form_data = {p['name']: "AutoVulnScanDefault" for p in target['params']}
            form_data[param_to_inject['name']] = payload
            try:
                headers = self._get_random_headers()
                response = None
                if method == 'post':
                    log.info(f"Injecting POST form: to {form_url} with param {param_to_inject['name']}")
                    response = await self.http_client.post(form_url, data=form_data, headers=headers)
                else:
                    log.info(f"Injecting GET form: to {form_url} with param {param_to_inject['name']}")
                    response = await self.http_client.get(form_url, params=form_data, headers=headers)
                
                # Immediately check the response URL for vulnerabilities
                await self._check_for_vulnerabilities(str(response.url), taint_id, "form", param_to_inject['name'], payload, method)

            except httpx.RequestError as e:
                log.warning(f"Failed to inject form to {form_url} with method {method.upper()}: {e}")

    async def _check_for_vulnerabilities(self, url: str, taint_id: str, inj_type: str, param_name: str, payload: str, method: str = 'GET'):
        """Helper to check for vulnerabilities and log them."""
        vulnerabilities = await self.xss_plugin.scan(url)
        if vulnerabilities:
            log.critical(f"<red>Reflected XSS Detected! URL: {url}, Param: {param_name}</red>")
            for vuln in vulnerabilities:
                vuln.injection_url = url
                vuln.param['name'] = param_name
                vuln.payload = payload
                self.report_generator.add_vulnerability(vuln)
        
        # Also save taint info for potential stored XSS detection later
        if self.redis:
            taint_info = {"url": url, "param": param_name, "payload": payload, "type": inj_type, "method": method}
            await self.redis.hset(TAINT_MAP_KEY, taint_id, json.dumps(taint_info))
