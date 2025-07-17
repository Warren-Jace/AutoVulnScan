import asyncio
import json
import random
from typing import Dict, Any, Optional
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
            await self.redis.delete(TAINT_MAP_KEY)

    async def start(self):
        """
        Starts the scanning process, ensuring authentication is shared.
        """
        try:
            self.redis = await RedisClient.create(self.settings.redis.url)
            # Only clear redis if the connection was successful and it's a fresh scan
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
            log.info("="*50)
            log.info("Phase 1: URL Discovery")
            await self.url_collector.collect_urls(str(self.settings.target.url))
            
            discovered_urls = await self.redis.smembers("avs:crawled_urls") if self.redis else set()
            log.info(f"Discovery phase complete. Found {len(discovered_urls)} URLs.")

            log.info("="*50)
            log.info("Phase 2: Injection")
            injection_tasks = [self._scan_url(url, "inject") for url in discovered_urls]
            await asyncio.gather(*injection_tasks)
            taint_map_size = await self.redis.hlen(TAINT_MAP_KEY) if self.redis else 0
            log.info(f"Injection phase complete. Taint map size: {taint_map_size}")

            log.info("="*50)
            log.info("Phase 3: Detection")
            all_urls_for_detection = await self.redis.smembers("avs:crawled_urls") if self.redis else discovered_urls
            detection_tasks = [self._scan_url(url, "detect") for url in all_urls_for_detection]
            await asyncio.gather(*detection_tasks)

            log.info("="*50)
            log.info("Generating report...")
            
            # --- Pass collected URLs to the report generator ---
            if self.url_collector:
                self.report_generator.set_crawled_urls(self.url_collector.crawled_urls)
                
                parameterized_urls = set()
                for url in self.url_collector.crawled_urls:
                    # A simple check to see if a URL has parameters
                    if '?' in url and '=' in url.split('?')[1]:
                        parameterized_urls.add(url)
                self.report_generator.set_parameterized_urls(parameterized_urls)
            # --- End of new code ---

            self.report_generator.generate(self.settings.reporting)
            log.info("Scan finished.")
        finally:
            log.info("Closing headless browser.")
            await self.headless_browser.stop()

    async def _scan_url(self, url: str, phase: str):
        assert self.redis is not None
        if phase == "inject":
            log.debug(f"Scanning URL for injection: {url}")
            try:
                headers = self._get_random_headers()
                response = await self.http_client.get(url, headers=headers, follow_redirects=True)
                response.raise_for_status()
                html_content = response.text
                injection_targets = self.param_extractor.extract(url, html_content)
                for target in injection_targets:
                    if target['type'] == 'url':
                        await self._inject_url_params(target)
                    elif target['type'] == 'form':
                        await self._inject_form(target)
            except httpx.RequestError as e:
                log.warning(f"Request failed during injection scan for {url}: {e}")
            except Exception as e:
                log.error(f"An unexpected error occurred during injection scan for {url}: {e}", exc_info=True)

        elif phase == "detect":
            log.debug(f"Scanning URL for detection: {url}")
            vulnerabilities = await self.xss_plugin.scan(url)
            for vuln in vulnerabilities:
                taint_id = vuln.param.get("taint_id")
                if taint_id and self.redis:
                    taint_info_json = await self.redis.hget(TAINT_MAP_KEY, taint_id)
                    if taint_info_json:
                        injection_info = json.loads(taint_info_json)
                        vuln.injection_url = injection_info.get("url", "")
                        vuln.param['name'] = injection_info.get("param", "")
                        vuln.payload = injection_info.get("payload", "")
                        log.critical(f"<red>Confirmed Stored XSS! Taint ID: {taint_id}, Injection: {vuln.injection_url}, Param: {vuln.param['name']}</red>")
                        self.report_generator.add_vulnerability(vuln)

    async def _inject_url_params(self, target: Dict[str, Any]):
        assert self.redis is not None
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
                await self.http_client.send(req)
                if self.redis:
                    taint_info = {"url": str(req.url), "param": param_to_inject['name'], "payload": payload, "type": "url"}
                    await self.redis.hset(TAINT_MAP_KEY, taint_id, json.dumps(taint_info))
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
                if method == 'post':
                    log.info(f"Injecting POST form: to {form_url} with param {param_to_inject['name']}")
                    await self.http_client.post(form_url, data=form_data, headers=headers)
                else:
                    log.info(f"Injecting GET form: to {form_url} with param {param_to_inject['name']}")
                    await self.http_client.get(form_url, params=form_data, headers=headers)
                if self.redis:
                    taint_info = {"url": form_url, "param": param_to_inject['name'], "payload": payload, "type": "form", "method": method}
                    await self.redis.hset(TAINT_MAP_KEY, taint_id, json.dumps(taint_info))
            except httpx.RequestError as e:
                log.warning(f"Failed to inject form to {form_url} with method {method.upper()}: {e}")
