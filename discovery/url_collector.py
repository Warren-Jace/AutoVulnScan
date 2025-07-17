import asyncio
from typing import Set, Optional
import httpx
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin, urlparse
from redis.asyncio import Redis as AsyncRedis
import logging

from core.logger import log
from core.redis_client import RedisClient
from discovery.headless_browser import HeadlessBrowser


class URLCollector:
    """
    Collects URLs from a given starting point, using both static analysis and headless browsing.
    """
    def __init__(self, http_client: httpx.AsyncClient, redis: Optional[RedisClient], headless_browser: HeadlessBrowser):
        self.http_client = http_client
        self.redis = redis
        self.headless_browser = headless_browser
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # In-memory cache for when Redis is not available
        self.crawled_urls: Set[str] = set()
        self.uncrawled_urls: Set[str] = set()

    async def collect_urls(self, base_url: str):
        """
        Crawls a URL using both static and dynamic analysis to find new URLs.
        It starts with a base_url and continues until no new URLs are found within the same domain.
        """
        if self.redis:
            await self.redis.sadd("avs:uncrawled_urls", base_url)
        else:
            self.uncrawled_urls.add(base_url)

        while True:
            url_to_crawl = None
            if self.redis:
                url_to_crawl = await self.redis.spop("avs:uncrawled_urls")
            else:
                if self.uncrawled_urls:
                    url_to_crawl = self.uncrawled_urls.pop()

            if not url_to_crawl:
                break # No more URLs to crawl

            is_crawled = False
            if self.redis:
                is_crawled = await self.redis.sismember("avs:crawled_urls", url_to_crawl)
            else:
                is_crawled = url_to_crawl in self.crawled_urls

            if is_crawled:
                continue

            self.logger.info(f"Crawling: {url_to_crawl}")
            if self.redis:
                await self.redis.sadd("avs:crawled_urls", url_to_crawl)
            else:
                self.crawled_urls.add(url_to_crawl)

            # 1. Static Crawling with httpx
            try:
                response = await self.http_client.get(url_to_crawl)
                soup = BeautifulSoup(response.text, 'html.parser')
                await self._extract_and_add_urls(url_to_crawl, soup)
            except httpx.RequestError as e:
                self.logger.error(f"HTTP request failed for {url_to_crawl}: {e}")
            except Exception as e:
                self.logger.error(f"Error during static crawling of {url_to_crawl}: {e}")

            # 2. Dynamic Crawling with Headless Browser
            try:
                page_content = await self.headless_browser.get_page_content(url_to_crawl)
                if page_content:
                    soup = BeautifulSoup(page_content, 'html.parser')
                    await self._extract_and_add_urls(url_to_crawl, soup)
            except Exception as e:
                self.logger.error(f"Error during dynamic crawling of {url_to_crawl}: {e}")

    async def _extract_and_add_urls(self, base_url: str, soup: BeautifulSoup):
        base_domain = urlparse(base_url).netloc
        for a_tag in soup.find_all('a', href=True):
            if not isinstance(a_tag, Tag):
                continue
            href = a_tag.get('href')
            if not isinstance(href, str) or href.startswith(('javascript:', 'mailto:', '#')):
                continue

            absolute_url = urljoin(base_url, href)
            url_domain = urlparse(absolute_url).netloc

            if url_domain == base_domain:
                is_member = False
                if self.redis:
                    is_member = await self.redis.sismember("avs:crawled_urls", absolute_url)
                else:
                    is_member = absolute_url in self.crawled_urls or absolute_url in self.uncrawled_urls

                if not is_member:
                    if self.redis:
                        await self.redis.sadd("avs:uncrawled_urls", absolute_url)
                    else:
                        self.uncrawled_urls.add(absolute_url)
                    self.logger.debug(f"Discovered new URL: {absolute_url}")
