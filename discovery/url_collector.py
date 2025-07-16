import asyncio
from typing import Set
import httpx
from bs4 import BeautifulSoup, Tag
from urllib.parse import urljoin, urlparse

from core.logger import log


class URLCollector:
    """
    Collects URLs from a starting URL by recursively crawling pages.
    """

    def __init__(self, start_url: str, max_depth: int = 2):
        """
        Initializes the URLCollector.

        Args:
            start_url: The URL to start crawling from.
            max_depth: The maximum depth to crawl.
        """
        self.start_url = start_url
        self.max_depth = max_depth
        self.visited: Set[str] = set()
        self.domain = urlparse(start_url).netloc

    async def collect(self) -> Set[str]:
        """
        Starts the URL collection process.

        Returns:
            A set of discovered URLs.
        """
        log.info(f"Starting URL collection from: {self.start_url}")
        await self._crawl(self.start_url, 0)
        log.info(f"URL collection finished. Found {len(self.visited)} URLs.")
        return self.visited

    async def _crawl(self, url: str, depth: int):
        """
        Recursively crawls a URL to discover new links.

        Args:
            url: The URL to crawl.
            depth: The current crawl depth.
        """
        if url in self.visited or depth > self.max_depth:
            return

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, follow_redirects=True)
                response.raise_for_status()

            self.visited.add(url)
            log.debug(f"Crawling: {url} at depth {depth}")

            soup = BeautifulSoup(response.text, 'html.parser')
            tasks = []
            for link in soup.find_all('a', href=True):
                if isinstance(link, Tag):
                    href = link.get('href')
                    if not href or not isinstance(href, str):
                        continue
                    
                    full_url = urljoin(url, href)
                    
                    if urlparse(full_url).netloc == self.domain:
                        tasks.append(self._crawl(full_url, depth + 1))
            
            await asyncio.gather(*tasks)

        except httpx.HTTPError as e:
            log.warning(f"HTTP error while crawling {url}: {e}")
        except Exception as e:
            log.error(f"An unexpected error occurred while crawling {url}: {e}")
