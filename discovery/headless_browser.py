from typing import List, Dict, Any, Optional

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright

from core.logger import log


class HeadlessBrowser:
    """
    Manages a headless browser instance using Playwright.
    """

    def __init__(self, cookies: Optional[List[Dict[str, Any]]] = None):
        """
        Initializes the HeadlessBrowser.
        
        Args:
            cookies: A list of cookies to be set in the browser context.
        """
        self.cookies = cookies
        self.p: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None

    async def start(self):
        """
        Initializes the browser and a browser context, optionally with cookies.
        """
        if self._browser:
            return
        
        self.p = await async_playwright().start()
        try:
            self._browser = await self.p.chromium.launch(headless=True)
            self._context = await self._browser.new_context()
            if self.cookies:
                # Ensure cookies are in the correct format for Playwright
                playwright_cookies = []
                for cookie in self.cookies:
                    if all(k in cookie for k in ['name', 'value', 'domain']):
                        playwright_cookies.append(cookie)
                if playwright_cookies:
                    await self._context.add_cookies(playwright_cookies)
        except Exception as e:
            log.error(f"Failed to start Playwright: {e}")
            await self.stop()
            raise

    async def stop(self):
        """Stops the browser and closes the context."""
        if self._context:
            await self._context.close()
            self._context = None
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self.p:
            await self.p.stop()
            self.p = None
        log.info("Headless browser stopped.")

    async def check_url_for_alert(self, url: str) -> List[str]:
        """
        Navigates to a URL and listens for any 'alert' events using the shared context.
        """
        if not self._context:
            raise RuntimeError("Browser context is not started. Call start() first.")

        triggered_alerts: List[str] = []
        page: Optional[Page] = None

        async def handle_dialog(dialog):
            """Inner function to handle dialogs as a closure."""
            if dialog.type == "alert":
                page_url = page.url if page else "unknown url"
                log.critical(f"Intercepted alert on {page_url}: '{dialog.message}'")
                if "avs-taint-" in dialog.message:
                    triggered_alerts.append(dialog.message)
            await dialog.dismiss()

        try:
            page = await self._context.new_page()
            page.on("dialog", handle_dialog)

            log.debug(f"Checking for alerts on: {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=60000)
            
        except Exception as e:
            log.warning(f"Error navigating to {url} in headless browser: {e}")
        finally:
            if page:
                await page.close()

        return triggered_alerts

    async def get_page_content(self, url: str) -> str:
        """
        Navigates to a URL, waits for the page to load, and returns its content.
        """
        if not self._browser or not self._context:
            raise Exception("Browser is not started. Call start() first.")
        
        page = await self._context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=60000)
            content = await page.content()
            return content
        except Exception as e:
            log.error(f"Error getting page content for {url}: {e}")
            return ""
        finally:
            await page.close()

    async def JUMP_IN_HERE__discover_xss(self, url: str) -> Optional[str]:
        """
        Opens a URL and listens for alert dialogs, returning the message if one appears.
        """
        if not self._browser or not self._context:
            raise Exception("Browser is not started. Call start() first.")

        page = await self._context.new_page()
        
        triggered_alert_message: Optional[str] = None

        async def handle_dialog(dialog):
            """Inner function to handle dialogs as a closure."""
            if dialog.type == "alert":
                page_url = page.url if page else "unknown url"
                log.critical(f"Intercepted alert on {page_url}: '{dialog.message}'")
                if "avs-taint-" in dialog.message:
                    nonlocal triggered_alert_message
                    triggered_alert_message = dialog.message
            await dialog.dismiss()
        
        page.on('dialog', handle_dialog)

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=60000)
            # Wait for a short period to allow any post-load JS to execute
            await page.wait_for_timeout(2000)
        except Exception as e:
            log.error(f"Error navigating to {url} in discover_xss: {e}")
        finally:
            await page.close()

        return triggered_alert_message

    async def close(self):
        """
        Closes the browser instance.
        """
        await self.stop()



