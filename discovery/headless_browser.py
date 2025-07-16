from playwright.async_api import async_playwright, Page, Browser
from typing import Optional, List
from core.logger import log

class HeadlessBrowser:
    """
    Manages a headless browser instance (Playwright) for rendering pages
    and detecting JavaScript events like 'alert'.
    """
    _browser: Optional[Browser] = None
    _triggered_alerts: List[str] = []

    async def start(self):
        """Initializes the browser."""
        if not self._browser:
            p = await async_playwright().start()
            self._browser = await p.chromium.launch()
            log.info("Headless browser (Chromium) started.")

    async def stop(self):
        """Stops the browser."""
        if self._browser:
            await self._browser.close()
            self._browser = None
            log.info("Headless browser stopped.")

    async def check_url_for_alert(self, url: str) -> List[str]:
        """
        Navigates to a URL and listens for any 'alert' events.

        Args:
            url: The URL to check.

        Returns:
            A list of messages from any triggered alerts.
        """
        if not self._browser:
            raise RuntimeError("Browser is not started. Call start() first.")

        self._triggered_alerts = []
        page = await self._browser.new_page()

        # Listen for the 'dialog' event, which includes alerts, confirms, etc.
        page.on("dialog", self._handle_dialog)

        try:
            log.debug(f"Checking for alerts on: {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            # Give some time for scripts to execute
            await page.wait_for_timeout(2000) 
        except Exception as e:
            log.warning(f"Error navigating to {url} in headless browser: {e}")
        finally:
            await page.close()

        return self._triggered_alerts

    async def _handle_dialog(self, dialog):
        """Callback to handle dialogs and capture their message."""
        if dialog.type == "alert":
            log.warning(f"Alert dialog triggered with message: {dialog.message}")
            self._triggered_alerts.append(dialog.message)
        await dialog.dismiss()



