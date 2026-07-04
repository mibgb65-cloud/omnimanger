import os
import unittest
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright


BASE_URL = os.environ.get("E2E_BASE_URL", "http://127.0.0.1:8787")


def server_available():
    try:
        with urlopen(BASE_URL, timeout=2) as response:
            return response.status < 500
    except (OSError, URLError):
        return False


@unittest.skipUnless(server_available(), f"E2E server is not available at {BASE_URL}")
class VaultUiSmokeTest(unittest.TestCase):
    def test_login_register_modes_are_separate(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            page.goto(BASE_URL)

            self.assertEqual(page.locator("#inviteTokenRow").count(), 1)
            self.assertIn("hidden", page.locator("#inviteTokenRow").get_attribute("class"))
            page.locator("#registerButton").click()
            self.assertNotIn("hidden", page.locator("#inviteTokenRow").get_attribute("class"))
            page.locator("#loginModeButton").click()
            self.assertIn("hidden", page.locator("#inviteTokenRow").get_attribute("class"))
            browser.close()

    def test_mobile_layout_keeps_primary_controls_visible(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.goto(BASE_URL)

            self.assertTrue(page.locator("#unlockForm").is_visible())
            self.assertTrue(page.locator("#themeToggleButton").is_visible())
            self.assertTrue(page.locator("#unlockSubmitButton").is_visible())
            browser.close()


if __name__ == "__main__":
    try:
        unittest.main()
    except PlaywrightError as error:
        raise SystemExit(str(error))
