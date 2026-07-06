import json
import os
import time
import unittest
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright


BASE_URL = os.environ.get("E2E_BASE_URL", "http://127.0.0.1:8787")
VISUAL_VIEWPORTS = [
    ("mobile", {"width": 390, "height": 844}),
    ("desktop", {"width": 1280, "height": 800}),
    ("wide", {"width": 1920, "height": 1080}),
    ("ultra", {"width": 2560, "height": 1440}),
]


def server_available():
    try:
        with urlopen(BASE_URL, timeout=2) as response:
            return response.status < 500
    except (OSError, URLError):
        return False


def open_ready_page(page, path="/"):
    page.goto(f"{BASE_URL}{path}")
    page.locator("body[data-app-ready='true']").wait_for()


def class_name(locator):
    return locator.get_attribute("class") or ""


def wait_for_input_value(locator, expected_text, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = locator.input_value()
        if expected_text in value:
            return value
        time.sleep(0.1)
    raise AssertionError(f"Expected input value to contain {expected_text!r}")


def assert_no_horizontal_overflow(page):
    metrics = page.evaluate(
        """() => ({
            scrollWidth: document.documentElement.scrollWidth,
            clientWidth: document.documentElement.clientWidth,
            bodyWidth: document.body.getBoundingClientRect().width
        })"""
    )
    assert metrics["scrollWidth"] <= metrics["clientWidth"] + 1, metrics
    assert metrics["bodyWidth"] <= metrics["clientWidth"] + 1, metrics


def assert_visible_elements_inside_viewport(page, selectors):
    failures = page.evaluate(
        """(selectors) => {
            const width = document.documentElement.clientWidth;
            return selectors.flatMap((selector) =>
                Array.from(document.querySelectorAll(selector))
                    .filter((element) => {
                        const style = getComputedStyle(element);
                        const rect = element.getBoundingClientRect();
                        return style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0;
                    })
                    .filter((element) => {
                        const rect = element.getBoundingClientRect();
                        return rect.left < -1 || rect.right > width + 1;
                    })
                    .map((element) => ({
                        selector,
                        tag: element.tagName,
                        id: element.id,
                        className: element.className,
                        left: Math.round(element.getBoundingClientRect().left),
                        right: Math.round(element.getBoundingClientRect().right),
                        width
                    }))
            );
        }""",
        selectors,
    )
    assert failures == [], failures


def assert_valid_screenshot(page):
    image = page.screenshot(full_page=True)
    assert image.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(image) > 5000


def install_vault_api_mock(page, is_admin=False):
    state = {
        "envelope": None,
        "audit": [],
        "invites": [],
        "revision": None,
        "registration_open": False,
        "put_count": 0,
        "user": None,
    }

    def handle(route):
        request = route.request
        path = request.url.split("://", 1)[-1].split("/", 1)[-1]
        path = "/" + path.split("?", 1)[0]
        method = request.method.upper()

        if path in ["/api/auth/register", "/api/auth/login"] and method == "POST":
            body = json.loads(request.post_data or "{}")
            state["user"] = {
                "id": "e2e-admin" if is_admin else "e2e-user",
                "email": body.get("email", "e2e@example.com"),
                "isAdmin": is_admin,
            }
            return fulfill_json(route, {"user": state["user"]})

        if path == "/api/vault" and method == "GET":
            return fulfill_json(
                route,
                {
                    "envelope": state["envelope"],
                    "updatedAt": state["envelope"].get("updatedAt") if state["envelope"] else None,
                    "revision": state["revision"],
                },
            )

        if path == "/api/vault" and method == "PUT":
            body = json.loads(request.post_data or "{}")
            state["put_count"] += 1
            state["revision"] = f"rev-{state['put_count']}"
            state["envelope"] = body.get("envelope")
            return fulfill_json(route, {"ok": True, "updatedAt": state["envelope"].get("updatedAt"), "revision": state["revision"]})

        if path == "/api/auth/verify-password" and method == "POST":
            return fulfill_json(route, {"ok": True})

        if path == "/api/admin/settings" and method == "GET":
            return fulfill_json(route, {"registrationOpen": state["registration_open"], "adminEmailConfigured": True})

        if path == "/api/admin/settings" and method == "PUT":
            body = json.loads(request.post_data or "{}")
            state["registration_open"] = bool(body.get("registrationOpen"))
            state["audit"].insert(0, audit_event("admin_registration_setting_changed", {"registrationOpen": state["registration_open"]}))
            return fulfill_json(route, {"registrationOpen": state["registration_open"]})

        if path == "/api/admin/invites" and method == "GET":
            return fulfill_json(route, {"invites": state["invites"]})

        if path == "/api/admin/invites" and method == "POST":
            token = f"invite-token-{len(state['invites']) + 1}"
            invite = {"token": token, "createdAt": "2026-07-04T00:00:00.000Z", "expiresAt": "2026-07-11T00:00:00.000Z", "status": "active"}
            state["invites"].insert(0, invite)
            state["audit"].insert(0, audit_event("invite_created", {"userId": state["user"]["id"] if state["user"] else "e2e-admin"}))
            return fulfill_json(route, {"token": token, "expiresAt": invite["expiresAt"]})

        if path == "/api/admin/invites/revoke" and method == "POST":
            body = json.loads(request.post_data or "{}")
            for invite in state["invites"]:
                if invite["token"] == body.get("token"):
                    invite["status"] = "revoked"
                    invite["revokedAt"] = "2026-07-04T00:01:00.000Z"
            state["audit"].insert(0, audit_event("invite_revoked", {"userId": state["user"]["id"] if state["user"] else "e2e-admin"}))
            return fulfill_json(route, {"ok": True, "revokedAt": "2026-07-04T00:01:00.000Z"})

        if path == "/api/admin/audit" and method == "GET":
            return fulfill_json(route, {"events": state["audit"]})

        return fulfill_json(route, {"error": "Not found."}, status=404)

    page.route("**/api/**", handle)
    return state


def audit_event(event_type, details):
    return {
        "schemaVersion": 1,
        "id": f"audit-{time.time_ns()}",
        "type": event_type,
        "at": "2026-07-04T00:00:00.000Z",
        "details": details,
    }


def fulfill_json(route, data, status=200):
    route.fulfill(status=status, content_type="application/json", body=json.dumps(data))


@unittest.skipUnless(server_available(), f"E2E server is not available at {BASE_URL}")
class VaultUiSmokeTest(unittest.TestCase):
    def test_login_register_modes_are_separate(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            open_ready_page(page)
            page.locator("#inviteTokenRow").wait_for(state="attached")

            self.assertEqual(page.locator("#inviteTokenRow").count(), 1)
            self.assertIn("hidden", class_name(page.locator("#inviteTokenRow")))
            page.locator("#registerButton").click()
            self.assertNotIn("hidden", class_name(page.locator("#inviteTokenRow")))
            page.locator("#loginModeButton").click()
            self.assertIn("hidden", class_name(page.locator("#inviteTokenRow")))
            browser.close()

    def test_invite_link_opens_register_mode(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            token = "inviteTokenForE2eSmokeTest01"
            open_ready_page(page, f"/?invite={token}")

            self.assertNotIn("hidden", class_name(page.locator("#inviteTokenRow")))
            self.assertEqual(page.locator("#inviteToken").input_value(), token)
            self.assertIn("注册", page.locator("#unlockSubmitButton").inner_text())
            browser.close()

    def test_register_password_strength_feedback(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            open_ready_page(page)

            page.locator("#registerButton").click()
            self.assertNotIn("hidden", class_name(page.locator("#masterPasswordStrength")))
            page.locator("#loginPassword").fill("short")
            self.assertIn("弱密码", page.locator("#masterPasswordStrength").inner_text())
            page.locator("#loginPassword").fill("Very-long-passphrase-2026!")
            self.assertIn("强密码", page.locator("#masterPasswordStrength").inner_text())
            browser.close()

    def test_theme_toggle_changes_theme(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            open_ready_page(page)

            current_theme = page.evaluate("document.documentElement.dataset.theme")
            page.locator("#themeToggleButton").click()
            next_theme = page.evaluate("document.documentElement.dataset.theme")

            self.assertIn(current_theme, ["light", "dark"])
            self.assertIn(next_theme, ["light", "dark"])
            self.assertNotEqual(current_theme, next_theme)
            browser.close()

    def test_register_save_reload_and_login_restores_entry(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            api_state = install_vault_api_mock(page)
            email = f"vault-e2e-{int(time.time() * 1000)}@example.com"
            password = "Very-long-passphrase-2026!"

            open_ready_page(page)
            page.locator("#registerButton").click()
            page.locator("#loginEmail").fill(email)
            page.locator("#loginPassword").fill(password)
            page.locator("#unlockSubmitButton").click()
            page.locator("#lockedView.hidden").wait_for(state="attached")
            page.locator("#vaultNavButton").click()
            page.locator("#vaultView").wait_for()
            page.locator("#saveStatus").get_by_text("已同步").wait_for()

            page.locator("#entryName").fill("GitHub 主账号")
            page.locator("#entryLogin").fill("github@example.com")
            page.locator("button[data-detail-tab='secret']").click()
            page.locator("#entryPassword").fill("S3cure-passphrase-2026!")
            page.locator("#saveButton").click()
            page.locator("#saveStatus").get_by_text("已同步").wait_for()
            self.assertGreaterEqual(api_state["put_count"], 2)

            page.reload()
            page.locator("body[data-app-ready='true']").wait_for()
            page.locator("#loginEmail").fill(email)
            page.locator("#loginPassword").fill(password)
            page.locator("#unlockSubmitButton").click()
            page.locator("#lockedView.hidden").wait_for(state="attached")
            page.locator("#vaultNavButton").click()
            page.locator("#vaultView").wait_for()
            page.locator("#entryList").get_by_text("GitHub 主账号").wait_for()
            page.locator("#entryList").get_by_text("github@example.com").wait_for()
            browser.close()

    def test_admin_settings_invite_and_audit_flow(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            page.add_init_script(
                "Object.defineProperty(navigator, 'clipboard', { value: { writeText: async () => {}, readText: async () => '' }, configurable: true });"
            )
            api_state = install_vault_api_mock(page, is_admin=True)

            open_ready_page(page)
            page.locator("#registerButton").click()
            page.locator("#loginEmail").fill("admin@example.com")
            page.locator("#loginPassword").fill("Very-long-passphrase-2026!")
            page.locator("#unlockSubmitButton").click()
            page.locator("#lockedView.hidden").wait_for(state="attached")
            page.locator("#settingsNavButton").click()
            page.locator("#adminSettingsTab").click()
            page.locator("#adminPanel").wait_for()

            page.locator("#createInviteButton").click()
            wait_for_input_value(page.locator("#inviteLink"), "invite-token-1")
            self.assertIn("invite-token-1", page.locator("#inviteLink").input_value())
            page.locator("#inviteList").get_by_text("可用邀请").wait_for()

            page.locator("#inviteList").get_by_text("撤销").click()
            page.locator("#appDialogConfirm").click()
            page.locator("#inviteList").get_by_text("已撤销", exact=True).wait_for()

            page.locator("#registrationOpenToggle").click()
            page.locator("#dialog-password").fill("Very-long-passphrase-2026!")
            page.locator("#appDialogConfirm").click()
            page.locator("#adminSettingsStatus").get_by_text("当前允许新用户注册").wait_for()
            self.assertTrue(api_state["registration_open"])

            page.locator("#auditList").get_by_text("创建邀请").wait_for()
            page.locator("#auditList").get_by_text("撤销邀请").wait_for()
            page.locator("#auditList").get_by_text("注册设置变更").wait_for()
            browser.close()

    def test_mobile_layout_keeps_primary_controls_visible(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 390, "height": 844})
            open_ready_page(page)
            page.locator("#unlockForm").wait_for()

            self.assertTrue(page.locator("#unlockForm").is_visible())
            self.assertTrue(page.locator("#themeToggleButton").is_visible())
            self.assertTrue(page.locator("#unlockSubmitButton").is_visible())
            browser.close()

    def test_visual_layout_screenshots_across_viewports(self):
        page_selectors = [".topbar", ".app-page:not(.hidden)", ".panel", ".status-strip"]

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                for viewport_name, viewport in VISUAL_VIEWPORTS:
                    with self.subTest(viewport=viewport_name):
                        page = browser.new_page(viewport=viewport)
                        install_vault_api_mock(page, is_admin=True)
                        open_ready_page(page)

                        assert_no_horizontal_overflow(page)
                        assert_visible_elements_inside_viewport(page, [".topbar", "#lockedView", "#unlockForm"])
                        assert_valid_screenshot(page)

                        page.locator("#registerButton").click()
                        page.locator("#loginEmail").fill(f"visual-{viewport_name}@example.com")
                        page.locator("#loginPassword").fill("Very-long-passphrase-2026!")
                        page.locator("#unlockSubmitButton").click()
                        page.locator("#lockedView.hidden").wait_for(state="attached")

                        for nav_selector in ["#overviewNavButton", "#vaultNavButton", "#settingsNavButton"]:
                            page.locator(nav_selector).click()
                            assert_no_horizontal_overflow(page)
                            assert_visible_elements_inside_viewport(page, page_selectors)
                            assert_valid_screenshot(page)

                        page.close()
            finally:
                browser.close()


if __name__ == "__main__":
    try:
        unittest.main()
    except PlaywrightError as error:
        raise SystemExit(str(error))
