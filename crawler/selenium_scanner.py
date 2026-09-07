import os
import time
import uuid
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class SeleniumScanner:
    """Automated Webpage Scanner & DOM Extractor using Selenium."""

    def __init__(self, headless=True, timeout=15):
        self.headless = headless
        self.timeout = timeout

    def _get_driver(self):
        options = Options()
        if self.headless:
            options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(self.timeout)
        return driver

    def scan_url(self, url, screenshots_dir="screenshots"):
        """
        Navigates to URL, waits for rendering, extracts visible UI elements,
        and captures screenshot evidence.
        """
        driver = None
        result = {
            "success": False,
            "url": url,
            "error": None,
            "page_title": "",
            "total_elements": 0,
            "elements": [],
            "page_screenshot_path": None
        }

        try:
            driver = self._get_driver()
            driver.get(url)

            # Wait for document body to be present
            WebDriverWait(driver, self.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(1) # Brief pause for dynamic script rendering

            result["page_title"] = driver.title or url

            # Capture initial page screenshot
            os.makedirs(screenshots_dir, exist_ok=True)
            screenshot_filename = f"scan_{uuid.uuid4().hex[:8]}.png"
            screenshot_full_path = os.path.join(screenshots_dir, screenshot_filename)
            driver.save_screenshot(screenshot_full_path)
            result["page_screenshot_path"] = f"screenshots/{screenshot_filename}"

            # Extract DOM UI elements
            elements_data = self._extract_elements(driver)
            result["elements"] = elements_data
            result["total_elements"] = len(elements_data)
            result["success"] = True

        except Exception as e:
            result["error"] = str(e)
        finally:
            if driver:
                driver.quit()

        return result

    def _extract_elements(self, driver):
        """Extracts text, buttons, links, forms, and inputs from the DOM."""
        extracted = []

        # Target selectors for UI components
        selectors = [
            ("button", "//button | //input[@type='button' or @type='submit'] | //*[@role='button']"),
            ("link", "//a[@href]"),
            ("checkbox", "//input[@type='checkbox']"),
            ("radio", "//input[@type='radio']"),
            ("form", "//form"),
            ("text_element", "//p | //span | //h1 | //h2 | //h3 | //h4 | //h5 | //h6 | //div | //b | //strong | //em | //label | //li")
        ]

        visited_elements = set()

        for category, xpath in selectors:
            try:
                web_elements = driver.find_elements(By.XPATH, xpath)
                for elem in web_elements:
                    try:
                        # Skip hidden or zero-size elements
                        if not elem.is_displayed():
                            continue

                        elem_id = elem.id
                        if elem_id in visited_elements:
                            continue
                        visited_elements.add(elem_id)

                        text_content = elem.text.strip() if elem.text else ""
                        tag_name = elem.tag_name.lower()
                        
                        # Get attributes
                        outer_html = elem.get_attribute("outerHTML") or ""
                        if len(outer_html) > 500:
                            outer_html = outer_html[:500] + "..."

                        is_checked = False
                        if tag_name == "input" and elem.get_attribute("type") in ["checkbox", "radio"]:
                            is_checked = elem.is_selected()

                        # Avoid registering huge containers without direct text unless relevant
                        if tag_name in ["div", "form"] and not text_content and not is_checked:
                            continue

                        extracted.append({
                            "element_type": category,
                            "tag_name": tag_name,
                            "text": text_content,
                            "is_checked": is_checked,
                            "html_snippet": outer_html,
                            "attributes": {
                                "id": elem.get_attribute("id") or "",
                                "class": elem.get_attribute("class") or "",
                                "name": elem.get_attribute("name") or "",
                                "type": elem.get_attribute("type") or "",
                                "value": elem.get_attribute("value") or "",
                                "href": elem.get_attribute("href") or "",
                                "role": elem.get_attribute("role") or ""
                            }
                        })
                    except Exception:
                        continue
            except Exception:
                continue

        return extracted
