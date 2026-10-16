import unittest
from detector.security_rules import SecurityRuleEngine
from detector.rules import RuleEngine

class TestSecurityRules(unittest.TestCase):
    def setUp(self):
        self.sec_engine = SecurityRuleEngine()
        self.rule_engine = RuleEngine()

    # Rule 1: Insecure Form
    def test_insecure_form_action(self):
        form_elem = {
            "element_type": "form",
            "tag_name": "form",
            "text": "Login Form",
            "attributes": {"action": "http://example.com/api/login", "method": "POST"},
            "html_snippet": "<form action='http://example.com/api/login'>"
        }
        res = self.sec_engine.evaluate_element(form_elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Insecure Form")
        self.assertEqual(res["severity"], "HIGH")

    def test_insecure_password_input(self):
        input_elem = {
            "element_type": "input",
            "tag_name": "input",
            "text": "",
            "attributes": {"type": "password", "name": "pwd", "action": "http://insecure.test/login"},
            "html_snippet": "<input type='password' action='http://insecure.test/login'>"
        }
        res = self.sec_engine.evaluate_element(input_elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Insecure Form")

    # Rule 2: Hidden/Overlay Deception
    def test_hidden_iframe_overlay(self):
        iframe_elem = {
            "element_type": "iframe",
            "tag_name": "iframe",
            "text": "",
            "attributes": {"style": "opacity:0; position:absolute; width:100%; height:100%;", "src": "http://evil.com/trap"},
            "html_snippet": "<iframe style='opacity:0;' src='http://evil.com/trap'></iframe>"
        }
        res = self.sec_engine.evaluate_element(iframe_elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Hidden/Overlay Deception")

    def test_offscreen_clickable_link(self):
        link_elem = {
            "element_type": "link",
            "tag_name": "a",
            "text": "Hidden Clickjacking Trigger",
            "attributes": {"style": "position:absolute; left:-9999px; top:-9999px;", "href": "/unintended-action"},
            "html_snippet": "<a href='/unintended-action' style='left:-9999px;'>Hidden</a>"
        }
        res = self.sec_engine.evaluate_element(link_elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Hidden/Overlay Deception")

    # Rule 3: Deceptive Links
    def test_deceptive_mismatched_domain_link(self):
        link_elem = {
            "element_type": "link",
            "tag_name": "a",
            "text": "Visit paypal.com to secure your account",
            "attributes": {"href": "https://paypal-verify-account.phish.com/login"},
            "html_snippet": "<a href='https://paypal-verify-account.phish.com/login'>Visit paypal.com</a>"
        }
        res = self.sec_engine.evaluate_element(link_elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Deceptive Links")
        self.assertIn("paypal.com", res["explanation"])

    def test_punycode_homograph_link(self):
        link_elem = {
            "element_type": "link",
            "tag_name": "a",
            "text": "Secure Bank Login",
            "attributes": {"href": "https://xn--pple-43d.com/login"},
            "html_snippet": "<a href='https://xn--pple-43d.com/login'>Secure Bank Login</a>"
        }
        res = self.sec_engine.evaluate_element(link_elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Deceptive Links")

    # Rule 4: Cookie/Consent Manipulation
    def test_asymmetrical_cookie_consent(self):
        banner_elem = {
            "element_type": "button",
            "tag_name": "button",
            "text": "Accept All Cookies",
            "attributes": {"class": "cookie-banner-accept", "style": "color:#fff; font-size:0.7rem;"},
            "html_snippet": "<button class='cookie-banner-accept' style='font-size:0.7rem;'>Accept All Cookies</button>"
        }
        res = self.sec_engine.evaluate_element(banner_elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Cookie/Consent Manipulation")

    # Rule 5: Excessive Permission Prompts
    def test_unsolicited_notification_permission_script(self):
        script_elem = {
            "element_type": "script",
            "tag_name": "script",
            "text": "window.onload = function() { Notification.requestPermission(); };",
            "attributes": {},
            "html_snippet": "<script>Notification.requestPermission();</script>"
        }
        res = self.sec_engine.evaluate_element(script_elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Excessive Permission Prompts")

    def test_geolocation_permission_prompt(self):
        script_elem = {
            "element_type": "script",
            "tag_name": "script",
            "text": "navigator.geolocation.getCurrentPosition(trackUser);",
            "attributes": {},
            "html_snippet": "<script>navigator.geolocation.getCurrentPosition(trackUser);</script>"
        }
        res = self.sec_engine.evaluate_element(script_elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Excessive Permission Prompts")

    # Integration test with RuleEngine
    def test_rule_engine_integration(self):
        insecure_form = {
            "element_type": "form",
            "tag_name": "form",
            "text": "Submit Payment",
            "attributes": {"action": "http://payment.gateway/checkout"},
            "html_snippet": "<form action='http://payment.gateway/checkout'>"
        }
        res = self.rule_engine.evaluate_element(insecure_form)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Insecure Form")

if __name__ == "__main__":
    unittest.main()
