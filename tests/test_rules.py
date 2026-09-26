import unittest
from detector.rules import RuleEngine

class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine()

    def test_urgency_detection(self):
        elem = {"text": "Hurry! Offer expires in 05:00", "element_type": "text_element", "tag_name": "div"}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Urgency")

    def test_scarcity_detection(self):
        elem = {"text": "Only 2 items left in stock", "element_type": "text_element", "tag_name": "div"}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Scarcity")

    def test_confirmshaming_detection(self):
        elem = {"text": "No, I don't want to save money and prefer paying full price", "element_type": "button", "tag_name": "button"}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Confirmshaming")

    def test_preselection_detection(self):
        elem = {"element_type": "checkbox", "tag_name": "input", "is_checked": True, "attributes": {"type": "checkbox", "name": "opt_in"}}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertIn(res["pattern"], ["Preselection", "Privacy Manipulation"])

    def test_misdirection_detection(self):
        elem = {"text": "Uncheck if you do not wish to receive marketing", "element_type": "link", "tag_name": "a"}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Misdirection")

    def test_privacy_manipulation_detection(self):
        elem = {"text": "Accept All Cookies and Share Personal Data with 500+ Ad Partners", "element_type": "button", "tag_name": "button"}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Privacy Manipulation")

    def test_forced_action_detection(self):
        elem = {"text": "You must create an account and subscribe to promotional emails to complete checkout", "element_type": "text"}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Forced Action")

    def test_normal_element_no_detection(self):
        elem = {"text": "View Product Details & Specifications", "element_type": "button", "tag_name": "button", "is_checked": False}
        res = self.engine.evaluate_element(elem)
        self.assertIsNone(res)

if __name__ == "__main__":
    unittest.main()
