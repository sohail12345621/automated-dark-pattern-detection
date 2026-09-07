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
        self.assertEqual(res["severity"], "HIGH")

    def test_scarcity_detection(self):
        elem = {"text": "Hurry! Only 2 items left in stock", "element_type": "text_element", "tag_name": "div"}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        # Note: Rule search order will match first matching rule
        self.assertIn(res["pattern"], ["Urgency", "Scarcity"])

        elem_pure_scarcity = {"text": "Only 2 items left in stock", "element_type": "text_element", "tag_name": "div"}
        res_scarcity = self.engine.evaluate_element(elem_pure_scarcity)
        self.assertEqual(res_scarcity["pattern"], "Scarcity")

    def test_confirmshaming_detection(self):
        elem = {"text": "No, I don't want to save money and prefer paying full price", "element_type": "button", "tag_name": "button"}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Confirmshaming")

    def test_preselection_detection(self):
        elem = {"element_type": "checkbox", "tag_name": "input", "is_checked": True, "attributes": {"type": "checkbox", "name": "newsletter"}}
        res = self.engine.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Preselection")

    def test_normal_element_no_detection(self):
        elem = {"text": "View Product & Add to Cart", "element_type": "button", "tag_name": "button", "is_checked": False}
        res = self.engine.evaluate_element(elem)
        self.assertIsNone(res)

if __name__ == "__main__":
    unittest.main()
