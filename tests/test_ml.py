import unittest
from detector.ml_classifier import MLClassifier

class TestMLClassifier(unittest.TestCase):
    def setUp(self):
        self.classifier = MLClassifier()

    def test_model_loaded(self):
        self.assertTrue(self.classifier.is_loaded, "ML model should be loaded from disk")
        self.assertIn("test_accuracy", self.classifier.metrics)
        self.assertGreaterEqual(self.classifier.metrics["test_accuracy"], 0.80)

    def test_urgency_classification(self):
        elem = {"text": "Hurry! Offer expires in 05:00 minutes!", "element_type": "text"}
        res = self.classifier.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Urgency")
        self.assertEqual(res["source"], "ML")

    def test_privacy_classification(self):
        elem = {"text": "We value your privacy: Accept All Cookies & Data Selling", "element_type": "button"}
        res = self.classifier.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Privacy Manipulation")

    def test_misdirection_classification(self):
        elem = {"text": "Uncheck this box if you DO NOT wish to NOT receive promotional offers", "element_type": "text"}
        res = self.classifier.evaluate_element(elem)
        self.assertIsNotNone(res)
        self.assertEqual(res["pattern"], "Misdirection")

    def test_normal_text_classification(self):
        elem = {"text": "View Product Specifications and User Manual", "element_type": "button"}
        res = self.classifier.evaluate_element(elem)
        self.assertIsNone(res, "Normal UI text should not be flagged by ML classifier")

if __name__ == "__main__":
    unittest.main()
